// This macro is required to include <immintrin.h> in the kernel
#ifdef __clang__
#define __MM_MALLOC_H
#else
#define _MM_MALLOC_H_INCLUDED
#endif

#include <asm/fpu/api.h>
#include <immintrin.h>
#include <linux/btf.h>
#include <linux/btf_ids.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <x86intrin.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Author");
MODULE_DESCRIPTION("xxhash64 SIMD (16 packets in parallel)");

/*
 * xxhash64 over the 16-byte padded 5-tuple, computed for 16 packets at once.
 *
 * Layout:
 *   buf : 16 packets, each 16 bytes = 2 x u64, contiguous (array-of-structs)
 *         index order: [k0_0 k1_0 k0_1 k1_1 ... k0_15 k1_15]
 *   out : 16 x u64, one hash per packet.
 *
 * Each of the 16 streams runs an independent xxhash64 "short input" chain
 * (len < 32) laid out one-per-lane across two ZMM registers (8 lanes each).
 * There are NO inter-lane permutes inside the hash body, only lane-wise ops,
 * so all 16 chains are fully independent and throughput-bound.
 *
 * The math has been validated bit-exactly against libxxhash (xxh64, seeded)
 * on 16-byte inputs, and the SIMD core validated against that scalar path.
 */

// xxhash64 primes (64-bit). The 32-bit primes in the old code were incorrect
// for xxhash64 and MUST NOT be used here.
#define PRIME64_1 0x9E3779B185EBCA87ULL
#define PRIME64_2 0xC2B2AE3D27D4EB4FULL
#define PRIME64_3 0x165667B19E3779F9ULL
#define PRIME64_4 0x85EBCA77C2B2AE63ULL
#define PRIME64_5 0x27D4EB2F165667C5ULL

// Fixed input length for the seeded short-path accumulator init.
#define XXH_INPUT_LEN 16ULL

__bpf_kfunc void xxhash16x16(const __u64 *buf, __u32 seed, __u64 *out);

/*
 * One xxhash64 8-byte round applied lane-wise to a whole ZMM (8 streams):
 *   k   = rotl64(k * PRIME64_2, 31) * PRIME64_1
 *   acc = rotl64(acc ^ k, 27) * PRIME64_1 + PRIME64_4
 */
#define XXH_ROUND(acc, K, P1, P2, P4)                                          \
  do {                                                                         \
    __m512i _k = _mm512_mullo_epi64((K), (P2));                                \
    _k = _mm512_rol_epi64(_k, 31);                                             \
    _k = _mm512_mullo_epi64(_k, (P1));                                         \
    (acc) = _mm512_xor_si512((acc), _k);                                       \
    (acc) = _mm512_rol_epi64((acc), 27);                                       \
    (acc) = _mm512_mullo_epi64((acc), (P1));                                   \
    (acc) = _mm512_add_epi64((acc), (P4));                                     \
  } while (0)

/*
 * xxhash64 final avalanche, lane-wise:
 *   acc ^= acc >> 33; acc *= PRIME64_2;
 *   acc ^= acc >> 29; acc *= PRIME64_3;
 *   acc ^= acc >> 32;
 * This step is what makes the four 16-bit sub-hashes of each result mutually
 * independent, which the count-min sketch relies on. Do not remove it.
 */
#define XXH_AVALANCHE(acc, P2, P3)                                             \
  do {                                                                         \
    (acc) = _mm512_xor_si512((acc), _mm512_srli_epi64((acc), 33));             \
    (acc) = _mm512_mullo_epi64((acc), (P2));                                   \
    (acc) = _mm512_xor_si512((acc), _mm512_srli_epi64((acc), 29));             \
    (acc) = _mm512_mullo_epi64((acc), (P3));                                   \
    (acc) = _mm512_xor_si512((acc), _mm512_srli_epi64((acc), 32));             \
  } while (0)

/*
 * De-interleave the contiguous AoS buffer into SoA fields using vpermi2q.
 * Faster than strided gather on Sapphire Rapids. 256 bytes = 4 ZMM loads.
 */
static __always_inline void xxh_deinterleave(const __u64 *buf, __m512i *k0_lo,
                                             __m512i *k0_hi, __m512i *k1_lo,
                                             __m512i *k1_hi) {
  __m512i z0 = _mm512_loadu_si512((const void *)(buf + 0));
  __m512i z1 = _mm512_loadu_si512((const void *)(buf + 8));
  __m512i z2 = _mm512_loadu_si512((const void *)(buf + 16));
  __m512i z3 = _mm512_loadu_si512((const void *)(buf + 24));

  // even lane indices -> k0 fields, odd -> k1 fields (across the src pair)
  const __m512i ev = _mm512_setr_epi64(0, 2, 4, 6, 8, 10, 12, 14);
  const __m512i od = _mm512_setr_epi64(1, 3, 5, 7, 9, 11, 13, 15);

  *k0_lo = _mm512_permutex2var_epi64(z0, ev, z1);
  *k1_lo = _mm512_permutex2var_epi64(z0, od, z1);
  *k0_hi = _mm512_permutex2var_epi64(z2, ev, z3);
  *k1_hi = _mm512_permutex2var_epi64(z2, od, z3);
}

__bpf_kfunc void xxhash16x16(const __u64 *buf, __u32 seed, __u64 *out) {
  const __m512i P1 = _mm512_set1_epi64(PRIME64_1);
  const __m512i P2 = _mm512_set1_epi64(PRIME64_2);
  const __m512i P3 = _mm512_set1_epi64(PRIME64_3);
  const __m512i P4 = _mm512_set1_epi64(PRIME64_4);

  kernel_fpu_begin();

  __m512i k0_lo, k0_hi, k1_lo, k1_hi;
  xxh_deinterleave(buf, &k0_lo, &k0_hi, &k1_lo, &k1_hi);

  // acc = seed + PRIME64_5 + len, broadcast to all 16 lanes
  __m512i acc_lo = _mm512_set1_epi64((__u64)seed + PRIME64_5 + XXH_INPUT_LEN);
  __m512i acc_hi = acc_lo;

  // two 8-byte rounds (16-byte input), interleaved lo/hi for ILP
  XXH_ROUND(acc_lo, k0_lo, P1, P2, P4);
  XXH_ROUND(acc_hi, k0_hi, P1, P2, P4);
  XXH_ROUND(acc_lo, k1_lo, P1, P2, P4);
  XXH_ROUND(acc_hi, k1_hi, P1, P2, P4);

  XXH_AVALANCHE(acc_lo, P2, P3);
  XXH_AVALANCHE(acc_hi, P2, P3);

  _mm512_storeu_si512((__m512i *)(out + 0), acc_lo);
  _mm512_storeu_si512((__m512i *)(out + 8), acc_hi);

  kernel_fpu_end();
}

/*
 * Alternative load path using strided gather instead of vpermi2q.
 * Kept for benchmarking; identical results. Uncomment the body call in the
 * kfunc above if you want to compare.
 */
__bpf_kfunc void xxhash16x16_gather(const __u64 *buf, __u32 seed, __u64 *out);
__bpf_kfunc void xxhash16x16_gather(const __u64 *buf, __u32 seed, __u64 *out) {
  const __m512i P1 = _mm512_set1_epi64(PRIME64_1);
  const __m512i P2 = _mm512_set1_epi64(PRIME64_2);
  const __m512i P3 = _mm512_set1_epi64(PRIME64_3);
  const __m512i P4 = _mm512_set1_epi64(PRIME64_4);

  const __m512i idx_lo = _mm512_setr_epi64(0, 2, 4, 6, 8, 10, 12, 14);
  const __m512i idx_hi = _mm512_setr_epi64(16, 18, 20, 22, 24, 26, 28, 30);
  const __m512i one = _mm512_set1_epi64(1);

  kernel_fpu_begin();

  __m512i k0_lo = _mm512_i64gather_epi64(idx_lo, buf, 8);
  __m512i k0_hi = _mm512_i64gather_epi64(idx_hi, buf, 8);
  __m512i k1_lo = _mm512_i64gather_epi64(_mm512_add_epi64(idx_lo, one), buf, 8);
  __m512i k1_hi = _mm512_i64gather_epi64(_mm512_add_epi64(idx_hi, one), buf, 8);

  __m512i acc_lo = _mm512_set1_epi64((__u64)seed + PRIME64_5 + XXH_INPUT_LEN);
  __m512i acc_hi = acc_lo;

  XXH_ROUND(acc_lo, k0_lo, P1, P2, P4);
  XXH_ROUND(acc_hi, k0_hi, P1, P2, P4);
  XXH_ROUND(acc_lo, k1_lo, P1, P2, P4);
  XXH_ROUND(acc_hi, k1_hi, P1, P2, P4);

  XXH_AVALANCHE(acc_lo, P2, P3);
  XXH_AVALANCHE(acc_hi, P2, P3);

  _mm512_storeu_si512((__m512i *)(out + 0), acc_lo);
  _mm512_storeu_si512((__m512i *)(out + 8), acc_hi);

  kernel_fpu_end();
}

BTF_SET8_START(bpf_task_set)
BTF_ID_FLAGS(func, xxhash16x16)
BTF_ID_FLAGS(func, xxhash16x16_gather)
BTF_SET8_END(bpf_task_set)

static const struct btf_kfunc_id_set bpf_task_kfunc_set = {
    .owner = THIS_MODULE,
    .set = &bpf_task_set,
};

static int __init xxhash_avx_init(void) {
  register_btf_kfunc_id_set(BPF_PROG_TYPE_XDP, &bpf_task_kfunc_set);
  pr_info("xxhash64 16x module loaded\n");
  return 0;
}

static void __exit xxhash_avx_exit(void) {
  pr_info("xxhash64 16x module unloaded\n");
}

module_init(xxhash_avx_init);
module_exit(xxhash_avx_exit);