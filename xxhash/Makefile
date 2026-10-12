obj-m += xxhash_avx.o
GCC_VERSION ?= 13
CLANG_VERSION ?= 18.1.3
CC_SIMD_OPTS ?= -mno-red-zone -mavx2 -mavx512vl -mavx512dq -mbmi -mavx512f -mavx512bw -mtune=generic -mavx512ifma
ifeq ($(LLVM),1)
ccflags-y += -I/usr/lib/llvm-$(shell echo $(CLANG_VERSION) | cut -d. -f1)/lib/clang/$(CLANG_VERSION)/include $(CC_SIMD_OPTS)
else
ccflags-y += -I/usr/lib/gcc/x86_64-linux-gnu/$(GCC_VERSION)/include $(CC_SIMD_OPTS)
endif


all:
	@echo "Building  xxhash_avx..."
	@echo "$(ccflags-y)"
	bear -- make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	@echo "Cleaning  xxhash_avx..."
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean

load:
	sudo insmod xxhash_avx.ko

unload:
	sudo rmmod xxhash_avx.ko

reload:
	sudo rmmod xxhash_avx.ko
	sudo insmod xxhash_avx.ko
