#include <arpa/inet.h>
#include <assert.h>
#include <stdio.h>

#include "obnat8.bpf.skel.h"
#include <bpf/libbpf.h>
#include <net/if.h>
#include <signal.h>
#include <sys/resource.h>

int if_index;
struct obnat8_bpf *obnat8;


void sig_handler(int sig) {
  bpf_xdp_detach(if_index, 0, NULL);
  obnat8_bpf__destroy(obnat8);
  exit(0);
}

void bump_memlock_rlimit(void) {
  struct rlimit rlim_new = {
      .rlim_cur = RLIM_INFINITY,
      .rlim_max = RLIM_INFINITY,
  };

  if (setrlimit(RLIMIT_MEMLOCK, &rlim_new)) {
    fprintf(stderr, "Failed to increase RLIMIT_MEMLOCK limit!\n");
    exit(1);
  }
  if (setrlimit(RLIMIT_STACK, &rlim_new)) {
    fprintf(stderr, "Failed to increase RLIMIT_STACK limit!\n");
    exit(1);
  }
  if (setrlimit(RLIMIT_DATA, &rlim_new)) {
    fprintf(stderr, "Failed to increase RLIMIT_DATA limit!\n");
    exit(1);
  }
  if (setrlimit(RLIMIT_AS, &rlim_new)) {
    fprintf(stderr, "Failed to increase RLIMIT_AS limit!\n");
    exit(1);
  }
}

#define INTERNO 0x0a0a0100 //
#define EXTERNO 0x0a0a0200 //

int fill_tbl(struct bpf_map *map, char *filename) {
  FILE *file = fopen(filename, "r");
  if (!file) {
    fprintf(stderr, "Failed to open file\n");
    return 1;
  }

  char *line;
  size_t len = 0;
  size_t read;
  int n = 0;
  while ((read = getline(&line, &len, file)) != -1) {
    int inutile_valore = (n % 2) ? INTERNO : EXTERNO;
    __be32 ip = inet_addr(line);
    int err = bpf_map__update_elem(map, &ip, sizeof(ip), &inutile_valore,
                                   sizeof(ip), BPF_ANY);
    if (err) {
      fprintf(stderr, "Failed to update map\n");
      return err;
    }
    n++;
  }

  fclose(file);
  return 0;
}

int main(int argc, char **argv) {

  int err;
  if (argc < 2) {
    fprintf(stderr, "Usage: %s <ifname> <file_tbl>\n", argv[0]);
    return 1;
  }

  bump_memlock_rlimit();

  obnat8 = obnat8_bpf__open_and_load();

  if (!obnat8) {
    fprintf(stderr, "Failed to open and load BPF object\n");
    return 1;
  }

  if_index = if_nametoindex(argv[1]);
  if (!if_index) {
    fprintf(stderr, "Failed to get ifindex of %s\n", argv[1]);
    return 1;
  }

  err = fill_tbl(obnat8->maps.external_map, argv[2]);
  if (err) {
    fprintf(stderr, "Failed to fill external map\n");
    return 1;
  }

  err = bpf_xdp_attach(if_index, bpf_program__fd(obnat8->progs.obnat8), 0, NULL);
  if (err) {
    fprintf(stderr, "Failed to attach BPF program\n");
    return 1;
  }

  printf("BPF program attached\n");

  signal(SIGINT, sig_handler);
  signal(SIGTERM, sig_handler);

  while (1)
    ;

  return 0;
}
