#include <bpf/libbpf.h>
#include <net/if.h>
#include <signal.h>
#include <stdio.h>
#include <sys/resource.h>
#include "pobconntrack.bpf.skel.h"
#include "conntrack_bpf_log.h"
#include "conntrack_common.h"


int if_index;
struct pobconntrack_bpf *pobconntrack;

void sig_handler(int sig)
{
	bpf_xdp_detach(if_index, 0, NULL);
	pobconntrack_bpf__destroy(pobconntrack);
	exit(0);
}

void bump_memlock_rlimit(void)
{
	struct rlimit rlim_new = {
		.rlim_cur = RLIM_INFINITY,
		.rlim_max = RLIM_INFINITY,
	};

	if (setrlimit(RLIMIT_MEMLOCK, &rlim_new))
	{
		fprintf(stderr, "Failed to increase RLIMIT_MEMLOCK limit!\n");
		exit(1);
	}
	if (setrlimit(RLIMIT_STACK, &rlim_new))
	{
		fprintf(stderr, "Failed to increase RLIMIT_STACK limit!\n");
		exit(1);
	}
	if (setrlimit(RLIMIT_DATA, &rlim_new))
	{
		fprintf(stderr, "Failed to increase RLIMIT_DATA limit!\n");
		exit(1);
	}
	if (setrlimit(RLIMIT_AS, &rlim_new))
	{
		fprintf(stderr, "Failed to increase RLIMIT_AS limit!\n");
		exit(1);
	}
}
int main(int argc, char **argv)
{
	struct pobconntrack_bpf *skel;
	int err;
	if (argc < 2)
	{
		fprintf(stderr, "Usage: %s <ifname>\n", argv[0]);
		return 1;
	}

	bump_memlock_rlimit();

	// pobconntrack = pobconntrack_bpf__open_and_load();
	// if (!pobconntrack)
	// {
	// 	fprintf(stderr, "Failed to open and load BPF object\n");
	// 	return 1;
	// }

	skel = pobconntrack_bpf__open();
	if (!skel) {
		fprintf(stderr, "Failed to open BPF skeleton\n");
		return 1;
	}
	
	// Set log level
	// skel->rodata->pobconntrack_cfg.log_level = DEBUG;
	//prints only bpf_log_err
	// skel->rodata->conntrack_cfg.log_level = ERR;
	//prints nothing
	skel->rodata->conntrack_cfg.log_level = DISABLED;

	err = pobconntrack_bpf__load(skel);
    if (err) {
        fprintf(stderr,"Failed to load XDP program\n");
        return 1;
    }

	if_index = if_nametoindex(argv[1]);
	if (!if_index)
	{
		fprintf(stderr, "Failed to get ifindex of %s\n", argv[1]);
		return 1;
	}

	err = bpf_xdp_attach(if_index, bpf_program__fd(skel->progs.pobconntrack), 0, NULL);
	if (err)
	{
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
