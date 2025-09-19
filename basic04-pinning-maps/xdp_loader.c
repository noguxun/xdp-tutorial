/* SPDX-License-Identifier: GPL-2.0 */
static const char *__doc__ = "XDP loader\n"
	" - Allows selecting BPF program --progname name to XDP-attach to --dev\n";

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <getopt.h>

#include <locale.h>
#include <unistd.h>
#include <time.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <xdp/libxdp.h>

#include <net/if.h>
#include <linux/if_link.h> /* depend on kernel-headers installed */

#include "../common/common_params.h"
#include "../common/common_user_bpf_xdp.h"
#include "../common/common_libbpf.h"
#include "common_kern_user.h"

static const char *default_filename = "xdp_prog_kern.o";

static const struct option_wrapper long_options[] = {

	{{"help",        no_argument,		NULL, 'h' },
	 "Show help", false},

	{{"dev",         required_argument,	NULL, 'd' },
	 "Operate on device <ifname>", "<ifname>", true},

	{{"skb-mode",    no_argument,		NULL, 'S' },
	 "Install XDP program in SKB (AKA generic) mode"},

	{{"native-mode", no_argument,		NULL, 'N' },
	 "Install XDP program in native mode"},

	{{"auto-mode",   no_argument,		NULL, 'A' },
	 "Auto-detect SKB or native mode"},

	{{"force",       no_argument,		NULL, 'F' },
	 "Force install, replacing existing program on interface"},

	{{"unload",      required_argument,	NULL, 'U' },
	 "Unload XDP program <id> instead of loading", "<id>"},

	{{"quiet",       no_argument,		NULL, 'q' },
	 "Quiet mode (no output)"},

	{{"filename",    required_argument,	NULL,  1  },
	 "Load program from <file>", "<file>"},

	{{"progname",    required_argument,	NULL,  2  },
	 "Load program from function <name> in the ELF file", "<name>"},

	{{0, 0, NULL,  0 }, NULL, false}
};

#ifndef PATH_MAX
#define PATH_MAX	4096
#endif

const char *pin_basedir =  "/sys/fs/bpf";
const char *map_name    =  "xdp_stats_map";


/* Load BPF and XDP program with map reuse - returns program FD */
int load_bpf_and_xdp_attach_reuse_maps(struct config *cfg, const char *pin_dir, struct bpf_object **obj_out)
{
	int err = 0;
	struct bpf_object *obj = NULL;
	struct bpf_program *prog = NULL;
	int prog_fd = -1;

	if (!cfg || !cfg->filename[0] || !cfg->progname[0] || !pin_dir) {
		fprintf(stderr, "ERR: invalid arguments\n");
		return -1;
	}

	/* 1) Open the object, but do NOT load yet */
	DECLARE_LIBBPF_OPTS(bpf_object_open_opts, open_opts);
	obj = bpf_object__open_file(cfg->filename, &open_opts);
	if (libbpf_get_error(obj)) {
		err = -libbpf_get_error(obj);
		fprintf(stderr, "ERR: bpf_object__open_file(%s): %s\n",
			cfg->filename, strerror(-err));
		return -1;
	}

	/* 2) Try to reuse the specific map */
	struct bpf_map *map = bpf_object__find_map_by_name(obj, map_name);
	if (map) {
		char map_path[PATH_MAX];
		int len = snprintf(map_path, PATH_MAX, "%s/%s", pin_dir, map_name);
		if (len < 0 || len >= PATH_MAX) {
			fprintf(stderr, "ERR: map path too long\n");
			err = -ENAMETOOLONG;
			goto cleanup;
		}

		int pinned_map_fd = bpf_obj_get(map_path);
		if (pinned_map_fd >= 0) {
			err = bpf_map__reuse_fd(map, pinned_map_fd);
			if (err) {
				close(pinned_map_fd);
				fprintf(stderr, "ERR: bpf_map__reuse_fd: %s\n", strerror(-err));
				goto cleanup;
			}
			if (verbose)
				printf(" - Reusing pinned map: %s\n", map_path);
		}
	}

	/* 3) Load the object now that maps have been injected */
	err = bpf_object__load(obj);
	if (err) {
		fprintf(stderr, "ERR: bpf_object__load: %s\n", strerror(-err));
		goto cleanup;
	}

	/* 4) Find the program by name */
	prog = bpf_object__find_program_by_name(obj, cfg->progname);
	if (!prog) {
		fprintf(stderr, "ERR: cannot find program '%s'\n", cfg->progname);
		err = -ENOENT;
		goto cleanup;
	}

	prog_fd = bpf_program__fd(prog);
	if (prog_fd < 0) {
		fprintf(stderr, "ERR: bpf_program__fd: %s\n", strerror(errno));
		err = -1;
		goto cleanup;
	}

	/* 5) Attach to XDP */
	err = bpf_xdp_attach(cfg->ifindex, prog_fd, cfg->attach_mode, NULL);
	if (err) {
		fprintf(stderr, "ERR: bpf_xdp_attach(ifindex=%d): %s\n",
			cfg->ifindex, strerror(-err));
		goto cleanup;
	}

	/* Success - pass object back to caller for map pinning */
	*obj_out = obj;
	return prog_fd;

cleanup:
	if (obj && !libbpf_get_error(obj))
		bpf_object__close(obj);
	return -1;
}

/* Pinning maps under /sys/fs/bpf in subdir */
int pin_maps_in_bpf_object(struct bpf_object *bpf_obj, const char *subdir)
{
	char map_filename[PATH_MAX];
	char pin_dir[PATH_MAX];
	int err, len;

	len = snprintf(pin_dir, PATH_MAX, "%s/%s", pin_basedir, subdir);
	if (len < 0) {
		fprintf(stderr, "ERR: creating pin dirname\n");
		return EXIT_FAIL_OPTION;
	}

	len = snprintf(map_filename, PATH_MAX, "%s/%s/%s",
		       pin_basedir, subdir, map_name);
	if (len < 0) {
		fprintf(stderr, "ERR: creating map_name\n");
		return EXIT_FAIL_OPTION;
	}

	/* Existing/previous XDP prog might not have cleaned up */
	if (access(map_filename, F_OK ) != -1 ) {
		if (verbose)
			printf(" - Unpinning (remove) prev maps in %s/\n",
			       pin_dir);

		/* Basically calls unlink(3) on map_filename */
		err = bpf_object__unpin_maps(bpf_obj, pin_dir);
		if (err) {
			fprintf(stderr, "ERR: UNpinning maps in %s\n", pin_dir);
			return EXIT_FAIL_BPF;
		}
	}
	if (verbose)
		printf(" - Pinning maps in %s/\n", pin_dir);

	/* This will pin all maps in our bpf_object */
	err = bpf_object__pin_maps(bpf_obj, pin_dir);
	if (err)
		return EXIT_FAIL_BPF;

	return 0;
}

int main(int argc, char **argv)
{
	int err;

	struct config cfg = {
		.attach_mode = XDP_MODE_NATIVE,
		.ifindex     = -1,
		.do_unload   = false,
	};
	/* Set default BPF-ELF object file and BPF program name */
	strncpy(cfg.filename, default_filename, sizeof(cfg.filename));
	/* Cmdline options can change progname */
	parse_cmdline_args(argc, argv, long_options, &cfg, __doc__);

	/* Required option */
	if (cfg.ifindex == -1) {
		fprintf(stderr, "ERR: required option --dev missing\n\n");
		usage(argv[0], __doc__, long_options, (argc == 1));
		return EXIT_FAIL_OPTION;
	}
	if (cfg.do_unload) {
		/* unpin the maps */
		char map_filename[PATH_MAX];
		int len;

		len = snprintf(map_filename, PATH_MAX, "%s/%s/%s", pin_basedir, cfg.ifname, map_name);
		if (len < 0) {
			fprintf(stderr, "ERR: creating map filename for unload\n");
			return EXIT_FAIL_OPTION;
		}

		/* Check if the map file exists and unpin it */
		if (access(map_filename, F_OK) == 0) {
			if (verbose)
				printf(" - Unpinning map %s\n", map_filename);
			
			/* Use unlink to remove the pinned map file */
			err = unlink(map_filename);
			if (err) {
				fprintf(stderr, "ERR: Failed to unpin map %s: %s\n", 
					map_filename, strerror(errno));
			}
		}

		/* unload the program */
		err = do_unload(&cfg);
		if (err) {
			char errmsg[1024];
			libxdp_strerror(err, errmsg, sizeof(errmsg));
			fprintf(stderr, "Couldn't unload XDP program: %s\n", errmsg);
			return err;
		}

		printf("Success: Unloaded XDP program\n");
		return EXIT_OK;
	}

	/* Try to reuse existing pinned maps before loading */
	char map_filename[PATH_MAX];
	int len = snprintf(map_filename, PATH_MAX, "%s/%s/%s", pin_basedir, cfg.ifname, map_name);
	if (len < 0) {
		fprintf(stderr, "ERR: creating map filename for reuse\n");
		return EXIT_FAIL_OPTION;
	}

	/* Use the common function to load and attach, with map reuse */
	char pin_dir[PATH_MAX];
	len = snprintf(pin_dir, PATH_MAX, "%s/%s", pin_basedir, cfg.ifname);
	if (len < 0) {
		fprintf(stderr, "ERR: creating pin dirname\n");
		return EXIT_FAIL_OPTION;
	}

	struct bpf_object *obj = NULL;
	int prog_fd = load_bpf_and_xdp_attach_reuse_maps(&cfg, pin_dir, &obj);
	if (prog_fd < 0) {
		return EXIT_FAIL_BPF;
	}

	if (verbose) {
		printf("Success: Loaded BPF-object(%s) and used program(%s)\n",
		       cfg.filename, cfg.progname);
		printf(" - XDP prog attached on device:%s(ifindex:%d)\n",
		       cfg.ifname, cfg.ifindex);
	}

	/* Use the --dev name as subdir for exporting/pinning maps */
	err = pin_maps_in_bpf_object(obj, cfg.ifname);
	if (err) {
		fprintf(stderr, "ERR: pinning maps\n");
		return err;
	}

	return EXIT_OK;
}
