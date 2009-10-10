/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */
/*
 * Copyright 2006 Ricardo Correia.
 * Use is subject to license terms.
 */

#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <getopt.h>
#include <syslog.h>
#include <stdlib.h>

#include "util.h"
#include "fuse_listener.h"
#include "zfs_operations.h"

extern uint64_t max_arc_size; // defined in arc.c
static const char *cf_pidfile = NULL;
static const char *cf_fuse_attr_timeout = NULL;
static const char *cf_fuse_entry_timeout = NULL;
static const char *cf_fuse_mount_options = NULL;
static int cf_disable_block_cache = 0;
static int cf_disable_page_cache = 0;
static int cf_daemonize = 1;

static void exit_handler(int sig)
{
	exit_fuse_listener = B_TRUE;
}

static int set_signal_handler(int sig, void (*handler)(int))
{
	struct sigaction sa;

	memset(&sa, 0, sizeof(struct sigaction));

	sa.sa_handler = handler;
	sigemptyset(&(sa.sa_mask));
	sa.sa_flags = 0;

	if(sigaction(sig, &sa, NULL) == -1) {
		perror("sigaction");
		return -1;
	}

	return 0;
}

extern char *optarg;
extern int optind, opterr, optopt;

extern int zfs_vdev_cache_size; // in lib/libzpool/vdev_cache.c
extern int zfs_prefetch_disable; // lib/libzpool/dmu_zfetch.c
extern int arg_log_uberblocks, arg_min_uberblock_txg; // uberblock.c

static struct option longopts[] = {
	{ "no-daemon",
	  0, /* has-arg */
	  &cf_daemonize, /* flag */
	  0 /* val */
	},
	{ "log-uberblocks",
	    0,
	    &arg_log_uberblocks,
	    1
	},
	{ "min-uberblock-txg",
	    1,
	    NULL,
	    'u'
	},
	{ "disable-block-cache",
	  0,
	  &cf_disable_block_cache,
	  1
	},
	{ "disable-page-cache",
	  0,
	  &cf_disable_page_cache,
	  1
	},
	{ "pidfile",
	  1,
	  NULL,
	  'p'
	},
	{ "max-arc-size",
		1,
		NULL,
		'm'
	},
	{ "zfs-prefetch-disable",
		0,
		&zfs_prefetch_disable,
		1
	},
	{ "vdev-cache-size",
		1,
		NULL,
		'v'
	},
	{ "fuse-attr-timeout",
	  1,
	  NULL,
	  'a'
	},
	{ "fuse-entry-timeout",
	  1,
	  NULL,
	  'e'
	},
	{ "fuse-mount-options",
	  1,
	  NULL,
	  'o'
	},
	{ "help",
	  0,
	  NULL,
	  'h'
	},
	{ 0, 0, 0, 0 }
};

void print_usage(int argc, char *argv[]) {
	const char *progname = "zfs-fuse";
	if (argc > 0)
		progname = argv[0];
	fprintf(stderr,
		"Usage: %s [OPTION]...\n"
		"Start the ZFS daemon.\n"
		"\n"
		"Options:\n"
		"  -p FILE, --pidfile FILE\n"
		"			Store the process ID of ZFS in the specified file.\n"
		"  --no-daemon\n"
		"			Do not daemonize ZFS.\n"
		"  --disable-block-cache\n"
		"			Enable direct I/O for disk operations. Completely\n"
		"			disables caching reads and writes in the kernel\n"
		"			block cache.  Breaks mmap() in ZFS datasets too.\n"
		"  --disable-page-cache\n"
		"			Disable the page cache for files residing within\n"
		"			ZFS filesystems.  Not recommended as it slows down\n"
		"			I/O operations considerably.\n"
		"  -a SECONDS, --fuse-attr-timeout SECONDS\n"
		"			Sets timeout for caching FUSE attributes in kernel.\n"
		"			Defaults to 0.0.\n"
		"			Higher values give a 40%% performance boost.\n"
		"  -e SECONDS, --fuse-entry-timeout SECONDS\n"
		"			Sets timeout for caching FUSE entries in kernel.\n"
		"			Defaults to 0.0.\n"
		"			Higher values give a 10000%% performance boost\n"
		"			but cause file permission checking security issues.\n"
		"  --log-uberblocks\n"
		"			Logs uberblocks of any mounted filesystem to syslog\n"
		"  -m MB, --max-arc-size MB\n"
		"			Forces the maximum ARC size (in megabytes).\n"
		"			Range: 16 to 16384.\n"
		"  -o OPT..., --fuse-mount-options OPT,OPT,OPT...\n"
		"			Sets FUSE mount options for all filesystems.\n"
		"			Format: comma-separated string of characters.\n"
		"  --min-uberblock-txg MIN, -u MIN\n"
		"			Skips uberblocks with a TXG < MIN when mounting any fs\n"
		"  -v MB, --vdev-cache-size MB\n"
		"			adjust the size of the vdev cache. Default : 10\n"
		"  --zfs-prefetch-disable\n"
		"			Disable the high level prefetch cache in zfs.\n"
		"			This thing can eat up to 150 Mb of ram, maybe more\n"
		"  -h, --help\n"
		"			Show this usage summary.\n"
		, progname);
}

static void check_opt(const char *progname,char *opt) {
	// checks if optarg is defined for an option requiring an argument
	if (!optarg) {
		fprintf(stderr,"%s: you need to specify an argument (%s)\n\n",progname,opt);
		exit(64);
	}
}

static void parse_args(int argc, char *argv[])
{
	int retval;
	char * detecterror;
	const char *progname = "zfs-fuse";
	if (argc > 0)
		progname = argv[0];

	optind = 0;
	optarg = NULL;
	while ((retval = getopt_long(argc, argv, "-hp:a:e:m:o:u:v:", longopts, NULL)) != -1) {
		switch (retval) {
			case 1: /* non-option argument passed (due to - in optstring) */
			case 'h':
			case '?':
				print_usage(argc, argv);
				exit(64);
			case 'p':
				if (cf_pidfile != NULL) {
					fprintf(stderr, "%s: you need to specify a file name\n\n", progname);
					print_usage(argc, argv);
					exit(64);
				}
				cf_pidfile = optarg;
				break;
			case 'o':
				if (cf_fuse_mount_options != NULL) {
					fprintf(stderr, "%s: you need to specify mount options\n\n", progname);
					print_usage(argc, argv);
					exit(64);
				}
				cf_fuse_mount_options = optarg;
				if (strcmp(cf_fuse_mount_options,"") == 0) {
					fprintf(stderr, "%s: empty mount options are not valid\n\n", progname);
					print_usage(argc, argv);
					exit(64);
				}
				 /* bug here, asprintf result not checked for malloc success, dunno what action to take if it fails */
				asprintf(&fuse_mount_options,",%s",optarg);
				break;
			case 'a':
				if (cf_fuse_attr_timeout != NULL) {
					fprintf(stderr, "%s: you need to specify an attribute timeout\n\n", progname);
					print_usage(argc, argv);
					exit(64);
				}
				cf_fuse_attr_timeout = optarg;
				fuse_attr_timeout = strtof(cf_fuse_attr_timeout,&detecterror);
				if ((fuse_attr_timeout == 0.0 && detecterror == cf_fuse_attr_timeout) || (fuse_attr_timeout < 0.0)) {
					fprintf(stderr, "%s: you need to specify a valid, non-zero attribute timeout\n\n", progname);
					print_usage(argc, argv);
					exit(64);
				}
				break;
			case 'e':
				if (cf_fuse_entry_timeout != NULL) {
					fprintf(stderr, "%s: you need to specify an entry timeout\n\n", progname);
					print_usage(argc, argv);
					exit(64);
				}
				cf_fuse_entry_timeout = optarg;
				fuse_entry_timeout = strtof(cf_fuse_entry_timeout,&detecterror);
				if ((fuse_entry_timeout == 0.0 && detecterror == cf_fuse_entry_timeout) || (fuse_entry_timeout < 0.0)) {
					fprintf(stderr, "%s: you need to specify a valid, non-zero entry timeout\n\n", progname);
					print_usage(argc, argv);
					exit(64);
				}
				break;
			case 'm':
				check_opt(progname,"-m");
				max_arc_size = strtol(optarg,&detecterror,10);
				if ((max_arc_size == 0 && detecterror == optarg) || (max_arc_size < 16) || (max_arc_size > 16384)) {
					fprintf(stderr, "%s: you need to specify a valid, in-range integer for the maximum ARC size\n\n", progname);
					print_usage(argc, argv);
					exit(64);
				}
				max_arc_size = max_arc_size<<20;
				break;
			case 'u':
				check_opt(progname,"-u");
				arg_min_uberblock_txg = atol(optarg);
				break;
			case 'v':
				check_opt(progname,"-v");
				zfs_vdev_cache_size = strtol(optarg,&detecterror,10)<<20;
				break;
			case 0:
				break; /* flag is not NULL */
			default:
				// This should never happen
				fprintf(stderr, "%s: option not recognized (Unrecognized getopt_long return 0x%02x)\n\n", progname, retval);
				print_usage(argc, argv);
				exit(64); /* 64 is standard UNIX EX_USAGE */
				break;
		}
	}	
}

static void split_command(char *field, char **argv, int *argc, int max) {
	char *s = field;
	*argc = 1;
	argv[0] = "zfs-fuse";
	while (*s && (*s == ' ' || *s==9)) // skip the leading spaces
		s++;
	if (*s) {
		if (*s == '#') return;
		memmove(&s[2],s,strlen(s)+1); // includes the traililng 0
		s[0] = s[1] = '-'; // add -- prefix
		argv[(*argc)++] = s;
	}
	while (*s) {
		while (*s != ' ' && *s)  {
			s++;
		}
		if (*s == ' ' || *s==9) {
			*s++ = 0;
			while (*s == ' ' || *s==9)
				s++;
			if (*s) {
				if (*s == '#') return;
				argv[(*argc)++] = s;
				if (*argc == max) // no more args, thanks !
					return;
			}
		}
	}
}

static void read_cfg() {
	FILE *f = fopen("/etc/zfs/zfsrc","r");
	if (!f)
		return;
	while (!feof(f)) {
		char buf[1024];
		int argc;
		char *argv[10];
		fgets(buf,1024,f);
		int l = strlen(buf)-1;
		while (l >= 0 && buf[l] < 32)
			buf[l--] = 0; // remove trailing cr (or any code < ' ')
		split_command(buf, argv, &argc, 10);
		if (argc == 1) continue;
		if (argc > 2 && *argv[2] ==  '=') {
			// remove the =
			memmove(&argv[2],&argv[3],sizeof(char*)*(argc-2));
			argc--;
		}
		parse_args(argc,argv);
	}
	fclose(f);
}

int main(int argc, char *argv[])
{
	/* one sane default a day keeps GDB away - Rudd-O */
	fuse_attr_timeout = 0.0;
	fuse_entry_timeout = 0.0;
	fuse_mount_options = "";
	zfs_vdev_cache_size = 10ULL << 20;         /* 10MB */
	read_cfg();
	parse_args(argc, argv);
	/* we invert the options positively, since they both default to enabled */
	block_cache = cf_disable_block_cache ? 0 : 1;
	page_cache = cf_disable_page_cache ? 0 : 1;

	/* notice about caching mechanisms */
	syslog(LOG_NOTICE,"caching mechanisms: ARC 1, block cache %d page cache %d", block_cache, page_cache);

	/* notice about ARC size */
	if (max_arc_size)	syslog(LOG_NOTICE,"ARC caching: maximum ARC size: %ld MiB", max_arc_size>>20);
	else 			syslog(LOG_NOTICE,"ARC caching: maximum ARC size: compiled-in default");

	/* notice about FUSE caching tunables */
	syslog(LOG_NOTICE, "FUSE caching: attribute timeout %f, entry timeout %f", fuse_attr_timeout, fuse_entry_timeout);

	 /* notice about extra FUSE mount options */
	if (strcmp(fuse_mount_options,"") != 0)
		syslog(LOG_NOTICE,"FUSE mount options (appended to compiled-in options): %s", fuse_mount_options);
	
	if (!block_cache) /* direct IO enabled */
		syslog(LOG_WARNING,"block cache disabled -- mmap() cannot be used in ZFS filesystems");
	if (!page_cache) /* page cache defeated */
		syslog(LOG_WARNING,"page cache disabled -- expect reduced I/O performance");
	if (fuse_entry_timeout > 0.0) /* security bug! */
		syslog(LOG_WARNING,"FUSE entry timeout > 0 -- expect insecure directory traversal");
	if (cf_daemonize) {
		do_daemon(cf_pidfile);
	}

	if(do_init() != 0) {
		do_exit();
		return 1;
	}

	if(set_signal_handler(SIGHUP, exit_handler) != 0 ||
	   set_signal_handler(SIGINT, exit_handler) != 0 ||
	   set_signal_handler(SIGTERM, exit_handler) != 0 ||
	   set_signal_handler(SIGPIPE, SIG_IGN) != 0) {
		do_exit();
		return 2;
	}

	int ret = zfsfuse_listener_start();

	do_exit();

	return ret;
}
