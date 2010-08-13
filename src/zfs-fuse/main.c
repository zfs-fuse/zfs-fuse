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
#include <sys/zfs_debug.h>
#include <semaphore.h>

#include "util.h"
#include "fuse_listener.h"
#include "zfs_operations.h"
#include "format.h"

extern uint64_t max_arc_size; // defined in arc.c
static const char *cf_pidfile = NULL;
static const char *cf_fuse_mount_options = NULL;
static int cf_disable_block_cache = 0;
static int cf_disable_page_cache = 0;
extern void fuse_unmount_all(); // in fuse_listener.c
static int cf_daemonize = 1;
extern int no_kstat_mount; // kstat.c

static sem_t daemon_shutdown;

static void exit_handler(int sig)
{
    sem_post(&daemon_shutdown);
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
size_t stack_size = 0;

static struct option longopts[] = {
	{ "no-daemon",
	  0, /* has-arg */
	  &cf_daemonize, /* flag */
	  0 /* val */
	},
	{ "no-kstat-mount",
	    0,
	    &no_kstat_mount,
	    1
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
	{ "disable-page-cache", // obsolete
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
	{ "stack-size",
	    1,
	    NULL,
	    's'
	},
	{ "enable-xattr",
	  0,
	  &cf_enable_xattr,
	  0
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
		"  --no-daemon, -n\n"
		"			Do not daemonize ZFS.\n"
		"  --no-kstat-mount\n"
		"			Do not mount kstats in /zfs-kstat\n"
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
		"  --stack-size=size\n"
		"			Limit the stack size of threads (in kb).\n"
		"			default : no limit (8 Mb for linux)\n"
  		"  -x, --enable-xattr\n"
  		"			Enable support for extended attributes. Not generally \n"
		"			recommended because it currently has a significant \n"
		"			performance penalty for many small IOPS\n"
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
	while ((retval = getopt_long(argc, argv, "-hp:a:e:m:nxo:u:v:s:", longopts, NULL)) != -1) {
		switch (retval) {
			case 1: /* non-option argument passed (due to - in optstring) */
			case 'h':
			case '?':
				print_usage(argc, argv);
				exit(64);
			case 'p':
				if (cf_pidfile != NULL)
					syslog(LOG_WARNING,"%s: duplicate pid-file setting, prior setting '%s' ignored", progname, cf_pidfile);

				cf_pidfile = optarg;

				if (cf_pidfile == NULL) {
					fprintf(stderr, "%s: you need to specify a file name\n\n", progname);
					print_usage(argc, argv);
					exit(64);
				}
				break;
			case 'n':
				cf_daemonize = 0;
				break;
			case 'o':
				if (fuse_mount_options != NULL)
					syslog(LOG_WARNING,"%s: multiple fuse-mount-options parameters, appending to prior setting '%s'", progname, fuse_mount_options);

				if (optarg == NULL) {
					fprintf(stderr, "%s: you need to specify mount options\n\n", progname);
					print_usage(argc, argv);
					exit(64);
				}
				if (strcmp(optarg,"") == 0) {
					fprintf(stderr, "%s: empty mount options are not valid\n\n", progname);
					print_usage(argc, argv);
					exit(64);
				}
				{
					char* tmpopts = fuse_mount_options;
					if (-1 == asprintf(&fuse_mount_options,"%s,%s",tmpopts?tmpopts:"",optarg))
					{
						fprintf(stderr, "%s: fatal allocation error\n", progname);
						abort();
					}
					if (tmpopts)
						free(tmpopts);
				}
				break;
			case 'a':
				check_opt(progname,"-a");
				if (fuse_attr_timeout != 0.0f)
					syslog(LOG_WARNING,"%s: conflicting fuse_attr_timeout, prior setting %f ignored", progname, fuse_attr_timeout);

				fuse_attr_timeout = strtof(optarg,&detecterror);
				if ((fuse_attr_timeout == 0.0 && detecterror == optarg) || (fuse_attr_timeout < 0.0)) {
					fprintf(stderr, "%s: you need to specify a valid, non-zero attribute timeout\n\n", progname);
					print_usage(argc, argv);
					exit(64);
				}
				break;
			case 'e':
				check_opt(progname,"-e");
				if (fuse_entry_timeout != 0.0f)
					syslog(LOG_WARNING,"%s: conflicting fuse_entry_timeout, prior setting %f ignored", progname, fuse_entry_timeout);

				fuse_entry_timeout = strtof(optarg,&detecterror);
				if ((fuse_entry_timeout == 0.0 && detecterror == optarg) || (fuse_entry_timeout < 0.0)) {
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
			case 's':
				check_opt(progname,"-s");
				if (stack_size != 0ul)
					syslog(LOG_WARNING,"%s: conflicting stack_size, prior setting %u ignored", progname, stack_size);

				stack_size=strtoul(optarg,&detecterror,10)<<10;
				syslog(LOG_WARNING,"stack size for threads %zd",stack_size);
				break;
			case 'x':
				cf_enable_xattr = 1;
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

static void read_cfg() {
	FILE *f = fopen("/etc/zfs/zfsrc","r");
	if (!f)
		return;
	while (!feof(f)) {
		char buf[1024];
		int argc = 0;
		char *argv[10];
		if (!fgets(buf,1024,f))
			continue;
		int l = strlen(buf)-1;
		while (l >= 0 && buf[l] < 32)
			buf[l--] = 0; // remove trailing cr (or any code < ' ')

		argv[argc++] = "/etc/zfs/zfsrc";

		////////////////////////////////////////////
		// more predictable parsing required
		int name_s = -1, name_e = -1, value_s = -1, value_e = -1;
		char first = 0;

		sscanf(buf, " %1[#]", &first);
		if ('#' == first)
			continue;

		sscanf(buf, " %n%*[a-z-]%n = %n%*[^#]%n", &name_s, &name_e, &value_s, &value_e);

		// unfortunately, can't trust the return value according to SCANF(3)
		if (!((-1 == name_s) || (-1 == name_e) || (-1 == value_s) || (-1 == value_e)))
		{
			// treat righthand side as shell quoted (--name='value')
			buf[name_e] = buf[value_e] = 0;
			argv[argc++] = buf+name_s;
			argv[argc++] = buf+value_s;
		} else
		{
			for (char* token=strtok(buf, " \t\n\r"); token && argc<10; token=strtok(NULL, " \t\n\r"))
			{
				if ('#' == *token) // keeping the old behaviour only
					break;
				else
					argv[argc++] = token;
			}
		}

		if (argc>1)
		{
			// prepend dashes for short or long options
			const char* original = argv[1];
			if ('-'!=*original)
				VERIFY(-1 != asprintf(&argv[1], strlen(original)>1? "--%s" : "-%s", original));

			// parse
			parse_args(argc,argv);

			if (original != argv[1])
				free(argv[1]);
		}
	}
	fclose(f);
}

int main(int argc, char *argv[])
{
    VERIFY(0 == sem_init(&daemon_shutdown, 0, 0));
    init_mmap();
	/* one sane default a day keeps GDB away - Rudd-O */
	fuse_attr_timeout = 0.0;
	fuse_entry_timeout = 0.0;
	fuse_mount_options = NULL;
	zfs_vdev_cache_size = 10ULL << 20;         /* 10MB */
	read_cfg();
	parse_args(argc, argv);
	/* we invert the options positively, since they both default to enabled */
	block_cache = cf_disable_block_cache ? 0 : 1;
	page_cache  = cf_disable_page_cache  ? 0 : 1;
	if (cf_disable_page_cache)
		syslog(LOG_WARNING,"deprecated option used (disable-page-cache)");
	if (cf_enable_xattr)
		fprintf(stderr, "%s: Warning: enabling xattr support should only be done when really required; performance will be affected\n", argv[0]);

	/* notice about ARC size */
	if (max_arc_size)	syslog(LOG_NOTICE,"ARC caching: maximum ARC size: " FU64 " MiB", max_arc_size>>20);
	else 			syslog(LOG_NOTICE,"ARC caching: maximum ARC size: compiled-in default");

	if (!block_cache) /* direct IO enabled */
		syslog(LOG_WARNING,"block cache disabled -- mmap() cannot be used in ZFS filesystems");
    if (do_init_fusesocket() != 0)
        return 1;
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

	VERIFY(0 == zfsfuse_listener_start());

    sem_wait(&daemon_shutdown);

	do_exit();
	sleep(1); // avoids a lockup while shutting down libc with a scrub running; FIXME!!

	return 1;
}
