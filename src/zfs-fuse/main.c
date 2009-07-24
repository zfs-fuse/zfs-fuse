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

#include "util.h"
#include "fuse_listener.h"
#include "zfs_operations.h"

static const char *cf_pidfile = NULL;
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

static struct option longopts[] = {
	{ "no-daemon",
	  0, /* has-arg */
	  &cf_daemonize, /* flag */
	  0 /* val */
	},
	{ "disable-block-cache",
	  0,
	  &disable_block_cache,
	  1
	},
	{ "disable-page-cache",
	  0,
	  &disable_page_cache,
	  1
	},
	{ "pidfile",
	  1,
	  NULL,
	  'p'
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
		"  -h, --help\n"
		"			Show this usage summary.\n"
		, progname);
}

static void parse_args(int argc, char *argv[])
{
	int retval;

	const char *progname = "zfs-fuse";
	if (argc > 0)
		progname = argv[0];

	while ((retval = getopt_long(argc, argv, "-hp:", longopts, NULL)) != -1) {
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

	/* we invert the options positively, since they both default to enabled */
	block_cache = disable_block_cache ? 0 : 1;
	page_cache = disable_page_cache ? 0 : 1;
	syslog(LOG_NOTICE,
		"zfs-fuse caching mechanisms: ARC 1, block cache %d page cache %d", block_cache,page_cache);
	if (disable_block_cache) /* direct IO enabled */
		syslog(LOG_WARNING,"block cache disabled -- mmap() cannot be used in ZFS filesystems");
	if (disable_page_cache) /* page cache defeated */
		syslog(LOG_WARNING,"page cache disabled -- expect reduced I/O performance");
}

int main(int argc, char *argv[])
{
	parse_args(argc, argv);

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
