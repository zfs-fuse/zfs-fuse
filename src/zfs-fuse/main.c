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
#include "util.h"
#include "fuse_listener.h"

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

int main(int argc, char *argv[])
{
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

	int ret = zfsfuse_listener_loop();

	do_exit();

	return ret;
}
