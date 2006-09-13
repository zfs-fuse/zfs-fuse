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

#include <sys/debug.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/poll.h>

#include <stdio.h>
#include <stdlib.h>

#include "zfs_ioctl.h"
#include "zfsfuse_ioctl.h"
#include "libsolkerncompat.h"

int main()
{
	int ret;

	libsolkerncompat_init();

	VERIFY(zfs_ioctl_init() == 0);

	int ioctl_fd = zfsfuse_ioctl_open();
	if(ioctl_fd == -1) {
		ret = 1;
		goto error;
	}

	dev_t dev = {0};

	struct pollfd fds[100];

	fds[0].fd = ioctl_fd;
	fds[0].events = POLLIN;

	int nfds = 1;

	for(;;) {
		if(poll(fds, nfds, -1) == -1) {
			perror("poll");
			break;
		}

		for(int i = 0; i < nfds; i++) {
			short rev = fds[i].revents;

			if(rev == 0)
				continue;

			ASSERT((rev & POLLNVAL) == 0);

			if((rev & POLLIN) == 0 && (rev & POLLERR) == 0 && (rev & POLLHUP) == 0)
				continue;

			if(i == 0) {
				int sock = accept(ioctl_fd, NULL, NULL);
				if(sock == -1) {
					perror("accept");
					continue;
				}
				ASSERT(nfds < 100);

				fds[nfds].fd = sock;
				fds[nfds].events = POLLIN;
				fds[nfds].revents = 0;
				nfds++;
			} else {
				int cmd, sock = fds[i].fd;
				intptr_t arg;

				cmd = zfsfuse_ioctl_read(sock, &arg);
				if(cmd == -1) {
					close(sock);
					fds[i].fd = -1;
					continue;
				}

				cur_fd = sock;
				int ioctl_ret = zfsdev_ioctl(dev, cmd, arg, 0, NULL, NULL);
				cur_fd = -1;

				if(zfsfuse_ioctl_write(sock, ioctl_ret) != 0) {
					close(sock);
					fds[i].fd = -1;
					continue;
				}
			}
		}

		/* Free file descriptors that are -1 */
		int write_ptr = 0;
		for(int read_ptr = 0; read_ptr < nfds; read_ptr++) {
			if(fds[read_ptr].fd == -1)
				continue;
			if(read_ptr != write_ptr)
				fds[write_ptr] = fds[read_ptr];

			write_ptr++;
		}
		nfds = write_ptr;
	}

error:
	ret = zfs_ioctl_fini();
	if(ret != 0)
		fprintf(stderr, "Error %i in zfs_ioctl_fini()\n", ret);

	zfsfuse_ioctl_close(ioctl_fd);

	libsolkerncompat_exit();

	return ret;
}
