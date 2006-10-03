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
#include <unistd.h>
#include <sys/poll.h>
#include <sys/debug.h>
#include <errno.h>

#include "fuse.h"

int newfs_fd[2];

typedef struct fuse_fs_info {
	int fd;
	size_t bufsize;
	struct fuse_chan *ch;
	struct fuse_session *se;
	int mntlen;
} fuse_fs_info_t;

#define MAX_FILESYSTEMS 1000

int zfsfuse_listener_init()
{
	if(pipe(newfs_fd) == -1) {
		perror("pipe");
		return -1;
	}
	return 0;
}

void zfsfuse_listener_exit()
{
	close(newfs_fd[0]);
	close(newfs_fd[1]);
}

int zfsfuse_newfs(char *mntpoint, struct fuse_chan *ch)
{
	fuse_fs_info_t info;

	info.fd = fuse_chan_fd(ch);
	info.bufsize = fuse_chan_bufsize(ch);
	info.ch = ch;
	info.se = fuse_chan_session(ch);
	info.mntlen = strlen(mntpoint);

	if(write(newfs_fd[1], &info, sizeof(info)) != sizeof(info)) {
		perror("Warning (while writing fsinfo to newfs_fd)");
		return -1;
	}

	if(write(newfs_fd[1], mntpoint, info.mntlen) != info.mntlen) {
		perror("Warning (while writing mntpoint to newfs_fd)");
		return -1;
	}
	return 0;
}

/*
 * This function is repeated in lib/libzfs/libzfs_zfsfuse.c
 * and in zfs-fuse/zfsfuse_socket.c
 */
int fd_read_loop(int fd, void *buf, int bytes)
{
	int read_bytes = 0;
	int left_bytes = bytes;

	while(left_bytes > 0) {
		int ret = read(fd, buf + read_bytes, left_bytes);
		if(ret == 0)
			return -1;

		if(ret == -1) {
			perror("read");
			return -1;
		}
		read_bytes += ret;
		left_bytes -= ret;
	}
	return 0;
}

#define MAX_FDS (MAX_FILESYSTEMS + 1)

int zfsfuse_listener_loop()
{
	struct pollfd fds[MAX_FDS];
	fuse_fs_info_t fsinfo[MAX_FDS];
	char *mountpoints[MAX_FDS];

	fds[0].fd = newfs_fd[0];
	fds[0].events = POLLIN;

	int nfds = 1;

	char *buf = NULL;
	size_t bufsize = 0;

	for(;;) {
		int ret = poll(fds, nfds, -1);
		if(ret == 0 || (ret == -1 && errno == EINTR))
			continue;

		if(ret == -1) {
			perror("poll");
			break;
		}

		int oldfds = nfds;

		for(int i = 0; i < oldfds; i++) {
			short rev = fds[i].revents;

			if(rev == 0)
				continue;

			fds[i].revents = 0;

			ASSERT((rev & POLLNVAL) == 0);

			if(!(rev & POLLIN) && !(rev & POLLERR) && !(rev & POLLHUP))
				continue;

			if(i == 0) {
				/* New FUSE session */

				fuse_fs_info_t fs;

				/*
				 * This should never fail (famous last words) since the fd
				 * is only closed in fuse_listener_exit()
				 */
				VERIFY(fd_read_loop(fds[0].fd, &fs, sizeof(fuse_fs_info_t)) == 0);

				char *mntpoint = malloc(fs.mntlen + 1);
				if(mntpoint == NULL) {
					fprintf(stderr, "Warning: out of memory!\n");
					continue;
				}

				VERIFY(fd_read_loop(fds[0].fd, mntpoint, fs.mntlen) == 0);

				mntpoint[fs.mntlen] = '\0';

				if(nfds == MAX_FDS) {
					fprintf(stderr, "Warning: filesystem limit (%i) reached, unmounting..\n", MAX_FILESYSTEMS);
					fuse_unmount(mntpoint);
					free(mntpoint);
					continue;
				}

				fprintf(stderr, "Adding filesystem %i at mntpoint %s\n", nfds, mntpoint);

				fsinfo[nfds] = fs;
				mountpoints[nfds] = mntpoint;

				fds[nfds].fd = fs.fd;
				fds[nfds].events = POLLIN;
				fds[nfds].revents = 0;
				nfds++;
			} else {
				/* Handle request */

				if(fsinfo[i].bufsize > bufsize)
					buf = realloc(buf, fsinfo[i].bufsize);

				int res = fuse_chan_receive(fsinfo[i].ch, buf, fsinfo[i].bufsize);
				if(res == 0)
					continue;

				if(res != -1)
					fuse_session_process(fsinfo[i].se, buf, res, fsinfo[i].ch);

				if(res == -1 || fuse_session_exited(fsinfo[i].se)) {
					fprintf(stderr, "Filesystem %i (%s) is being unmounted\n", i, mountpoints[i]);
					fuse_session_reset(fsinfo[i].se);
					fuse_session_destroy(fsinfo[i].se);
					close(fds[i].fd);
					fds[i].fd = -1;
					free(mountpoints[i]);
					continue;
				}
			}
		}

		/* Free file descriptors that are -1 */
		int write_ptr = 0;
		for(int read_ptr = 0; read_ptr < nfds; read_ptr++) {
			if(fds[read_ptr].fd == -1)
				continue;
			if(read_ptr != write_ptr) {
				fds[write_ptr] = fds[read_ptr];
				fsinfo[write_ptr] = fsinfo[read_ptr];
				mountpoints[write_ptr] = mountpoints[read_ptr];
			}
			write_ptr++;
		}
		nfds = write_ptr;
	}

	if(buf != NULL)
		free(buf);

	return 1;
}
