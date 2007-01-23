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
#include <sys/types.h>
#include <sys/taskq.h>
#include <sys/disp.h>
#include <sys/kmem.h>
#include <errno.h>

#include "fuse.h"

static const int listener_threads = 40;

#define MAX_FILESYSTEMS 1000

boolean_t exit_fuse_listener = B_FALSE;

taskq_t *fuse_tq;

int newfs_fd[2];

typedef struct fuse_fs_info {
	int fd;
	size_t bufsize;
	struct fuse_chan *ch;
	struct fuse_session *se;
	int mntlen;
} fuse_fs_info_t;

typedef struct fuse_request {
	char *buf;
	size_t len;
	struct fuse_chan *ch;
	struct fuse_session *se;
} fuse_request_t;

int zfsfuse_listener_init()
{
	if(pipe(newfs_fd) == -1) {
		perror("pipe");
		return -1;
	}

	fuse_tq = taskq_create("fuse_tq", listener_threads, minclsyspri, 20, 100, TASKQ_PREPOPULATE);

	return 0;
}

void zfsfuse_listener_exit()
{
	close(newfs_fd[0]);
	close(newfs_fd[1]);
	taskq_destroy(fuse_tq);
}

int zfsfuse_newfs(char *mntpoint, struct fuse_chan *ch)
{
	fuse_fs_info_t info = { 0 };

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
static int fd_read_loop(int fd, void *buf, int bytes)
{
	int read_bytes = 0;
	int left_bytes = bytes;

	while(left_bytes > 0) {
		int ret = read(fd, ((char *) buf) + read_bytes, left_bytes);
		if(ret == 0)
			return -1;

		if(ret == -1) {
			if(errno == EINTR)
				continue;
			perror("read");
			return -1;
		}
		read_bytes += ret;
		left_bytes -= ret;
	}
	return 0;
}

static void zfsfuse_dispatcher(void *arg)
{
	fuse_request_t *req = (fuse_request_t *) arg;

	fuse_session_process(req->se, req->buf, req->len, req->ch);

	free(req->buf);
	free(req);
}

#define MAX_FDS (MAX_FILESYSTEMS + 1)

static void new_fs(int *nfds, struct pollfd *fds, char **mountpoints, fuse_fs_info_t *fsinfo)
{
	fuse_fs_info_t fs;

	/*
	 * This should never fail (famous last words) since the fd
	 * is only closed in fuse_listener_exit()
	 */
	VERIFY(fd_read_loop(fds[0].fd, &fs, sizeof(fuse_fs_info_t)) == 0);

	char *mntpoint = malloc(fs.mntlen + 1);
	if(mntpoint == NULL) {
		fprintf(stderr, "Warning: out of memory!\n");
		return;
	}

	VERIFY(fd_read_loop(fds[0].fd, mntpoint, fs.mntlen) == 0);

	mntpoint[fs.mntlen] = '\0';

	if(*nfds == MAX_FDS) {
		fprintf(stderr, "Warning: filesystem limit (%i) reached, unmounting..\n", MAX_FILESYSTEMS);
		fuse_unmount(mntpoint);
		free(mntpoint);
		return;
	}

#ifdef DEBUG
	fprintf(stderr, "Adding filesystem %i at mntpoint %s\n", *nfds, mntpoint);
#endif
	fsinfo[*nfds] = fs;
	mountpoints[*nfds] = mntpoint;

	fds[*nfds].fd = fs.fd;
	fds[*nfds].events = POLLIN;
	fds[*nfds].revents = 0;
	(*nfds)++;
}

static void destroy_fs(int i, struct pollfd *fds, char **mountpoints, fuse_fs_info_t *fsinfo)
{
#ifdef DEBUG
	fprintf(stderr, "Filesystem %i (%s) is being unmounted\n", i, mountpoints[i]);
#endif
	fuse_session_reset(fsinfo[i].se);
	fuse_session_destroy(fsinfo[i].se);
	close(fds[i].fd);
	fds[i].fd = -1;
	free(mountpoints[i]);
}

int zfsfuse_listener_loop()
{
	struct pollfd fds[MAX_FDS];
	fuse_fs_info_t fsinfo[MAX_FDS];
	char *mountpoints[MAX_FDS];

	fds[0].fd = newfs_fd[0];
	fds[0].events = POLLIN;

	int nfds = 1;

	size_t bufsize = 0;

	while(!exit_fuse_listener) {
		int ret = poll(fds, nfds, 1000);
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
				new_fs(&nfds, fds, mountpoints, fsinfo);
			} else {
				/* Handle request */

				char *buf = malloc(fsinfo[i].bufsize);
				if(buf == NULL) {
					fprintf(stderr, "Warning: out of memory!\n");
					continue;
				}

				int res = fuse_chan_receive(fsinfo[i].ch, buf, fsinfo[i].bufsize);
				if(res == -1 || fuse_session_exited(fsinfo[i].se)) {
					free(buf);
					destroy_fs(i, fds, mountpoints, fsinfo);
					continue;
				}

				if(res == 0) {
					free(buf);
					continue;
				}

				fuse_request_t *req = malloc(sizeof(fuse_request_t));
				if(req == NULL) {
					fprintf(stderr, "Warning: out of memory!\n");
					free(buf);
					continue;
				}

				req->buf = buf;
				req->len = res;
				req->ch = fsinfo[i].ch;
				req->se = fsinfo[i].se;

				/* buf and req are freed in zfsfuse_dispatcher */
				taskq_dispatch(fuse_tq, zfsfuse_dispatcher, req, KM_SLEEP);
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

#ifdef DEBUG
	fprintf(stderr, "Exiting...\n");
#endif

	taskq_wait(fuse_tq);

	for(int i = 1; i < nfds; i++) {
		if(fds[i].fd == -1)
			continue;

		fuse_session_exit(fsinfo[i].se);
		fuse_session_reset(fsinfo[i].se);
		fuse_unmount(mountpoints[i]);
		fuse_session_destroy(fsinfo[i].se);

		free(mountpoints[i]);
	}

	return 1;
}
