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
#include <sys/mount.h>
#include <sys/types.h>
#include <sys/cred.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>

#include "libsolkerncompat.h"
#include "zfs_ioctl.h"
#include "zfsfuse_socket.h"

#include "cmd_listener.h"
#include "fuse_listener.h"

#include "fuse.h"
#include "zfs_operations.h"
#include "util.h"

int ioctl_fd = -1;

boolean_t listener_thread_started = B_FALSE;
pthread_t listener_thread;

int num_filesystems;


extern vfsops_t *zfs_vfsops;
extern int zfs_vfsinit(int fstype, char *name);

int do_init()
{
	libsolkerncompat_init();

	zfs_vfsinit(zfstype, NULL);

	VERIFY(zfs_ioctl_init() == 0);

	ioctl_fd = zfsfuse_socket_create();
	if(ioctl_fd == -1)
		return -1;

	if(pthread_create(&listener_thread, NULL, listener_loop, (void *) &ioctl_fd) != 0) {
		fprintf(stderr, "Error creating listener thread\n");
		return -1;
	}

	listener_thread_started = B_TRUE;

	return zfsfuse_listener_init();
}

void do_exit()
{
	if(listener_thread_started) {
		exit_listener = B_TRUE;
		if(pthread_join(listener_thread, NULL) != 0)
			fprintf(stderr, "Error in pthread_join()\n");
	}

	zfsfuse_listener_exit();

	if(ioctl_fd != -1)
		zfsfuse_socket_close(ioctl_fd);

	int ret = zfs_ioctl_fini();
	if(ret != 0)
		fprintf(stderr, "Error %i in zfs_ioctl_fini()\n", ret);

	libsolkerncompat_exit();
}

#define FUSE_OPTIONS "fsname=%s,allow_other"

#ifdef DEBUG
uint32_t mounted = 0;
#endif

int do_mount(char *spec, char *dir, int mflag, char *opt)
{
	VERIFY(mflag == 0);
	VERIFY(opt[0] == '\0');

	vfs_t *vfs = kmem_zalloc(sizeof(vfs_t), KM_SLEEP);
	if(vfs == NULL)
		return ENOMEM;

	VFS_INIT(vfs, zfs_vfsops, 0);
	VFS_HOLD(vfs);

	struct mounta uap = {spec, dir, mflag, NULL, opt, strlen(opt)};

	int ret = VFS_MOUNT(vfs, rootdir, &uap, kcred);

	if(ret != 0)
		return ret;

#ifdef DEBUG
	atomic_inc_32(&mounted);;

	fprintf(stderr, "mounting %s\n", dir);
#endif

	char *fuse_opts;
	if(asprintf(&fuse_opts, FUSE_OPTIONS, spec) == -1) {
		VERIFY(do_umount(vfs, B_FALSE) == 0);
		return ENOMEM;
	}

	struct fuse_args args = FUSE_ARGS_INIT(0, NULL);

	if(fuse_opt_add_arg(&args, "") == -1 ||
	   fuse_opt_add_arg(&args, "-o") == -1 ||
	   fuse_opt_add_arg(&args, fuse_opts) == -1) {
		fuse_opt_free_args(&args);
		free(fuse_opts);
		VERIFY(do_umount(vfs, B_FALSE) == 0);
		return ENOMEM;
	}
	free(fuse_opts);

	int fd = fuse_mount(dir, &args);

	if(fd == -1) {
		VERIFY(do_umount(vfs, B_FALSE) == 0);
		return EIO;
	}

	struct fuse_session *se = fuse_lowlevel_new(&args, &zfs_operations, sizeof(zfs_operations), vfs);
	fuse_opt_free_args(&args);

	if(se == NULL) {
		VERIFY(do_umount(vfs, 0) == B_FALSE); /* ZFSFUSE: FIXME?? */
		close(fd);
		fuse_unmount(dir);
		return EIO;
	}

	struct fuse_chan *ch = fuse_kern_chan_new(fd);
	if(ch == NULL) {
		fuse_session_destroy(se);
		close(fd);
		fuse_unmount(dir);
		return EIO;
	}

	fuse_session_add_chan(se, ch);

	if(zfsfuse_newfs(dir, ch) != 0) {
		fuse_session_destroy(se);
		close(fd);
		fuse_unmount(dir);
		return EIO;
	}

	return 0;
}

int do_umount(vfs_t *vfs, boolean_t force)
{
	VFS_SYNC(vfs, 0, kcred);

	int ret = VFS_UNMOUNT(vfs, force ? MS_FORCE : 0, kcred);
	if(ret != 0)
		return ret;

	ASSERT(force || vfs->vfs_count == 1);
	VFS_RELE(vfs);

#ifdef DEBUG
	fprintf(stderr, "mounted filesystems: %i\n", atomic_dec_32_nv(&mounted));
#endif

	return 0;
}
