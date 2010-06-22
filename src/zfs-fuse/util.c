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
#include <sys/cmn_err.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>
#include <syslog.h>

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

char * fuse_mount_options;

extern vfsops_t *zfs_vfsops;
extern int zfs_vfsinit(int fstype, char *name);

void do_daemon(const char *pidfile)
{
	chdir("/");
	if (pidfile) {
		struct stat dummy;
		if (0 == stat(pidfile, &dummy)) {
			cmn_err(CE_WARN, "%s already exists; aborting.", pidfile);
			exit(1);
		}
	}

	daemon(0, 0);

	if (pidfile) {
		FILE *f = fopen(pidfile, "w");
		if (!f) {
			cmn_err(CE_WARN, "Error opening %s.", pidfile);
			exit(1);
		}
		if (fprintf(f, "%d\n", getpid()) < 0) {
			unlink(pidfile);
			exit(1);
		}
		if (fclose(f) != 0) {
			unlink(pidfile);
			exit(1);
		}
	}
}

extern size_t stack_size;

int do_init_fusesocket()
{
	ioctl_fd = zfsfuse_socket_create();
	if(ioctl_fd == -1)
		return -1;
    return 0;
}

int do_init()
{
	libsolkerncompat_init();

	zfs_vfsinit(zfstype, NULL);

	VERIFY(zfs_ioctl_init() == 0);

    VERIFY(ioctl_fd != -1); // initialization moved to do_init_fusesocket

    VERIFY(cmd_listener_init() == 0);

	pthread_attr_t attr;
	VERIFY(0 == pthread_attr_init(&attr));
	if (stack_size)
	    pthread_attr_setstacksize(&attr,stack_size);
	if(pthread_create(&listener_thread, &attr, listener_loop, (void *) &ioctl_fd) != 0) {
		VERIFY(0 == pthread_attr_destroy(&attr));
		cmn_err(CE_WARN, "Error creating listener thread.");
		return -1;
	}
	VERIFY(0 == pthread_attr_destroy(&attr));

	listener_thread_started = B_TRUE;

	return zfsfuse_listener_init();
}

void do_exit()
{
	if(listener_thread_started) {
		exit_listener = B_TRUE;
		if(pthread_join(listener_thread, NULL) != 0)
			cmn_err(CE_WARN, "Error in pthread_join().");
	}

    cmd_listener_fini();
	zfsfuse_listener_exit();

	if(ioctl_fd != -1)
		zfsfuse_socket_close(ioctl_fd);

	int ret = zfs_ioctl_fini();
	if(ret != 0)
		cmn_err(CE_WARN, "Error %i in zfs_ioctl_fini().\n", ret);

	libsolkerncompat_exit();
}

/* big_writes added if fuse 2.8 is detected at runtime */
/* other mount options are added if specified in the command line */
#define FUSE_OPTIONS "fsname=%s,allow_other,suid,dev%s" // ,big_writes"

#ifdef DEBUG
uint32_t mounted = 0;
#endif

int do_mount(char *spec, char *dir, int mflag, char *opt)
{
	VERIFY(mflag == 0);

	vfs_t *vfs = kmem_zalloc(sizeof(vfs_t), KM_SLEEP);
	if(vfs == NULL)
		return ENOMEM;

	VFS_INIT(vfs, zfs_vfsops, 0);
	VFS_HOLD(vfs);

	struct mounta uap = {
	.spec = spec,
	.dir = dir,
	.flags = mflag | MS_SYSSPACE,
	.fstype = "zfs-fuse",
	.dataptr = "",
	.datalen = 0,
	.optptr = opt,
	.optlen = strlen(opt)
	};

	int ret;
	if ((ret = VFS_MOUNT(vfs, rootdir, &uap, kcred)) != 0) {
		kmem_free(vfs, sizeof(vfs_t));
		return ret;
	}
	/* Actually, optptr is totally ignored by VFS_MOUNT.
	 * So we are going to pass this with fuse_mount_options if possible */
	char real_opts[1024];
	*real_opts = 0;
	if (*fuse_mount_options)
		strcat(real_opts,fuse_mount_options); // comes with a starting ,
	if (*opt)
		sprintf(&real_opts[strlen(real_opts)],",%s",opt);

#ifdef DEBUG
	atomic_inc_32(&mounted);;

	fprintf(stderr, "mounting %s\n", dir);
#endif

	char *fuse_opts = NULL;
	int has_default_perm = 0;
	if (fuse_version() <= 27) {
	if(asprintf(&fuse_opts, FUSE_OPTIONS, spec, real_opts) == -1) {
		VERIFY(do_umount(vfs, B_FALSE) == 0);
		return ENOMEM;
	}
	} else {
	  if(asprintf(&fuse_opts, FUSE_OPTIONS ",big_writes", spec, real_opts) == -1) {
	    VERIFY(do_umount(vfs, B_FALSE) == 0);
	    return ENOMEM;
	  }
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
	if (strstr(fuse_opts,"default_permissions"))
		has_default_perm = 1;
	free(fuse_opts);

	struct fuse_chan *ch = fuse_mount(dir, &args);

	if(ch == NULL) {
		VERIFY(do_umount(vfs, B_FALSE) == 0);
		return EIO;
	}

	if (has_default_perm)
	    vfs->fuse_attribute = FUSE_VFS_HAS_DEFAULT_PERM;

	struct fuse_session *se = fuse_lowlevel_new(&args, &zfs_operations, sizeof(zfs_operations), vfs);
	fuse_opt_free_args(&args);

	if(se == NULL) {
		VERIFY(do_umount(vfs, B_FALSE) == 0); /* ZFSFUSE: FIXME?? */
		fuse_unmount(dir,ch);
		return EIO;
	}

	fuse_session_add_chan(se, ch);

	if(zfsfuse_newfs(dir, ch) != 0) {
		fuse_session_destroy(se);
		fuse_unmount(dir,ch);
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
