/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Copyright 2006 Ricardo Correia.
 * Use is subject to license terms.
 */

#include <sys/debug.h>
#include <sys/vfs.h>
#include <sys/vnode.h>
#include <sys/kmem.h>
#include <sys/atomic.h>

#include <pthread.h>

static struct vfs st_rootvfs = {};
static vnode_t st_rootdir = {};
static pthread_rwlock_t vfslist;

/*
 * VFS global data.
 */
vnode_t *rootdir = &st_rootdir; /* pointer to root inode vnode. */
struct vfs *rootvfs = &st_rootvfs;

void vfs_init()
{
	VERIFY(pthread_rwlock_init(&vfslist, NULL) == 0);

	rootvfs->vfs_next = rootvfs;
	rootvfs->vfs_prev = rootvfs;

	rootdir->v_vfsp = rootvfs;
}

void vfs_list_lock()
{
	VERIFY(pthread_rwlock_wrlock(&vfslist) == 0);
}

void vfs_list_read_lock()
{
	VERIFY(pthread_rwlock_rdlock(&vfslist) == 0);
}

void vfs_list_unlock()
{
	VERIFY(pthread_rwlock_unlock(&vfslist) == 0);
}

void vfs_exit()
{
	VERIFY(pthread_rwlock_destroy(&vfslist) == 0);
}

/*
 * Increments the vfs reference count by one atomically.
 */
void
vfs_hold(vfs_t *vfsp)
{
	atomic_add_32(&vfsp->vfs_count, 1);
	ASSERT(vfsp->vfs_count != 0);
}

/*
 * Decrements the vfs reference count by one atomically. When
 * vfs reference count becomes zero, it calls the file system
 * specific vfs_freevfs() to free up the resources.
 */
void
vfs_rele(vfs_t *vfsp)
{
	ASSERT(vfsp->vfs_count != 0);
	if (atomic_add_32_nv(&vfsp->vfs_count, -1) == 0) {
/*		VFS_FREEVFS(vfsp);
		vfs_freemnttab(vfsp);
		if (vfsp->vfs_implp)
			vfsimpl_teardown(vfsp);
		sema_destroy(&vfsp->vfs_reflock);*/
		kmem_free(vfsp, sizeof (*vfsp));
	}
}
