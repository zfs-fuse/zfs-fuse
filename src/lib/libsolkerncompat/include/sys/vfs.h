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

#ifndef _SYS_VFS_H
#define _SYS_VFS_H

#include <sys/types.h>
#include <sys/refstr.h>
#include <sys/cred.h>
#include <sys/statvfs.h>

typedef int fid_t;

/* Please look at vfs_init() if you change this structure */
typedef struct vfs {
	struct vfs   *vfs_next;
	struct vfs   *vfs_prev;

	struct vnode *vfs_vnodecovered;
	uint_t        vfs_count;
	refstr_t     *vfs_resource;
} vfs_t;

extern struct vfs *rootvfs;

extern void vfs_list_lock();
extern void vfs_list_read_lock();
extern void vfs_list_unlock();

extern void vfs_hold(vfs_t *);
extern void vfs_rele(vfs_t *);

extern int dounmount(struct vfs *, int, cred_t *);

#define VFS_HOLD(vfsp) vfs_hold(vfsp)
#define VFS_RELE(vfsp) vfs_rele(vfsp)

#endif
