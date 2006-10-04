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

typedef void fid_t;
typedef void vfsops_t;

/* Please look at vfs_init() if you change this structure */
typedef struct vfs {
	struct vfs   *vfs_next;
	struct vfs   *vfs_prev;

	struct vnode *vfs_vnodecovered;
	uint_t        vfs_flag;
	uint_t        vfs_bsize;
	int           vfs_fstype;
	void         *vfs_data;
	dev_t         vfs_dev;
	ulong_t       vfs_bcount;
	uint_t        vfs_count;
	refstr_t     *vfs_resource;
} vfs_t;

/*
 * Argument structure for mount(2).
 *
 * Flags are defined in <sys/mount.h>.
 *
 * Note that if the MS_SYSSPACE bit is set in flags, the pointer fields in
 * this structure are to be interpreted as kernel addresses.  File systems
 * should be prepared for this possibility.
 */
struct mounta {
	char *spec;
	char *dir;
	int   flags;
	char *fstype;
	char *dataptr;
	int   datalen;
	char *optptr;
	int   optlen;
};

extern struct vfs *rootvfs;

extern void vfs_list_lock();
extern void vfs_list_read_lock();
extern void vfs_list_unlock();

extern void vfs_hold(vfs_t *);
extern void vfs_rele(vfs_t *);

extern int dounmount(struct vfs *, int, cred_t *);

#define VFS_HOLD(vfsp) vfs_hold(vfsp)
#define VFS_RELE(vfsp) vfs_rele(vfsp)

#define vfs_devismounted(dev) (0)
#define vfs_clearmntopt(vfs,opt) ((void) 0)
#define vfs_setmntopt(vfs,opt,a,b) ((void) 0)
#define vfs_optionisset(vfs,opt,a) (0)
#define vfs_setfsops(a,b,c) (0)
#define vfs_freevfsops_by_type(fstype) (0)

/*
 * VFS flags.
 */
#define VFS_RDONLY     0x01   /* read-only vfs */
#define VFS_MLOCK      0x02   /* lock vfs so that subtree is stable */
#define VFS_MWAIT      0x04   /* someone is waiting for lock */
#define VFS_NOSETUID   0x08   /* setuid disallowed */
#define VFS_REMOUNT    0x10   /* modify mount options only */
#define VFS_NOTRUNC    0x20   /* does not truncate long file names */
#define VFS_UNLINKABLE 0x40   /* unlink(2) can be applied to root */
#define VFS_PXFS       0x80   /* clustering: global fs proxy vfs */
#define VFS_UNMOUNTED  0x100  /* file system has been unmounted */
#define VFS_NBMAND     0x200  /* allow non-blocking mandatory locks */
#define VFS_XATTR      0x400  /* fs supports extended attributes */
#define VFS_NODEVICES  0x800  /* device-special files disallowed */
#define VFS_NOEXEC     0x1000 /* executables disallowed */
#define VFS_STATS      0x2000 /* file system can collect stats */

#endif
