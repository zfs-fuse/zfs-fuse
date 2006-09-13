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

#ifndef _SYS_VNODE_H
#define _SYS_VNODE_H

#include <sys/types.h>
#include <sys/rwstlock.h>
#include <sys/cred.h>
#include <sys/uio.h>
#include <sys/resource.h>

typedef struct vn_vfslocks_entry {
	rwslock_t ve_lock;
} vn_vfslocks_entry_t;

/* Please look at vfs_init() if you change this structure */
typedef struct vnode {
	struct vfs          *v_vfsp;      /* ptr to containing VFS */
	vn_vfslocks_entry_t  v_vfsmhlock; /* Protects v_vfsmountedhere */
	int                  v_fd;
	uint64_t             v_size;
	char                *v_path;
} vnode_t;

typedef struct vattr {
	uint_t     va_mask; /* bit-mask of attributes */
	u_offset_t va_size; /* file size in bytes */
} vattr_t;

typedef int vsecattr_t;

#define AT_TYPE    0x0001
#define AT_MODE    0x0002
#define AT_UID     0x0004
#define AT_GID     0x0008
#define AT_FSID    0x0010
#define AT_NODEID  0x0020
#define AT_NLINK   0x0040
#define AT_SIZE    0x0080
#define AT_ATIME   0x0100
#define AT_MTIME   0x0200
#define AT_CTIME   0x0400
#define AT_RDEV    0x0800
#define AT_BLKSIZE 0x1000
#define AT_NBLOCKS 0x2000
#define AT_SEQ     0x8000

/*
 * Flags for vnode operations.
 */
enum rm { RMFILE, RMDIRECTORY };           /* rm or rmdir (remove) */
enum symfollow { NO_FOLLOW, FOLLOW };      /* follow symlinks (or not) */
enum vcexcl { NONEXCL, EXCL };             /* (non)excl create */
enum create { CRCREAT, CRMKNOD, CRMKDIR }; /* reason for create */

typedef enum rm        rm_t;
typedef enum symfollow symfollow_t;
typedef enum vcexcl    vcexcl_t;
typedef enum create    create_t;

extern int vn_vfswlock(vnode_t *);
extern vn_vfslocks_entry_t *vn_vfslocks_getlock_vnode(vnode_t *);
#define vn_vfslocks_rele(x) ((void) (0))

#define VOP_GETATTR(vp, vap, fl, cr)    ((vap)->va_size = (vp)->v_size, 0)
#define VOP_FSYNC(vp, f, cr)            fsync((vp)->v_fd)
#define VOP_PUTPAGE(vp, of, sz, fl, cr) 0
#define VOP_CLOSE(vp, f, c, o, cr)      0
#define VN_RELE(vp)                     vn_close(vp)

extern int vn_open(char *pnamep, enum uio_seg seg, int filemode, int createmode, struct vnode **vpp, enum create crwhy, mode_t umask);
extern int vn_openat(char *pnamep, enum uio_seg seg, int filemode, int createmode, struct vnode **vpp, enum create crwhy, mode_t umask, struct vnode *startvp);
extern int vn_rdwr(enum uio_rw rw, struct vnode *vp, caddr_t base, ssize_t len, offset_t offset, enum uio_seg seg, int ioflag, rlim64_t ulimit, cred_t *cr, ssize_t *residp);
extern void vn_close(vnode_t *vp);

#define vn_remove(path, x1, x2) remove(path)
#define vn_rename(from, to, seg) rename((from), (to))

//#define vn_is_readonly(vp) (vp->v_vfsp->vfs_flag & VFS_RDONLY)
#define vn_is_readonly(vp) B_FALSE

#endif
