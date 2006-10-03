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
#include <sys/vfs.h>

typedef struct vn_vfslocks_entry {
	rwslock_t ve_lock;
} vn_vfslocks_entry_t;

/*
 * vnode types.  VNON means no type.  These values are unrelated to
 * values in on-disk inodes.
 */
typedef enum vtype {
	VNON  = 0,
	VREG  = 1,
	VDIR  = 2,
	VBLK  = 3,
	VCHR  = 4,
	VLNK  = 5,
	VFIFO = 6,
	VDOOR = 7,
	VPROC = 8,
	VSOCK = 9,
	VPORT = 10,
	VBAD  = 11
} vtype_t;

/*
 * vnode flags.
 */
#define VROOT      0x01   /* root of its file system */
#define VNOCACHE   0x02   /* don't keep cache pages on vnode */
#define VNOMAP     0x04   /* file cannot be mapped/faulted */
#define VDUP       0x08   /* file should be dup'ed rather then opened */
#define VNOSWAP    0x10   /* file cannot be used as virtual swap device */
#define VNOMOUNT   0x20   /* file cannot be covered by mount */
#define VISSWAP    0x40   /* vnode is being used for swap */
#define VSWAPLIKE  0x80   /* vnode acts like swap (but may not be) */

#define V_XATTRDIR 0x4000 /* attribute unnamed directory */
#define VMODSORT   0x10000

#define IS_SWAPVP(vp) (((vp)->v_flag & (VISSWAP | VSWAPLIKE)) != 0)

/* Please look at vfs_init() if you change this structure */
typedef struct vnode {
	kmutex_t             v_lock;      /* protects vnode fields */
	uint_t               v_flag;      /* vnode flags (see below) */
	struct vfs          *v_vfsp;      /* ptr to containing VFS */
	vn_vfslocks_entry_t  v_vfsmhlock; /* Protects v_vfsmountedhere */
	int                  v_fd;
	uint64_t             v_size;
	char                *v_path;
	void                *v_data;
	uint_t               v_count;
	enum vtype           v_type;  /* vnode type */
} vnode_t;

typedef struct vattr {
	uint_t       va_mask;    /* bit-mask of attributes */
	vtype_t      va_type;    /* vnode type (for create) */
	mode_t       va_mode;    /* file access mode */
	uid_t        va_uid;     /* owner user id */
	gid_t        va_gid;     /* owner group id */
	u_longlong_t va_nodeid;  /* node id */
	u_offset_t   va_size;    /* file size in bytes */
	timestruc_t  va_atime;   /* time of last access */
	timestruc_t  va_mtime;   /* time of last modification */
	timestruc_t  va_ctime;   /* time of last status change */
	dev_t        va_rdev;    /* device the file represents */
	u_longlong_t va_nblocks; /* # of blocks allocated */
} vattr_t;

typedef void vsecattr_t;
typedef int fs_operation_def_t;

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
extern void vn_vfsunlock(vnode_t *vp);
/*
 * I don't think fancy hash tables are needed in zfs-fuse
 */
#define vn_vfslocks_getlock(vn)       (&(vn)->v_vfsmhlock)
#define vn_vfslocks_getlock_vnode(vn) vn_vfslocks_getlock(vn)
#define vn_vfslocks_rele(x)           ((void) (0))

#define VOP_GETATTR(vp, vap, fl, cr)    ((vap)->va_size = (vp)->v_size, 0)
#define VOP_FSYNC(vp, f, cr)            fsync((vp)->v_fd)
#define VOP_PUTPAGE(vp, of, sz, fl, cr) 0
#define VOP_CLOSE(vp, f, c, o, cr)      0
#define VN_RELE(vp)                     vn_rele(vp)
#define	VN_HOLD(vp) { \
	mutex_enter(&(vp)->v_lock); \
	(vp)->v_count++; \
	mutex_exit(&(vp)->v_lock); \
}

extern vnode_t *vn_alloc(int kmflag);
extern void vn_reinit(vnode_t *vp);
extern void vn_recycle(vnode_t *vp);
extern void vn_free(vnode_t *vp);
extern void vn_rele(vnode_t *vp);

extern int vn_open(char *pnamep, enum uio_seg seg, int filemode, int createmode, struct vnode **vpp, enum create crwhy, mode_t umask);
extern int vn_openat(char *pnamep, enum uio_seg seg, int filemode, int createmode, struct vnode **vpp, enum create crwhy, mode_t umask, struct vnode *startvp);
extern int vn_rdwr(enum uio_rw rw, struct vnode *vp, caddr_t base, ssize_t len, offset_t offset, enum uio_seg seg, int ioflag, rlim64_t ulimit, cred_t *cr, ssize_t *residp);
extern void vn_close(vnode_t *vp);

#define vn_remove(path,x1,x2)    remove(path)
#define vn_rename(from,to,seg)   rename((from), (to))
#define vn_invalid(vp)           ((void) 0)
#define vn_exists(vp)            ((void) 0)
#define vn_setops(vn,ops)        ((void) 0)
#define vn_freevnodeops(ops)     ((void) 0)
#define vn_make_ops(a,b,c)       (0)
#define vn_has_cached_data(v)    (0)

/* FIXME FIXME FIXME */
#define vn_ismntpt(vp) B_FALSE

static inline int vn_is_readonly(vnode_t *vp)
{
	return (vp->v_vfsp->vfs_flag & VFS_RDONLY);
}

#endif
