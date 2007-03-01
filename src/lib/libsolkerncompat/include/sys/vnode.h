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
#include <sys/kmem.h>
#include <vm/seg_enum.h>

extern kmem_cache_t *vnode_cache;

typedef int (*fs_generic_func_p) ();

/*
 * File systems use arrays of fs_operation_def structures to form
 * name/value pairs of operations.  These arrays get passed to:
 *
 * 	- vn_make_ops() to create vnodeops
 * 	- vfs_makefsops()/vfs_setfsops() to create vfsops.
 */
typedef struct fs_operation_def {
	char *name;			/* name of operation (NULL at end) */
	fs_generic_func_p func;		/* function implementing operation */
} fs_operation_def_t;

/*
 * The operation registration mechanism uses two master tables of operations:
 * one for vnode operations (vn_ops_table[]) and one for vfs operations
 * (vfs_ops_table[]).  These tables are arrays of fs_operation_trans_def
 * structures.  They contain all of the information necessary for the system
 * to populate an operations structure (e.g., vnodeops, vfsops).
 *
 * File systems call registration routines (vfs_setfsops(), vfs_makefsops(),
 * and vn_make_ops()) and pass in their operations specification tables
 * (arrays of fs_operation_def structures).  These routines use the master
 * table(s) of operations to build a vnodeops or vfsops structure.
 */
typedef struct fs_operation_trans_def {
	char *name;			/* name of operation (NULL at end) */
	int offset;			/* byte offset within ops vector */
	fs_generic_func_p defaultFunc;	/* default function */
	fs_generic_func_p errorFunc; 	/* error function */
} fs_operation_trans_def_t;

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

/*
 * Flags for VOP_LOOKUP
 */
#define LOOKUP_DIR       0x01 /* want parent dir vp */
#define LOOKUP_XATTR     0x02 /* lookup up extended attr dir */
#define CREATE_XATTR_DIR 0x04 /* Create extended attr dir */

/*
 * Flags for VOP_RWLOCK/VOP_RWUNLOCK
 * VOP_RWLOCK will return the flag that was actually set, or -1 if none.
 */
#define V_WRITELOCK_TRUE  (1) /* Request write-lock on the vnode */
#define V_WRITELOCK_FALSE (0) /* Request read-lock on the vnode */

/*
 *  Modes.  Some values same as S_xxx entries from stat.h for convenience.
 */
#define VSUID    04000 /* set user id on execution */
#define VSGID    02000 /* set group id on execution */
#define VSVTX    01000 /* save swapped text even after use */

/*
 * Permissions.
 */
#define VREAD    00400
#define VWRITE   00200
#define VEXEC    00100

#define MODEMASK 07777
#define PERMMASK 00777

/*
 * Check whether mandatory file locking is enabled.
 */

#define MANDMODE(mode)     (((mode) & (VSGID|(VEXEC>>3))) == VSGID)
#define MANDLOCK(vp, mode) ((vp)->v_type == VREG && MANDMODE(mode))

#define IS_SWAPVP(vp) (((vp)->v_flag & (VISSWAP | VSWAPLIKE)) != 0)
#define IS_DEVVP(vp) \
	((vp)->v_type == VCHR || (vp)->v_type == VBLK || (vp)->v_type == VFIFO)

/* Please look at vfs_init() if you change this structure */
typedef struct vnode {
	kmutex_t             v_lock;      /* protects vnode fields */
	uint_t               v_flag;      /* vnode flags (see below) */
	struct vfs          *v_vfsp;      /* ptr to containing VFS */
	vn_vfslocks_entry_t  v_vfsmhlock; /* protects v_vfsmountedhere */
	int                  v_fd;
	uint64_t             v_size;
	char                *v_path;      /* cached path */
	uint_t               v_rdcnt;     /* open for read count  (VREG only) */
	uint_t               v_wrcnt;     /* open for write count (VREG only) */
	void                *v_data;      /* private data for fs */
	uint_t               v_count;     /* reference count */
	enum vtype           v_type;      /* vnode type */
	dev_t                v_rdev;      /* device (VCHR, VBLK) */
	struct vnodeops      *v_op;       /* vnode operations */
} vnode_t;

typedef struct vattr {
	uint_t       va_mask;    /* bit-mask of attributes */
	vtype_t      va_type;    /* vnode type (for create) */
	mode_t       va_mode;    /* file access mode */
	uid_t        va_uid;     /* owner user id */
	gid_t        va_gid;     /* owner group id */
	dev_t        va_fsid;    /* file system id (dev for now) */
	u_longlong_t va_nodeid;  /* node id */
	nlink_t      va_nlink;   /* number of references to file */
	u_offset_t   va_size;    /* file size in bytes */
	timestruc_t  va_atime;   /* time of last access */
	timestruc_t  va_mtime;   /* time of last modification */
	timestruc_t  va_ctime;   /* time of last status change */
	dev_t        va_rdev;    /* device the file represents */
	uint_t       va_blksize; /* fundamental block size */
	u_longlong_t va_nblocks; /* # of blocks allocated */
	uint_t       va_seq;     /* sequence number */
} vattr_t;

/*
 * Structure used on VOP_GETSECATTR and VOP_SETSECATTR operations
 */

typedef struct vsecattr {
	uint_t		vsa_mask;	/* See below */
	int		vsa_aclcnt;	/* ACL entry count */
	void		*vsa_aclentp;	/* pointer to ACL entries */
	int		vsa_dfaclcnt;	/* default ACL entry count */
	void		*vsa_dfaclentp;	/* pointer to default ACL entries */
} vsecattr_t;

/* vsa_mask values */
#define VSA_ACL      0x0001
#define VSA_ACLCNT   0x0002
#define VSA_DFACL    0x0004
#define VSA_DFACLCNT 0x0008
#define VSA_ACE      0x0010
#define VSA_ACECNT   0x0020

typedef int caller_context_t;

/*
 * Structure tags for function prototypes, defined elsewhere.
 */
struct pathname;
struct fid;
struct flock64;
struct flk_callback;
struct shrlock;
struct page;
struct seg;
struct as;
struct pollhead;

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

#define AT_ALL   (AT_TYPE|AT_MODE|AT_UID|AT_GID|AT_FSID|AT_NODEID|\
                 AT_NLINK|AT_SIZE|AT_ATIME|AT_MTIME|AT_CTIME|\
                 AT_RDEV|AT_BLKSIZE|AT_NBLOCKS|AT_SEQ)

#define AT_STAT  (AT_MODE|AT_UID|AT_GID|AT_FSID|AT_NODEID|AT_NLINK|\
                 AT_SIZE|AT_ATIME|AT_MTIME|AT_CTIME|AT_RDEV|AT_TYPE)

#define AT_TIMES (AT_ATIME|AT_MTIME|AT_CTIME)
#define AT_NOSET (AT_NLINK|AT_RDEV|AT_FSID|AT_NODEID|AT_TYPE|\
                 AT_BLKSIZE|AT_NBLOCKS|AT_SEQ)

/*
 * Flags for vnode operations.
 */
enum rm { RMFILE, RMDIRECTORY };           /* rm or rmdir (remove) */
enum symfollow { NO_FOLLOW, FOLLOW };      /* follow symlinks (or not) */
enum vcexcl { NONEXCL, EXCL };             /* (non)excl create */
enum create { CRCREAT, CRMKNOD, CRMKDIR }; /* reason for create */

/*
 * Flags to VOP_SETATTR/VOP_GETATTR.
 */
#define ATTR_UTIME 0x01 /* non-default utime(2) request */

/* Vnode Events - Used by VOP_VNEVENT */
typedef enum vnevent	{
	VE_SUPPORT	= 0,	/* Query */
	VE_RENAME_SRC	= 1,	/* Rename, with vnode as source */
	VE_RENAME_DEST	= 2,	/* Rename, with vnode as target/destination */
	VE_REMOVE	= 3,	/* Remove of vnode's name */
	VE_RMDIR	= 4	/* Remove of directory vnode's name */
} vnevent_t;

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

#if 0
#define VOP_GETATTR(vp, vap, fl, cr)    ((vap)->va_size = (vp)->v_size, 0)
#define VOP_FSYNC(vp, f, cr)            fsync((vp)->v_fd)
#define VOP_PUTPAGE(vp, of, sz, fl, cr) 0
#define VOP_CLOSE(vp, f, c, o, cr)      0
#endif

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

#define vn_invalid(vp)           ((void) 0)
#define vn_has_cached_data(v)    (0)

/* FIXME */
#define vn_remove(path,x1,x2)    remove(path)
#define vn_rename(from,to,seg)   rename((from), (to))
#define vn_exists(vp)            ((void) 0)

/* Vnode event notification */
/* Not implemented in zfs-fuse */
#define vn_event_rename_src(v) ((void) 0)
#define vnevent_rename_src(v)  ((void) 0)
#define vnevent_rename_dest(v) ((void) 0)
#define vnevent_remove(v)      ((void) 0)
#define vnevent_rmdir(v)       ((void) 0)
#define vnevent_support(v)     (EINVAL)

#if 0
#define vn_setops(vn,ops)        ((void) 0)
#define vn_make_ops(a,b,c)       (0)
#endif

/* FIXME FIXME FIXME */
#define vn_ismntpt(vp) B_FALSE

struct vnodeops;

extern int vn_make_ops(const char *name, const fs_operation_def_t *templ, struct vnodeops **actual);
extern void vn_freevnodeops(struct vnodeops *vnops);
extern int vn_is_readonly(vnode_t *vp);
extern void vn_setops(vnode_t *vp, struct vnodeops *vnodeops);

/*
 * Operations on vnodes.  Note: File systems should never operate directly
 * on a 'vnodeops' structure -- it WILL change in future releases!  They
 * should use vn_make_ops() to create the structure.
 */
typedef struct vnodeops {
	const char *vnop_name;
	int	(*vop_open)(vnode_t **, int, cred_t *);
	int	(*vop_close)(vnode_t *, int, int, offset_t, cred_t *);
	int	(*vop_read)(vnode_t *, uio_t *, int, cred_t *,
				caller_context_t *);
	int	(*vop_write)(vnode_t *, uio_t *, int, cred_t *,
				caller_context_t *);
	int	(*vop_ioctl)(vnode_t *, int, intptr_t, int, cred_t *, int *);
	int	(*vop_setfl)(vnode_t *, int, int, cred_t *);
	int	(*vop_getattr)(vnode_t *, vattr_t *, int, cred_t *);
	int	(*vop_setattr)(vnode_t *, vattr_t *, int, cred_t *,
				caller_context_t *);
	int	(*vop_access)(vnode_t *, int, int, cred_t *);
	int	(*vop_lookup)(vnode_t *, char *, vnode_t **, struct pathname *,
				int, vnode_t *, cred_t *);
	int	(*vop_create)(vnode_t *, char *, vattr_t *, vcexcl_t, int,
				vnode_t **, cred_t *, int);
	int	(*vop_remove)(vnode_t *, char *, cred_t *);
	int	(*vop_link)(vnode_t *, vnode_t *, char *, cred_t *);
	int	(*vop_rename)(vnode_t *, char *, vnode_t *, char *, cred_t *);
	int	(*vop_mkdir)(vnode_t *, char *, vattr_t *, vnode_t **,
				cred_t *);
	int	(*vop_rmdir)(vnode_t *, char *, vnode_t *, cred_t *);
	int	(*vop_readdir)(vnode_t *, uio_t *, cred_t *, int *);
	int	(*vop_symlink)(vnode_t *, char *, vattr_t *, char *, cred_t *);
	int	(*vop_readlink)(vnode_t *, uio_t *, cred_t *);
	int	(*vop_fsync)(vnode_t *, int, cred_t *);
	void	(*vop_inactive)(vnode_t *, cred_t *);
	int	(*vop_fid)(vnode_t *, struct fid *);
	int	(*vop_rwlock)(vnode_t *, int, caller_context_t *);
	void	(*vop_rwunlock)(vnode_t *, int, caller_context_t *);
	int	(*vop_seek)(vnode_t *, offset_t, offset_t *);
	int	(*vop_cmp)(vnode_t *, vnode_t *);
	int	(*vop_frlock)(vnode_t *, int, struct flock64 *, int, offset_t,
				struct flk_callback *, cred_t *);
	int	(*vop_space)(vnode_t *, int, struct flock64 *, int, offset_t,
				cred_t *, caller_context_t *);
	int	(*vop_realvp)(vnode_t *, vnode_t **);
	int	(*vop_getpage)(vnode_t *, offset_t, size_t, uint_t *,
				struct page **, size_t, struct seg *,
				caddr_t, enum seg_rw, cred_t *);
	int	(*vop_putpage)(vnode_t *, offset_t, size_t, int, cred_t *);
	int	(*vop_map)(vnode_t *, offset_t, struct as *, caddr_t *, size_t,
				uchar_t, uchar_t, uint_t, cred_t *);
	int	(*vop_addmap)(vnode_t *, offset_t, struct as *, caddr_t, size_t,
				uchar_t, uchar_t, uint_t, cred_t *);
	int	(*vop_delmap)(vnode_t *, offset_t, struct as *, caddr_t, size_t,
				uint_t, uint_t, uint_t, cred_t *);
	int	(*vop_poll)(vnode_t *, short, int, short *, struct pollhead **);
	int	(*vop_dump)(vnode_t *, caddr_t, int, int);
	int	(*vop_pathconf)(vnode_t *, int, ulong_t *, cred_t *);
	int	(*vop_pageio)(vnode_t *, struct page *, u_offset_t, size_t,
				int, cred_t *);
	int	(*vop_dumpctl)(vnode_t *, int, int *);
	void	(*vop_dispose)(vnode_t *, struct page *, int, int, cred_t *);
	int	(*vop_setsecattr)(vnode_t *, vsecattr_t *, int, cred_t *);
	int	(*vop_getsecattr)(vnode_t *, vsecattr_t *, int, cred_t *);
	int	(*vop_shrlock)(vnode_t *, int, struct shrlock *, int, cred_t *);
	int	(*vop_vnevent)(vnode_t *, vnevent_t);
} vnodeops_t;

#ifdef	_KERNEL

extern int	fop_open(vnode_t **, int, cred_t *);
extern int	fop_close(vnode_t *, int, int, offset_t, cred_t *);
extern int	fop_read(vnode_t *, uio_t *, int, cred_t *, caller_context_t *);
extern int	fop_write(vnode_t *, uio_t *, int, cred_t *,
				caller_context_t *);
extern int	fop_ioctl(vnode_t *, int, intptr_t, int, cred_t *, int *);
extern int	fop_setfl(vnode_t *, int, int, cred_t *);
extern int	fop_getattr(vnode_t *, vattr_t *, int, cred_t *);
extern int	fop_setattr(vnode_t *, vattr_t *, int, cred_t *,
				caller_context_t *);
extern int	fop_access(vnode_t *, int, int, cred_t *);
extern int	fop_lookup(vnode_t *, char *, vnode_t **, struct pathname *,
				int, vnode_t *, cred_t *);
extern int	fop_create(vnode_t *, char *, vattr_t *, vcexcl_t, int,
				vnode_t **, cred_t *, int);
extern int	fop_remove(vnode_t *vp, char *, cred_t *);
extern int	fop_link(vnode_t *, vnode_t *, char *, cred_t *);
extern int	fop_rename(vnode_t *, char *, vnode_t *, char *, cred_t *);
extern int	fop_mkdir(vnode_t *, char *, vattr_t *, vnode_t **, cred_t *);
extern int	fop_rmdir(vnode_t *, char *, vnode_t *, cred_t *);
extern int	fop_readdir(vnode_t *, uio_t *, cred_t *, int *);
extern int	fop_symlink(vnode_t *, char *, vattr_t *, char *, cred_t *);
extern int	fop_readlink(vnode_t *, uio_t *, cred_t *);
extern int	fop_fsync(vnode_t *, int, cred_t *);
extern void	fop_inactive(vnode_t *, cred_t *);
extern int	fop_fid(vnode_t *, struct fid *);
extern int	fop_rwlock(vnode_t *, int, caller_context_t *);
extern void	fop_rwunlock(vnode_t *, int, caller_context_t *);
extern int	fop_seek(vnode_t *, offset_t, offset_t *);
extern int	fop_cmp(vnode_t *, vnode_t *);
extern int	fop_frlock(vnode_t *, int, struct flock64 *, int, offset_t,
				struct flk_callback *, cred_t *);
extern int	fop_space(vnode_t *, int, struct flock64 *, int, offset_t,
				cred_t *, caller_context_t *);
extern int	fop_realvp(vnode_t *, vnode_t **);
extern int	fop_getpage(vnode_t *, offset_t, size_t, uint_t *,
				struct page **, size_t, struct seg *,
				caddr_t, enum seg_rw, cred_t *);
extern int	fop_putpage(vnode_t *, offset_t, size_t, int, cred_t *);
extern int	fop_map(vnode_t *, offset_t, struct as *, caddr_t *, size_t,
				uchar_t, uchar_t, uint_t, cred_t *cr);
extern int	fop_addmap(vnode_t *, offset_t, struct as *, caddr_t, size_t,
				uchar_t, uchar_t, uint_t, cred_t *);
extern int	fop_delmap(vnode_t *, offset_t, struct as *, caddr_t, size_t,
				uint_t, uint_t, uint_t, cred_t *);
extern int	fop_poll(vnode_t *, short, int, short *, struct pollhead **);
extern int	fop_dump(vnode_t *, caddr_t, int, int);
extern int	fop_pathconf(vnode_t *, int, ulong_t *, cred_t *);
extern int	fop_pageio(vnode_t *, struct page *, u_offset_t, size_t, int,
				cred_t *);
extern int	fop_dumpctl(vnode_t *, int, int *);
extern void	fop_dispose(vnode_t *, struct page *, int, int, cred_t *);
extern int	fop_setsecattr(vnode_t *, vsecattr_t *, int, cred_t *);
extern int	fop_getsecattr(vnode_t *, vsecattr_t *, int, cred_t *);
extern int	fop_shrlock(vnode_t *, int, struct shrlock *, int, cred_t *);
extern int	fop_vnevent(vnode_t *, vnevent_t);

#endif	/* _KERNEL */

#define	VOP_OPEN(vpp, mode, cr) \
	fop_open(vpp, mode, cr)
#define	VOP_CLOSE(vp, f, c, o, cr) \
	fop_close(vp, f, c, o, cr)
#define	VOP_READ(vp, uiop, iof, cr, ct) \
	fop_read(vp, uiop, iof, cr, ct)
#define	VOP_WRITE(vp, uiop, iof, cr, ct) \
	fop_write(vp, uiop, iof, cr, ct)
#define	VOP_IOCTL(vp, cmd, a, f, cr, rvp) \
	fop_ioctl(vp, cmd, a, f, cr, rvp)
#define	VOP_SETFL(vp, f, a, cr) \
	fop_setfl(vp, f, a, cr)
#define	VOP_GETATTR(vp, vap, f, cr) \
	fop_getattr(vp, vap, f, cr)
#define	VOP_SETATTR(vp, vap, f, cr, ct) \
	fop_setattr(vp, vap, f, cr, ct)
#define	VOP_ACCESS(vp, mode, f, cr) \
	fop_access(vp, mode, f, cr)
#define	VOP_LOOKUP(vp, cp, vpp, pnp, f, rdir, cr) \
	fop_lookup(vp, cp, vpp, pnp, f, rdir, cr)
#define	VOP_CREATE(dvp, p, vap, ex, mode, vpp, cr, flag) \
	fop_create(dvp, p, vap, ex, mode, vpp, cr, flag)
#define	VOP_REMOVE(dvp, p, cr) \
	fop_remove(dvp, p, cr)
#define	VOP_LINK(tdvp, fvp, p, cr) \
	fop_link(tdvp, fvp, p, cr)
#define	VOP_RENAME(fvp, fnm, tdvp, tnm, cr) \
	fop_rename(fvp, fnm, tdvp, tnm, cr)
#define	VOP_MKDIR(dp, p, vap, vpp, cr) \
	fop_mkdir(dp, p, vap, vpp, cr)
#define	VOP_RMDIR(dp, p, cdir, cr) \
	fop_rmdir(dp, p, cdir, cr)
#define	VOP_READDIR(vp, uiop, cr, eofp) \
	fop_readdir(vp, uiop, cr, eofp)
#define	VOP_SYMLINK(dvp, lnm, vap, tnm, cr) \
	fop_symlink(dvp, lnm, vap, tnm, cr)
#define	VOP_READLINK(vp, uiop, cr) \
	fop_readlink(vp, uiop, cr)
#define	VOP_FSYNC(vp, syncflag, cr) \
	fop_fsync(vp, syncflag, cr)
#define	VOP_INACTIVE(vp, cr) \
	fop_inactive(vp, cr)
#define	VOP_FID(vp, fidp) \
	fop_fid(vp, fidp)
#define	VOP_RWLOCK(vp, w, ct) \
	fop_rwlock(vp, w, ct)
#define	VOP_RWUNLOCK(vp, w, ct) \
	fop_rwunlock(vp, w, ct)
#define	VOP_SEEK(vp, ooff, noffp) \
	fop_seek(vp, ooff, noffp)
#define	VOP_CMP(vp1, vp2) \
	fop_cmp(vp1, vp2)
#define	VOP_FRLOCK(vp, cmd, a, f, o, cb, cr) \
	fop_frlock(vp, cmd, a, f, o, cb, cr)
#define	VOP_SPACE(vp, cmd, a, f, o, cr, ct) \
	fop_space(vp, cmd, a, f, o, cr, ct)
#define	VOP_REALVP(vp1, vp2) \
	fop_realvp(vp1, vp2)
#define	VOP_GETPAGE(vp, of, sz, pr, pl, ps, sg, a, rw, cr) \
	fop_getpage(vp, of, sz, pr, pl, ps, sg, a, rw, cr)
#define	VOP_PUTPAGE(vp, of, sz, fl, cr) \
	fop_putpage(vp, of, sz, fl, cr)
#define	VOP_MAP(vp, of, as, a, sz, p, mp, fl, cr) \
	fop_map(vp, of, as, a, sz, p, mp, fl, cr)
#define	VOP_ADDMAP(vp, of, as, a, sz, p, mp, fl, cr) \
	fop_addmap(vp, of, as, a, sz, p, mp, fl, cr)
#define	VOP_DELMAP(vp, of, as, a, sz, p, mp, fl, cr) \
	fop_delmap(vp, of, as, a, sz, p, mp, fl, cr)
#define	VOP_POLL(vp, events, anyyet, reventsp, phpp) \
	fop_poll(vp, events, anyyet, reventsp, phpp)
#define	VOP_DUMP(vp, addr, bn, count) \
	fop_dump(vp, addr, bn, count)
#define	VOP_PATHCONF(vp, cmd, valp, cr) \
	fop_pathconf(vp, cmd, valp, cr)
#define	VOP_PAGEIO(vp, pp, io_off, io_len, flags, cr) \
	fop_pageio(vp, pp, io_off, io_len, flags, cr)
#define	VOP_DUMPCTL(vp, action, blkp) \
	fop_dumpctl(vp, action, blkp)
#define	VOP_DISPOSE(vp, pp, flag, dn, cr) \
	fop_dispose(vp, pp, flag, dn, cr)
#define	VOP_GETSECATTR(vp, vsap, f, cr) \
	fop_getsecattr(vp, vsap, f, cr)
#define	VOP_SETSECATTR(vp, vsap, f, cr) \
	fop_setsecattr(vp, vsap, f, cr)
#define	VOP_SHRLOCK(vp, cmd, shr, f, cr) \
	fop_shrlock(vp, cmd, shr, f, cr)
#define	VOP_VNEVENT(vp, vnevent) \
	fop_vnevent(vp, vnevent)

#define	VOPNAME_OPEN		"open"
#define	VOPNAME_CLOSE		"close"
#define	VOPNAME_READ		"read"
#define	VOPNAME_WRITE		"write"
#define	VOPNAME_IOCTL		"ioctl"
#define	VOPNAME_SETFL		"setfl"
#define	VOPNAME_GETATTR		"getattr"
#define	VOPNAME_SETATTR		"setattr"
#define	VOPNAME_ACCESS		"access"
#define	VOPNAME_LOOKUP		"lookup"
#define	VOPNAME_CREATE		"create"
#define	VOPNAME_REMOVE		"remove"
#define	VOPNAME_LINK		"link"
#define	VOPNAME_RENAME		"rename"
#define	VOPNAME_MKDIR		"mkdir"
#define	VOPNAME_RMDIR		"rmdir"
#define	VOPNAME_READDIR		"readdir"
#define	VOPNAME_SYMLINK		"symlink"
#define	VOPNAME_READLINK	"readlink"
#define	VOPNAME_FSYNC		"fsync"
#define	VOPNAME_INACTIVE	"inactive"
#define	VOPNAME_FID		"fid"
#define	VOPNAME_RWLOCK		"rwlock"
#define	VOPNAME_RWUNLOCK	"rwunlock"
#define	VOPNAME_SEEK		"seek"
#define	VOPNAME_CMP		"cmp"
#define	VOPNAME_FRLOCK		"frlock"
#define	VOPNAME_SPACE		"space"
#define	VOPNAME_REALVP		"realvp"
#define	VOPNAME_GETPAGE		"getpage"
#define	VOPNAME_PUTPAGE		"putpage"
#define	VOPNAME_MAP		"map"
#define	VOPNAME_ADDMAP		"addmap"
#define	VOPNAME_DELMAP		"delmap"
#define	VOPNAME_POLL		"poll"
#define	VOPNAME_DUMP		"dump"
#define	VOPNAME_PATHCONF	"pathconf"
#define	VOPNAME_PAGEIO		"pageio"
#define	VOPNAME_DUMPCTL		"dumpctl"
#define	VOPNAME_DISPOSE		"dispose"
#define	VOPNAME_GETSECATTR	"getsecattr"
#define	VOPNAME_SETSECATTR	"setsecattr"
#define	VOPNAME_SHRLOCK		"shrlock"
#define	VOPNAME_VNEVENT		"vnevent"

#endif
