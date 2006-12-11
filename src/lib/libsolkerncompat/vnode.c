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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1983, 1984, 1985, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

/*
 * University Copyright- Copyright (c) 1982, 1986, 1988
 * The Regents of the University of California
 * All Rights Reserved
 *
 * University Acknowledgment- Portions of this document are derived from
 * software developed by the University of California, Berkeley, and its
 * contributors.
 */

#include <sys/vnode.h>
#include <sys/errno.h>
#include <sys/stat.h>
#include <sys/file.h>
#include <sys/debug.h>
#include <sys/systm.h>
#include <sys/kmem.h>
#include <sys/rwstlock.h>
#include <sys/vfs.h>
#include <sys/cmn_err.h>
#include <sys/atomic.h>
#include <sys/types.h>
#include <sys/atomic.h>
#include <sys/pathname.h>
#include <fs/fs_subr.h>

#include <stdio.h>
#include <fcntl.h>
#include <string.h>
#include <umem.h>
#include <unistd.h>

#include <sys/ioctl.h>
/* LINUX BLKGETSIZE64 */
#include <sys/mount.h>

#define VOPSTATS_UPDATE(vp, counter) ((void) 0)

/*
 * Convert stat(2) formats to vnode types and vice versa.  (Knows about
 * numerical order of S_IFMT and vnode types.)
 */
enum vtype iftovt_tab[] = {
	VNON, VFIFO, VCHR, VNON, VDIR, VNON, VBLK, VNON,
	VREG, VNON, VLNK, VNON, VSOCK, VNON, VNON, VNON
};

ushort_t vttoif_tab[] = {
	0, S_IFREG, S_IFDIR, S_IFBLK, S_IFCHR, S_IFLNK, S_IFIFO,
	0, 0, S_IFSOCK, 0, 0
};

/*
 * Vnode operations vector.
 */

static const fs_operation_trans_def_t vn_ops_table[] = {
	VOPNAME_OPEN, offsetof(struct vnodeops, vop_open),
	    fs_nosys, fs_nosys,

	VOPNAME_CLOSE, offsetof(struct vnodeops, vop_close),
	    fs_nosys, fs_nosys,

	VOPNAME_READ, offsetof(struct vnodeops, vop_read),
	    fs_nosys, fs_nosys,

	VOPNAME_WRITE, offsetof(struct vnodeops, vop_write),
	    fs_nosys, fs_nosys,

	VOPNAME_IOCTL, offsetof(struct vnodeops, vop_ioctl),
	    fs_nosys, fs_nosys,

	VOPNAME_SETFL, offsetof(struct vnodeops, vop_setfl),
	    fs_setfl, fs_nosys,

	VOPNAME_GETATTR, offsetof(struct vnodeops, vop_getattr),
	    fs_nosys, fs_nosys,

	VOPNAME_SETATTR, offsetof(struct vnodeops, vop_setattr),
	    fs_nosys, fs_nosys,

	VOPNAME_ACCESS, offsetof(struct vnodeops, vop_access),
	    fs_nosys, fs_nosys,

	VOPNAME_LOOKUP, offsetof(struct vnodeops, vop_lookup),
	    fs_nosys, fs_nosys,

	VOPNAME_CREATE, offsetof(struct vnodeops, vop_create),
	    fs_nosys, fs_nosys,

	VOPNAME_REMOVE, offsetof(struct vnodeops, vop_remove),
	    fs_nosys, fs_nosys,

	VOPNAME_LINK, offsetof(struct vnodeops, vop_link),
	    fs_nosys, fs_nosys,

	VOPNAME_RENAME, offsetof(struct vnodeops, vop_rename),
	    fs_nosys, fs_nosys,

	VOPNAME_MKDIR, offsetof(struct vnodeops, vop_mkdir),
	    fs_nosys, fs_nosys,

	VOPNAME_RMDIR, offsetof(struct vnodeops, vop_rmdir),
	    fs_nosys, fs_nosys,

	VOPNAME_READDIR, offsetof(struct vnodeops, vop_readdir),
	    fs_nosys, fs_nosys,

	VOPNAME_SYMLINK, offsetof(struct vnodeops, vop_symlink),
	    fs_nosys, fs_nosys,

	VOPNAME_READLINK, offsetof(struct vnodeops, vop_readlink),
	    fs_nosys, fs_nosys,

	VOPNAME_FSYNC, offsetof(struct vnodeops, vop_fsync),
	    fs_nosys, fs_nosys,

	VOPNAME_INACTIVE, offsetof(struct vnodeops, vop_inactive),
	    fs_nosys, fs_nosys,

	VOPNAME_FID, offsetof(struct vnodeops, vop_fid),
	    fs_nosys, fs_nosys,

	VOPNAME_RWLOCK, offsetof(struct vnodeops, vop_rwlock),
	    fs_rwlock, fs_rwlock,

	VOPNAME_RWUNLOCK, offsetof(struct vnodeops, vop_rwunlock),
	    (fs_generic_func_p) fs_rwunlock,
	    (fs_generic_func_p) fs_rwunlock,	/* no errors allowed */

	VOPNAME_SEEK, offsetof(struct vnodeops, vop_seek),
	    fs_nosys, fs_nosys,

	VOPNAME_CMP, offsetof(struct vnodeops, vop_cmp),
	    fs_cmp, fs_cmp,		/* no errors allowed */

	VOPNAME_FRLOCK, offsetof(struct vnodeops, vop_frlock),
	    fs_frlock, fs_nosys,

	VOPNAME_SPACE, offsetof(struct vnodeops, vop_space),
	    fs_nosys, fs_nosys,

	VOPNAME_REALVP, offsetof(struct vnodeops, vop_realvp),
	    fs_nosys, fs_nosys,

	VOPNAME_GETPAGE, offsetof(struct vnodeops, vop_getpage),
	    fs_nosys, fs_nosys,

	VOPNAME_PUTPAGE, offsetof(struct vnodeops, vop_putpage),
	    fs_nosys, fs_nosys,

	VOPNAME_MAP, offsetof(struct vnodeops, vop_map),
	    (fs_generic_func_p) fs_nosys_map,
	    (fs_generic_func_p) fs_nosys_map,

	VOPNAME_ADDMAP, offsetof(struct vnodeops, vop_addmap),
	    (fs_generic_func_p) fs_nosys_addmap,
	    (fs_generic_func_p) fs_nosys_addmap,

	VOPNAME_DELMAP, offsetof(struct vnodeops, vop_delmap),
	    fs_nosys, fs_nosys,

	VOPNAME_POLL, offsetof(struct vnodeops, vop_poll),
	    (fs_generic_func_p) fs_poll, (fs_generic_func_p) fs_nosys_poll,

	VOPNAME_DUMP, offsetof(struct vnodeops, vop_dump),
	    fs_nosys, fs_nosys,

	VOPNAME_PATHCONF, offsetof(struct vnodeops, vop_pathconf),
	    fs_pathconf, fs_nosys,

	VOPNAME_PAGEIO, offsetof(struct vnodeops, vop_pageio),
	    fs_nosys, fs_nosys,

	VOPNAME_DUMPCTL, offsetof(struct vnodeops, vop_dumpctl),
	    fs_nosys, fs_nosys,

	VOPNAME_DISPOSE, offsetof(struct vnodeops, vop_dispose),
	    (fs_generic_func_p) fs_dispose,
	    (fs_generic_func_p) fs_nodispose,

	VOPNAME_SETSECATTR, offsetof(struct vnodeops, vop_setsecattr),
	    fs_nosys, fs_nosys,

	VOPNAME_GETSECATTR, offsetof(struct vnodeops, vop_getsecattr),
	    fs_fab_acl, fs_nosys,

	VOPNAME_SHRLOCK, offsetof(struct vnodeops, vop_shrlock),
	    fs_shrlock, fs_nosys,

	VOPNAME_VNEVENT, offsetof(struct vnodeops, vop_vnevent),
	    (fs_generic_func_p) fs_vnevent_nosupport,
	    (fs_generic_func_p) fs_vnevent_nosupport,

	NULL, 0, NULL, NULL
};

extern struct vnodeops *root_fvnodeops;

/*
 * vn_vfswlock is used to implement a lock which is logically a writers lock
 * protecting the v_vfsmountedhere field.
 */
int
vn_vfswlock(vnode_t *vp)
{
	vn_vfslocks_entry_t *vpvfsentry;

	/*
	 * If vp is NULL then somebody is trying to lock the covered vnode
	 * of /.  (vfs_vnodecovered is NULL for /).  This situation will
	 * only happen when unmounting /.  Since that operation will fail
	 * anyway, return EBUSY here instead of in VFS_UNMOUNT.
	 */
	if (vp == NULL)
		return (EBUSY);

	vpvfsentry = vn_vfslocks_getlock_vnode(vp);

	if (rwst_tryenter(&vpvfsentry->ve_lock, RW_WRITER))
		return (0);

	vn_vfslocks_rele(vpvfsentry);
	return (EBUSY);
}

void
vn_vfsunlock(vnode_t *vp)
{
	vn_vfslocks_entry_t *vpvfsentry;

	/*
	 * ve_refcnt needs to be decremented twice.
	 * 1. To release refernce after a call to vn_vfslocks_getlock()
	 * 2. To release the reference from the locking routines like
	 *    vn_vfsrlock/vn_vfswlock etc,.
	 */
	vpvfsentry = vn_vfslocks_getlock(vp);
	vn_vfslocks_rele(vpvfsentry);

	rwst_exit(&vpvfsentry->ve_lock);
	vn_vfslocks_rele(vpvfsentry);
}

vnode_t *vn_alloc(int kmflag)
{
	ASSERT(kmflag == 0 || kmflag == UMEM_NOFAIL);

	vnode_t *vp;

	vp = umem_alloc(sizeof(vnode_t), kmflag);

	/* taken from vn_cache_constructor */
	mutex_init(&vp->v_lock, NULL, MUTEX_DEFAULT, NULL);
	rwst_init(&vp->v_vfsmhlock.ve_lock, NULL, RW_DEFAULT, NULL);

	if(vp != NULL) {
		vp->v_path = NULL;
		vp->v_data = NULL;
		vn_reinit(vp);
	}

	return vp;
}

void vn_reinit(vnode_t *vp)
{
	vp->v_vfsp = NULL;
	vp->v_fd = -1;
	vp->v_size = 0;
	vp->v_count = 1;

	vn_recycle(vp);
}

void vn_recycle(vnode_t *vp)
{
	/*
	 * XXX - This really belongs in vn_reinit(), but we have some issues
	 * with the counts.  Best to have it here for clean initialization.
	 */
	vp->v_rdcnt = 0;
	vp->v_wrcnt = 0;

	if(vp->v_path != NULL) {
		free(vp->v_path);
		vp->v_path = NULL;
	}
}

void vn_free(vnode_t *vp)
{
	ASSERT(vp->v_count == 0 || vp->v_count == 1);

	vn_close(vp);
}

/*
 * Note: for the xxxat() versions of these functions, we assume that the
 * starting vp is always rootdir (which is true for spa_directory.c, the only
 * ZFS consumer of these interfaces).  We assert this is true, and then emulate
 * them by adding '/' in front of the path.
 */

/*ARGSUSED*/
int
vn_open(char *path, enum uio_seg x1, int flags, int mode, vnode_t **vpp, enum create x2, mode_t x3)
{
	int fd;
	vnode_t *vp;
	int old_umask = 0;
	char realpath[MAXPATHLEN];
	struct stat64 st;

	/*
	 * If we're accessing a real disk from userland, we need to use
	 * the character interface to avoid caching.  This is particularly
	 * important if we're trying to look at a real in-kernel storage
	 * pool from userland, e.g. via zdb, because otherwise we won't
	 * see the changes occurring under the segmap cache.
	 * On the other hand, the stupid character device returns zero
	 * for its size.  So -- gag -- we open the block device to get
	 * its size, and remember it for subsequent VOP_GETATTR().
	 */
	/* FIXME: Clean this up */
	if (strncmp(path, "/dev/", 5) == 0) {
		char *dsk;
		fd = open64(path, O_RDONLY);
		if (fd == -1)
			return (errno);
		if (fstat64(fd, &st) == -1) {
			close(fd);
			return (errno);
		}
		close(fd);
		(void) sprintf(realpath, "%s", path);
		dsk = strstr(path, "/dsk/");
		if (dsk != NULL)
			(void) sprintf(realpath + (dsk - path) + 1, "r%s",
			    dsk + 1);
	} else {
		(void) sprintf(realpath, "%s", path);
		if (!(flags & FCREAT) && stat64(realpath, &st) == -1)
			return (errno);
	}

	if (flags & FCREAT)
		old_umask = umask(0);

	/*
	 * The construct 'flags - FREAD' conveniently maps combinations of
	 * FREAD and FWRITE to the corresponding O_RDONLY, O_WRONLY, and O_RDWR.
	 */
	fd = open64(realpath, flags - FREAD, mode);

	if (flags & FCREAT)
		(void) umask(old_umask);

	if (fd == -1)
		return (errno);

	if (fstat64(fd, &st) == -1) {
		close(fd);
		return (errno);
	}

	(void) fcntl(fd, F_SETFD, FD_CLOEXEC);

	*vpp = vp = umem_zalloc(sizeof (vnode_t), UMEM_NOFAIL);

	vp->v_fd = fd;
	if(S_ISBLK(st.st_mode)) {
		/* LINUX */
		if(ioctl(fd, BLKGETSIZE64, &vp->v_size) != 0)
			return errno;
	} else
		vp->v_size = st.st_size;
	vp->v_path = strdup(path);

	vp->v_type = VNON;

	if(S_ISREG(st.st_mode)) {
		vp->v_type = VREG;
		vn_setops(vp, root_fvnodeops);
		if (flags & FREAD)
			atomic_add_32(&((*vpp)->v_rdcnt), 1);
		if (flags & FWRITE)
			atomic_add_32(&((*vpp)->v_wrcnt), 1);
	} else if(S_ISDIR(st.st_mode))
		vp->v_type = VDIR;
	else if(S_ISCHR(st.st_mode))
		vp->v_type = VCHR;
	else if(S_ISBLK(st.st_mode))
		vp->v_type = VBLK;
	else if(S_ISFIFO(st.st_mode))
		vp->v_type = VFIFO;
	else if(S_ISLNK(st.st_mode))
		vp->v_type = VLNK;
	else if(S_ISSOCK(st.st_mode))
		vp->v_type = VSOCK;

	VERIFY(vp->v_type != VNON);

	zmutex_init(&vp->v_lock);
	rwst_init(&vp->v_vfsmhlock.ve_lock, NULL, RW_DEFAULT, NULL);

	vp->v_count = 1;

	return (0);
}

int
vn_openat(char *path, enum uio_seg x1, int flags, int mode, vnode_t **vpp, enum create x2,
    mode_t x3, vnode_t *startvp)
{
	char *realpath = umem_alloc(strlen(path) + 2, UMEM_NOFAIL);
	int ret;

	ASSERT(startvp == rootdir);
	(void) sprintf(realpath, "/%s", path);

	ret = vn_open(realpath, x1, flags, mode, vpp, x2, x3);

	umem_free(realpath, strlen(path) + 2);

	return (ret);
}

/*ARGSUSED*/
int
vn_rdwr(enum uio_rw uio, vnode_t *vp, caddr_t addr, ssize_t len, offset_t offset,
	enum uio_seg x1, int x2, rlim64_t x3, cred_t *x4, ssize_t *residp)
{
	ssize_t iolen;

	if (uio == UIO_READ)
		iolen = pread64(vp->v_fd, addr, len, offset);
	else
		iolen = pwrite64(vp->v_fd, addr, len, offset);

	if(iolen < len)
		fprintf(stderr, "%s: len: %lli iolen: %lli offset: %lli file: %s\n", uio == UIO_READ ? "UIO_READ" : "UIO_WRITE", (longlong_t) len, (longlong_t) iolen, (longlong_t) offset, vp->v_path);

	if (iolen == -1)
		return (errno);
	if (residp)
		*residp = len - iolen;
	else if (iolen != len)
		return (EIO);
	return (0);
}

void vn_rele(vnode_t *vp)
{
	ASSERT(vp->v_count > 0);

	mutex_enter(&vp->v_lock);
	if(vp->v_count == 1) {
		mutex_exit(&vp->v_lock);
		/* ZFSFUSE: FIXME FIXME */
		VOP_INACTIVE(vp, CRED());
	} else {
		vp->v_count--;
		mutex_exit(&vp->v_lock);
	}
}

void vn_close(vnode_t *vp)
{
	rwst_destroy(&vp->v_vfsmhlock.ve_lock);
	zmutex_destroy(&vp->v_lock);
	if(vp->v_fd != -1)
		close(vp->v_fd);
	if(vp->v_path != NULL)
		free(vp->v_path);
	umem_free(vp, sizeof (vnode_t));
}

int
vn_make_ops(
	const char *name,			/* Name of file system */
	const fs_operation_def_t *templ,	/* Operation specification */
	vnodeops_t **actual)			/* Return the vnodeops */
{
	int unused_ops;
	int error;

	*actual = (vnodeops_t *)kmem_alloc(sizeof (vnodeops_t), KM_SLEEP);

	(*actual)->vnop_name = name;

	error = fs_build_vector(*actual, &unused_ops, vn_ops_table, templ);
	if (error) {
		kmem_free(*actual, sizeof (vnodeops_t));
	}

#if DEBUG
	if (unused_ops != 0)
		cmn_err(CE_WARN, "vn_make_ops: %s: %d operations supplied "
		    "but not used", name, unused_ops);
#endif

	return (error);
}

/*
 * Free the vnodeops created as a result of vn_make_ops()
 */
void
vn_freevnodeops(vnodeops_t *vnops)
{
	kmem_free(vnops, sizeof (vnodeops_t));
}

/*
 * Set the operations vector for a vnode.
 */
void
vn_setops(vnode_t *vp, vnodeops_t *vnodeops)
{
	ASSERT(vp != NULL);
	ASSERT(vnodeops != NULL);

	vp->v_op = vnodeops;
}

int
vn_is_readonly(vnode_t *vp)
{
	return (vp->v_vfsp->vfs_flag & VFS_RDONLY);
}

/*
 * Given a starting vnode and a path, updates the path in the target vnode in
 * a safe manner.  If the vnode already has path information embedded, then the
 * cached path is left untouched.
 */
void
vn_setpath(vnode_t *rootvp, struct vnode *startvp, struct vnode *vp,
    const char *path, size_t plen)
{
	char	*rpath;
	vnode_t	*base;
	size_t	rpathlen, rpathalloc;
	int	doslash = 1;

	if (*path == '/') {
		base = rootvp;
		path++;
		plen--;
	} else {
		base = startvp;
	}

	/*
	 * We cannot grab base->v_lock while we hold vp->v_lock because of
	 * the potential for deadlock.
	 */
	mutex_enter(&base->v_lock);
	if (base->v_path == NULL) {
		mutex_exit(&base->v_lock);
		return;
	}

	rpathlen = strlen(base->v_path);
	rpathalloc = rpathlen + plen + 1;
	/* Avoid adding a slash if there's already one there */
	if (base->v_path[rpathlen-1] == '/')
		doslash = 0;
	else
		rpathalloc++;

	/*
	 * We don't want to call kmem_alloc(KM_SLEEP) with kernel locks held,
	 * so we must do this dance.  If, by chance, something changes the path,
	 * just give up since there is no real harm.
	 */
	mutex_exit(&base->v_lock);

	rpath = kmem_alloc(rpathalloc, KM_SLEEP);

	mutex_enter(&base->v_lock);
	if (base->v_path == NULL || strlen(base->v_path) != rpathlen) {
		mutex_exit(&base->v_lock);
		kmem_free(rpath, rpathalloc);
		return;
	}
	bcopy(base->v_path, rpath, rpathlen);
	mutex_exit(&base->v_lock);

	if (doslash)
		rpath[rpathlen++] = '/';
	bcopy(path, rpath + rpathlen, plen);
	rpath[rpathlen + plen] = '\0';

	mutex_enter(&vp->v_lock);
	if (vp->v_path != NULL) {
		mutex_exit(&vp->v_lock);
		kmem_free(rpath, rpathalloc);
	} else {
		vp->v_path = rpath;
		mutex_exit(&vp->v_lock);
	}
}

int
fop_close(
	vnode_t *vp,
	int flag,
	int count,
	offset_t offset,
	cred_t *cr)
{
	int err;

	err = (*(vp)->v_op->vop_close)(vp, flag, count, offset, cr);
	VOPSTATS_UPDATE(vp, close);
	/*
	 * Check passed in count to handle possible dups. Vnode counts are only
	 * kept on regular files
	 */
	if ((vp->v_type == VREG) && (count == 1))  {
		if (flag & FREAD) {
			ASSERT(vp->v_rdcnt > 0);
			atomic_add_32(&(vp->v_rdcnt), -1);
		}
		if (flag & FWRITE) {
			ASSERT(vp->v_wrcnt > 0);
			atomic_add_32(&(vp->v_wrcnt), -1);
		}
	}
	return (err);
}

int
fop_fsync(
	vnode_t *vp,
	int syncflag,
	cred_t *cr)
{
	int	err;

	err = (*(vp)->v_op->vop_fsync)(vp, syncflag, cr);
	VOPSTATS_UPDATE(vp, fsync);
	return (err);
}

int
fop_getattr(
	vnode_t *vp,
	vattr_t *vap,
	int flags,
	cred_t *cr)
{
	int	err;

	err = (*(vp)->v_op->vop_getattr)(vp, vap, flags, cr);
	VOPSTATS_UPDATE(vp, getattr);
	return (err);
}

void
fop_inactive(
	vnode_t *vp,
	cred_t *cr)
{
	/* Need to update stats before vop call since we may lose the vnode */
	VOPSTATS_UPDATE(vp, inactive);
	(*(vp)->v_op->vop_inactive)(vp, cr);
}

int
fop_putpage(
	vnode_t *vp,
	offset_t off,
	size_t len,
	int flags,
	cred_t *cr)
{
	int	err;

	err = (*(vp)->v_op->vop_putpage)(vp, off, len, flags, cr);
	VOPSTATS_UPDATE(vp, putpage);
	return (err);
}

int
fop_realvp(
	vnode_t *vp,
	vnode_t **vpp)
{
	int	err;

	err = (*(vp)->v_op->vop_realvp)(vp, vpp);
	VOPSTATS_UPDATE(vp, realvp);
	return (err);
}

int
fop_lookup(
	vnode_t *dvp,
	char *nm,
	vnode_t **vpp,
	pathname_t *pnp,
	int flags,
	vnode_t *rdir,
	cred_t *cr)
{
	int ret;

	ret = (*(dvp)->v_op->vop_lookup)(dvp, nm, vpp, pnp, flags, rdir, cr);
	if (ret == 0 && *vpp) {
		VOPSTATS_UPDATE(*vpp, lookup);
		if ((*vpp)->v_path == NULL) {
			vn_setpath(rootdir, dvp, *vpp, nm, strlen(nm));
		}
	}

	return (ret);
}

static int
root_getattr(vnode_t *vp, vattr_t *vap, int flags, cred_t *cr)
{
	vap->va_size = vp->v_size;
	return 0;
}

static int
root_fsync(vnode_t *vp, int syncflag, cred_t *cr)
{
	return fsync(vp->v_fd);
}

static int
root_close(vnode_t *vp, int flag, int count, offset_t offset, cred_t *cr)
{
	return close(vp->v_fd);
}

const fs_operation_def_t root_fvnodeops_template[] = {
	VOPNAME_GETATTR, root_getattr,
	VOPNAME_FSYNC, root_fsync,
	VOPNAME_CLOSE, root_close,
	NULL, NULL
};
