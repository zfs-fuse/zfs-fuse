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

#include "fuse.h"

#include <sys/statfs.h>
#include <sys/statvfs.h>
#include <sys/debug.h>
#include <sys/vnode.h>
#include <sys/cred_impl.h>
#include <sys/zfs_vfsops.h>
#include <sys/zfs_znode.h>
#include <sys/mode.h>

#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <time.h>

#include "util.h"
#include "fuse_listener.h"

#define ZFS_MAGIC 0x2f52f5

typedef struct file_info {
	vnode_t *vp;
	int flags;
} file_info_t;

static void zfsfuse_getcred(fuse_req_t req, cred_t *cred)
{
	const struct fuse_ctx *ctx = fuse_req_ctx(req);

	cred->cr_uid = ctx->uid;
	cred->cr_gid = ctx->gid;
}

static void zfsfuse_destroy(void *userdata)
{
	vfs_t *vfs = (vfs_t *) userdata;

	struct timespec req;
	req.tv_sec = 0;
	req.tv_nsec = 100000000; /* 100 ms */

#ifdef DEBUG
	fprintf(stderr, "Calling do_umount()...\n");
#endif
	/*
	 * If exit_fuse_listener is true, then we received a signal
	 * and we're terminating the process. Therefore we need to
	 * force unmount since there could still be opened files
	 */
	while(do_umount(vfs, exit_fuse_listener) != 0)
		nanosleep(&req, NULL);
#ifdef DEBUG
	fprintf(stderr, "do_umount() done\n");
#endif
}

static void zfsfuse_statfs(fuse_req_t req)
{
	vfs_t *vfs = (vfs_t *) fuse_req_userdata(req);

	struct statvfs64 zfs_stat;

	int ret = VFS_STATVFS(vfs, &zfs_stat);
	if(ret != 0) {
		fuse_reply_err(req, ret);
		return;
	}

	struct statvfs stat = { 0 };

	/* There's a bug somewhere in FUSE, in the kernel or in df(1) where
	   f_bsize is being used to calculate filesystem size instead of
	   f_frsize, so we must use that instead */
	stat.f_bsize = zfs_stat.f_frsize;
	stat.f_frsize = zfs_stat.f_frsize;
	stat.f_blocks = zfs_stat.f_blocks;
	stat.f_bfree = zfs_stat.f_bfree;
	stat.f_bavail = zfs_stat.f_bavail;
	stat.f_files = zfs_stat.f_files;
	stat.f_ffree = zfs_stat.f_ffree;
	stat.f_favail = zfs_stat.f_favail;
	stat.f_fsid = zfs_stat.f_fsid;
	stat.f_flag = zfs_stat.f_flag;
	stat.f_namemax = zfs_stat.f_namemax;

	int error = -fuse_reply_statfs(req, &stat);
	if(error)
		fuse_reply_err(req, error);
}

static int zfsfuse_stat(vnode_t *vp, struct stat *stbuf, cred_t *cred)
{
	ASSERT(vp != NULL);
	ASSERT(stbuf != NULL);

	vattr_t vattr;
	vattr.va_mask = AT_STAT | AT_NBLOCKS | AT_BLKSIZE | AT_SIZE;

	int error = VOP_GETATTR(vp, &vattr, 0, cred);
	if(error)
		return error;

	memset(stbuf, 0, sizeof(struct stat));

	stbuf->st_dev = vattr.va_fsid;
	stbuf->st_ino = vattr.va_nodeid == 3 ? 1 : vattr.va_nodeid;
	stbuf->st_mode = VTTOIF(vattr.va_type) | vattr.va_mode;
	stbuf->st_nlink = vattr.va_nlink;
	stbuf->st_uid = vattr.va_uid;
	stbuf->st_gid = vattr.va_gid;
	stbuf->st_rdev = vattr.va_rdev;
	stbuf->st_size = vattr.va_size;
	stbuf->st_blksize = vattr.va_blksize;
	stbuf->st_blocks = vattr.va_nblocks;
	TIMESTRUC_TO_TIME(vattr.va_atime, &stbuf->st_atime);
	TIMESTRUC_TO_TIME(vattr.va_mtime, &stbuf->st_mtime);
	TIMESTRUC_TO_TIME(vattr.va_ctime, &stbuf->st_ctime);

	return 0;
}

static int zfsfuse_getattr(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi)
{
	vfs_t *vfs = (vfs_t *) fuse_req_userdata(req);
	zfsvfs_t *zfsvfs = vfs->vfs_data;

	ZFS_ENTER(zfsvfs);

	znode_t *znode;

	int error = zfs_zget(zfsvfs, ino, &znode);
	if(error) {
		ZFS_EXIT(zfsvfs);
		/* If the inode we are trying to get was recently deleted
		   dnode_hold_impl will return EEXIST instead of ENOENT */
		return error == EEXIST ? ENOENT : error;
	}

	ASSERT(znode != NULL);
	vnode_t *vp = ZTOV(znode);
	ASSERT(vp != NULL);

	cred_t cred;
	zfsfuse_getcred(req, &cred);

	struct stat stbuf;
	error = zfsfuse_stat(vp, &stbuf, &cred);

	VN_RELE(vp);
	ZFS_EXIT(zfsvfs);

	if(!error)
		error = -fuse_reply_attr(req, &stbuf, 0.0);

	return error;
}

static void zfsfuse_getattr_helper(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi)
{
	fuse_ino_t real_ino = ino == 1 ? 3 : ino;

	int error = zfsfuse_getattr(req, real_ino, fi);
	if(error)
		fuse_reply_err(req, error);
}

static int zfsfuse_lookup(fuse_req_t req, fuse_ino_t parent, const char *name)
{
	vfs_t *vfs = (vfs_t *) fuse_req_userdata(req);
	zfsvfs_t *zfsvfs = vfs->vfs_data;

	ZFS_ENTER(zfsvfs);

	znode_t *znode;

	int error = zfs_zget(zfsvfs, parent, &znode);
	if(error) {
		ZFS_EXIT(zfsvfs);
		/* If the inode we are trying to get was recently deleted
		   dnode_hold_impl will return EEXIST instead of ENOENT */
		return error == EEXIST ? ENOENT : error;
	}

	ASSERT(znode != NULL);
	vnode_t *dvp = ZTOV(znode);
	ASSERT(dvp != NULL);

	vnode_t *vp = NULL;

	cred_t cred;
	zfsfuse_getcred(req, &cred);

	error = VOP_LOOKUP(dvp, (char *) name, &vp, NULL, 0, NULL, &cred);
	if(error)
		goto out;

	struct fuse_entry_param e = { 0 };

	e.attr_timeout = 0.0;
	e.entry_timeout = 0.0;

	if(vp == NULL)
		goto out;

	e.ino = VTOZ(vp)->z_id;
	if(e.ino == 3)
		e.ino = 1;

	e.generation = VTOZ(vp)->z_phys->zp_gen;

	error = zfsfuse_stat(vp, &e.attr, &cred);

out:
	if(vp != NULL)
		VN_RELE(vp);
	VN_RELE(dvp);
	ZFS_EXIT(zfsvfs);

	if(!error)
		error = -fuse_reply_entry(req, &e);

	return error;
}

static void zfsfuse_lookup_helper(fuse_req_t req, fuse_ino_t parent, const char *name)
{
	fuse_ino_t real_parent = parent == 1 ? 3 : parent;

	int error = zfsfuse_lookup(req, real_parent, name);
	if(error)
		fuse_reply_err(req, error);
}

static int zfsfuse_opendir(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi)
{
	vfs_t *vfs = (vfs_t *) fuse_req_userdata(req);
	zfsvfs_t *zfsvfs = vfs->vfs_data;

	ZFS_ENTER(zfsvfs);

	znode_t *znode;

	int error = zfs_zget(zfsvfs, ino, &znode);
	if(error) {
		ZFS_EXIT(zfsvfs);
		/* If the inode we are trying to get was recently deleted
		   dnode_hold_impl will return EEXIST instead of ENOENT */
		return error == EEXIST ? ENOENT : error;
	}

	ASSERT(znode != NULL);
	vnode_t *vp = ZTOV(znode);
	ASSERT(vp != NULL);

	if(vp->v_type != VDIR) {
		error = ENOTDIR;
		goto out;
	}

	cred_t cred;
	zfsfuse_getcred(req, &cred);

	/*
	 * Check permissions.
	 */
	if (error = VOP_ACCESS(vp, VREAD | VEXEC, 0, &cred))
		goto out;

	vnode_t *old_vp = vp;

	/* XXX: not sure about flags */
	error = VOP_OPEN(&vp, FREAD, &cred);

	ASSERT(old_vp == vp);

	if(!error) {
		file_info_t *info = malloc(sizeof(file_info_t));
		if(info == NULL) {
			error = ENOMEM;
			goto out;
		}

		info->vp = vp;
		info->flags = FREAD;

		fi->fh = (uint64_t) (uintptr_t) info;
	}

out:
	if(error)
		VN_RELE(vp);
	ZFS_EXIT(zfsvfs);

	if(!error)
		error = -fuse_reply_open(req, fi);

	return error;
}

static void zfsfuse_opendir_helper(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi)
{
	fuse_ino_t real_ino = ino == 1 ? 3 : ino;

	int error = zfsfuse_opendir(req, real_ino, fi);
	if(error)
		fuse_reply_err(req, error);
}

static int zfsfuse_release(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi)
{
	vfs_t *vfs = (vfs_t *) fuse_req_userdata(req);
	zfsvfs_t *zfsvfs = vfs->vfs_data;

	ZFS_ENTER(zfsvfs);

	file_info_t *info = (file_info_t *)(uintptr_t) fi->fh;
	ASSERT(info->vp != NULL);
	ASSERT(VTOZ(info->vp) != NULL);
	ASSERT(VTOZ(info->vp)->z_id == ino);

	cred_t cred;
	zfsfuse_getcred(req, &cred);

	int error = VOP_CLOSE(info->vp, info->flags, 1, (offset_t) 0, &cred);
	VERIFY(error == 0);

	VN_RELE(info->vp);

	ASSERT(fi->fh != 0);
	free((void *)(uintptr_t) fi->fh);

	ZFS_EXIT(zfsvfs);

	return error;
}

static void zfsfuse_release_helper(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi)
{
	fuse_ino_t real_ino = ino == 1 ? 3 : ino;

	int error = zfsfuse_release(req, real_ino, fi);
	/* Release events always reply_err */
	fuse_reply_err(req, error);
}

static int zfsfuse_readdir(fuse_req_t req, fuse_ino_t ino, size_t size, off_t off, struct fuse_file_info *fi)
{
	vnode_t *vp = ((file_info_t *)(uintptr_t) fi->fh)->vp;
	ASSERT(vp != NULL);
	ASSERT(VTOZ(vp) != NULL);
	ASSERT(VTOZ(vp)->z_id == ino);

	if(vp->v_type != VDIR)
		return ENOTDIR;

	vfs_t *vfs = (vfs_t *) fuse_req_userdata(req);
	zfsvfs_t *zfsvfs = vfs->vfs_data;

	char *outbuf = malloc(size);
	if(outbuf == NULL)
		return ENOMEM;

	ZFS_ENTER(zfsvfs);

	cred_t cred;
	zfsfuse_getcred(req, &cred);

	union {
		char buf[DIRENT64_RECLEN(MAXNAMELEN)];
		struct dirent64 dirent;
	} entry;

	struct stat fstat = { 0 };

	iovec_t iovec;
	uio_t uio;
	uio.uio_iov = &iovec;
	uio.uio_iovcnt = 1;
	uio.uio_segflg = UIO_SYSSPACE;
	uio.uio_fmode = 0;
	uio.uio_llimit = RLIM64_INFINITY;

	int eofp = 0;

	int outbuf_off = 0;
	int outbuf_resid = size;

	off_t next = off;

	int error;

	for(;;) {
		iovec.iov_base = entry.buf;
		iovec.iov_len = sizeof(entry.buf);
		uio.uio_resid = iovec.iov_len;
		uio.uio_loffset = next;

		error = VOP_READDIR(vp, &uio, &cred, &eofp);
		if(error)
			goto out;

		/* No more directory entries */
		if(iovec.iov_base == entry.buf)
			break;

		fstat.st_ino = entry.dirent.d_ino;
		fstat.st_mode = 0;

		int dsize = fuse_dirent_size(strlen(entry.dirent.d_name));
		if(dsize > outbuf_resid)
			break;

		fuse_add_dirent(outbuf + outbuf_off, entry.dirent.d_name, &fstat, entry.dirent.d_off);

		outbuf_off += dsize;
		outbuf_resid -= dsize;
		next = entry.dirent.d_off;
	}

out:
	ZFS_EXIT(zfsvfs);

	if(!error)
		error = -fuse_reply_buf(req, outbuf, outbuf_off);

	free(outbuf);

	return error;
}

static void zfsfuse_readdir_helper(fuse_req_t req, fuse_ino_t ino, size_t size, off_t off, struct fuse_file_info *fi)
{
	fuse_ino_t real_ino = ino == 1 ? 3 : ino;

	int error = zfsfuse_readdir(req, real_ino, size, off, fi);
	if(error)
		fuse_reply_err(req, error);
}

static int zfsfuse_opencreate(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi, int fflags, mode_t createmode, const char *name)
{
	vfs_t *vfs = (vfs_t *) fuse_req_userdata(req);
	zfsvfs_t *zfsvfs = vfs->vfs_data;

	ZFS_ENTER(zfsvfs);

	cred_t cred;
	zfsfuse_getcred(req, &cred);

	/* Map flags */
	int mode, flags;

	if(fflags & O_WRONLY) {
		mode = VWRITE;
		flags = FWRITE;
	} else if(fflags & O_RDWR) {
		mode = VREAD | VWRITE;
		flags = FREAD | FWRITE;
	} else {
		mode = VREAD;
		flags = FREAD;
	}

	if(fflags & O_CREAT)
		flags |= FCREAT;
	if(fflags & O_SYNC)
		flags |= FSYNC;
	if(fflags & O_DSYNC)
		flags |= FDSYNC;
	if(fflags & O_RSYNC)
		flags |= FRSYNC;
	if(fflags & O_APPEND)
		flags |= FAPPEND;
	if(fflags & O_LARGEFILE)
		flags |= FOFFMAX;
	if(fflags & O_NOFOLLOW)
		flags |= FNOFOLLOW;
	if(fflags & O_TRUNC)
		flags |= FTRUNC;
	if(fflags & O_EXCL)
		flags |= FEXCL;

	znode_t *znode;

	int error = zfs_zget(zfsvfs, ino, &znode);
	if(error) {
		ZFS_EXIT(zfsvfs);
		return error;
	}

	ASSERT(znode != NULL);
	vnode_t *vp = ZTOV(znode);
	ASSERT(vp != NULL);

	if (flags & FCREAT) {
		enum vcexcl excl;

		/*
		 * Wish to create a file.
		 */
		vattr_t vattr;
		vattr.va_type = VREG;
		vattr.va_mode = createmode;
		vattr.va_mask = AT_TYPE|AT_MODE;
		if (flags & FTRUNC) {
			vattr.va_size = 0;
			vattr.va_mask |= AT_SIZE;
		}
		if (flags & FEXCL)
			excl = EXCL;
		else
			excl = NONEXCL;

		vnode_t *new_vp;
		/* FIXME: check filesystem boundaries */
		error = VOP_CREATE(vp, (char *) name, &vattr, excl, mode, &new_vp, &cred, 0);

		if(error)
			goto out;

		VN_RELE(vp);
		vp = new_vp;
	}

	/*
	 * Get the attributes to check whether file is large.
	 * We do this only if the O_LARGEFILE flag is not set and
	 * only for regular files.
	 */
	if (!(flags & FOFFMAX) && (vp->v_type == VREG)) {
		vattr_t vattr;
		vattr.va_mask = AT_SIZE;
		if ((error = VOP_GETATTR(vp, &vattr, 0, &cred)))
			goto out;

		if (vattr.va_size > (u_offset_t) MAXOFF32_T) {
			/*
			 * Large File API - regular open fails
			 * if FOFFMAX flag is set in file mode
			 */
			error = EOVERFLOW;
			goto out;
		}
	}

	/*
	 * Check permissions.
	 */
	if (error = VOP_ACCESS(vp, mode, 0, &cred))
		goto out;

	if ((flags & FNOFOLLOW) && vp->v_type == VLNK) {
		error = ELOOP;
		goto out;
	}

	vnode_t *old_vp = vp;

	error = VOP_OPEN(&vp, flags, &cred);

	ASSERT(old_vp == vp);

	if(error)
		goto out;

	struct fuse_entry_param e = { 0 };

	if(flags & FCREAT) {
		error = zfsfuse_stat(vp, &e.attr, &cred);
		if(error)
			goto out;
	}

	file_info_t *info = malloc(sizeof(file_info_t));
	if(info == NULL) {
		error = ENOMEM;
		goto out;
	}

	info->vp = vp;
	info->flags = flags;

	fi->fh = (uint64_t) (uintptr_t) info;

	if(flags & FCREAT) {
		e.attr_timeout = 0.0;
		e.entry_timeout = 0.0;
		e.ino = VTOZ(vp)->z_id;
		if(e.ino == 3)
			e.ino = 1;
		e.generation = VTOZ(vp)->z_phys->zp_gen;
	}

out:
	if(error) {
		ASSERT(vp->v_count > 0);
		VN_RELE(vp);
	}

	ZFS_EXIT(zfsvfs);

	if(!error) {
		if(!(flags & FCREAT))
			error = -fuse_reply_open(req, fi);
		else
			error = -fuse_reply_create(req, &e, fi);
	}
	return error;
}

static void zfsfuse_open_helper(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi)
{
	fuse_ino_t real_ino = ino == 1 ? 3 : ino;

	int error = zfsfuse_opencreate(req, real_ino, fi, fi->flags, 0, NULL);
	if(error)
		fuse_reply_err(req, error);
}

static void zfsfuse_create_helper(fuse_req_t req, fuse_ino_t parent, const char *name, mode_t mode, struct fuse_file_info *fi)
{
	fuse_ino_t real_parent = parent == 1 ? 3 : parent;

	int error = zfsfuse_opencreate(req, real_parent, fi, fi->flags | O_CREAT, mode, name);
	if(error)
		fuse_reply_err(req, error);
}

static int zfsfuse_readlink(fuse_req_t req, fuse_ino_t ino)
{
	vfs_t *vfs = (vfs_t *) fuse_req_userdata(req);
	zfsvfs_t *zfsvfs = vfs->vfs_data;

	ZFS_ENTER(zfsvfs);

	znode_t *znode;

	int error = zfs_zget(zfsvfs, ino, &znode);
	if(error) {
		ZFS_EXIT(zfsvfs);
		/* If the inode we are trying to get was recently deleted
		   dnode_hold_impl will return EEXIST instead of ENOENT */
		return error == EEXIST ? ENOENT : error;
	}

	ASSERT(znode != NULL);
	vnode_t *vp = ZTOV(znode);
	ASSERT(vp != NULL);

	char buffer[PATH_MAX];

	iovec_t iovec;
	uio_t uio;
	uio.uio_iov = &iovec;
	uio.uio_iovcnt = 1;
	uio.uio_segflg = UIO_SYSSPACE;
	uio.uio_fmode = 0;
	uio.uio_llimit = RLIM64_INFINITY;
	iovec.iov_base = buffer;
	iovec.iov_len = sizeof(buffer) - 1;
	uio.uio_resid = iovec.iov_len;
	uio.uio_loffset = 0;

	cred_t cred;
	zfsfuse_getcred(req, &cred);

	error = VOP_READLINK(vp, &uio, &cred);

	VN_RELE(vp);
	ZFS_EXIT(zfsvfs);

	if(!error) {
		VERIFY(uio.uio_loffset < sizeof(buffer));
		buffer[uio.uio_loffset] = '\0';
		error = -fuse_reply_buf(req, buffer, uio.uio_loffset + 1);
	}

	return error;
}

static void zfsfuse_readlink_helper(fuse_req_t req, fuse_ino_t ino)
{
	fuse_ino_t real_ino = ino == 1 ? 3 : ino;

	int error = zfsfuse_readlink(req, real_ino);
	if(error)
		fuse_reply_err(req, error);
}

static int zfsfuse_read(fuse_req_t req, fuse_ino_t ino, size_t size, off_t off, struct fuse_file_info *fi)
{
	file_info_t *info = (file_info_t *)(uintptr_t) fi->fh;

	vnode_t *vp = info->vp;
	ASSERT(vp != NULL);
	ASSERT(VTOZ(vp) != NULL);
	ASSERT(VTOZ(vp)->z_id == ino);

	vfs_t *vfs = (vfs_t *) fuse_req_userdata(req);
	zfsvfs_t *zfsvfs = vfs->vfs_data;

	char *outbuf = malloc(size);
	if(outbuf == NULL)
		return ENOMEM;

	ZFS_ENTER(zfsvfs);

	iovec_t iovec;
	uio_t uio;
	uio.uio_iov = &iovec;
	uio.uio_iovcnt = 1;
	uio.uio_segflg = UIO_SYSSPACE;
	uio.uio_fmode = 0;
	uio.uio_llimit = RLIM64_INFINITY;

	iovec.iov_base = outbuf;
	iovec.iov_len = size;
	uio.uio_resid = iovec.iov_len;
	uio.uio_loffset = off;

	cred_t cred;
	zfsfuse_getcred(req, &cred);

	int error = VOP_READ(vp, &uio, info->flags, &cred, NULL);

	ZFS_EXIT(zfsvfs);

	if(!error)
		error = -fuse_reply_buf(req, outbuf, uio.uio_loffset - off);

	free(outbuf);

	return error;
}

static void zfsfuse_read_helper(fuse_req_t req, fuse_ino_t ino, size_t size, off_t off, struct fuse_file_info *fi)
{
	fuse_ino_t real_ino = ino == 1 ? 3 : ino;

	int error = zfsfuse_read(req, real_ino, size, off, fi);
	if(error)
		fuse_reply_err(req, error);
}

static int zfsfuse_mkdir(fuse_req_t req, fuse_ino_t parent, const char *name, mode_t mode)
{
	vfs_t *vfs = (vfs_t *) fuse_req_userdata(req);
	zfsvfs_t *zfsvfs = vfs->vfs_data;

	ZFS_ENTER(zfsvfs);

	znode_t *znode;

	int error = zfs_zget(zfsvfs, parent, &znode);
	if(error) {
		ZFS_EXIT(zfsvfs);
		return error;
	}

	ASSERT(znode != NULL);
	vnode_t *dvp = ZTOV(znode);
	ASSERT(dvp != NULL);

	vnode_t *vp = NULL;

	vattr_t vattr = { 0 };
	vattr.va_type = VDIR;
	vattr.va_mode = mode & PERMMASK;
	vattr.va_mask = AT_TYPE | AT_MODE;

	cred_t cred;
	zfsfuse_getcred(req, &cred);

	error = VOP_MKDIR(dvp, (char *) name, &vattr, &vp, &cred);
	if(error)
		goto out;

	ASSERT(vp != NULL);

	struct fuse_entry_param e = { 0 };

	e.attr_timeout = 0.0;
	e.entry_timeout = 0.0;

	e.ino = VTOZ(vp)->z_id;
	if(e.ino == 3)
		e.ino = 1;

	e.generation = VTOZ(vp)->z_phys->zp_gen;

	error = zfsfuse_stat(vp, &e.attr, &cred);

out:
	if(vp != NULL)
		VN_RELE(vp);
	VN_RELE(dvp);
	ZFS_EXIT(zfsvfs);

	if(!error)
		error = -fuse_reply_entry(req, &e);

	return error;
}

static void zfsfuse_mkdir_helper(fuse_req_t req, fuse_ino_t parent, const char *name, mode_t mode)
{
	fuse_ino_t real_parent = parent == 1 ? 3 : parent;

	int error = zfsfuse_mkdir(req, real_parent, name, mode);
	if(error)
		fuse_reply_err(req, error);
}

static int zfsfuse_rmdir(fuse_req_t req, fuse_ino_t parent, const char *name)
{
	vfs_t *vfs = (vfs_t *) fuse_req_userdata(req);
	zfsvfs_t *zfsvfs = vfs->vfs_data;

	ZFS_ENTER(zfsvfs);

	znode_t *znode;

	int error = zfs_zget(zfsvfs, parent, &znode);
	if(error) {
		ZFS_EXIT(zfsvfs);
		/* If the inode we are trying to get was recently deleted
		   dnode_hold_impl will return EEXIST instead of ENOENT */
		return error == EEXIST ? ENOENT : error;
	}

	ASSERT(znode != NULL);
	vnode_t *dvp = ZTOV(znode);
	ASSERT(dvp != NULL);

	cred_t cred;
	zfsfuse_getcred(req, &cred);

	/* FUSE doesn't care if we remove the current working directory
	   so we just pass NULL as the cwd parameter (no problem for ZFS) */
	error = VOP_RMDIR(dvp, (char *) name, NULL, &cred);

	VN_RELE(dvp);
	ZFS_EXIT(zfsvfs);

	return error;
}

static void zfsfuse_rmdir_helper(fuse_req_t req, fuse_ino_t parent, const char *name)
{
	fuse_ino_t real_parent = parent == 1 ? 3 : parent;

	int error = zfsfuse_rmdir(req, real_parent, name);
	/* rmdir events always reply_err */
	fuse_reply_err(req, error);
}

static int zfsfuse_setattr(fuse_req_t req, fuse_ino_t ino, struct stat *attr, int to_set, struct fuse_file_info *fi)
{
	vfs_t *vfs = (vfs_t *) fuse_req_userdata(req);
	zfsvfs_t *zfsvfs = vfs->vfs_data;

	ZFS_ENTER(zfsvfs);

	vnode_t *vp;
	boolean_t release;

	int error;

	if(fi == NULL) {
		znode_t *znode;

		error = zfs_zget(zfsvfs, ino, &znode);
		if(error) {
			ZFS_EXIT(zfsvfs);
			/* If the inode we are trying to get was recently deleted
			   dnode_hold_impl will return EEXIST instead of ENOENT */
			return error == EEXIST ? ENOENT : error;
		}
		ASSERT(znode != NULL);
		vp = ZTOV(znode);
		release = B_TRUE;
	} else {
		file_info_t *info = (file_info_t *)(uintptr_t) fi->fh;
		vp = info->vp;
		release = B_FALSE;
	}

	ASSERT(vp != NULL);

	vattr_t vattr = { 0 };

	if(to_set & FUSE_SET_ATTR_MODE) {
		vattr.va_mask |= AT_MODE;
		vattr.va_mode = attr->st_mode;
	}
	if(to_set & FUSE_SET_ATTR_UID) {
		vattr.va_mask |= AT_UID;
		vattr.va_uid = attr->st_uid;
	}
	if(to_set & FUSE_SET_ATTR_GID) {
		vattr.va_mask |= AT_GID;
		vattr.va_gid = attr->st_gid;
	}
	if(to_set & FUSE_SET_ATTR_SIZE) {
		vattr.va_mask |= AT_SIZE;
		vattr.va_size = attr->st_size;
	}
	if(to_set & FUSE_SET_ATTR_ATIME) {
		vattr.va_mask |= AT_ATIME;
		TIME_TO_TIMESTRUC(attr->st_atime, &vattr.va_atime);
	}
	if(to_set & FUSE_SET_ATTR_MTIME) {
		vattr.va_mask |= AT_MTIME;
		TIME_TO_TIMESTRUC(attr->st_mtime, &vattr.va_mtime);
	}

	cred_t cred;
	zfsfuse_getcred(req, &cred);

	int flags = (to_set & (FUSE_SET_ATTR_ATIME | FUSE_SET_ATTR_MTIME)) ? ATTR_UTIME : 0;
	error = VOP_SETATTR(vp, &vattr, flags, &cred, NULL);

	struct stat stat_reply;

	if(!error)
		error = zfsfuse_stat(vp, &stat_reply, &cred);

	/* Do not release if vp was an opened inode */
	if(release)
		VN_RELE(vp);

	ZFS_EXIT(zfsvfs);

	if(!error)
		error = -fuse_reply_attr(req, &stat_reply, 0.0);

	return error;
}

static void zfsfuse_setattr_helper(fuse_req_t req, fuse_ino_t ino, struct stat *attr, int to_set, struct fuse_file_info *fi)
{
	fuse_ino_t real_ino = ino == 1 ? 3 : ino;

	int error = zfsfuse_setattr(req, real_ino, attr, to_set, fi);
	if(error)
		fuse_reply_err(req, error);
}

static int zfsfuse_unlink(fuse_req_t req, fuse_ino_t parent, const char *name)
{
	vfs_t *vfs = (vfs_t *) fuse_req_userdata(req);
	zfsvfs_t *zfsvfs = vfs->vfs_data;

	ZFS_ENTER(zfsvfs);

	znode_t *znode;

	int error = zfs_zget(zfsvfs, parent, &znode);
	if(error) {
		ZFS_EXIT(zfsvfs);
		/* If the inode we are trying to get was recently deleted
		   dnode_hold_impl will return EEXIST instead of ENOENT */
		return error == EEXIST ? ENOENT : error;
	}

	ASSERT(znode != NULL);
	vnode_t *dvp = ZTOV(znode);
	ASSERT(dvp != NULL);

	cred_t cred;
	zfsfuse_getcred(req, &cred);

	error = VOP_REMOVE(dvp, (char *) name, &cred);

	VN_RELE(dvp);
	ZFS_EXIT(zfsvfs);

	return error;
}

static void zfsfuse_unlink_helper(fuse_req_t req, fuse_ino_t parent, const char *name)
{
	fuse_ino_t real_parent = parent == 1 ? 3 : parent;

	int error = zfsfuse_unlink(req, real_parent, name);
	/* unlink events always reply_err */
	fuse_reply_err(req, error);
}

static int zfsfuse_write(fuse_req_t req, fuse_ino_t ino, const char *buf, size_t size, off_t off, struct fuse_file_info *fi)
{
	file_info_t *info = (file_info_t *)(uintptr_t) fi->fh;

	vnode_t *vp = info->vp;
	ASSERT(vp != NULL);
	ASSERT(VTOZ(vp) != NULL);
	ASSERT(VTOZ(vp)->z_id == ino);

	vfs_t *vfs = (vfs_t *) fuse_req_userdata(req);
	zfsvfs_t *zfsvfs = vfs->vfs_data;

	ZFS_ENTER(zfsvfs);

	iovec_t iovec;
	uio_t uio;
	uio.uio_iov = &iovec;
	uio.uio_iovcnt = 1;
	uio.uio_segflg = UIO_SYSSPACE;
	uio.uio_fmode = 0;
	uio.uio_llimit = RLIM64_INFINITY;

	iovec.iov_base = (void *) buf;
	iovec.iov_len = size;
	uio.uio_resid = iovec.iov_len;
	uio.uio_loffset = off;

	cred_t cred;
	zfsfuse_getcred(req, &cred);

	int error = VOP_WRITE(vp, &uio, info->flags, &cred, NULL);

	ZFS_EXIT(zfsvfs);

	if(!error) {
		/* When not using direct_io, we must always write 'size' bytes */
		VERIFY(uio.uio_resid == 0);
		error = -fuse_reply_write(req, size - uio.uio_resid);
	}

	return error;
}

static void zfsfuse_write_helper(fuse_req_t req, fuse_ino_t ino, const char *buf, size_t size, off_t off, struct fuse_file_info *fi)
{
	fuse_ino_t real_ino = ino == 1 ? 3 : ino;

	int error = zfsfuse_write(req, real_ino, buf, size, off, fi);
	if(error)
		fuse_reply_err(req, error);
}

static int zfsfuse_mknod(fuse_req_t req, fuse_ino_t parent, const char *name, mode_t mode, dev_t rdev)
{
	vfs_t *vfs = (vfs_t *) fuse_req_userdata(req);
	zfsvfs_t *zfsvfs = vfs->vfs_data;

	ZFS_ENTER(zfsvfs);

	znode_t *znode;

	int error = zfs_zget(zfsvfs, parent, &znode);
	if(error) {
		ZFS_EXIT(zfsvfs);
		return error;
	}

	ASSERT(znode != NULL);
	vnode_t *dvp = ZTOV(znode);
	ASSERT(dvp != NULL);

	cred_t cred;
	zfsfuse_getcred(req, &cred);

	vattr_t vattr;
	vattr.va_type = IFTOVT(mode);
	vattr.va_mode = mode & PERMMASK;
	vattr.va_mask = AT_TYPE | AT_MODE;

	if(mode & (S_IFCHR | S_IFBLK)) {
		vattr.va_rdev = rdev;
		vattr.va_mask |= AT_RDEV;
	}

	vnode_t *vp = NULL;

	/* FIXME: check filesystem boundaries */
	error = VOP_CREATE(dvp, (char *) name, &vattr, EXCL, 0, &vp, &cred, 0);

	VN_RELE(dvp);

	if(error)
		goto out;

	ASSERT(vp != NULL);

	struct fuse_entry_param e = { 0 };

	e.attr_timeout = 0.0;
	e.entry_timeout = 0.0;

	e.ino = VTOZ(vp)->z_id;
	if(e.ino == 3)
		e.ino = 1;

	e.generation = VTOZ(vp)->z_phys->zp_gen;

	error = zfsfuse_stat(vp, &e.attr, &cred);

out:
	if(vp != NULL)
		VN_RELE(vp);
	ZFS_EXIT(zfsvfs);

	if(!error)
		error = -fuse_reply_entry(req, &e);

	return error;
}

static void zfsfuse_mknod_helper(fuse_req_t req, fuse_ino_t parent, const char *name, mode_t mode, dev_t rdev)
{
	fuse_ino_t real_parent = parent == 1 ? 3 : parent;

	int error = zfsfuse_mknod(req, real_parent, name, mode, rdev);
	if(error)
		fuse_reply_err(req, error);
}

static int zfsfuse_symlink(fuse_req_t req, const char *link, fuse_ino_t parent, const char *name)
{
	vfs_t *vfs = (vfs_t *) fuse_req_userdata(req);
	zfsvfs_t *zfsvfs = vfs->vfs_data;

	ZFS_ENTER(zfsvfs);

	znode_t *znode;

	int error = zfs_zget(zfsvfs, parent, &znode);
	if(error) {
		ZFS_EXIT(zfsvfs);
		return error;
	}

	ASSERT(znode != NULL);
	vnode_t *dvp = ZTOV(znode);
	ASSERT(dvp != NULL);

	cred_t cred;
	zfsfuse_getcred(req, &cred);

	vattr_t vattr;
	vattr.va_type = VLNK;
	vattr.va_mode = 0777;
	vattr.va_mask = AT_TYPE | AT_MODE;

	error = VOP_SYMLINK(dvp, (char *) name, &vattr, (char *) link, &cred);

	vnode_t *vp = NULL;

	if(error)
		goto out;

	error = VOP_LOOKUP(dvp, (char *) name, &vp, NULL, 0, NULL, &cred);
	if(error)
		goto out;

	ASSERT(vp != NULL);

	struct fuse_entry_param e = { 0 };

	e.attr_timeout = 0.0;
	e.entry_timeout = 0.0;

	e.ino = VTOZ(vp)->z_id;
	if(e.ino == 3)
		e.ino = 1;

	e.generation = VTOZ(vp)->z_phys->zp_gen;

	error = zfsfuse_stat(vp, &e.attr, &cred);

out:
	if(vp != NULL)
		VN_RELE(vp);
	VN_RELE(dvp);

	ZFS_EXIT(zfsvfs);

	if(!error)
		error = -fuse_reply_entry(req, &e);

	return error;
}

static void zfsfuse_symlink_helper(fuse_req_t req, const char *link, fuse_ino_t parent, const char *name)
{
	fuse_ino_t real_parent = parent == 1 ? 3 : parent;

	int error = zfsfuse_symlink(req, link, real_parent, name);
	if(error)
		fuse_reply_err(req, error);
}

static int zfsfuse_rename(fuse_req_t req, fuse_ino_t parent, const char *name, fuse_ino_t newparent, const char *newname)
{
	vfs_t *vfs = (vfs_t *) fuse_req_userdata(req);
	zfsvfs_t *zfsvfs = vfs->vfs_data;

	ZFS_ENTER(zfsvfs);

	znode_t *p_znode, *np_znode;

	int error = zfs_zget(zfsvfs, parent, &p_znode);
	if(error) {
		ZFS_EXIT(zfsvfs);
		return error;
	}

	ASSERT(p_znode != NULL);

	error = zfs_zget(zfsvfs, newparent, &np_znode);
	if(error) {
		VN_RELE(ZTOV(p_znode));
		ZFS_EXIT(zfsvfs);
		return error;
	}

	ASSERT(np_znode != NULL);

	vnode_t *p_vp = ZTOV(p_znode);
	vnode_t *np_vp = ZTOV(np_znode);
	ASSERT(p_vp != NULL);
	ASSERT(np_vp != NULL);

	cred_t cred;
	zfsfuse_getcred(req, &cred);

	error = VOP_RENAME(p_vp, (char *) name, np_vp, (char *) newname, &cred);

	VN_RELE(p_vp);
	VN_RELE(np_vp);

	ZFS_EXIT(zfsvfs);

	return error;
}

static void zfsfuse_rename_helper(fuse_req_t req, fuse_ino_t parent, const char *name, fuse_ino_t newparent, const char *newname)
{
	fuse_ino_t real_parent = parent == 1 ? 3 : parent;
	fuse_ino_t real_newparent = newparent == 1 ? 3 : newparent;

	int error = zfsfuse_rename(req, real_parent, name, real_newparent, newname);

	/* rename events always reply_err */
	fuse_reply_err(req, error);
}

static int zfsfuse_fsync(fuse_req_t req, fuse_ino_t ino, int datasync, struct fuse_file_info *fi)
{
	vfs_t *vfs = (vfs_t *) fuse_req_userdata(req);
	zfsvfs_t *zfsvfs = vfs->vfs_data;

	ZFS_ENTER(zfsvfs);

	file_info_t *info = (file_info_t *)(uintptr_t) fi->fh;
	ASSERT(info->vp != NULL);
	ASSERT(VTOZ(info->vp) != NULL);
	ASSERT(VTOZ(info->vp)->z_id == ino);

	vnode_t *vp = info->vp;

	cred_t cred;
	zfsfuse_getcred(req, &cred);

	int error = VOP_FSYNC(vp, datasync ? FDSYNC : FSYNC, &cred);

	ZFS_EXIT(zfsvfs);

	return error;
}

static void zfsfuse_fsync_helper(fuse_req_t req, fuse_ino_t ino, int datasync, struct fuse_file_info *fi)
{
	fuse_ino_t real_ino = ino == 1 ? 3 : ino;

	int error = zfsfuse_fsync(req, real_ino, datasync, fi);

	/* fsync events always reply_err */
	fuse_reply_err(req, error);
}

static int zfsfuse_link(fuse_req_t req, fuse_ino_t ino, fuse_ino_t newparent, const char *newname)
{
	vfs_t *vfs = (vfs_t *) fuse_req_userdata(req);
	zfsvfs_t *zfsvfs = vfs->vfs_data;

	ZFS_ENTER(zfsvfs);

	znode_t *td_znode, *s_znode;

	int error = zfs_zget(zfsvfs, ino, &s_znode);
	if(error) {
		ZFS_EXIT(zfsvfs);
		return error;
	}

	ASSERT(s_znode != NULL);

	error = zfs_zget(zfsvfs, newparent, &td_znode);
	if(error) {
		VN_RELE(ZTOV(s_znode));
		ZFS_EXIT(zfsvfs);
		return error;
	}

	vnode_t *svp = ZTOV(s_znode);
	vnode_t *tdvp = ZTOV(td_znode);
	ASSERT(svp != NULL);
	ASSERT(tdvp != NULL);

	cred_t cred;
	zfsfuse_getcred(req, &cred);

	error = VOP_LINK(tdvp, svp, (char *) newname, &cred);

	vnode_t *vp = NULL;

	if(error)
		goto out;

	error = VOP_LOOKUP(tdvp, (char *) newname, &vp, NULL, 0, NULL, &cred);
	if(error)
		goto out;

	ASSERT(vp != NULL);

	struct fuse_entry_param e = { 0 };

	e.attr_timeout = 0.0;
	e.entry_timeout = 0.0;

	e.ino = VTOZ(vp)->z_id;
	if(e.ino == 3)
		e.ino = 1;

	e.generation = VTOZ(vp)->z_phys->zp_gen;

	error = zfsfuse_stat(vp, &e.attr, &cred);

out:
	if(vp != NULL)
		VN_RELE(vp);
	VN_RELE(tdvp);
	VN_RELE(svp);

	ZFS_EXIT(zfsvfs);

	if(!error)
		error = -fuse_reply_entry(req, &e);

	return error;
}

static void zfsfuse_link_helper(fuse_req_t req, fuse_ino_t ino, fuse_ino_t newparent, const char *newname)
{
	fuse_ino_t real_ino = ino == 1 ? 3 : ino;
	fuse_ino_t real_newparent = newparent == 1 ? 3 : newparent;

	int error = zfsfuse_link(req, real_ino, real_newparent, newname);
	if(error)
		fuse_reply_err(req, error);
}

static int zfsfuse_access(fuse_req_t req, fuse_ino_t ino, int mask)
{
	vfs_t *vfs = (vfs_t *) fuse_req_userdata(req);
	zfsvfs_t *zfsvfs = vfs->vfs_data;

	ZFS_ENTER(zfsvfs);

	znode_t *znode;

	int error = zfs_zget(zfsvfs, ino, &znode);
	if(error) {
		ZFS_EXIT(zfsvfs);
		return error;
	}

	ASSERT(znode != NULL);
	vnode_t *vp = ZTOV(znode);
	ASSERT(vp != NULL);

	cred_t cred;
	zfsfuse_getcred(req, &cred);

	int mode = 0;
	if(mask & R_OK)
		mode |= VREAD;
	if(mask & W_OK)
		mode |= VWRITE;
	if(mask & X_OK)
		mode |= VEXEC;

	error = VOP_ACCESS(vp, mode, 0, &cred);

	VN_RELE(vp);

	ZFS_EXIT(zfsvfs);

	return error;
}

static void zfsfuse_access_helper(fuse_req_t req, fuse_ino_t ino, int mask)
{
	fuse_ino_t real_ino = ino == 1 ? 3 : ino;

	int error = zfsfuse_access(req, real_ino, mask);

	/* access events always reply_err */
	fuse_reply_err(req, error);
}

struct fuse_lowlevel_ops zfs_operations =
{
	.open       = zfsfuse_open_helper,
	.read       = zfsfuse_read_helper,
	.write      = zfsfuse_write_helper,
	.release    = zfsfuse_release_helper,
	.opendir    = zfsfuse_opendir_helper,
	.readdir    = zfsfuse_readdir_helper,
	.releasedir = zfsfuse_release_helper,
	.lookup     = zfsfuse_lookup_helper,
	.getattr    = zfsfuse_getattr_helper,
	.readlink   = zfsfuse_readlink_helper,
	.mkdir      = zfsfuse_mkdir_helper,
	.rmdir      = zfsfuse_rmdir_helper,
	.create     = zfsfuse_create_helper,
	.unlink     = zfsfuse_unlink_helper,
	.mknod      = zfsfuse_mknod_helper,
	.symlink    = zfsfuse_symlink_helper,
	.link       = zfsfuse_link_helper,
	.rename     = zfsfuse_rename_helper,
	.setattr    = zfsfuse_setattr_helper,
	.fsync      = zfsfuse_fsync_helper,
	.fsyncdir   = zfsfuse_fsync_helper,
	.access     = zfsfuse_access_helper,
	.statfs     = zfsfuse_statfs,
	.destroy    = zfsfuse_destroy,
};
