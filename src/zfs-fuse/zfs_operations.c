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
 * Portions Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
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
#include <attr/xattr.h>
#include <sys/fcntl.h>
#include <sys/sa.h>

#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <time.h>

#include "util.h"
#include "fuse_listener.h"
#include <syslog.h>

// DEBUG_LEVEL : combination of:
// 1 : functions calls
// 2 : lookup
// 4 : buffers
// 8 : read and write calls
// #define DEBUG_LEVEL (4 | 1)

static struct {
	file_info_t **info;
	int alloc,used;
	pthread_mutex_t lock;
} infos;

static void add_info(file_info_t *info) {
	int n;
	pthread_mutex_lock(&infos.lock);
	for (n=0; n<infos.used; n++)
		if (infos.info[n] == info) {
			pthread_mutex_unlock(&infos.lock);
			return;
		}
	if (infos.used == infos.alloc) {
		infos.alloc += 10;
		infos.info = realloc(infos.info,sizeof(file_info_t*)*infos.alloc);
	}
	infos.info[infos.used++] = info;
	pthread_mutex_unlock(&infos.lock);
}

static file_info_t *get_info(vfs_t *vfs, ino_t ino) {
	pthread_mutex_lock(&infos.lock);
	int n;
	for (n=0; n<infos.used; n++) {
		vnode_t *vn = infos.info[n]->vp;
		if (vn->v_vfsp == vfs && VTOZ(vn)->z_id == ino) {
			pthread_mutex_unlock(&infos.lock);
			return infos.info[n];
		}
	}
	pthread_mutex_unlock(&infos.lock);
	return NULL;
}

static void free_info(file_info_t *info) {
	pthread_mutex_lock(&infos.lock);
	int n;
	for (n=0; n<infos.used; n++) {
		if (infos.info[n] == info) {
			if (n < infos.used-1)
				memmove(&infos.info[n],&infos.info[n+1],
						sizeof(file_info_t*)*(infos.used-1-n));
			infos.used--;
			if (infos.used == 0) {
				infos.alloc = 0;
				free(infos.info);
				infos.info = NULL;
			}
			break;
		}
	}
	pthread_mutex_unlock(&infos.lock);
}

#if DEBUG_LEVEL
static void print_debug(int debug_level,const char *format, ...)
{
  if(debug_level & DEBUG_LEVEL){
      
      char debug_str[256];
      va_list ap;
      va_start(ap,format);
      vsprintf(debug_str,format,ap);
      va_end(ap);
      printf("%d:%s",debug_level,debug_str);
      fflush(stdout);
  }
}
#else
#define print_debug
#endif

// these quick-n-dirty macros help if you already hae the zfsvfs pointer
#define FUSE2ZFS(ino,vfs) ((ino)==1? vfs->z_root : (ino))
#define ZFS2FUSE(ino,vfs) ((ino)==vfs->z_root? 1 : (ino))

 /* the command-line options */
int block_cache, page_cache;
int cf_enable_xattr = 0;
float fuse_attr_timeout, fuse_entry_timeout;

static void zfsfuse_getcred(fuse_req_t req, cred_t *cred)
{
	const struct fuse_ctx *ctx = fuse_req_ctx(req);

	cred->cr_uid = ctx->uid;
	cred->cr_gid = ctx->gid;
	cred->req = req;
}

static void zfsfuse_destroy(void *userdata)
{
	vfs_t *vfs = (vfs_t *) userdata;

#ifdef DEBUG
	fprintf(stderr, "Calling do_umount()... force %d\n",exit_fuse_listener);
#endif
	/*
	 * If exit_fuse_listener is true, then we received a signal
	 * and we're terminating the process. Therefore we need to
	 * force unmount since there could still be opened files
	 */
	sync();
	while(do_umount(vfs, exit_fuse_listener) != 0)
	    sync();
#ifdef DEBUG
	fprintf(stderr, "do_umount() done\n");
#endif
}

static void zfsfuse_statfs(fuse_req_t req, fuse_ino_t ino)
{
    print_debug(1,"function %s\n",__FUNCTION__);
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
	/* Still there with fuse 2.7.4 apparently (you get a size in To so it shows a lot !) */
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

	fuse_reply_statfs(req, &stat);
}

static int zfs_enter(zfsvfs_t *zfsvfs) {
	ZFS_ENTER(zfsvfs);
	return 0;
}

static int basic_write(zfsvfs_t *zfsvfs, cred_t *cred, fuse_ino_t ino, const char *buf, size_t size, off_t off, file_info_t *info)
{
	vnode_t *vp = info->vp;
#if DEBUG
	ino = FUSE2ZFS(ino, zfsvfs);
	ASSERT(vp != NULL);
	ASSERT(VTOZ(vp) != NULL);
	ASSERT(VTOZ(vp)->z_id == ino);
#endif

    print_debug(1,"function %s\n",__FUNCTION__);

	int error = zfs_enter(zfsvfs);
	if (error) {
		print_debug(4,"basic_write: error on zfs_enter\n");
		return -error;
	}

	iovec_t iovec;
	uio_t uio;
	uio.uio_iov = &iovec;
	uio.uio_iovcnt = 1;
	uio.uio_segflg = UIO_SYSSPACE;
	uio.uio_fmode = FWRITE;
	uio.uio_llimit = RLIM64_INFINITY;

	iovec.iov_base = (void *) buf;
	iovec.iov_len = size;
	uio.uio_resid = iovec.iov_len;
	uio.uio_loffset = off;
	uio.uio_extflg = UIO_COPY_DEFAULT;

	error = VOP_WRITE(vp, &uio, info->flags, cred, NULL);
	if (error) {
		print_debug(4,"basic_write: error on write %d\n",error);
	}

	ZFS_EXIT(zfsvfs);
	return error;
}

static int zfsfuse_stat(zfsvfs_t* zfsvfs, vnode_t *vp, struct stat *stbuf, cred_t *cred)
{
	ASSERT(vp != NULL);
	ASSERT(stbuf != NULL);
	file_info_t *info;
	ino_t ino = VTOZ(vp)->z_id;

	vattr_t vattr;
	vattr.va_mask = AT_STAT | AT_NBLOCKS | AT_BLKSIZE | AT_SIZE;

	int error = VOP_GETATTR(vp, &vattr, 0, cred, NULL);
	if(error)
		return error;

	memset(stbuf, 0, sizeof(struct stat));

	stbuf->st_dev = vattr.va_fsid;
	stbuf->st_ino = ZFS2FUSE(vattr.va_nodeid, zfsvfs);
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

static int int_zfs_enter(zfsvfs_t *zfsvfs) {
    ZFS_ENTER(zfsvfs);
    return 0;
}

#define ERROR( err ) \
{ \
    fuse_reply_err(req, err); \
    return; \
}

// This macro allows to call ZFS_ENTER from a void function without warning
#define ZFS_VOID_ENTER(a) \
    int error; \
    if ((error = int_zfs_enter(zfsvfs)) != 0) ERROR( error);

static void zfsfuse_getattr(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi)
{
    print_debug(1,"function %s\n",__FUNCTION__);
	vfs_t *vfs = (vfs_t *) fuse_req_userdata(req);
	zfsvfs_t *zfsvfs = vfs->vfs_data;
	ino = FUSE2ZFS(ino, zfsvfs);

	cred_t cred;
	zfsfuse_getcred(req, &cred);

	ZFS_VOID_ENTER(zfsvfs);

	znode_t *znode;

	 error = zfs_zget(zfsvfs, ino, &znode, B_TRUE);
	 if(error) {
		/* If the inode we are trying to get was recently deleted
		   dnode_hold_impl will return EEXIST instead of ENOENT */
		error = (error == EEXIST ? ENOENT : error);
		goto out;
	}

	ASSERT(znode != NULL);
	vnode_t *vp = ZTOV(znode);
	ASSERT(vp != NULL);

	struct stat stbuf;
	error = zfsfuse_stat(zfsvfs, vp, &stbuf, &cred);

	file_info_t *info = get_info(vfs,ino);
	/* Some programs use stat or equivalent to get the file size while writing to
	 * it instead of ftell. Well apparently fuse didn't think about that, there
	 * is no way to get the fi parameter passed to open from getattr().
	 * So I'll try to do this as lightly as possible : we get info, then if a
	 * buffer exists for the file and if when written it will increase the size
	 * of the file then fix it */
	if (info && info->used && info->last_off > stbuf.st_size) {
		stbuf.st_size = info->last_off;
	}

	print_debug(2,"getattr: ino %ld got size %zd\n",ino,stbuf.st_size);

	VN_RELE(vp);
out:
	ZFS_EXIT(zfsvfs);

	if(!error)
		fuse_reply_attr(req, &stbuf, fuse_attr_timeout);
	else
		fuse_reply_err(req, error);
}

/* This macro makes the lookup for the xattr directory, necessary for listxattr
 * getxattr and setxattr */
#define MY_LOOKUP_XATTR() \
    vfs_t *vfs = (vfs_t *) fuse_req_userdata(req);		\
    zfsvfs_t *zfsvfs = vfs->vfs_data;				\
    ino = FUSE2ZFS(ino, zfsvfs);					\
								\
    ZFS_VOID_ENTER(zfsvfs);					\
								\
    znode_t *znode;						\
								\
    error = zfs_zget(zfsvfs, ino, &znode, B_FALSE);		\
    if(error) {							\
	ZFS_EXIT(zfsvfs);					\
	fuse_reply_err(req, error == EEXIST ? ENOENT : error);	\
	return;							\
    }								\
								\
    ASSERT(znode != NULL);					\
    vnode_t *dvp = ZTOV(znode);					\
    ASSERT(dvp != NULL);					\
								\
    vnode_t *vp = NULL;						\
								\
    cred_t cred;						\
    zfsfuse_getcred(req, &cred);				\
								\
    error = VOP_LOOKUP(dvp, "", &vp, NULL, LOOKUP_XATTR |	\
	    CREATE_XATTR_DIR, NULL, &cred, NULL, NULL, NULL);	\
    if(error || vp == NULL) {					\
	if (error != EACCES) error = ENOSYS; 			\
	goto out;						\
    }

static void zfsfuse_listxattr(fuse_req_t req, fuse_ino_t ino, size_t size)
{
	if (!cf_enable_xattr)
	{
		fuse_reply_err(req, ENOSYS);
		return;
	}
	union {
		char buf[DIRENT64_RECLEN(MAXNAMELEN)];
		struct dirent64 dirent;
	} entry;

    /* It's like a lookup, but passing LOOKUP_XATTR as a flag to VOP_LOOKUP */
    MY_LOOKUP_XATTR();

    error = VOP_OPEN(&vp, FREAD, &cred, NULL);
    if (error) {
	goto out;
    }

    // Now try a readdir...
	char *outbuf = NULL;
	int alloc = 0,used = 0;

	struct stat fstat = { 0 };

	iovec_t iovec;
	uio_t uio;
	uio.uio_iov = &iovec;
	uio.uio_iovcnt = 1;
	uio.uio_segflg = UIO_SYSSPACE;
	uio.uio_fmode = 0;
	uio.uio_llimit = RLIM64_INFINITY;
	/* I have taken the values for this flag from the zfs sources.
	 * Apprently it's UIO_COPY_CACHED for reads and UIO_COPY_DEFAULT for
	 * writes, not sure it makes a big difference anyway.
	 * But what is sure is that it must be initialized to avoid random
	 * values */
	uio.uio_extflg = UIO_COPY_CACHED;

	int eofp = 0;

	off_t next = 0;

	for(;;) {
		iovec.iov_base = entry.buf;
		iovec.iov_len = sizeof(entry.buf);
		uio.uio_resid = iovec.iov_len;
		uio.uio_loffset = next;

		error = VOP_READDIR(vp, &uio, &cred, &eofp, NULL, 0);
		if(error)
			goto out;

		/* No more directory entries */
		if(iovec.iov_base == entry.buf)
			break;

		next = entry.dirent.d_off;
		char *s = entry.dirent.d_name;
		if (*s == '.' && (s[1] == 0 || (s[1] == '.' && s[2] == 0)))
			continue;
		while (used + strlen(s)+1 > alloc) {
		    alloc += 1024;
		    outbuf = realloc(outbuf, alloc);
		}
		strcpy(&outbuf[used],s);
		used += strlen(s)+1;

	}

	error = VOP_CLOSE(vp, FREAD, 1, (offset_t) 0, &cred, NULL);
	if (size == 0) {
	    fuse_reply_xattr(req,used);
	} else if (size < used) {
	    error = ERANGE;
	} else {
	    fuse_reply_buf(req,outbuf,used);
	}
	free(outbuf);
out:
    if(vp != NULL)
	VN_RELE(vp);
    VN_RELE(dvp);
    ZFS_EXIT(zfsvfs);
    if (error)
	fuse_reply_err(req,error);
}

static void zfsfuse_setxattr(fuse_req_t req, fuse_ino_t ino, const char *name, const char *value, size_t size, int flags)
{
	if (!cf_enable_xattr)
	{
		fuse_reply_err(req, ENOSYS);
		return;
	}
    MY_LOOKUP_XATTR();
    // Now the idea is to create a file inside the xattr directory with the
    // wanted attribute.

    vattr_t vattr;
    vattr.va_type = VREG;
    vattr.va_mode = 0660;
    vattr.va_mask = AT_TYPE|AT_MODE|AT_SIZE;
    vattr.va_size = 0;

    vnode_t *new_vp;
    error = VOP_CREATE(vp, (char *) name, &vattr, NONEXCL, VWRITE, &new_vp, &cred, 0, NULL, NULL);
    if(error)
	goto out;

    VN_RELE(vp);
    vp = new_vp;
    error = VOP_OPEN(&vp, FWRITE, &cred, NULL);
    if (error) goto out;

    iovec_t iovec;
    uio_t uio;
    uio.uio_iov = &iovec;
    uio.uio_iovcnt = 1;
    uio.uio_segflg = UIO_SYSSPACE;
    uio.uio_fmode = 0;
    uio.uio_llimit = RLIM64_INFINITY;
    uio.uio_extflg = UIO_COPY_DEFAULT;

    iovec.iov_base = (void *) value;
    iovec.iov_len = size;
    uio.uio_resid = iovec.iov_len;
    uio.uio_loffset = 0;

    error = VOP_WRITE(vp, &uio, FWRITE, &cred, NULL);
    if (error) goto out;
    error = VOP_CLOSE(vp, FWRITE, 1, (offset_t) 0, &cred, NULL);

out:
    if(vp != NULL)
	VN_RELE(vp);
    VN_RELE(dvp);
    ZFS_EXIT(zfsvfs);
	// The fuse_reply_err at the end seems to be an mandatory even if there is no error
    fuse_reply_err(req,error);
}

static void zfsfuse_getxattr(fuse_req_t req, fuse_ino_t ino, const char *name,
	size_t size)
{
	if (!cf_enable_xattr)
	{
		fuse_reply_err(req, ENOSYS);
		return;
	}
    MY_LOOKUP_XATTR();
    vnode_t *new_vp = NULL;
    error = VOP_LOOKUP(vp, (char *) name, &new_vp, NULL, 0, NULL, &cred, NULL, NULL, NULL);  
    if (error) {
	error = ENOATTR;
	goto out;
    }
    VN_RELE(vp);
    vp = new_vp;
    vattr_t vattr;
    vattr.va_mask = AT_STAT | AT_NBLOCKS | AT_BLKSIZE | AT_SIZE;

    // We are obliged to get the size 1st because of the stupid handling of the
    // size parameter
    error = VOP_GETATTR(vp, &vattr, 0, &cred, NULL);
    if (error) goto out;
    if (size == 0) {
	fuse_reply_xattr(req,vattr.va_size);
	goto out;
    } else if (size < vattr.va_size) {
	fuse_reply_xattr(req, ERANGE);
	goto out;
    }
    char *buf = malloc(vattr.va_size);
    if (!buf)
	goto out;

    error = VOP_OPEN(&vp, FREAD, &cred, NULL);
    if (error) {
	free(buf);
	goto out;
    }

    iovec_t iovec;
    uio_t uio;
    uio.uio_iov = &iovec;
    uio.uio_iovcnt = 1;
    uio.uio_segflg = UIO_SYSSPACE;
    uio.uio_fmode = 0;
    uio.uio_llimit = RLIM64_INFINITY;
    uio.uio_extflg = UIO_COPY_CACHED;

    iovec.iov_base = buf;
    iovec.iov_len = vattr.va_size;
    uio.uio_resid = iovec.iov_len;
    uio.uio_loffset = 0;

    error = VOP_READ(vp, &uio, FREAD, &cred, NULL);
    if (error) {
	free(buf);
	goto out;
    }
    fuse_reply_buf(req,buf,vattr.va_size);
    free(buf);
    error = VOP_CLOSE(vp, FREAD, 1, (offset_t) 0, &cred, NULL);

out:
    if(vp != NULL)
	VN_RELE(vp);
    VN_RELE(dvp);
    ZFS_EXIT(zfsvfs);
    if (error)
	fuse_reply_err(req,error);
}

static void zfsfuse_removexattr(fuse_req_t req, fuse_ino_t ino, const char *name)
{
	if (!cf_enable_xattr)
	{
		fuse_reply_err(req, ENOSYS);
		return;
	}
    MY_LOOKUP_XATTR();
    error = VOP_REMOVE(vp, (char *) name, &cred, NULL, 0);

out:
    if(vp != NULL)
	VN_RELE(vp);
    VN_RELE(dvp);
    ZFS_EXIT(zfsvfs);
	if (error == ENOENT)
		error = ENOATTR;
    fuse_reply_err(req,error);
}

static void zfsfuse_lookup(fuse_req_t req, fuse_ino_t parent, const char *name)
{
	if(strlen(name) >= MAXNAMELEN) 
		ERROR(ENAMETOOLONG);

    print_debug(1,"function %s\n",__FUNCTION__);
	vfs_t *vfs = (vfs_t *) fuse_req_userdata(req);
	zfsvfs_t *zfsvfs = vfs->vfs_data;
	parent = FUSE2ZFS(parent, zfsvfs);

	ZFS_VOID_ENTER(zfsvfs);

	znode_t *znode;

	error = zfs_zget(zfsvfs, parent, &znode, B_TRUE);
	if(error) {
		ZFS_EXIT(zfsvfs);
		/* If the inode we are trying to get was recently deleted
		   dnode_hold_impl will return EEXIST instead of ENOENT */
		ERROR(error == EEXIST ? ENOENT : error);
	}

	ASSERT(znode != NULL);
	vnode_t *dvp = ZTOV(znode);
	ASSERT(dvp != NULL);

	vnode_t *vp = NULL;

	cred_t cred;
	zfsfuse_getcred(req, &cred);
	struct fuse_entry_param e = { 0 };

	 /* > 0.0 gives a 40% performance boost in bonnie 0-byte file tests */
	e.attr_timeout = fuse_attr_timeout;
	 /* > 0.0 gives you a 10000% performance boost in stat() calls, but unfortunately you get a security issue. */
	e.entry_timeout = fuse_entry_timeout;

	error = VOP_LOOKUP(dvp, (char *) name, &vp, NULL, 0, NULL, &cred, NULL, NULL, NULL);
	if(error)
	{
		if (error == ENOENT) {
			error = 0;
			e.ino = 0;
		}
		goto out;
	}

	if(vp == NULL)
		goto out;

	e.ino = VTOZ(vp)->z_id;
	e.ino = ZFS2FUSE(e.ino, zfsvfs);

	znode_t *zp = VTOZ(vp);
	sa_lookup(zp->z_sa_hdl, SA_ZPL_GEN(zp->z_zfsvfs), &e.generation,
		sizeof(e.generation));

	error = zfsfuse_stat(zfsvfs, vp, &e.attr, &cred);
	print_debug(2,"%s -> %ld size %zd\n",name,e.ino,e.attr.st_size);

out:
	if(vp != NULL)
		VN_RELE(vp);
	VN_RELE(dvp);
	ZFS_EXIT(zfsvfs);

	if(!error)
		fuse_reply_entry(req, &e);
	else
		fuse_reply_err(req, error);

}

static void zfsfuse_opendir(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi)
{
    print_debug(1,"function %s\n",__FUNCTION__);
	vfs_t *vfs = (vfs_t *) fuse_req_userdata(req);
	zfsvfs_t *zfsvfs = vfs->vfs_data;
	ino = FUSE2ZFS(ino, zfsvfs);

	ZFS_VOID_ENTER(zfsvfs);

	znode_t *znode;

	error = zfs_zget(zfsvfs, ino, &znode, B_TRUE);
	if(error) {
		/* If the inode we are trying to get was recently deleted
		   dnode_hold_impl will return EEXIST instead of ENOENT */
		ZFS_EXIT(zfsvfs);
		ERROR (error == EEXIST ? ENOENT : error);
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
	if (!(vfs->fuse_attribute & FUSE_VFS_HAS_DEFAULT_PERM)) {
	    if (error = VOP_ACCESS(vp, VREAD | VEXEC, 0, &cred, NULL))
		goto out;
	}

	vnode_t *old_vp = vp;

	/* XXX: not sure about flags */
	error = VOP_OPEN(&vp, FREAD, &cred, NULL);

	ASSERT(old_vp == vp);

	if(!error) {
		file_info_t *info = kmem_cache_alloc(file_info_cache, KM_NOSLEEP);
		if(info == NULL) {
			error = ENOMEM;
			goto out;
		}

		info->vp = vp;
		info->flags = FREAD;
		info->alloc = info->used = 0;
		info->buffer = NULL;

		fi->fh = (uint64_t) (uintptr_t) info;
	}

out:
	if(error)
		VN_RELE(vp);
	ZFS_EXIT(zfsvfs);

	if(!error)
		fuse_reply_open(req, fi);
	else
		fuse_reply_err(req, error);
}

static void zfsfuse_readdir(fuse_req_t req, fuse_ino_t ino, size_t size, off_t off, struct fuse_file_info *fi)
{
	vfs_t *vfs = (vfs_t *) fuse_req_userdata(req);
	zfsvfs_t *zfsvfs = vfs->vfs_data;
	ino = FUSE2ZFS(ino, zfsvfs);
	vnode_t *vp = ((file_info_t *)(uintptr_t) fi->fh)->vp;
	ASSERT(vp != NULL);
	ASSERT(VTOZ(vp) != NULL);
	ASSERT(VTOZ(vp)->z_id == ino);

	if(vp->v_type != VDIR) 
		ERROR( ENOTDIR);

    print_debug(1,"function %s\n",__FUNCTION__);

	char *outbuf = kmem_alloc(size, KM_NOSLEEP);
	if(outbuf == NULL) 
	    ERROR(ENOMEM);

	ZFS_VOID_ENTER(zfsvfs);

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
	uio.uio_extflg = UIO_COPY_CACHED;

	int eofp = 0;

	int outbuf_off = 0;
	int outbuf_resid = size;

	off_t next = off;

	for(;;) {
		iovec.iov_base = entry.buf;
		iovec.iov_len = sizeof(entry.buf);
		uio.uio_resid = iovec.iov_len;
		uio.uio_loffset = next;

		error = VOP_READDIR(vp, &uio, &cred, &eofp, NULL, 0);
		if(error)
			goto out;

		/* No more directory entries */
		if(iovec.iov_base == entry.buf)
			break;

		fstat.st_ino = entry.dirent.d_ino;
		fstat.st_mode = 0;

		int dsize = fuse_add_direntry(req, NULL, 0, entry.dirent.d_name, NULL, 0);
		print_debug(2,"readdir: %s -> %ld\n",entry.dirent.d_name,fstat.st_ino);
		if(dsize > outbuf_resid)
			break;

		outbuf_resid -= dsize;
		fuse_add_direntry(req, outbuf + outbuf_off, 
		    dsize, entry.dirent.d_name, &fstat,
		    entry.dirent.d_off);

		outbuf_off += dsize;
		next = entry.dirent.d_off;
	}

out:
	ZFS_EXIT(zfsvfs);

	if(!error)
		fuse_reply_buf(req, outbuf, outbuf_off);
	else
		fuse_reply_err(req, error);

	kmem_free(outbuf, size);
}

static void zfsfuse_flush(fuse_req_t req, fuse_ino_t ino,
		       struct fuse_file_info *fi)
{
	file_info_t *info = (file_info_t *)(uintptr_t) fi->fh;
	vfs_t *vfs = (vfs_t *) fuse_req_userdata(req);
	zfsvfs_t *zfsvfs = vfs->vfs_data;
	ino = FUSE2ZFS(ino, zfsvfs);
	cred_t cred;
	zfsfuse_getcred(req, &cred);
	if (info->used) {
		print_debug(4,"flush: flush ino %ld size %zd off %zd\n",ino,info->used,info->last_off-info->used);
		basic_write(zfsvfs,&cred,ino,info->buffer,info->used,info->last_off-info->used,info);
		info->used = 0;
	} else {
		print_debug(4,"flush: no info for ino %ld\n",ino);
	}
	fuse_reply_err(req,0);
}

static void zfsfuse_opencreate(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi, int fflags, mode_t createmode, const char *name)
{
	if(name && strlen(name) >= MAXNAMELEN)
		ERROR( ENAMETOOLONG);

    print_debug(1,"function %s\n",__FUNCTION__);
	vfs_t *vfs = (vfs_t *) fuse_req_userdata(req);
	zfsvfs_t *zfsvfs = vfs->vfs_data;
	ino = FUSE2ZFS(ino, zfsvfs);

	ZFS_VOID_ENTER(zfsvfs);

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

	flags |= (fflags & (~3)); // copy all the other flags (except r/w)

	znode_t *znode;

	error = zfs_zget(zfsvfs, ino, &znode, B_FALSE);
	if(error) {
		ZFS_EXIT(zfsvfs);
		/* If the inode we are trying to get was recently deleted
		   dnode_hold_impl will return EEXIST instead of ENOENT */
		ERROR( error == EEXIST ? ENOENT : error);
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
		error = VOP_CREATE(vp, (char *) name, &vattr, excl, mode, &new_vp, &cred, 0, NULL, NULL);

		if(error)
			goto out;

		VN_RELE(vp);
		vp = new_vp;
	} else {
		/*
		 * Get the attributes to check whether file is large.
		 * We do this only if the O_LARGEFILE flag is not set and
		 * only for regular files.
		 */
		if (!(flags & FOFFMAX) && (vp->v_type == VREG)) {
			vattr_t vattr;
			vattr.va_mask = AT_SIZE;
			if ((error = VOP_GETATTR(vp, &vattr, 0, &cred, NULL)))
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
		if (!(vfs->fuse_attribute & FUSE_VFS_HAS_DEFAULT_PERM)) {
		    if (error = VOP_ACCESS(vp, mode, 0, &cred, NULL)) {
			print_debug(1,"open fails on access\n");
			goto out;
		    }
		}
	}

	if ((flags & FNOFOLLOW) && vp->v_type == VLNK) {
		error = ELOOP;
		goto out;
	}

	vnode_t *old_vp = vp;

	error = VOP_OPEN(&vp, flags, &cred, NULL);

	ASSERT(old_vp == vp);

	if(error)
		goto out;

	struct fuse_entry_param e = { 0 };

	if(flags & FCREAT) {
		error = zfsfuse_stat(zfsvfs, vp, &e.attr, &cred );
		if(error)
			goto out;
		print_debug(2,"opencreat: ino %ld stat got size %zd on create\n",ino,e.attr.st_size);
	}

	file_info_t *info = kmem_cache_alloc(file_info_cache, KM_NOSLEEP);
	if(info == NULL) {
		error = ENOMEM;
		goto out;
	}

	info->vp = vp;
	info->flags = flags;
	info->alloc = info->used = 0;
	info->buffer = NULL;

	fi->fh = (uint64_t) (uintptr_t) info;
	/* keep_cache is forced to 1.
	 * Be sure to remount a fs if you rollback a snapshot on it */
	fi->keep_cache = 1;
	fi->direct_io = block_cache ? 0 : 1;

	if(flags & FCREAT) {
		e.attr_timeout = fuse_attr_timeout;
		e.entry_timeout = fuse_entry_timeout;
		znode_t *zp = VTOZ(vp);
		e.ino = zp->z_id;
		e.ino = ZFS2FUSE(e.ino, zfsvfs);
		sa_lookup(zp->z_sa_hdl, SA_ZPL_GEN(zp->z_zfsvfs), &e.generation,
			sizeof(e.generation));
	}

out:
	if(error) {
		ASSERT(vp->v_count > 0);
		VN_RELE(vp);
	}

	ZFS_EXIT(zfsvfs);

	if(!error) {
		if(!(flags & FCREAT))
			fuse_reply_open(req, fi);
		else
			fuse_reply_create(req, &e, fi);
	} else
		fuse_reply_err(req, error);
}

static void zfsfuse_open_helper(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi)
{
	zfsfuse_opencreate(req, ino, fi, fi->flags, 0, NULL);
}

static void zfsfuse_create_helper(fuse_req_t req, fuse_ino_t parent, const char *name, mode_t mode, struct fuse_file_info *fi)
{
	zfsfuse_opencreate(req, parent, fi, fi->flags | O_CREAT, mode, name);
}

static void zfsfuse_readlink(fuse_req_t req, fuse_ino_t ino)
{
    print_debug(1,"function %s\n",__FUNCTION__);
	vfs_t *vfs = (vfs_t *) fuse_req_userdata(req);
	zfsvfs_t *zfsvfs = vfs->vfs_data;
	ino = FUSE2ZFS(ino, zfsvfs);

	ZFS_VOID_ENTER(zfsvfs);

	znode_t *znode;

	error = zfs_zget(zfsvfs, ino, &znode, B_FALSE);
	if(error) {
		ZFS_EXIT(zfsvfs);
		/* If the inode we are trying to get was recently deleted
		   dnode_hold_impl will return EEXIST instead of ENOENT */
		ERROR( error == EEXIST ? ENOENT : error);
	}

	ASSERT(znode != NULL);
	vnode_t *vp = ZTOV(znode);
	ASSERT(vp != NULL);

	char buffer[PATH_MAX + 1];

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
	uio.uio_extflg = UIO_COPY_CACHED;

	cred_t cred;
	zfsfuse_getcred(req, &cred);

	error = VOP_READLINK(vp, &uio, &cred, NULL);

	VN_RELE(vp);
	ZFS_EXIT(zfsvfs);

	if(!error) {
		VERIFY(uio.uio_loffset < sizeof(buffer));
		buffer[uio.uio_loffset] = '\0';
		fuse_reply_readlink(req, buffer);
	} else
		fuse_reply_err(req, error);
}

static void zfsfuse_mkdir(fuse_req_t req, fuse_ino_t parent, const char *name, mode_t mode)
{
	if(strlen(name) >= MAXNAMELEN)
		ERROR( ENAMETOOLONG);

    print_debug(1,"function %s\n",__FUNCTION__);
	vfs_t *vfs = (vfs_t *) fuse_req_userdata(req);
	zfsvfs_t *zfsvfs = vfs->vfs_data;
	parent = FUSE2ZFS(parent, zfsvfs);

	ZFS_VOID_ENTER(zfsvfs);

	znode_t *znode;

	error = zfs_zget(zfsvfs, parent, &znode, B_FALSE);
	if(error) {
		ZFS_EXIT(zfsvfs);
		/* If the inode we are trying to get was recently deleted
		   dnode_hold_impl will return EEXIST instead of ENOENT */
		ERROR( error == EEXIST ? ENOENT : error);
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

	error = VOP_MKDIR(dvp, (char *) name, &vattr, &vp, &cred, NULL, 0, NULL);
	if(error)
		goto out;

	ASSERT(vp != NULL);

	struct fuse_entry_param e = { 0 };

	e.attr_timeout = fuse_attr_timeout;
	e.entry_timeout = fuse_entry_timeout;

	znode_t *zp = VTOZ(vp);
	e.ino = zp->z_id;
	e.ino = ZFS2FUSE(e.ino, zfsvfs);

	sa_lookup(zp->z_sa_hdl, SA_ZPL_GEN(zp->z_zfsvfs), &e.generation,
		sizeof(e.generation));

	error = zfsfuse_stat(zfsvfs, vp, &e.attr, &cred);

out:
	if(vp != NULL)
		VN_RELE(vp);
	VN_RELE(dvp);
	ZFS_EXIT(zfsvfs);

	if(!error)
		fuse_reply_entry(req, &e);
	else
		fuse_reply_err(req, error);
}

static void zfsfuse_rmdir(fuse_req_t req, fuse_ino_t parent, const char *name)
{
	if(strlen(name) >= MAXNAMELEN)
		ERROR( ENAMETOOLONG);

    print_debug(1,"function %s\n",__FUNCTION__);
	vfs_t *vfs = (vfs_t *) fuse_req_userdata(req);
	zfsvfs_t *zfsvfs = vfs->vfs_data;
	parent = FUSE2ZFS(parent, zfsvfs);

	ZFS_VOID_ENTER(zfsvfs);

	znode_t *znode;

	error = zfs_zget(zfsvfs, parent, &znode, B_FALSE);
	if(error) {
		ZFS_EXIT(zfsvfs);
		/* If the inode we are trying to get was recently deleted
		   dnode_hold_impl will return EEXIST instead of ENOENT */
		ERROR( error == EEXIST ? ENOENT : error);
	}

	ASSERT(znode != NULL);
	vnode_t *dvp = ZTOV(znode);
	ASSERT(dvp != NULL);

	cred_t cred;
	zfsfuse_getcred(req, &cred);

	/* FUSE doesn't care if we remove the current working directory
	   so we just pass NULL as the cwd parameter (no problem for ZFS) */
	error = VOP_RMDIR(dvp, (char *) name, NULL, &cred, NULL, 0);

	/* Linux uses ENOTEMPTY when trying to remove a non-empty directory */
	if(error == EEXIST)
		error = ENOTEMPTY;

	VN_RELE(dvp);
	ZFS_EXIT(zfsvfs);
	/* rmdir events always reply_err */
	fuse_reply_err(req, error);
}

static void zfsfuse_setattr(fuse_req_t req, fuse_ino_t ino, struct stat *attr, int to_set, struct fuse_file_info *fi)
{
    print_debug(1,"function %s\n",__FUNCTION__);
	vfs_t *vfs = (vfs_t *) fuse_req_userdata(req);
	zfsvfs_t *zfsvfs = vfs->vfs_data;
	ino = FUSE2ZFS(ino, zfsvfs);

	ZFS_VOID_ENTER(zfsvfs);

	vnode_t *vp;
	boolean_t release;

	cred_t cred;
	zfsfuse_getcred(req, &cred);

	if(fi == NULL) {
		znode_t *znode;

		error = zfs_zget(zfsvfs, ino, &znode, B_TRUE);
		if(error) {
			ZFS_EXIT(zfsvfs);
			/* If the inode we are trying to get was recently deleted
			   dnode_hold_impl will return EEXIST instead of ENOENT */
			ERROR( error == EEXIST ? ENOENT : error);
		}
		ASSERT(znode != NULL);
		vp = ZTOV(znode);
		release = B_TRUE;
	} else {
		file_info_t *info = (file_info_t *)(uintptr_t) fi->fh;
		vp = info->vp;
		release = B_FALSE;

		/*
		 * Special treatment for ftruncate().
		 * This is needed because otherwise ftruncate() would
		 * fail with permission denied on read-only files.
		 * (Solaris calls VOP_SPACE instead of VOP_SETATTR on
		 * ftruncate).
		 */
		if(to_set & FUSE_SET_ATTR_SIZE) {
			/* Check if file is opened for writing */
			if((info->flags & FWRITE) == 0) {
				error = EBADF;
				goto out;
			}
			/* Sanity check */
			if(vp->v_type != VREG) {
				error = EINVAL;
				goto out;
			}

			flock64_t bf;

			bf.l_whence = 0; /* beginning of file */
			bf.l_start = attr->st_size;
			bf.l_type = F_WRLCK;
			bf.l_len = (off_t) 0;

			/* FIXME: check locks */
			error = VOP_SPACE(vp, F_FREESP, &bf, info->flags, 0, &cred, NULL);
			if(error)
				goto out;

			to_set &= ~FUSE_SET_ATTR_SIZE;
			if(to_set == 0)
				goto out;
		}
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
		if (vattr.va_uid > MAXUID) {
			error = EINVAL;
			goto out;
		}
	}
	if(to_set & FUSE_SET_ATTR_GID) {
		vattr.va_mask |= AT_GID;
		vattr.va_gid = attr->st_gid;
		if (vattr.va_gid > MAXUID) {
			error = EINVAL;
			goto out;
		}
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

	int flags = (to_set & (FUSE_SET_ATTR_ATIME | FUSE_SET_ATTR_MTIME)) ? ATTR_UTIME : 0;
	error = VOP_SETATTR(vp, &vattr, flags, &cred, NULL);

out: ;
	struct stat stat_reply;

	if(!error)
		error = zfsfuse_stat(zfsvfs, vp, &stat_reply, &cred );

	/* Do not release if vp was an opened inode */
	if(release)
		VN_RELE(vp);

	ZFS_EXIT(zfsvfs);

	if(!error)
		fuse_reply_attr(req, &stat_reply, fuse_attr_timeout);
	else
		fuse_reply_err(req, error);
}

static void zfsfuse_unlink(fuse_req_t req, fuse_ino_t parent, const char *name)
{
	if(strlen(name) >= MAXNAMELEN)
		ERROR( ENAMETOOLONG);

    print_debug(1,"function %s\n",__FUNCTION__);
	vfs_t *vfs = (vfs_t *) fuse_req_userdata(req);
	zfsvfs_t *zfsvfs = vfs->vfs_data;
	parent = FUSE2ZFS(parent, zfsvfs);

	ZFS_VOID_ENTER(zfsvfs);

	znode_t *znode;

	error = zfs_zget(zfsvfs, parent, &znode, B_FALSE);
	if(error) {
		ZFS_EXIT(zfsvfs);
		/* If the inode we are trying to get was recently deleted
		   dnode_hold_impl will return EEXIST instead of ENOENT */
		ERROR(error == EEXIST ? ENOENT : error);
	}

	ASSERT(znode != NULL);
	vnode_t *dvp = ZTOV(znode);
	ASSERT(dvp != NULL);

	cred_t cred;
	zfsfuse_getcred(req, &cred);

	error = VOP_REMOVE(dvp, (char *) name, &cred, NULL, 0);

	VN_RELE(dvp);
	ZFS_EXIT(zfsvfs);

	/* unlink events always reply_err */
	fuse_reply_err(req, error);
}

static void release_common(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi)
{
	/* Shared code between release and releasedir */
	vfs_t *vfs = (vfs_t *) fuse_req_userdata(req);
	zfsvfs_t *zfsvfs = vfs->vfs_data;
	ino = FUSE2ZFS(ino, zfsvfs);
	cred_t cred;
	zfsfuse_getcred(req, &cred);
	file_info_t *info = (file_info_t *)(uintptr_t) fi->fh;

	ZFS_VOID_ENTER(zfsvfs);

	ASSERT(info->vp != NULL);
	ASSERT(VTOZ(info->vp) != NULL);
	ASSERT(VTOZ(info->vp)->z_id == ino);

	error = VOP_CLOSE(info->vp, info->flags, 1, (offset_t) 0, &cred, NULL);
	if (error)
		syslog(LOG_WARNING, "zfsfuse_release: stale inode (%s)?", strerror(error));

	VN_RELE(info->vp);

	kmem_cache_free(file_info_cache, info);

	ZFS_EXIT(zfsvfs);
	/* Release events always reply_err */
	fuse_reply_err(req, error);
}

static void zfsfuse_release(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi)
{
	/* Specific code to release : handling of rec, buffer and lock */
    print_debug(1,"function %s\n",__FUNCTION__);
	vfs_t *vfs = (vfs_t *) fuse_req_userdata(req);
	zfsvfs_t *zfsvfs = vfs->vfs_data;
	ino = FUSE2ZFS(ino, zfsvfs);
	cred_t cred;
	zfsfuse_getcred(req, &cred);

	file_info_t *info = (file_info_t *)(uintptr_t) fi->fh;
	if (info->used) {
		print_debug(4,"release: flush ino %ld size %zd off %zd\n",ino,info->used,info->last_off-info->used);
		basic_write(zfsvfs,&cred,ino,info->buffer,info->used,info->last_off-info->used,info);
	}
	if (info->alloc) {
		print_debug(4,"release: ino %ld freeing buffer\n",ino);
		free_info(info);
		free(info->buffer);
	}
	release_common(req,ino,fi);
}

static void zfsfuse_read(fuse_req_t req, fuse_ino_t ino, size_t size, off_t off, struct fuse_file_info *fi)
{
	vfs_t *vfs = (vfs_t *) fuse_req_userdata(req);
	zfsvfs_t *zfsvfs = vfs->vfs_data;
	ino = FUSE2ZFS(ino, zfsvfs);
	file_info_t *info = (file_info_t *)(uintptr_t) fi->fh;
	cred_t cred;
	zfsfuse_getcred(req, &cred);
	file_info_t *info2 = info;
	if (!info->used) {
		// if a same file is opened for reading after it has been opened for
		// writing and it has some buffers, then the read will not see the
		// buffers, we have to find them...
		info2 = get_info(vfs,ino);
		if (info2 && info2->used) {
			syslog(LOG_WARNING,"read: found info on buffers from get_info");
		}
	}

	if (info2 && info2->used) {
		print_debug(4,"read: flush ino %ld size %zd off %zd\n",ino,info2->used,info2->last_off-info2->used);
		basic_write(zfsvfs,&cred,ino,info2->buffer,info2->used,info2->last_off-info2->used,info2);
		info2->used = 0;
	}

	vnode_t *vp = info->vp;
	ASSERT(vp != NULL);
	ASSERT(VTOZ(vp) != NULL);
	ASSERT(VTOZ(vp)->z_id == ino);

    print_debug(1,"function %s\n",__FUNCTION__);
    print_debug(8,"read ino %ld size %zd off %zd\n",ino,size,off);

	char *outbuf = kmem_alloc(size, KM_NOSLEEP);
	if(outbuf == NULL)
		ERROR( ENOMEM);

	ZFS_VOID_ENTER(zfsvfs);

	iovec_t iovec;
	uio_t uio;
	uio.uio_iov = &iovec;
	uio.uio_iovcnt = 1;
	uio.uio_segflg = UIO_SYSSPACE;
	uio.uio_fmode = FREAD;
	uio.uio_llimit = RLIM64_INFINITY;
	uio.uio_extflg = UIO_COPY_CACHED;

	iovec.iov_base = outbuf;
	iovec.iov_len = size;
	uio.uio_resid = iovec.iov_len;
	uio.uio_loffset = off;

	error = VOP_READ(vp, &uio, info->flags, &cred, NULL);

	ZFS_EXIT(zfsvfs);

	if(!error)
		fuse_reply_buf(req, outbuf, uio.uio_loffset - off);
	else
		fuse_reply_err(req, error);

	kmem_free(outbuf, size);
}

int no_buffers = 0; // command line switch: no-buffers

static void push(zfsvfs_t *zfsvfs, cred_t *cred, fuse_ino_t ino, file_info_t *info, const char *buf, size_t size, off_t off)
{
	if (info->used + size < 128<<10) {
		if (!info->used || info->last_off == off) {
			if (info->alloc < info->used + size) {
				int plus = info->used + size - info->alloc;
				if (plus < 4096) plus = 4096;
				if (!info->alloc) add_info(info);
				info->alloc += plus;
				info->buffer = realloc(info->buffer,info->alloc);
			}
			memcpy(&info->buffer[info->used],buf,size);
			print_debug(4,"push: ino %ld old size %zd new %zd\n",ino,info->used,info->used+size);
			info->used += size;
			info->last_off = off + size;
			return;
		} else { // offset just changed, need to flush
		  print_debug(4,"push: ino %ld offset changed, expected %zd, got %zd\n",ino,info->last_off,off);
		  basic_write(zfsvfs,cred,ino,info->buffer,info->used,info->last_off-info->used,info);
		  info->used = 0;
		  if (size < 4096)
			  push(zfsvfs, cred,ino,info,buf,size,off);
		  else
			  basic_write(zfsvfs, cred,ino,buf,size,off,info); 
		  return;
		}
	} else {
		// to write + buffer > 128k, need to flush everything
		if (info->used + size > info->alloc) {
			info->alloc = info->used + size;
			info->buffer = realloc(info->buffer,info->alloc);
		}
		memcpy(&info->buffer[info->used],buf,size);
		print_debug(4,"push: ino %ld flushing full buffer size %zd off %zd\n",ino,info->used+size,info->last_off-info->used);
		basic_write(zfsvfs,cred,ino,info->buffer,info->used+size,info->last_off-info->used,info);
		info->used = 0;
	}
}

static void zfsfuse_write(fuse_req_t req, fuse_ino_t ino, const char *buf, size_t size, off_t off, struct fuse_file_info *fi)
{
	file_info_t *info = (file_info_t *)(uintptr_t) fi->fh;
	vfs_t *vfs = (vfs_t *) fuse_req_userdata(req);
	zfsvfs_t *zfsvfs = vfs->vfs_data;
	cred_t cred;
	zfsfuse_getcred(req, &cred);
	if (fi->flush || info->flags & FSYNC) {
		if (info->used) {
			print_debug(4,"write: flushing ino %ld on fsync size %zd off %zd\n",ino,info->used,info->last_off-info->used,info);
			basic_write(zfsvfs,&cred,ino,info->buffer,info->used,info->last_off-info->used,info);
			info->used = 0;
		}
	}
	if (!no_buffers && !(fi->flush || (info->flags & FSYNC))) {
		if (!info->used) {
			file_info_t *info2 = get_info(vfs,ino);
			if (info2 && info2->used) {
				syslog(LOG_WARNING,"write: found info from get_info");
				info = info2; // handle it with buffers then
			}
		}

		if (size < 4096 || info->used) {
			push(zfsvfs,&cred,ino,info,buf,size,off);
			fuse_reply_write(req, size /* - uio.uio_resid */);
			return;
		}
	}
	print_debug(8,"write ino %ld size %zd off %zd\n",ino,size,off);
	
	int error = basic_write(zfsvfs,&cred, ino, buf, size, off, info);

	if(!error) {
		/* When not using direct_io, we must always write 'size' bytes */
		fuse_reply_write(req, size /* - uio.uio_resid */);
	} else
		fuse_reply_err(req, error);
}

static void zfsfuse_mknod(fuse_req_t req, fuse_ino_t parent, const char *name, mode_t mode, dev_t rdev)
{
	if(strlen(name) >= MAXNAMELEN)
		ERROR(ENAMETOOLONG);

    print_debug(1,"function %s\n",__FUNCTION__);
	vfs_t *vfs = (vfs_t *) fuse_req_userdata(req);
	zfsvfs_t *zfsvfs = vfs->vfs_data;
	parent = FUSE2ZFS(parent, zfsvfs);

	ZFS_VOID_ENTER(zfsvfs);

	znode_t *znode;

	error = zfs_zget(zfsvfs, parent, &znode, B_FALSE);
	if(error) {
		ZFS_EXIT(zfsvfs);
		/* If the inode we are trying to get was recently deleted
		   dnode_hold_impl will return EEXIST instead of ENOENT */
		ERROR(error == EEXIST ? ENOENT : error);
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
	error = VOP_CREATE(dvp, (char *) name, &vattr, EXCL, 0, &vp, &cred, 0, NULL, NULL);

	VN_RELE(dvp);

	if(error)
		goto out;

	ASSERT(vp != NULL);

	struct fuse_entry_param e = { 0 };

	e.attr_timeout = fuse_attr_timeout;
	e.entry_timeout = fuse_entry_timeout;

	znode_t *zp = VTOZ(vp);
	e.ino = zp->z_id;
	e.ino = ZFS2FUSE(e.ino, zfsvfs);

	sa_lookup(zp->z_sa_hdl, SA_ZPL_GEN(zp->z_zfsvfs), &e.generation,
		sizeof(e.generation));

	error = zfsfuse_stat(zfsvfs, vp, &e.attr, &cred );

out:
	if(vp != NULL)
		VN_RELE(vp);
	ZFS_EXIT(zfsvfs);

	if(!error)
		fuse_reply_entry(req, &e);
	else
		fuse_reply_err(req, error);
}

static void zfsfuse_symlink(fuse_req_t req, const char *link, fuse_ino_t parent, const char *name)
{
	if(strlen(name) >= MAXNAMELEN)
		ERROR(ENAMETOOLONG);

    print_debug(1,"function %s\n",__FUNCTION__);
	vfs_t *vfs = (vfs_t *) fuse_req_userdata(req);
	zfsvfs_t *zfsvfs = vfs->vfs_data;
	parent = FUSE2ZFS(parent, zfsvfs);

	ZFS_VOID_ENTER(zfsvfs);

	znode_t *znode;

	error = zfs_zget(zfsvfs, parent, &znode, B_FALSE);
	if(error) {
		ZFS_EXIT(zfsvfs);
		/* If the inode we are trying to get was recently deleted
		   dnode_hold_impl will return EEXIST instead of ENOENT */
		ERROR(error == EEXIST ? ENOENT : error);
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

	error = VOP_SYMLINK(dvp, (char *) name, &vattr, (char *) link, &cred, NULL, 0);

	vnode_t *vp = NULL;

	if(error)
		goto out;

	error = VOP_LOOKUP(dvp, (char *) name, &vp, NULL, 0, NULL, &cred, NULL, NULL, NULL);
	if(error)
		goto out;

	ASSERT(vp != NULL);

	struct fuse_entry_param e = { 0 };

	e.attr_timeout = fuse_attr_timeout;
	e.entry_timeout = fuse_entry_timeout;

	znode_t *zp = VTOZ(vp);
	e.ino = zp->z_id;
	e.ino = ZFS2FUSE(e.ino, zfsvfs);

	sa_lookup(zp->z_sa_hdl, SA_ZPL_GEN(zp->z_zfsvfs), &e.generation,
		sizeof(e.generation));

	error = zfsfuse_stat(zfsvfs, vp, &e.attr, &cred );

out:
	if(vp != NULL)
		VN_RELE(vp);
	VN_RELE(dvp);

	ZFS_EXIT(zfsvfs);

	if(!error)
		fuse_reply_entry(req, &e);
	else
		fuse_reply_err(req, error);
}

static void zfsfuse_rename(fuse_req_t req, fuse_ino_t parent, const char *name, fuse_ino_t newparent, const char *newname)
{
	if(strlen(name) >= MAXNAMELEN)
		ERROR(ENAMETOOLONG);
	if(strlen(newname) >= MAXNAMELEN)
		ERROR(ENAMETOOLONG);

    print_debug(1,"function %s\n",__FUNCTION__);
	vfs_t *vfs = (vfs_t *) fuse_req_userdata(req);
	zfsvfs_t *zfsvfs = vfs->vfs_data;
	/* Here, it's probably over zealous, there are no chances to rename
	 * the root znode. It's more to do like for all the other inodes
	 * manipulations... */
	parent = FUSE2ZFS(parent, zfsvfs);
	newparent = FUSE2ZFS(newparent,zfsvfs);

	ZFS_VOID_ENTER(zfsvfs);

	znode_t *p_znode, *np_znode;

	error = zfs_zget(zfsvfs, parent, &p_znode, B_FALSE);
	if(error) {
		ZFS_EXIT(zfsvfs);
		/* If the inode we are trying to get was recently deleted
		   dnode_hold_impl will return EEXIST instead of ENOENT */
		ERROR(error == EEXIST ? ENOENT : error);
	}

	ASSERT(p_znode != NULL);

	error = zfs_zget(zfsvfs, newparent, &np_znode, B_FALSE);
	if(error) {
		VN_RELE(ZTOV(p_znode));
		ZFS_EXIT(zfsvfs);
		/* If the inode we are trying to get was recently deleted
		   dnode_hold_impl will return EEXIST instead of ENOENT */
		ERROR(error == EEXIST ? ENOENT : error);
	}

	ASSERT(np_znode != NULL);

	vnode_t *p_vp = ZTOV(p_znode);
	vnode_t *np_vp = ZTOV(np_znode);
	ASSERT(p_vp != NULL);
	ASSERT(np_vp != NULL);

	cred_t cred;
	zfsfuse_getcred(req, &cred);

	error = VOP_RENAME(p_vp, (char *) name, np_vp, (char *) newname, &cred, NULL, 0);

	VN_RELE(p_vp);
	VN_RELE(np_vp);

	ZFS_EXIT(zfsvfs);

	/* rename events always reply_err */
	fuse_reply_err(req, error);
}

static void zfsfuse_fsync(fuse_req_t req, fuse_ino_t ino, int datasync, struct fuse_file_info *fi)
{
    print_debug(1,"function %s\n",__FUNCTION__);
	vfs_t *vfs = (vfs_t *) fuse_req_userdata(req);
	zfsvfs_t *zfsvfs = vfs->vfs_data;
	file_info_t *info = (file_info_t *)(uintptr_t) fi->fh;
	cred_t cred;
	zfsfuse_getcred(req, &cred);
	if (info->used) {
		print_debug(4,"fsync: flushing ino %ld size %zd off %zd\n",ino,info->used,info->last_off-info->used,info);
		basic_write(zfsvfs,&cred,ino,info->buffer,info->used,info->last_off-info->used,info);
		info->used = 0;
	} else {
		print_debug(4,"fsync: no info ino %ld\n",ino);
	}

	ZFS_VOID_ENTER(zfsvfs);

#if DEBUG
	ino = FUSE2ZFS(ino, zfsvfs);
	ASSERT(info->vp != NULL);
	ASSERT(VTOZ(info->vp) != NULL);
	ASSERT(VTOZ(info->vp)->z_id == ino);
#endif

	vnode_t *vp = info->vp;

	error = VOP_FSYNC(vp, datasync ? FDSYNC : FSYNC, &cred, NULL);

	ZFS_EXIT(zfsvfs);

	/* fsync events always reply_err */
	fuse_reply_err(req, error);
}

static void zfsfuse_link(fuse_req_t req, fuse_ino_t ino, fuse_ino_t newparent, const char *newname)
{
	if(strlen(newname) >= MAXNAMELEN)
		ERROR(ENAMETOOLONG);

    print_debug(1,"function %s\n",__FUNCTION__);
	vfs_t *vfs = (vfs_t *) fuse_req_userdata(req);
	zfsvfs_t *zfsvfs = vfs->vfs_data;
	ino = FUSE2ZFS(ino, zfsvfs);
	newparent = FUSE2ZFS(newparent, zfsvfs);

	ZFS_VOID_ENTER(zfsvfs);

	znode_t *td_znode, *s_znode;

	error = zfs_zget(zfsvfs, ino, &s_znode, B_FALSE);
	if(error) {
		ZFS_EXIT(zfsvfs);
		/* If the inode we are trying to get was recently deleted
		   dnode_hold_impl will return EEXIST instead of ENOENT */
		ERROR(error == EEXIST ? ENOENT : error);
	}

	ASSERT(s_znode != NULL);

	error = zfs_zget(zfsvfs, newparent, &td_znode, B_FALSE);
	if(error) {
		VN_RELE(ZTOV(s_znode));
		ZFS_EXIT(zfsvfs);
		/* If the inode we are trying to get was recently deleted
		   dnode_hold_impl will return EEXIST instead of ENOENT */
		ERROR(error == EEXIST ? ENOENT : error);
	}

	vnode_t *svp = ZTOV(s_znode);
	vnode_t *tdvp = ZTOV(td_znode);
	ASSERT(svp != NULL);
	ASSERT(tdvp != NULL);

	cred_t cred;
	zfsfuse_getcred(req, &cred);

	error = VOP_LINK(tdvp, svp, (char *) newname, &cred, NULL, 0);

	vnode_t *vp = NULL;

	if(error)
		goto out;

	error = VOP_LOOKUP(tdvp, (char *) newname, &vp, NULL, 0, NULL, &cred, NULL, NULL, NULL);
	if(error)
		goto out;

	ASSERT(vp != NULL);

	struct fuse_entry_param e = { 0 };

	e.attr_timeout = fuse_attr_timeout;
	e.entry_timeout = fuse_entry_timeout;

	znode_t *zp = VTOZ(vp);
	e.ino = zp->z_id;
	e.ino = ZFS2FUSE(e.ino, zfsvfs);

	sa_lookup(zp->z_sa_hdl, SA_ZPL_GEN(zp->z_zfsvfs), &e.generation,
		sizeof(e.generation));

	error = zfsfuse_stat(zfsvfs, vp, &e.attr, &cred );

out:
	if(vp != NULL)
		VN_RELE(vp);
	VN_RELE(tdvp);
	VN_RELE(svp);

	ZFS_EXIT(zfsvfs);

	if(!error)
		fuse_reply_entry(req, &e);
	else
		fuse_reply_err(req, error);
}

static void zfsfuse_access(fuse_req_t req, fuse_ino_t ino, int mask)
{
    print_debug(1,"function %s\n",__FUNCTION__);
	vfs_t *vfs = (vfs_t *) fuse_req_userdata(req);
	zfsvfs_t *zfsvfs = vfs->vfs_data;
	ino = FUSE2ZFS(ino, zfsvfs);

	ZFS_VOID_ENTER(zfsvfs);

	znode_t *znode;

	error = zfs_zget(zfsvfs, ino, &znode, B_TRUE);
	if(error) {
		ZFS_EXIT(zfsvfs);
		/* If the inode we are trying to get was recently deleted
		   dnode_hold_impl will return EEXIST instead of ENOENT */
		ERROR(error == EEXIST ? ENOENT : error);
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

	error = VOP_ACCESS(vp, mode, 0, &cred, NULL);

	VN_RELE(vp);

	ZFS_EXIT(zfsvfs);

	/* access events always reply_err */
	fuse_reply_err(req, error);
}

struct fuse_lowlevel_ops zfs_operations =
{
	.open       = zfsfuse_open_helper,
	.read       = zfsfuse_read,
	.write      = zfsfuse_write,
	.release    = zfsfuse_release,
	.opendir    = zfsfuse_opendir,
	.readdir    = zfsfuse_readdir,
	.releasedir = release_common,
	.lookup     = zfsfuse_lookup,
	.getattr    = zfsfuse_getattr,
	.readlink   = zfsfuse_readlink,
	.mkdir      = zfsfuse_mkdir,
	.rmdir      = zfsfuse_rmdir,
	.create     = zfsfuse_create_helper,
	.unlink     = zfsfuse_unlink,
	.mknod      = zfsfuse_mknod,
	.symlink    = zfsfuse_symlink,
	.link       = zfsfuse_link,
	.rename     = zfsfuse_rename,
	.setattr    = zfsfuse_setattr,
	.fsync      = zfsfuse_fsync,
	.fsyncdir   = zfsfuse_fsync,
	.access     = zfsfuse_access,
	.statfs     = zfsfuse_statfs,
	.destroy    = zfsfuse_destroy,
	.listxattr  = zfsfuse_listxattr,
	.setxattr   = zfsfuse_setxattr,
	.getxattr   = zfsfuse_getxattr,
	.removexattr= zfsfuse_removexattr,
	.flush	    = zfsfuse_flush,
};

void init_xattr() {
	memset(&infos,0,sizeof(infos));
	pthread_mutex_init(&infos.lock,NULL);
    if (cf_enable_xattr) {
	zfs_operations.listxattr  = zfsfuse_listxattr;
	zfs_operations.setxattr   = zfsfuse_setxattr;
	zfs_operations.getxattr   = zfsfuse_getxattr;
	zfs_operations.removexattr= zfsfuse_removexattr;
    } else {
	zfs_operations.listxattr  = NULL;
	zfs_operations.setxattr   = NULL;
	zfs_operations.getxattr   = NULL;
	zfs_operations.removexattr= NULL;
    }
}

