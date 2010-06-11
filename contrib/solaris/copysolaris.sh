#!/bin/sh

. ./config.rc

DEST_DIR="$ORIG_DIR/src"

mkdir -p $DEST_DIR/lib

mkdir -p $DEST_DIR/lib/libavl/include/sys
if ! [ -d $OPENSOLARIS_SRC ]; then
    echo run hg first
    exit 1
fi
cp $OPENSOLARIS_SRC/common/avl/avl.c $DEST_DIR/lib/libavl/ || exit 1
cp $OPENSOLARIS_SRC/uts/common/sys/avl.h $DEST_DIR/lib/libavl/include/sys/ || exit 1
cp $OPENSOLARIS_SRC/uts/common/sys/avl_impl.h $DEST_DIR/lib/libavl/include/sys/ || exit 1

mkdir -p $DEST_DIR/lib/libsolkerncompat/include/sys
mkdir -p $DEST_DIR/lib/libsolkerncompat/include/fs
mkdir -p $DEST_DIR/lib/libsolkerncompat/include/acl
cp $OPENSOLARIS_SRC/uts/common/os/refstr.c $DEST_DIR/lib/libsolkerncompat/ || exit 1
cp $OPENSOLARIS_SRC/uts/common/fs/pathname.c $DEST_DIR/lib/libsolkerncompat/ || exit 1
cp $OPENSOLARIS_SRC/uts/common/fs/zfs/sys/zfs_context.h $DEST_DIR/lib/libsolkerncompat/include/sys/ || exit 1
cp $OPENSOLARIS_SRC/uts/common/fs/fs_subr.h $DEST_DIR/lib/libsolkerncompat/include/fs/ || exit 1
cp $OPENSOLARIS_SRC/common/acl/acl_common.h $DEST_DIR/lib/libsolkerncompat/include/acl/ || exit 1
cp $OPENSOLARIS_SRC/common/acl/acl_common.c $DEST_DIR/lib/libsolkerncompat/ || exit 1

FILES="cred.h dirent.h dditypes.h extdirent.h mode.h pathname.h refstr.h refstr_impl.h sid.h statvfs.h t_lock.h taskq.h uio.h vfs_opreg.h"

for f in $FILES; do
	cp $OPENSOLARIS_SRC/uts/common/sys/$f $DEST_DIR/lib/libsolkerncompat/include/sys/ || exit 1
done

mkdir -p $DEST_DIR/lib/libsolcompat/include/sys
mkdir -p $DEST_DIR/lib/libsolcompat/include/sys/sysevent
cp $OPENSOLARIS_SRC/lib/libc/port/gen/strlcpy.c $DEST_DIR/lib/libsolcompat/ || exit 1
cp $OPENSOLARIS_SRC/lib/libc/port/gen/strlcat.c $DEST_DIR/lib/libsolcompat/ || exit 1
cp $OPENSOLARIS_SRC/lib/libgen/common/mkdirp.c $DEST_DIR/lib/libsolcompat/ || exit 1
cp $OPENSOLARIS_SRC/common/unicode/u8_textprep.c $DEST_DIR/lib/libsolcompat/ || exit 1
cp $OPENSOLARIS_SRC/lib/libshare/common/libshare.h $DEST_DIR/lib/libsolcompat/include/ || exit 1
cp $OPENSOLARIS_SRC/head/zone.h $DEST_DIR/lib/libsolcompat/include/ || exit 1
cp $OPENSOLARIS_SRC/uts/common/sys/atomic.h $DEST_DIR/lib/libsolcompat/include/ || exit 1

FILES="acl.h acl_impl.h byteorder.h dklabel.h dkio.h idmap.h isa_defs.h kstat.h mntent.h note.h types32.h u8_textprep.h u8_textprep_data.h uuid.h vtoc.h zmod.h sysevent/eventdefs.h"

for f in $FILES; do
	cp $OPENSOLARIS_SRC/uts/common/sys/$f $DEST_DIR/lib/libsolcompat/include/sys/$f || exit 1
done

mkdir -p $DEST_DIR/lib/libsolcompat/i386
mkdir -p $DEST_DIR/lib/libsolcompat/amd64
mkdir -p $DEST_DIR/lib/libsolcompat/sparc64
cp $OPENSOLARIS_SRC/common/atomic/i386/atomic.s $DEST_DIR/lib/libsolcompat/i386/atomic.S || exit 1
cp $OPENSOLARIS_SRC/common/atomic/amd64/atomic.s $DEST_DIR/lib/libsolcompat/amd64/atomic.S || exit 1
cp $OPENSOLARIS_SRC/common/atomic/sparc/atomic.s $DEST_DIR/lib/libsolcompat/sparc64/atomic.S || exit 1
mkdir -p $DEST_DIR/lib/libsolcompat/include/ia32/sys
mkdir -p $DEST_DIR/lib/libsolcompat/include/sparc64/sys
cp $OPENSOLARIS_SRC/uts/intel/ia32/sys/asm_linkage.h $DEST_DIR/lib/libsolcompat/include/ia32/sys/ || exit 1
cp $OPENSOLARIS_SRC/uts/sparc/sys/asm_linkage.h $DEST_DIR/lib/libsolcompat/include/sparc64/sys/ || exit 1

mkdir -p $DEST_DIR/lib/libnvpair/include/sys
cp $OPENSOLARIS_SRC/lib/libnvpair/libnvpair.c $DEST_DIR/lib/libnvpair/ || exit 1
cp $OPENSOLARIS_SRC/lib/libnvpair/libnvpair.h $DEST_DIR/lib/libnvpair/include/ || exit 1
cp $OPENSOLARIS_SRC/lib/libnvpair/nvpair_alloc_system.c $DEST_DIR/lib/libnvpair/ || exit 1
cp $OPENSOLARIS_SRC/common/nvpair/nvpair_alloc_fixed.c $DEST_DIR/lib/libnvpair/ || exit 1
cp $OPENSOLARIS_SRC/common/nvpair/nvpair.c $DEST_DIR/lib/libnvpair/ || exit 1
cp $OPENSOLARIS_SRC/uts/common/sys/nvpair.h $DEST_DIR/lib/libnvpair/include/sys/ || exit 1
cp $OPENSOLARIS_SRC/uts/common/sys/nvpair_impl.h $DEST_DIR/lib/libnvpair/include/sys/ || exit 1

mkdir -p $DEST_DIR/lib/libumem/include
cp $OPENSOLARIS_SRC/lib/libumem/common/umem.h $DEST_DIR/lib/libumem/include/ || exit 1

mkdir -p $DEST_DIR/lib/libuutil/include
cp $OPENSOLARIS_SRC/lib/libuutil/common/libuutil.h $DEST_DIR/lib/libuutil/include/ || exit 1
cp $OPENSOLARIS_SRC/lib/libuutil/common/libuutil_common.h $DEST_DIR/lib/libuutil/include/ || exit 1
cp $OPENSOLARIS_SRC/lib/libuutil/common/libuutil_impl.h $DEST_DIR/lib/libuutil/include/ || exit 1

FILES="uu_alloc.c uu_avl.c uu_dprintf.c uu_ident.c uu_list.c uu_misc.c uu_open.c uu_pname.c uu_strtoint.c"

for f in $FILES; do
	cp $OPENSOLARIS_SRC/lib/libuutil/common/$f $DEST_DIR/lib/libuutil/ || exit 1
done

mkdir -p $DEST_DIR/lib/libzfs/include
cp $OPENSOLARIS_SRC/lib/libzfs/common/libzfs.h $DEST_DIR/lib/libzfs/include/ || exit 1
cp $OPENSOLARIS_SRC/lib/libzfs/common/libzfs_impl.h $DEST_DIR/lib/libzfs/include/ || exit 1

FILES="libzfs_dataset.c libzfs_util.c libzfs_graph.c libzfs_mount.c libzfs_pool.c libzfs_changelist.c libzfs_config.c libzfs_import.c libzfs_status.c libzfs_sendrecv.c"

for f in $FILES; do
	cp $OPENSOLARIS_SRC/lib/libzfs/common/$f $DEST_DIR/lib/libzfs/ || exit 1
done

mkdir -p $DEST_DIR/lib/libzfscommon/include/sys/fs
mkdir -p $DEST_DIR/lib/libzfscommon/include/sys/fm/fs
cp $OPENSOLARIS_SRC/uts/common/sys/fs/zfs.h $DEST_DIR/lib/libzfscommon/include/sys/fs/ || exit 1
cp $OPENSOLARIS_SRC/uts/common/sys/fm/fs/zfs.h $DEST_DIR/lib/libzfscommon/include/sys/fm/fs/ || exit 1
cp -R $OPENSOLARIS_SRC/uts/common/fs/zfs/sys/* $DEST_DIR/lib/libzfscommon/include/sys/ || exit 1
rm -f $DEST_DIR/lib/libzfscommon/include/sys/zfs_context.h
cp $OPENSOLARIS_SRC/common/zfs/zfs_namecheck.c $DEST_DIR/lib/libzfscommon/ || exit 1
cp $OPENSOLARIS_SRC/common/zfs/zfs_namecheck.h $DEST_DIR/lib/libzfscommon/include/ || exit 1
cp $OPENSOLARIS_SRC/common/zfs/zfs_prop.c $DEST_DIR/lib/libzfscommon/ || exit 1
cp $OPENSOLARIS_SRC/common/zfs/zfs_prop.h $DEST_DIR/lib/libzfscommon/include/ || exit 1
cp $OPENSOLARIS_SRC/common/zfs/zfs_deleg.c $DEST_DIR/lib/libzfscommon/ || exit 1
cp $OPENSOLARIS_SRC/common/zfs/zfs_deleg.h $DEST_DIR/lib/libzfscommon/include/ || exit 1
cp $OPENSOLARIS_SRC/common/zfs/zfs_comutil.c $DEST_DIR/lib/libzfscommon/ || exit 1
cp $OPENSOLARIS_SRC/common/zfs/zfs_comutil.h $DEST_DIR/lib/libzfscommon/include/ || exit 1
cp $OPENSOLARIS_SRC/common/zfs/zpool_prop.c $DEST_DIR/lib/libzfscommon/ || exit 1
cp $OPENSOLARIS_SRC/common/zfs/zprop_common.c $DEST_DIR/lib/libzfscommon/ || exit 1

cp $OPENSOLARIS_SRC/uts/common/sys/compress.h $DEST_DIR/lib/libzfscommon/include/sys/ || exit 1
cp $OPENSOLARIS_SRC/uts/common/os/compress.c $DEST_DIR/lib/libzfscommon/ || exit 1

cp $OPENSOLARIS_SRC/uts/common/sys/list.h $DEST_DIR/lib/libzfscommon/include/sys/ || exit 1
cp $OPENSOLARIS_SRC/uts/common/sys/list_impl.h $DEST_DIR/lib/libzfscommon/include/sys/ || exit 1
cp $OPENSOLARIS_SRC/uts/common/os/list.c $DEST_DIR/lib/libzfscommon/ || exit 1

mkdir -p $DEST_DIR/lib/libzpool/include/sys
cp $OPENSOLARIS_SRC/lib/libzpool/common/sys/zfs_context.h $DEST_DIR/lib/libzpool/include/sys/ || exit 1
cp $OPENSOLARIS_SRC/lib/libzpool/common/kernel.c $DEST_DIR/lib/libzpool/ || exit 1
cp $OPENSOLARIS_SRC/lib/libzpool/common/taskq.c $DEST_DIR/lib/libzpool/ || exit 1
cp $OPENSOLARIS_SRC/lib/libzpool/common/util.c $DEST_DIR/lib/libzpool/ || exit 1

for f in $OPENSOLARIS_SRC/uts/common/fs/zfs/*.c; do
	cp $f $DEST_DIR/lib/libzpool/ || exit 1
done

mkdir -p $DEST_DIR/cmd/zdb
cp $OPENSOLARIS_SRC/cmd/zdb/zdb.c $DEST_DIR/cmd/zdb/ || exit 1
cp $OPENSOLARIS_SRC/cmd/zdb/zdb_il.c $DEST_DIR/cmd/zdb/ || exit 1

mkdir -p $DEST_DIR/cmd/ztest
cp $OPENSOLARIS_SRC/cmd/ztest/ztest.c $DEST_DIR/cmd/ztest/ || exit 1

mkdir -p $DEST_DIR/cmd/zpool
FILES="zpool_main.c zpool_vdev.c zpool_iter.c zpool_util.c zpool_util.h"

for f in $FILES; do
	cp $OPENSOLARIS_SRC/cmd/zpool/$f $DEST_DIR/cmd/zpool/ || exit 1
done

mkdir -p $DEST_DIR/cmd/zfs
FILES="zfs_main.c zfs_iter.c zfs_iter.h zfs_util.h"

for f in $FILES; do
	cp $OPENSOLARIS_SRC/cmd/zfs/$f $DEST_DIR/cmd/zfs/ || exit 1
done

mkdir -p $DEST_DIR/zfs-fuse
FILES="zfs_acl.c zfs_dir.c zfs_ioctl.c zfs_log.c zfs_replay.c zfs_rlock.c zfs_vfsops.c zfs_vnops.c zvol.c"

for f in $FILES; do
	cp $OPENSOLARIS_SRC/uts/common/fs/zfs/$f $DEST_DIR/zfs-fuse/ || exit 1
done

find $DEST_DIR -type f -exec chmod 644 {} \;

./fixfiles.py "$DEST_DIR"

echo All done!

