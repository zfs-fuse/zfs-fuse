#!/bin/sh

. ./config.rc

DEST_DIR="$UMEM_DEST/src/lib/libumem"

mkdir -p $DEST_DIR/include
mkdir -p $DEST_DIR/sys

cp $UMEM_SRC/umem.h $DEST_DIR/include/ || exit 1
#cp $OPENSOLARIS_SRC/uts/common/sys/vmem.h $DEST_DIR/sys/ || exit 1
cp -v $UMEM_SRC/sys/vmem.h $DEST_DIR/sys/ || exit 1
cp -v $UMEM_SRC/sys/vmem_impl_user.h $DEST_DIR/sys/ || exit 1

FILES="AUTHORS ChangeLog COPYING COPYRIGHT NEWS OPENSOLARIS.LICENSE README README-alpha TODO envvar.c getpcstack.c init_lib.c misc.c misc.h sol_compat.h umem_agent_support.c umem_base.h umem.c umem_fail.c umem_fork.c umem_impl.h umem_update_thread.c vmem_base.c vmem_base.h vmem.c vmem_mmap.c vmem_sbrk.c vmem_stand.h"
#FILES="envvar.c getpcstack.c init_lib.c misc.c misc.h umem_agent_support.c umem_base.h umem.c umem_fail.c umem_fork.c umem_impl.h umem_update_thread.c vmem_base.c vmem_base.h vmem.c vmem_mmap.c vmem_sbrk.c vmem_stand.h"

for f in $FILES; do
	cp $UMEM_SRC/$f $DEST_DIR/ || exit 1
done
