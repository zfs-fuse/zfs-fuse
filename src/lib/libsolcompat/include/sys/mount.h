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
 * Use is subject to license terms.
 */

#ifndef _SOL_SYS_MOUNT_H
#define _SOL_SYS_MOUNT_H

#include <assert.h>
#include_next <sys/mount.h>

/* LINUX */
/*
 * Some old glibc headers don't define BLKGETSIZE64
 * and we don't want to require the kernel headers
 */
#if !defined(BLKGETSIZE64)
#define BLKGETSIZE64 _IOR(0x12,114,size_t)
#endif

#define MS_FORCE     MNT_FORCE
#define MS_OVERLAY   32768
#define MS_NOMNTTAB  0         /* Not supported in Linux */
#define MS_OPTIONSTR 0         /* Not necessary in Linux */

static inline int _sol_mount(const char *spec, const char *dir, int mflag, char *fstype, char *dataptr, int datalen, char *optptr, int optlen)
{
	assert(dataptr == NULL);
	assert(datalen == 0);
	assert(mflag == 0);

	return mount(spec, dir, fstype, mflag, optptr);
}

#define mount _sol_mount

#endif
