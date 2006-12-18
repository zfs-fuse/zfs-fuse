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

#ifndef _SYS_POLICY_H
#define _SYS_POLICY_H

#define secpolicy_sys_config(c, co) (0)
#define secpolicy_zfs(c) (0)
#define secpolicy_zinject(c) (0)
#define secpolicy_fs_mount(c,vnode,vfs) (0)
#define secpolicy_fs_unmount(c,vfs) (0)

#define secpolicy_setid_setsticky_clear(v,va,ova,c) (EPERM)
#define secpolicy_vnode_setid_retain(c,s) (EPERM)
#define secpolicy_vnode_stky_modify(c) (EPERM)
#define secpolicy_vnode_setattr(a,b,c,d,e,f,g) (EPERM)

#define secpolicy_basic_link(c) (EPERM)

static inline void
secpolicy_setid_clear(vattr_t *vap, cred_t *cr)
{
	if ((vap->va_mode & (S_ISUID | S_ISGID)) != 0 &&
	    secpolicy_vnode_setid_retain(cr,
	    (vap->va_mode & S_ISUID) != 0 &&
	    (vap->va_mask & AT_UID) != 0 && vap->va_uid == 0) != 0) {
		vap->va_mask |= AT_MODE;
		vap->va_mode &= ~(S_ISUID|S_ISGID);
	}
}

#endif
