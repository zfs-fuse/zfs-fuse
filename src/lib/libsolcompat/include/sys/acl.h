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

#ifndef _SOL_SYS_ACL_H
#define _SOL_SYS_ACL_H

#define MAX_ACL_ENTRIES (1024) /* max entries of each type */

typedef struct ace {
	uid_t    a_who;         /* uid or gid */
	uint32_t a_access_mask; /* read,write,... */
	uint16_t a_flags;       /* see below */
	uint16_t a_type;        /* allow or deny */
} ace_t;

/*
 * The following are defined for ace_t.
 */
#define ACE_READ_DATA         0x00000001
#define ACE_LIST_DIRECTORY    0x00000001
#define ACE_WRITE_DATA        0x00000002
#define ACE_ADD_FILE          0x00000002
#define ACE_APPEND_DATA       0x00000004
#define ACE_ADD_SUBDIRECTORY  0x00000004
#define ACE_READ_NAMED_ATTRS  0x00000008
#define ACE_WRITE_NAMED_ATTRS 0x00000010
#define ACE_EXECUTE           0x00000020
#define ACE_DELETE_CHILD      0x00000040
#define ACE_READ_ATTRIBUTES   0x00000080
#define ACE_WRITE_ATTRIBUTES  0x00000100
#define ACE_DELETE            0x00010000
#define ACE_READ_ACL          0x00020000
#define ACE_WRITE_ACL         0x00040000
#define ACE_WRITE_OWNER       0x00080000
#define ACE_SYNCHRONIZE       0x00100000

#define ACE_FILE_INHERIT_ACE           0x0001
#define ACE_DIRECTORY_INHERIT_ACE      0x0002
#define ACE_NO_PROPAGATE_INHERIT_ACE   0x0004
#define ACE_INHERIT_ONLY_ACE           0x0008
#define ACE_SUCCESSFUL_ACCESS_ACE_FLAG 0x0010
#define ACE_FAILED_ACCESS_ACE_FLAG     0x0020
#define ACE_IDENTIFIER_GROUP           0x0040
#define ACE_OWNER                      0x1000
#define ACE_GROUP                      0x2000
#define ACE_EVERYONE                   0x4000

#define ACE_ACCESS_ALLOWED_ACE_TYPE 0x0000
#define ACE_ACCESS_DENIED_ACE_TYPE  0x0001
#define ACE_SYSTEM_AUDIT_ACE_TYPE   0x0002
#define ACE_SYSTEM_ALARM_ACE_TYPE   0x0003

#define ACE_ALL_PERMS     (ACE_READ_DATA|ACE_LIST_DIRECTORY|ACE_WRITE_DATA| \
    ACE_ADD_FILE|ACE_APPEND_DATA|ACE_ADD_SUBDIRECTORY|ACE_READ_NAMED_ATTRS| \
    ACE_WRITE_NAMED_ATTRS|ACE_EXECUTE|ACE_DELETE_CHILD|ACE_READ_ATTRIBUTES| \
    ACE_WRITE_ATTRIBUTES|ACE_DELETE|ACE_READ_ACL|ACE_WRITE_ACL| \
    ACE_WRITE_OWNER|ACE_SYNCHRONIZE)

#endif
