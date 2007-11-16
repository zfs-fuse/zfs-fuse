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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _SOL_SUNDDI_H
#define _SOL_SUNDDI_H

#ifdef _KERNEL

#include <stdlib.h>

/*
 * UTF-8 text preparation functions and their macros.
 * (sunddi.h)
 */
#define U8_STRCMP_CS                    0x00000001
#define U8_STRCMP_CI_UPPER              0x00000002
#define U8_STRCMP_CI_LOWER              0x00000004

#define U8_TEXTPREP_TOUPPER             U8_STRCMP_CI_UPPER
#define U8_TEXTPREP_TOLOWER             U8_STRCMP_CI_LOWER
#define U8_TEXTPREP_IGNORE_NULL         0x00010000

#define U8_UNICODE_320                  (0)
#define U8_UNICODE_500                  (1)
#define U8_UNICODE_LATEST               U8_UNICODE_500

static inline size_t u8_textprep_str(char *i, size_t *il, char *o, size_t *ol, int nf, size_t vers, int *err)
{
	*err = EINVAL;
	return ((size_t)-1);
}

static inline int
ddi_strtoul(const char *hw_serial, char **nptr, int base, unsigned long *result)
{
	char *end;

	*result = strtoul(hw_serial, &end, base);
	if (*result == 0)
		return (errno);
	return (0);
}
#endif

#endif

