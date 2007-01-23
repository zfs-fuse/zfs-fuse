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
 * Copyright 2007 Ricardo Correia
 * Use is subject to license terms.
 */

#include <sys/kmem.h>
#include <sys/atomic.h>
#include <umem.h>

uint64_t kern_memusage = 0;

void *kmem_alloc(size_t size, int kmflags)
{
	atomic_add_64(&kern_memusage, size);
	return umem_alloc(size, kmflags);
}

void *kmem_zalloc(size_t size, int kmflags)
{
	atomic_add_64(&kern_memusage, size);
	return umem_zalloc(size, kmflags);
}

void kmem_free(void *buf, size_t size)
{
	umem_free(buf, size);
	atomic_add_64(&kern_memusage, -size);
}

void *kmem_cache_alloc(kmem_cache_t *cp, int kmflag)
{
	atomic_add_64(&kern_memusage, umem_get_bufsize(cp));
	return umem_cache_alloc(cp, kmflag);
}

void kmem_cache_free(kmem_cache_t *cp, void *buf)
{
	umem_cache_free(cp, buf);
	atomic_add_64(&kern_memusage, -umem_get_bufsize(cp));
}
