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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

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
	atomic_add_64(&kern_memusage, umem_cache_get_bufsize(cp));
	return umem_cache_alloc(cp, kmflag);
}

void kmem_cache_free(kmem_cache_t *cp, void *buf)
{
	umem_cache_free(cp, buf);
	atomic_add_64(&kern_memusage, -umem_cache_get_bufsize(cp));
}

/* This really sucks but we have no choice since getrusage() doesn't work.. */
uint64_t get_real_memusage()
{
	int error_n = -1;

	FILE *f = fopen("/proc/self/status", "r");

	if(f == NULL) {
		error_n = errno;
		goto error;
	}

	uint64_t memusage = 0;

	for(;;) {
		char buf[512];
		char key[100];
		u_longlong_t val;

		if(fgets(buf, sizeof(buf), f) == NULL)
			goto error;
 
		int res = sscanf(buf, "%99[^:]: %Lu", key, &val);

		if(res == 2 && strcmp(key, "VmRSS") == 0) {
			memusage = val << 10;
			break;
		}
	}

	fclose(f);

	return memusage;

error:
	if(f == NULL)
		fprintf(stderr, "Error: unable to open /proc/self/status (error %i)\nMake sure you have the proc filesystem mounted.\n", error_n);
	else {
		fprintf(stderr, "Error: unable to read /proc/self/status (error %i)\n", error_n);
		fclose(f);
	}

	exit(1);
}
