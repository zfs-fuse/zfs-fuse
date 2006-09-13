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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <sys/debug.h>
#include <sys/mutex.h>
#include <sys/thread.h>
#include <sys/types.h>

#include <pthread.h>

void
zmutex_init(kmutex_t *mp)
{
	mp->m_owner = NULL;
	(void) pthread_mutex_init(&mp->m_lock, NULL);
}

void
zmutex_destroy(kmutex_t *mp)
{
	ASSERT(mp->m_owner == NULL);
	(void) pthread_mutex_destroy(&(mp)->m_lock);
	mp->m_owner = (void *)-1UL;
}

void
mutex_enter(kmutex_t *mp)
{
	ASSERT(mp->m_owner != (void *)-1UL);
	ASSERT(mp->m_owner != curthread);
	VERIFY(pthread_mutex_lock(&mp->m_lock) == 0);
	ASSERT(mp->m_owner == NULL);
	mp->m_owner = curthread;
}

int
mutex_tryenter(kmutex_t *mp)
{
	ASSERT(mp->m_owner != (void *)-1UL);
	if (0 == pthread_mutex_trylock(&mp->m_lock)) {
		ASSERT(mp->m_owner == NULL);
		mp->m_owner = curthread;
		return (1);
	} else {
		return (0);
	}
}

void
mutex_exit(kmutex_t *mp)
{
	ASSERT(mutex_owner(mp) == curthread);
	mp->m_owner = NULL;
	VERIFY(pthread_mutex_unlock(&mp->m_lock) == 0);
}

void *
mutex_owner(kmutex_t *mp)
{
	return (mp->m_owner);
}
