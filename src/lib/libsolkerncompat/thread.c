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
 * Copyright 2006 Ricardo Correia
 * Use is subject to license terms.
 */

#include <sys/thread.h>
#include <sys/debug.h>
#include <sys/types.h>

#include <pthread.h>
#include <sched.h>

extern size_t stack_size;

#ifndef minclsyspri
#define	minclsyspri	60
#define	maxclsyspri	99
#endif

kthread_t *
zk_thread_create(void (*func)(), void *arg, int pri)
{
	pthread_t tid;

	pthread_attr_t attr;
	pthread_attr_init(&attr);

	pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
	if (stack_size)
	    pthread_attr_setstacksize(&attr,stack_size);

	VERIFY(pthread_create(&tid, &attr, (void *(*)(void *)) func, arg) == 0);
	if (pri == minclsyspri) {
	    struct sched_param param;
	    param.sched_priority = 0;
#ifndef SCHED_IDLE
#define SCHED_IDLE 5
#endif
	    pthread_setschedparam(tid,SCHED_IDLE,&param);
	} else if (pri == maxclsyspri) {
	    struct sched_param param;
	    param.sched_priority = sched_get_priority_max(SCHED_FIFO);
	    pthread_setschedparam(tid,SCHED_FIFO,&param);
	} 

	pthread_attr_destroy(&attr);

	return ((void *)(uintptr_t)tid);
}
