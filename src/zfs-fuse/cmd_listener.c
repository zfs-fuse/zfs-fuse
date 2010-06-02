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
 * Copyright 2006 Ricardo Correia.
 * Use is subject to license terms.
 */

#include <sys/debug.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/poll.h>
#include <errno.h>

#include <stdio.h>
#include <unistd.h>
#include <fuse/fuse.h>
#include <syslog.h>

#include "zfs_ioctl.h"
#include "zfsfuse_socket.h"
#include "util.h"

#include "semaphore.h"
#include <sys/time.h>

#define MAX_CONNECTIONS 100
#define IOCTLQUEUE_MAX_PENDING 256 // recommend to at least match MAX_CONNECTIONS so no regressions occur
#define IOCTLQUEUE_WORKERS 8

boolean_t exit_listener = B_FALSE;

int cmd_mount_req(int sock, zfsfuse_cmd_t *cmd)
{
	uint32_t speclen = cmd->cmd_u.mount_req.speclen;
	uint32_t dirlen = cmd->cmd_u.mount_req.dirlen;
	int32_t optlen = cmd->cmd_u.mount_req.optlen;

	char *spec = kmem_alloc(speclen + 1,KM_SLEEP);
	char *dir = kmem_alloc(dirlen + 1,KM_SLEEP);
	char *opt = kmem_alloc(optlen + 1,KM_SLEEP);

	int ret = 0; // no error

	if(zfsfuse_socket_read_loop(sock, spec, speclen) == 0 &&
		zfsfuse_socket_read_loop(sock, dir, dirlen) == 0 &&
		zfsfuse_socket_read_loop(sock, opt, optlen) == 0) {
		spec[speclen] = '\0';
		dir[dirlen] = '\0';
		opt[optlen] = '\0';
#ifdef DEBUG
		fprintf(stderr, "mount request: \"%s\", \"%s\", \"%i\", \"%s\"\n", spec, dir, cmd->cmd_u.mount_req.mflag, opt);
#endif
		uint32_t ret_m = do_mount(spec, dir, cmd->cmd_u.mount_req.mflag, opt);
		if(write(sock, &ret_m, sizeof(uint32_t)) != sizeof(uint32_t))
			ret = -1;;
	} else
	    ret = -1;
	kmem_free(opt,optlen+1);
	kmem_free(dir,dirlen+1);
	kmem_free(spec,speclen+1);

	return ret;
}

/* --------------------------------------------------
 * new ioctl queue facility
 * --------------------------------------------------
 */

typedef struct {
    int socket;
} ioctl_queue_item_t;

extern size_t stack_size;

static void handle_connection(int sock)
{
    /* Handle request */
    zfsfuse_cmd_t cmd;
	dev_t dev = {0};
	cred_t cr;

    while (-1 != zfsfuse_socket_read_loop(sock, &cmd, sizeof(zfsfuse_cmd_t)))
    {
        switch(cmd.cmd_type) 
        {
            case IOCTL_REQ:
                cr.cr_uid = cmd.uid;
                cr.cr_gid = cmd.gid;
                cr.req = NULL;
                cur_fd = sock; // thread local; used outside this module
                int ioctl_ret = zfsdev_ioctl(dev, cmd.cmd_u.ioctl_req.cmd, (uintptr_t) cmd.cmd_u.ioctl_req.arg, 0, &cr, NULL);
                
                if (zfsfuse_socket_ioctl_write(sock, ioctl_ret) != 0) 
                    goto done;
                break;
            case MOUNT_REQ:
                if(cmd_mount_req(sock, &cmd) != 0)
                    goto done;
                break;
            default:
                abort();
        }
    }

done:
    cur_fd = -1;
    close(sock);
}

typedef struct {
    sem_t pending;              // pending connections (items) in queue
    pthread_mutex_t lock;
    pthread_cond_t handling;    // to efficiently wait for room in the queue

    // shutdown support
    int active;
    int inshutdown;
    pthread_cond_t handled;     // worker is going idle

    ioctl_queue_item_t items[IOCTLQUEUE_MAX_PENDING];
#ifdef DEBUG
    int max_pending;
    int max_active;
#endif
} queue_t;

static queue_t ioctl_queue;

static ioctl_queue_item_t* zfsfuse_ioctl_queue_find(int free/*bool*/)
{
    int i;
    for (i=0;i<IOCTLQUEUE_MAX_PENDING;i++)
        if ((0!=free) == (-1==ioctl_queue.items[i].socket))
            return &ioctl_queue.items[i];

    return 0;
}

static void* zfsfuse_ioctl_queue_worker_thread(void* init)
{
    queue_t* queue = (queue_t*) init;
    ASSERT(queue);
    int must_exit = 0;
    ioctl_queue_item_t job;
    
    while((0 == sem_wait(&queue->pending)) && !must_exit) // await next job pending
    {
        // fetch job and signal queue popped
        VERIFY(0 == pthread_mutex_lock(&queue->lock));

        if (queue->inshutdown)
            must_exit = 1;

        ioctl_queue_item_t* item = zfsfuse_ioctl_queue_find(0); // locate pending job
        if (!item)
        {
            ASSERT(queue->inshutdown);
            VERIFY(0 == sem_post(&queue->pending)); // pass the word
            VERIFY(0 == pthread_mutex_unlock(&queue->lock));
            break;
        }

        // copy local
        memcpy(&job,item,sizeof(ioctl_queue_item_t));

        // feedback
        queue->active++;
        item->socket = -1;
        VERIFY(0 == pthread_cond_signal(&queue->handling));
#ifdef DEBUG
        if (queue->active > queue->max_active)
            queue->max_active = queue->active;
#endif

        VERIFY(0 == pthread_mutex_unlock(&queue->lock));

        // actually process item (outside of lock)
        handle_connection(job.socket);

        VERIFY(0 == pthread_mutex_lock(&queue->lock));
        queue->active--;
        VERIFY(0 == pthread_cond_signal(&queue->handled));
        VERIFY(0 == pthread_mutex_unlock(&queue->lock));
    }

    ASSERT(must_exit); // sem_wait failed?

    return queue; /*unused*/
}

int zfsfuse_ioctl_queue_init(queue_t* queue)
{
    ASSERT(queue);

    pthread_mutexattr_t a;
    if (0 != pthread_mutexattr_init(&a) ||
            0 != pthread_mutexattr_settype(&a, PTHREAD_MUTEX_RECURSIVE_NP) ||
            0 != pthread_mutex_init(&queue->lock, &a))
        return -1;
    if (0 != pthread_cond_init(&queue->handling, NULL))
        return -1;
    if (0 != sem_init(&queue->pending, 0, 0))
        return -1;
    if (0 != pthread_cond_init(&queue->handled, NULL))
        return -1;

    int i;
    for (i=0; i<IOCTLQUEUE_MAX_PENDING; i++)
        queue->items[i].socket = -1; 

    queue->active = 0;
    queue->inshutdown = 0;
#ifdef DEBUG
    queue->max_pending = 0;
    queue->max_active = 0;
#endif

    // send in the drones!
    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    if (stack_size) pthread_attr_setstacksize(&attr,stack_size);
    pthread_t worker;

    for (i=0; i<IOCTLQUEUE_WORKERS; i++)
        if (pthread_create(&worker, &attr, &zfsfuse_ioctl_queue_worker_thread, (void *) queue) != 0) 
            return -1;

    return 0; 
}

int zfsfuse_ioctl_queue_fini(queue_t* queue)
{
    if (!queue)
        return 0;

    if (0 != pthread_mutex_lock(&ioctl_queue.lock))
    {
        syslog(LOG_ERR,"cmd_listener: synchronization broken, cannot wait for running threads");
        return -1;
    }

    ioctl_queue.inshutdown = 1; // signal shutdown to all workers; stop accepting jobs

    struct timeval now;
    struct timespec timeout;
    int retcode = 0;

    // wait a maximum of 10 seconds
    gettimeofday(&now, NULL);
    timeout.tv_sec = now.tv_sec + 10;
    timeout.tv_nsec = now.tv_usec * 1000;

    while (queue->active && retcode != ETIMEDOUT)
    {
        syslog(LOG_WARNING,"cmd_listener: waiting for %i active workers to exit", queue->active);
        retcode = pthread_cond_timedwait(&ioctl_queue.handled, &ioctl_queue.lock, &timeout);
    }
    
    if (retcode == ETIMEDOUT)
        syslog(LOG_WARNING,"cmd_listener: timeout reached, ignoring %i more active", queue->active);

    sem_post(&queue->pending); // tickling a worker with no queued request tells them to commit suicide and pass the word
    pthread_mutex_unlock(&ioctl_queue.lock); // ignore errors at this stage...

    return retcode;
}

/********************************************************************************************************/

static void enqueue_connection(queue_t* queue, int sock) 
{
    ASSERT(queue);
    VERIFY(0 == pthread_mutex_lock(&queue->lock));

    if (queue->inshutdown)
    {
        VERIFY(0 == pthread_mutex_unlock(&queue->lock));
        syslog(LOG_WARNING, "cmd_listener: refusing new connection (shutting down)");
        close(sock);
        return;
    }

    ioctl_queue_item_t* item = zfsfuse_ioctl_queue_find(1); // locate free item

    if (0 == item)
    {
        VERIFY(0 == pthread_cond_wait(&queue->handling, &queue->lock)); // block until any worker has popped it's job
        item = zfsfuse_ioctl_queue_find(1); // locate free item
    }

    // fill queue item
    VERIFY(0 != item);
    item->socket = sock;

#ifdef DEBUG
    int count;
    VERIFY(0 == sem_getvalue(&queue->pending, &count));
    if (count>=queue->max_pending)
        queue->max_pending = count+1;
#endif
    VERIFY(0 == pthread_mutex_unlock(&queue->lock));

    // signal a worker
    VERIFY(0 == sem_post(&queue->pending));
}

void *listener_loop(void *arg)
{
	int *ioctl_fd = (int *) arg;
	struct pollfd fds[MAX_CONNECTIONS];


	fds[0].fd = *ioctl_fd;
	fds[0].events = POLLIN;

	int nfds = 1;

	while(!exit_listener) {
		/* Poll all sockets with a 1 second timeout */
		int ret = poll(fds, nfds, 1000);
		if(ret == 0 || (ret == -1 && errno == EINTR))
			continue;

		if(ret == -1) {
			perror("poll");
			break;
		}

		int oldfds = nfds;

		for(int i = 0; i < oldfds; i++) {
			short rev = fds[i].revents;
			fds[i].revents = 0;

			if(rev == 0)
				continue;

			ASSERT((rev & POLLNVAL) == 0);

			if(!(rev & POLLIN) && !(rev & POLLERR) && !(rev & POLLHUP))
				continue;

			if(i == 0) {
				/* Receive a new connection */

				int sock = accept(*ioctl_fd, NULL, NULL);
				if(sock == -1) {
					perror("accept");
					continue;
				}

				if(nfds == MAX_CONNECTIONS) {
					fprintf(stderr, "Warning: connection limit reached (%i), closing connection.\n", MAX_CONNECTIONS);
					close(sock);
					continue;
				}

				fds[nfds].fd = sock;
				fds[nfds].events = POLLIN;
				fds[nfds].revents = 0;
				nfds++;
			} else {
				int sock = fds[i].fd;
				/* queue request */
                enqueue_connection(&ioctl_queue, fds[i].fd);

                /* socket is now handled by queue and can be removed from list */
                fds[i].fd = -1;
                continue;
			}
		}

		/* Free file descriptors that are -1 */
		int write_ptr = 0;
		for(int read_ptr = 0; read_ptr < nfds; read_ptr++) {
			if(fds[read_ptr].fd == -1)
				continue;
			if(read_ptr != write_ptr)
				fds[write_ptr] = fds[read_ptr];
			write_ptr++;
		}
		nfds = write_ptr;
	}

	return NULL;
}

int cmd_listener_init()
{
    return zfsfuse_ioctl_queue_init(&ioctl_queue);
}

int cmd_listener_fini()
{
#   ifdef DEBUG
    fprintf(stderr, "Peak number of pending requests was %i\n", ioctl_queue.max_pending);
    fprintf(stderr, "Peak number of active workers was %i\n", ioctl_queue.max_active);
#   endif
    return zfsfuse_ioctl_queue_fini(&ioctl_queue);
}

