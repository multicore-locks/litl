/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2016 Hugo Guiroux <hugo.guiroux at gmail dot com>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of his software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */
#ifndef __CTKT_H__
#define __CTKT_H__

#include <stdint.h>
#include <topology.h>

#include "padding.h"
#define LOCK_ALGORITHM "C-TKT-TKT"
#define NEED_CONTEXT 0
#define SUPPORT_WAITING 0
// How many local locking before release the global lock (default number in the
// paper)
#define BATCH_COUNT 100

// Use union for compare and swap
typedef union __ticket_lock {
    volatile uint64_t u;
    struct {
        volatile uint32_t grant;
        volatile uint32_t request;
    } s;
} ticket_lock_t __attribute__((aligned(L_CACHE_LINE_SIZE)));

typedef struct local_ticket_lock {
    ticket_lock_t u;
    volatile uint32_t top_grant;
    int32_t batch_count;
    char __pad[pad_to_cache_line(sizeof(ticket_lock_t) + sizeof(uint32_t) +
                                 sizeof(int32_t))];

} local_tkt_lock_t __attribute__((aligned(L_CACHE_LINE_SIZE)));

typedef struct global_ticket_lock {
    ticket_lock_t u;
    char __pad[pad_to_cache_line(sizeof(ticket_lock_t))];
} global_tkt_lock_t __attribute__((aligned(L_CACHE_LINE_SIZE)));

typedef struct c_ptl_tkt {
    global_tkt_lock_t top_lock;
    local_tkt_lock_t local_locks[NUMA_NODES];
#if COND_VAR
    pthread_mutex_t posix_lock;
#endif
    local_tkt_lock_t *volatile top_home;
} ctkt_mutex_t __attribute__((aligned(L_CACHE_LINE_SIZE)));

typedef pthread_cond_t ctkt_cond_t;
typedef void *ctkt_node_t;

ctkt_mutex_t *ctkt_mutex_create(const pthread_mutexattr_t *attr);
int ctkt_mutex_lock(ctkt_mutex_t *impl, ctkt_node_t *me);
int ctkt_mutex_trylock(ctkt_mutex_t *impl, ctkt_node_t *me);
void ctkt_mutex_unlock(ctkt_mutex_t *impl, ctkt_node_t *me);
int ctkt_mutex_destroy(ctkt_mutex_t *lock);
int ctkt_cond_init(ctkt_cond_t *cond, const pthread_condattr_t *attr);
int ctkt_cond_timedwait(ctkt_cond_t *cond, ctkt_mutex_t *lock, ctkt_node_t *me,
                        const struct timespec *ts);
int ctkt_cond_wait(ctkt_cond_t *cond, ctkt_mutex_t *lock, ctkt_node_t *me);
int ctkt_cond_signal(ctkt_cond_t *cond);
int ctkt_cond_broadcast(ctkt_cond_t *cond);
int ctkt_cond_destroy(ctkt_cond_t *cond);
void ctkt_thread_start(void);
void ctkt_thread_exit(void);
void ctkt_application_init(void);
void ctkt_application_exit(void);

typedef ctkt_mutex_t lock_mutex_t;
typedef void *lock_context_t;
typedef ctkt_cond_t lock_cond_t;

#define lock_mutex_create ctkt_mutex_create
#define lock_mutex_lock ctkt_mutex_lock
#define lock_mutex_trylock ctkt_mutex_trylock
#define lock_mutex_unlock ctkt_mutex_unlock
#define lock_mutex_destroy ctkt_mutex_destroy
#define lock_cond_init ctkt_cond_init
#define lock_cond_timedwait ctkt_cond_timedwait
#define lock_cond_wait ctkt_cond_wait
#define lock_cond_signal ctkt_cond_signal
#define lock_cond_broadcast ctkt_cond_broadcast
#define lock_cond_destroy ctkt_cond_destroy
#define lock_thread_start ctkt_thread_start
#define lock_thread_exit ctkt_thread_exit
#define lock_application_init ctkt_application_init
#define lock_application_exit ctkt_application_exit
#define lock_init_context ctkt_init_context

#endif // __CTKT_H__
