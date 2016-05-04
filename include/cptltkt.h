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
#ifndef __CPT_H__
#define __CPT_H__

#include <stdint.h>
#include "padding.h"
#define LOCK_ALGORITHM "C-PTL-TKT"
#define NEED_CONTEXT 0
#define SUPPORT_WAITING 0

// Number of slots for the partitioned ticket locks
// Note from the paper: For performance, slots should be >= # of NUMA nodes
#define PTL_SLOTS NUMA_NODES
// How many local locking before release the global lock (default number in the
// paper)
#define BATCH_COUNT 100

typedef struct ticket_lock {
    // Use union for compare and swap
    union {
        volatile uint64_t u;
        struct {
            volatile uint32_t grant;
            volatile uint32_t request;
        } s;
    } u __attribute__((aligned(L_CACHE_LINE_SIZE)));
    char __pad[pad_to_cache_line(sizeof(uint32_t) + sizeof(uint32_t))];
    volatile uint32_t top_grant;
    int32_t batch_count;

} tkt_lock_t __attribute__((aligned(L_CACHE_LINE_SIZE)));

struct grant_slot {
    volatile uint32_t grant;
    char __pad[pad_to_cache_line(sizeof(uint32_t))];
} __attribute__((aligned(L_CACHE_LINE_SIZE)));

typedef struct partitioned_ticket_lock {
    volatile uint32_t request;
    volatile uint32_t owner_ticket;
    char __pad[pad_to_cache_line(sizeof(uint32_t) + sizeof(uint32_t))];
    // Each slot is cache align, the purpose of PLT is avoid cache line
    // transfers
    struct grant_slot grants[PTL_SLOTS];
} ptl_lock_t __attribute__((aligned(L_CACHE_LINE_SIZE)));

typedef struct c_ptl_tkt {
    ptl_lock_t top_lock;
    tkt_lock_t local_locks[NUMA_NODES];
#if COND_VAR
    pthread_mutex_t posix_lock;
#endif
    tkt_lock_t *volatile top_home;
} cpt_mutex_t __attribute__((aligned(L_CACHE_LINE_SIZE)));

typedef pthread_cond_t cpt_cond_t;
typedef void *cpt_node_t;

cpt_mutex_t *cpt_mutex_create(const pthread_mutexattr_t *attr);
int cpt_mutex_lock(cpt_mutex_t *impl, cpt_node_t *me);
int cpt_mutex_trylock(cpt_mutex_t *impl, cpt_node_t *me);
void cpt_mutex_unlock(cpt_mutex_t *impl, cpt_node_t *me);
int cpt_mutex_destroy(cpt_mutex_t *lock);
int cpt_cond_init(cpt_cond_t *cond, const pthread_condattr_t *attr);
int cpt_cond_timedwait(cpt_cond_t *cond, cpt_mutex_t *lock, cpt_node_t *me,
                       const struct timespec *ts);
int cpt_cond_wait(cpt_cond_t *cond, cpt_mutex_t *lock, cpt_node_t *me);
int cpt_cond_signal(cpt_cond_t *cond);
int cpt_cond_broadcast(cpt_cond_t *cond);
int cpt_cond_destroy(cpt_cond_t *cond);
void cpt_thread_start(void);
void cpt_thread_exit(void);
void cpt_application_init(void);
void cpt_application_exit(void);

typedef cpt_mutex_t lock_mutex_t;
typedef void *lock_context_t;
typedef cpt_cond_t lock_cond_t;

#define lock_mutex_create cpt_mutex_create
#define lock_mutex_lock cpt_mutex_lock
#define lock_mutex_trylock cpt_mutex_trylock
#define lock_mutex_unlock cpt_mutex_unlock
#define lock_mutex_destroy cpt_mutex_destroy
#define lock_cond_init cpt_cond_init
#define lock_cond_timedwait cpt_cond_timedwait
#define lock_cond_wait cpt_cond_wait
#define lock_cond_signal cpt_cond_signal
#define lock_cond_broadcast cpt_cond_broadcast
#define lock_cond_destroy cpt_cond_destroy
#define lock_thread_start cpt_thread_start
#define lock_thread_exit cpt_thread_exit
#define lock_application_init cpt_application_init
#define lock_application_exit cpt_application_exit
#define lock_init_context cpt_init_context

#endif // __CPT_H__
