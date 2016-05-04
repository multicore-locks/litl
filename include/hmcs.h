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
#ifndef __HMCS_H__
#define __HMCS_H__

#include "padding.h"
#define LOCK_ALGORITHM "HMCS"
#define NEED_CONTEXT 1
#define SUPPORT_WAITING 0

// How many local locking before release the global lock (default number in the
// paper)
#define RELEASE_THRESHOLD 100 // Same as cohort for comparison

struct hmcs_hnode;
typedef struct hmcs_qnode {
    struct hmcs_qnode *volatile next;
    char __pad[pad_to_cache_line(sizeof(struct hmcs_qnode *))];
    volatile uint64_t status __attribute__((aligned(L_CACHE_LINE_SIZE)));
    char __pad2[pad_to_cache_line(sizeof(uint64_t))];
    struct hmcs_hnode *last_local __attribute__((aligned(L_CACHE_LINE_SIZE)));
} hmcs_qnode_t __attribute__((aligned(L_CACHE_LINE_SIZE)));

typedef struct hmcs_hnode {
    struct hmcs_hnode *parent __attribute__((aligned(L_CACHE_LINE_SIZE)));
    struct hmcs_qnode *volatile tail;
    char __pad[pad_to_cache_line(sizeof(struct hmcs_qnode *) +
                                 sizeof(struct hmcs_hnode *))];
    hmcs_qnode_t node;
} hmcs_hnode_t __attribute__((aligned(L_CACHE_LINE_SIZE)));

typedef struct hmcs_mutex {
#if COND_VAR
    pthread_mutex_t posix_lock;
    char __pad[pad_to_cache_line(sizeof(pthread_mutex_t))];
#endif
    hmcs_hnode_t global;
    hmcs_hnode_t local[NUMA_NODES];
} hmcs_mutex_t __attribute__((aligned(L_CACHE_LINE_SIZE)));

typedef pthread_cond_t hmcs_cond_t;
hmcs_mutex_t *hmcs_mutex_create(const pthread_mutexattr_t *attr);
int hmcs_mutex_lock(hmcs_mutex_t *impl, hmcs_qnode_t *me);
int hmcs_mutex_trylock(hmcs_mutex_t *impl, hmcs_qnode_t *me);
void hmcs_mutex_unlock(hmcs_mutex_t *impl, hmcs_qnode_t *me);
int hmcs_mutex_destroy(hmcs_mutex_t *lock);
int hmcs_cond_init(hmcs_cond_t *cond, const pthread_condattr_t *attr);
int hmcs_cond_timedwait(hmcs_cond_t *cond, hmcs_mutex_t *lock, hmcs_qnode_t *me,
                        const struct timespec *ts);
int hmcs_cond_wait(hmcs_cond_t *cond, hmcs_mutex_t *lock, hmcs_qnode_t *me);
int hmcs_cond_signal(hmcs_cond_t *cond);
int hmcs_cond_broadcast(hmcs_cond_t *cond);
int hmcs_cond_destroy(hmcs_cond_t *cond);
void hmcs_thread_start(void);
void hmcs_thread_exit(void);
void hmcs_application_init(void);
void hmcs_application_exit(void);
void hmcs_init_context(hmcs_mutex_t *impl, hmcs_qnode_t *context, int number);

typedef hmcs_mutex_t lock_mutex_t;
typedef hmcs_qnode_t lock_context_t;
typedef hmcs_cond_t lock_cond_t;

#define lock_mutex_create hmcs_mutex_create
#define lock_mutex_lock hmcs_mutex_lock
#define lock_mutex_trylock hmcs_mutex_trylock
#define lock_mutex_unlock hmcs_mutex_unlock
#define lock_mutex_destroy hmcs_mutex_destroy
#define lock_cond_init hmcs_cond_init
#define lock_cond_timedwait hmcs_cond_timedwait
#define lock_cond_wait hmcs_cond_wait
#define lock_cond_signal hmcs_cond_signal
#define lock_cond_broadcast hmcs_cond_broadcast
#define lock_cond_destroy hmcs_cond_destroy
#define lock_thread_start hmcs_thread_start
#define lock_thread_exit hmcs_thread_exit
#define lock_application_init hmcs_application_init
#define lock_application_exit hmcs_application_exit
#define lock_init_context hmcs_init_context

#endif // __HMCS_H__
