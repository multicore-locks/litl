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
#ifndef __MALTHUSIAN_H__
#define __MALTHUSIAN_H__

#include "padding.h"
#define LOCK_ALGORITHM "MALTHUSIAN"
#define NEED_CONTEXT 1
#define SUPPORT_WAITING 1

// This is the number of thread to let take the lock before taking the inactive
// list back to the active list
#define UNLOCK_COUNT_THRESHOLD 1024 //!\\ Must be a power of 2!

typedef struct malthusian_node {
    volatile int spin __attribute__((aligned(L_CACHE_LINE_SIZE)));
    char __pad[pad_to_cache_line(sizeof(int))];
    struct malthusian_node *volatile next;
    struct malthusian_node *volatile prev;
} malthusian_node_t __attribute__((aligned(L_CACHE_LINE_SIZE)));

typedef struct malthusian_mutex {
    struct malthusian_node *volatile tail
        __attribute__((aligned(L_CACHE_LINE_SIZE)));
    char __pad[pad_to_cache_line(sizeof(struct malthusian_node *))];
    struct malthusian_node *volatile passive_set_head;
    struct malthusian_node *volatile passive_set_tail;
#if COND_VAR
    pthread_mutex_t posix_lock;
#endif
} malthusian_mutex_t __attribute__((aligned(L_CACHE_LINE_SIZE)));

typedef pthread_cond_t malthusian_cond_t;
malthusian_mutex_t *malthusian_mutex_create(const pthread_mutexattr_t *attr);
int malthusian_mutex_lock(malthusian_mutex_t *impl, malthusian_node_t *me);
int malthusian_mutex_trylock(malthusian_mutex_t *impl, malthusian_node_t *me);
void malthusian_mutex_unlock(malthusian_mutex_t *impl, malthusian_node_t *me);
int malthusian_mutex_destroy(malthusian_mutex_t *lock);
int malthusian_cond_init(malthusian_cond_t *cond,
                         const pthread_condattr_t *attr);
int malthusian_cond_timedwait(malthusian_cond_t *cond, malthusian_mutex_t *lock,
                              malthusian_node_t *me, const struct timespec *ts);
int malthusian_cond_wait(malthusian_cond_t *cond, malthusian_mutex_t *lock,
                         malthusian_node_t *me);
int malthusian_cond_signal(malthusian_cond_t *cond);
int malthusian_cond_broadcast(malthusian_cond_t *cond);
int malthusian_cond_destroy(malthusian_cond_t *cond);
void malthusian_thread_start(void);
void malthusian_thread_exit(void);
void malthusian_application_init(void);
void malthusian_application_exit(void);
void malthusian_init_context(malthusian_mutex_t *impl,
                             malthusian_node_t *context, int number);

typedef malthusian_mutex_t lock_mutex_t;
typedef malthusian_node_t lock_context_t;
typedef malthusian_cond_t lock_cond_t;

#define lock_mutex_create malthusian_mutex_create
#define lock_mutex_lock malthusian_mutex_lock
#define lock_mutex_trylock malthusian_mutex_trylock
#define lock_mutex_unlock malthusian_mutex_unlock
#define lock_mutex_destroy malthusian_mutex_destroy
#define lock_cond_init malthusian_cond_init
#define lock_cond_timedwait malthusian_cond_timedwait
#define lock_cond_wait malthusian_cond_wait
#define lock_cond_signal malthusian_cond_signal
#define lock_cond_broadcast malthusian_cond_broadcast
#define lock_cond_destroy malthusian_cond_destroy
#define lock_thread_start malthusian_thread_start
#define lock_thread_exit malthusian_thread_exit
#define lock_application_init malthusian_application_init
#define lock_application_exit malthusian_application_exit
#define lock_init_context malthusian_init_context

#endif // __MALTHUSIAN_H__
