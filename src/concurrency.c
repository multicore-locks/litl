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
 *
 *
 * Compute the max, the mean and the stdev regarding concurrency for each lock.
 * The concurrency level is the number of concurrent threads waiting for the
 * same lock
 *
 * Simply compute a running mean of the number of thread trying to acquire a
 * lock at the same time.
 * This is not so efficient because we need one atomic f&a before grabbing the
 * lock and one after.
 * The result is printed to stderr when a lock is destroyed.
 */
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <sys/mman.h>
#include <pthread.h>
#include <assert.h>
#include <concurrency.h>

#include "waiting_policy.h"
#include "interpose.h"
#include "utils.h"

extern __thread unsigned int cur_thread_id;

concurrency_mutex_t *concurrency_mutex_create(const pthread_mutexattr_t *attr) {
    concurrency_mutex_t *impl =
        (concurrency_mutex_t *)alloc_cache_align(sizeof(concurrency_mutex_t));
    memset(impl, 0, sizeof *impl);

    impl->count   = 0;
    impl->mean    = 0;
    impl->max     = 0;
    impl->current = 0;

    REAL(pthread_mutex_init)(&impl->lock, attr);

    return impl;
}

int concurrency_mutex_lock(concurrency_mutex_t *impl,
                           concurrency_context_t *UNUSED(me)) {
    uint64_t my_count = __sync_fetch_and_add(&impl->current, 1) + 1;

    int ret = REAL(pthread_mutex_lock)(&impl->lock);

    // Update max
    if (my_count > impl->max) {
        impl->max = my_count;
    }

    // Mean
    impl->count++;
    impl->mean -= impl->mean / (double)impl->count;
    impl->mean += (double)my_count / (double)impl->count;

    __sync_fetch_and_sub(&impl->current, 1);

    return ret;
}

int concurrency_mutex_trylock(concurrency_mutex_t *impl,
                              concurrency_context_t *UNUSED(me)) {
    uint64_t my_count = __sync_fetch_and_add(&impl->current, 1) + 1;

    int ret = REAL(pthread_mutex_trylock)(&impl->lock);

    // Update max
    if (my_count > impl->max) {
        impl->max = my_count;
    }

    // Mean
    impl->count++;
    impl->mean -= impl->mean / (double)impl->count;
    impl->mean += (double)my_count / (double)impl->count;

    __sync_fetch_and_sub(&impl->current, 1);

    return ret;
}

void concurrency_mutex_unlock(concurrency_mutex_t *impl,
                              concurrency_context_t *UNUSED(me)) {
    REAL(pthread_mutex_unlock)(&impl->lock);
}

int concurrency_mutex_destroy(concurrency_mutex_t *lock) {
    REAL(pthread_mutex_destroy)(&lock->lock);

    fprintf(stderr, "\n%p,%lu,%f\n", lock, lock->max, lock->mean);

    free(lock);
    lock = NULL;

    return 0;
}

int concurrency_cond_init(concurrency_cond_t *cond,
                          const pthread_condattr_t *attr) {
    return REAL(pthread_cond_init)(cond, attr);
}

int concurrency_cond_timedwait(concurrency_cond_t *cond,
                               concurrency_mutex_t *lock,
                               concurrency_context_t *UNUSED(me),
                               const struct timespec *ts) {
    return REAL(pthread_cond_timedwait)(cond, &lock->lock, ts);
}

int concurrency_cond_wait(concurrency_cond_t *cond, concurrency_mutex_t *lock,
                          concurrency_context_t *UNUSED(me)) {
    return REAL(pthread_cond_wait)(cond, &lock->lock);
}

int concurrency_cond_signal(concurrency_cond_t *cond) {
    return REAL(pthread_cond_signal)(cond);
}

int concurrency_cond_broadcast(concurrency_cond_t *cond) {
    return REAL(pthread_cond_broadcast)(cond);
}

int concurrency_cond_destroy(concurrency_cond_t *cond) {
    return REAL(pthread_cond_destroy)(cond);
}

void concurrency_thread_start(void) {
}

void concurrency_thread_exit(void) {
}

void concurrency_application_init(void) {
}

void concurrency_application_exit(void) {
}
void concurrency_init_context(lock_mutex_t *UNUSED(impl),
                              lock_context_t *UNUSED(context),
                              int UNUSED(number)) {
}
