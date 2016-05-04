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
 * Just a proxy to pthread_mutex, to evaluate overhead of library
 * interposition.
 */
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <sys/mman.h>
#include <pthread.h>
#include <assert.h>
#include <empty.h>
#include <linux/futex.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <fcntl.h>

#include "interpose.h"
#include "utils.h"

// Posix functions
int empty_mutex_lock(empty_mutex_t *impl, empty_context_t *UNUSED(me)) {
    return REAL(pthread_mutex_lock)(impl);
}

int empty_mutex_trylock(empty_mutex_t *impl, empty_context_t *UNUSED(me)) {
    return REAL(pthread_mutex_trylock)(impl);
}
void empty_mutex_unlock(empty_mutex_t *impl, empty_context_t *UNUSED(me)) {
    REAL(pthread_mutex_unlock)(impl);
}

int empty_mutex_destroy(empty_mutex_t *lock) {
    return REAL(pthread_mutex_destroy)(lock);
}

int empty_cond_init(empty_cond_t *cond, const pthread_condattr_t *attr) {
    return REAL(pthread_cond_init)(cond, attr);
}

int empty_cond_timedwait(empty_cond_t *cond, empty_mutex_t *lock,
                         empty_context_t *me, const struct timespec *ts) {
    return REAL(pthread_cond_timedwait)(cond, lock, ts);
}

int empty_cond_wait(empty_cond_t *cond, empty_mutex_t *lock,
                    empty_context_t *UNUSED(me)) {
    return REAL(pthread_cond_wait)(cond, lock);
}

int empty_cond_signal(empty_cond_t *cond) {
    return REAL(pthread_cond_signal)(cond);
}

int empty_cond_broadcast(empty_cond_t *cond) {
    return REAL(pthread_cond_broadcast)(cond);
}

int empty_cond_destroy(empty_cond_t *cond) {
    return REAL(pthread_cond_destroy)(cond);
}

void empty_thread_start(void) {
}

void empty_thread_exit(void) {
}

void empty_application_init(void) {
}

void empty_application_exit(void) {
}

void empty_init_context(lock_mutex_t *UNUSED(impl),
                        lock_context_t *UNUSED(context), int UNUSED(number)) {
}

empty_mutex_t *empty_mutex_create(const pthread_mutexattr_t *attr) {
    assert(0);
    return NULL;
}

// Define library function ptr
// lock_mutex_unlock_fct     lock_mutex_unlock     = empty_mutex_unlock;
