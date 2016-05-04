/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2016 Hugo Guiroux <hugo.guiroux at gmail dot com>
 *               2013 Tudor David
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
 * T. E. Anderson. 1990.
 * The Performance of Spin Lock Alternatives for Shared-Memory Multiprocessors.
 * IEEE Trans. Parallel Distrib. Syst. 1, 1 (January 1990).
 *
 * The implementation is largely taken from libslock.
 * https://github.com/tudordavid/libslock/blob/master/src/alock.c
 *
 * Lock design summary:
 * - There is one slot for each thread in a fixed-size array
 * - When a thread wants to lock, it get its slot number via an atomic increment
 * - The thread spins (if needed) on the memory address of its slot
 * - On unlock, the thread wakes the thread of the slot next to its own
 */
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <sys/mman.h>
#include <pthread.h>
#include <assert.h>
#include <alockepfl.h>

#include "waiting_policy.h"
#include "interpose.h"
#include "utils.h"

extern __thread unsigned int cur_thread_id;

alockepfl_mutex_t *alockepfl_mutex_create(const pthread_mutexattr_t *attr) {
    alockepfl_mutex_t *impl =
        (alockepfl_mutex_t *)alloc_cache_align(sizeof(alockepfl_mutex_t));

    // The first thread will be unlocked
    impl->flags[0].flag = UNLOCKED;

    // Init the counter
    impl->tail = 0;

#if COND_VAR
    REAL(pthread_mutex_init)(&impl->posix_lock, /*&errattr */ attr);
    DEBUG("Mutex init lock=%p posix_lock=%p\n", impl, &impl->posix_lock);
#endif

    return impl;
}

static int __alockepfl_mutex_lock(alockepfl_mutex_t *impl,
                                  alockepfl_context_t *me) {
    PREFETCHW(me);
    PREFETCHW(impl);

    // Ask for a new slot
    uint32_t slot =
        __sync_fetch_and_add(&impl->tail, 1) % MAX_THREADS_SUPPORTED;
    me->my_index = slot;

    volatile uint16_t *flag = &impl->flags[slot].flag;
    PREFETCHW(flag);

    // Wait while the previous thread (slot - 1) wakes us
    while (*flag == LOCKED) {
        CPU_PAUSE();
        pause_rep(REP_VAL);
        PREFETCHW(flag);
    }

    return 0;
}

int alockepfl_mutex_lock(alockepfl_mutex_t *impl, alockepfl_context_t *me) {
    int ret = __alockepfl_mutex_lock(impl, me);
    assert(ret == 0);
#if COND_VAR
    if (ret == 0) {
        DEBUG_PTHREAD("[%d] Lock posix=%p\n", cur_thread_id, &impl->posix_lock);
        assert(REAL(pthread_mutex_lock)(&impl->posix_lock) == 0);
    }
#endif
    DEBUG("[%d] Lock acquired posix=%p\n", cur_thread_id, &impl->posix_lock);
    return ret;
}

int alockepfl_mutex_trylock(alockepfl_mutex_t *impl, alockepfl_context_t *me) {
    uint32_t tail = impl->tail;

    // The trylock first checks if the lock is unlocked, then does a cmp&swap to
    // get a slot
    if (impl->flags[tail % MAX_THREADS_SUPPORTED].flag == UNLOCKED) {
        if (__sync_val_compare_and_swap(&(impl->tail), tail, tail + 1) ==
            tail) {
            me->my_index = tail % MAX_THREADS_SUPPORTED;

#if COND_VAR
            int ret = 0;
            while ((ret = REAL(pthread_mutex_trylock)(&impl->posix_lock)) ==
                   EBUSY)
                ;
#endif

            return 0;
        }
    }

    return EBUSY;
}

static void __alockepfl_mutex_unlock(alockepfl_mutex_t *impl,
                                     alockepfl_context_t *me) {
    PREFETCHW(me);
    PREFETCHW(impl);

    uint32_t slot = me->my_index;
    // Reset our slot for the next thread that will have it
    impl->flags[slot].flag = LOCKED;
    COMPILER_BARRIER();
    // Wake up the next thread
    impl->flags[(slot + 1) % MAX_THREADS_SUPPORTED].flag = UNLOCKED;
}

void alockepfl_mutex_unlock(alockepfl_mutex_t *impl, alockepfl_context_t *me) {
#if COND_VAR
    DEBUG_PTHREAD("[%d] Unlock posix=%p\n", cur_thread_id, &impl->posix_lock);
    assert(REAL(pthread_mutex_unlock)(&impl->posix_lock) == 0);
#endif
    __alockepfl_mutex_unlock(impl, me);
}

int alockepfl_mutex_destroy(alockepfl_mutex_t *lock) {
#if COND_VAR
    REAL(pthread_mutex_destroy)(&lock->posix_lock);
#endif
    free(lock);
    lock = NULL;

    return 0;
}

int alockepfl_cond_init(alockepfl_cond_t *cond,
                        const pthread_condattr_t *attr) {
#if COND_VAR
    return REAL(pthread_cond_init)(cond, attr);
#else
    fprintf(stderr, "Error cond_var not supported.");
    assert(0);
#endif
}

int alockepfl_cond_timedwait(alockepfl_cond_t *cond, alockepfl_mutex_t *lock,
                             alockepfl_context_t *me,
                             const struct timespec *ts) {
    int res;
#if COND_VAR

    __alockepfl_mutex_unlock(lock, me);
    DEBUG("[%d] Sleep cond=%p lock=%p posix_lock=%p\n", cur_thread_id, cond,
          lock, &(lock->posix_lock));
    DEBUG_PTHREAD("[%d] Cond posix = %p lock = %p\n", cur_thread_id, cond,
                  &lock->posix_lock);

    if (ts)
        res = REAL(pthread_cond_timedwait)(cond, &lock->posix_lock, ts);
    else
        res = REAL(pthread_cond_wait)(cond, &lock->posix_lock);

    if (res != 0 && res != ETIMEDOUT) {
        fprintf(stderr, "Error on cond_{timed,}wait %d\n", res);
        assert(0);
    }

    int ret = 0;
    if ((ret = REAL(pthread_mutex_unlock)(&lock->posix_lock)) != 0) {
        fprintf(stderr, "Error on mutex_unlock %d\n", ret == EPERM);
        assert(0);
    }

    alockepfl_mutex_lock(lock, me);
#else
    fprintf(stderr, "Error cond_var not supported.");
    assert(0);
#endif
    return res;
}

int alockepfl_cond_wait(alockepfl_cond_t *cond, alockepfl_mutex_t *lock,
                        alockepfl_context_t *me) {
    return alockepfl_cond_timedwait(cond, lock, me, 0);
}

int alockepfl_cond_signal(alockepfl_cond_t *cond) {
#if COND_VAR
    return REAL(pthread_cond_signal)(cond);
#else
    fprintf(stderr, "Error cond_var not supported.");
    assert(0);
#endif
}

int alockepfl_cond_broadcast(alockepfl_cond_t *cond) {
#if COND_VAR
    DEBUG("[%d] Broadcast cond=%p\n", cur_thread_id, cond);
    return REAL(pthread_cond_broadcast)(cond);
#else
    fprintf(stderr, "Error cond_var not supported.");
    assert(0);
#endif
}

int alockepfl_cond_destroy(alockepfl_cond_t *cond) {
#if COND_VAR
    return REAL(pthread_cond_destroy)(cond);
#else
    fprintf(stderr, "Error cond_var not supported.");
    assert(0);
#endif
}

void alockepfl_thread_start(void) {
}

void alockepfl_thread_exit(void) {
}

void alockepfl_application_init(void) {
}

void alockepfl_application_exit(void) {
}

void alockepfl_init_context(lock_mutex_t *impl, lock_context_t *context,
                            int number) {
    int i;
    for (i = 0; i < number; i++) {
        context[i].my_index = LOCKED;
    }
}
