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
#ifndef __WAITING_POLICY_H__
#define __WAITING_POLICY_H__

/**
 * Maximum number of spinning loop iterations before parking a thread.
 * We set this number based on the measured time of a context switch.
 * On our Linux machine, with lmbench, we measured a context switch time
 * of 9 us. Then, the corresponding number of iterations has been
 * determined through rdtscll measurements at the maximum CPU frequency.
 **/
#define SPINNING_THRESHOLD 2700LL

/**
 * waiting_policy_sleep: wait until *var is 0 (and potentially send the thread
 * to sleep)
 *
 * waiting_policy_wake: set *var to 1 (and potentially wake one process
 * sleeping)
 */

#include <linux/futex.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <errno.h>
#include "utils.h"

#define LOCKED 0
#define UNLOCKED 1
/**
 * If some algorithms do not support a generic waiting policy, and a generic
 * waiting policy is specified, raise a compiler error.
 */
#if defined(WAITING_ORIGINAL) &&                                               \
    (defined(WAITING_SPINLOCK) || defined(WAITING_SPINLOCK_ATOMIC) ||          \
     defined(WAITING_SPIN_THEN_PARK))
#error "The lock algorithm used only support its original waiting policy"
#endif

#define __maybe_unused __attribute__((unused))

#if defined(WAITING_PARK) || defined(WAITING_SPIN_THEN_PARK)
static inline int sys_futex(int *uaddr, int op, int val,
                            const struct timespec *timeout, int *uaddr2,
                            int val3) {
    return syscall(SYS_futex, uaddr, op, val, timeout, uaddr2, val3);
}
#endif

#if defined(WAITING_SPINLOCK)
#define WAITING_POLICY "WAITING_SPINLOCK"
static inline void waiting_policy_sleep(volatile int *var) {
    while (*var == LOCKED)
        CPU_PAUSE();
}

static inline void waiting_policy_wake(volatile int *var) {
    *var = UNLOCKED;
}
#elif defined(WAITING_SPINLOCK_ATOMIC)
#define WAITING_POLICY "WAITING_SPINLOCK_ATOMIC"
static inline void waiting_policy_sleep(volatile int *var) {
    while (__sync_val_compare_and_swap(var, UNLOCKED, LOCKED) == LOCKED)
        CPU_PAUSE();
}

static inline void waiting_policy_wake(volatile int *var) {
    int old = __sync_val_compare_and_swap(var, LOCKED, UNLOCKED);
    assert(old == 0);
}
#elif defined(WAITING_SPIN_THEN_PARK)
#define WAITING_POLICY "WAITING_SPIN_THEN_PARK"
static inline void waiting_policy_sleep(volatile int *var) {
    // First spin with a given threshold.
    unsigned long long i = 0;
    while (i < SPINNING_THRESHOLD && *var != UNLOCKED) {
        i++;
        CPU_PAUSE();
    }

    if (*var == UNLOCKED)
        return;

    int ret = 0;
    while ((ret = sys_futex((int *)var, FUTEX_WAIT_PRIVATE, LOCKED, NULL, 0,
                            0)) != 0) {
        if (ret == -1 && errno != EINTR) {
            /**
             * futex returns EAGAIN if *var is not 0 anymore.
             * This can happen when the value of *var is changed by another
             *thread after the spinning loop.
             * Note: FUTEX_WAIT_PRIVATE acts like an atomic operation.
             **/
            if (errno == EAGAIN) {
                DEBUG("[-1] Race\n");
                break;
            }
            perror("Unable to futex wait");
            exit(-1);
        }
    }

    /**
     * *var is not always 1 immediately when the thread wakes up
     * (but eventually it is).
     * Maybe related to memory reordering?
     **/
    while (*var != UNLOCKED)
        CPU_PAUSE();
}

static inline void waiting_policy_wake(volatile int *var) {
    *var    = 1;
    int ret = sys_futex((int *)var, FUTEX_WAKE_PRIVATE, UNLOCKED, NULL, 0, 0);
    if (ret == -1) {
        perror("Unable to futex wake");
        exit(-1);
    }
}
#elif defined(WAITING_PARK)
#define WAITING_POLICY "WAITING_PARK"
static inline void waiting_policy_sleep(volatile int *var) {
    int ret = 0;
    while ((ret = sys_futex((int *)var, FUTEX_WAIT_PRIVATE, LOCKED, NULL, 0,
                            0)) != 0) {
        if (ret == -1 && errno != EINTR) {
            /**
             * futex returns EAGAIN if *var is not 0 anymore.
             * This can happen when the value of *var is changed by another
             * thread after the spinning loop.
             * Note: FUTEX_WAIT_PRIVATE acts like an atomic operation.
             **/
            if (errno == EAGAIN) {
                break;
            }
            perror("Unable to futex wait");
            exit(-1);
        }
    }

    /**
     * *var is not always 1 immediately when the thread wake-up
     * (but eventually it is).
     * Maybe related to memory reordering?
     **/
    while (*var != UNLOCKED)
        CPU_PAUSE();
}

static inline void waiting_policy_wake(volatile int *var) {
    *var    = 1;
    int ret = sys_futex((int *)var, FUTEX_WAKE_PRIVATE, UNLOCKED, NULL, 0, 0);
    if (ret == -1) {
        perror("Unable to futex wake");
        exit(-1);
    }
}
#elif defined(WAITING_ORIGINAL)
#define WAITING_POLICY "WAITING_ORIGINAL"
#else
#error                                                                         \
    "No waiting policy defined (WAITING_SPINLOCK | WAITING_SPINLOCK_ATOMIC | WAITING_SPIN_THEN_PARK | WAITING_PARK | WAITING_ORIGINAL)"
#endif

#endif // __WAITING_POLICY_H__
