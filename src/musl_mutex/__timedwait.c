#include "pthread_musl.h"
#include "errno.h"
#include "futex.h"
#include "syscall.h"
#include "pthread_impl.h"
#include <time.h>

#include "pthread_setcancelstate_glibc.h" // pthread_setcancelstate
#include <stdio.h>

#define IS32BIT(x) !((x)+0x80000000ULL>>32)
#define CLAMP(x) (int)(IS32BIT(x) ? (x) : 0x7fffffffU+((0ULL+(x))>>63))

static int __futex4_cp(volatile void *addr, int op, int val, const struct timespec *to)
{
	// fprintf(stderr, "Error __futex4_cp.\n");
	int r;
#ifdef SYS_futex_time64
	time_t s = to ? to->tv_sec : 0;
	long ns = to ? to->tv_nsec : 0;
	r = -ENOSYS;
	if (SYS_futex == SYS_futex_time64 || !IS32BIT(s))
		r = __syscall_cp(SYS_futex_time64, addr, op, val,
			to ? ((long long[]){s, ns}) : 0);
	if (SYS_futex == SYS_futex_time64 || r!=-ENOSYS) return r;
	to = to ? (void *)(long[]){CLAMP(s), ns} : 0;
#endif
	// fprintf(stderr, "Error __futex4_cp 1.\n");
	r = __syscall_cp(SYS_futex, addr, op, val, to);
	// fprintf(stderr, "Error __futex4_cp 2.\n");
	if (r != -ENOSYS) return r;
	// fprintf(stderr, "Error __futex4_cp 3.\n");
	return __syscall_cp(SYS_futex, addr, op & ~FUTEX_PRIVATE, val, to);
}

static volatile int __eintr_valid_flag = 0;

int __timedwait_cp(volatile int *addr, int val,
	clockid_t clk, const struct timespec *at, int priv)
{
	// fprintf(stderr, "Error __timedwait_cp.\n");
	int r;
	struct timespec to, *top=0;

	if (priv) priv = FUTEX_PRIVATE;

	if (at) {
		if (at->tv_nsec >= 1000000000UL) return EINVAL;
		if (clock_gettime(clk, &to)) return EINVAL;
		// clock_gettime(clk, &to);
		to.tv_sec = at->tv_sec - to.tv_sec;
		if ((to.tv_nsec = at->tv_nsec - to.tv_nsec) < 0) {
			to.tv_sec--;
			to.tv_nsec += 1000000000;
		}
		if (to.tv_sec < 0) return ETIMEDOUT;
		top = &to;
	}
	// fprintf(stderr, "Error __timedwait_cp 1.\n");
	r = -__futex4_cp(addr, FUTEX_WAIT|priv, val, top);
	// fprintf(stderr, "Error __timedwait_cp 2.\n");
	if (r != EINTR && r != ETIMEDOUT && r != ECANCELED) r = 0;
	/* Mitigate bug in old kernels wrongly reporting EINTR for non-
	 * interrupting (SA_RESTART) signal handlers. This is only practical
	 * when NO interrupting signal handlers have been installed, and
	 * works by sigaction tracking whether that's the case. */
	if (r == EINTR && !__eintr_valid_flag) r = 0;
	// fprintf(stderr, "Error __timedwait_cp return.\n");
	return r;
}


int __timedwait(volatile int *addr, int val, clockid_t clk, const struct timespec *at, int priv)
{
	// fprintf(stderr, "Error __timedwait.\n");
	int cs, r;
	pthread_setcancelstate_glibc(PTHREAD_CANCEL_DISABLE, &cs);
	// fprintf(stderr, "Error __timedwait 1.\n");
	r = __timedwait_cp(addr, val, clk, at, priv);
	// fprintf(stderr, "Error __timedwait 2.\n");
	pthread_setcancelstate_glibc(cs, 0);
	// fprintf(stderr, "Error __timedwait return.\n");
	return r;
}
