#include "pthread_setcancelstate_glibc.h"

#include <pthread.h>

int pthread_setcancelstate_glibc(int state, int *oldstate) {
	return pthread_setcancelstate(state, oldstate);
}
