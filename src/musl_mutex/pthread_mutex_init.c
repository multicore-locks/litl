#include "pthread_impl.h"
#include <stdio.h>
#include "assert.h"

int __pthread_musl_mutex_init(__pthread_mutex_t *restrict m, const __pthread_mutexattr_t *restrict a)
{
	// fprintf(stderr, "Error __pthread_musl_mutex_init.\n");
    // assert(0);
	// return 0;
	
	*m = (__pthread_mutex_t){0};
	if (a) m->_m_type = a->__attr;
	return 0;
}	