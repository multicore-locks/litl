#include "pthread_impl.h"
#include <stdio.h>
#include <assert.h>

int __pthread_musl_mutex_lock(__pthread_mutex_t *m, musl_context_t *me)
{
	// fprintf(stderr, "Error __pthread_musl_mutex_lock.\n");

	if ((m->_m_type&15) == PTHREAD_MUTEX_NORMAL
	    && !a_cas(&m->_m_lock, 0, EBUSY))
		return 0;

	return __pthread_musl_mutex_timedlock(m, 0, me);
}
