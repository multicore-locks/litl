#include "pthread_impl.h"

int __pthread_musl_condattr_init(__pthread_condattr_t *a)
{
	*a = (__pthread_condattr_t){0};
	return 0;
}
