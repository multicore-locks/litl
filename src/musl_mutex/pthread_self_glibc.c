#include <pthread.h>

#include "pthread_self_glibc.h"

unsigned long int pthread_self_glibc () {
    return pthread_self();
}
