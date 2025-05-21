#ifndef TIME_H
#define TIME_H

#include "alltypes_make.h"

int __clock_gettime(clockid_t, struct timespec *);

#define CLOCK_REALTIME           0

#endif
