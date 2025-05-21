#pragma once

#define _Addr long
#define _Int64 long
#define _Reg long

#define __BYTE_ORDER 1234
#define __LONG_MAX 0x7fffffffffffffffL


#define __LITTLE_ENDIAN 1234
#define __BIG_ENDIAN 4321
#define __USE_TIME_BITS64 1

//#if defined(__NEED_size_t) && !defined(__DEFINED_size_t)
typedef unsigned _Addr size_t;
//#define __DEFINED_size_t
//#endif

//#if defined(__NEED_uintptr_t) && !defined(__DEFINED_uintptr_t)
typedef unsigned _Addr uintptr_t;
//#define __DEFINED_uintptr_t
//#endif

//#if defined(__NEED_intptr_t) && !defined(__DEFINED_intptr_t)
typedef _Addr intptr_t;
//#define __DEFINED_intptr_t
//#endif

//#if defined(__NEED_time_t) && !defined(__DEFINED_time_t)
typedef _Int64 time_t;
//#define __DEFINED_time_t
//#endif


//#if defined(__NEED_int8_t) && !defined(__DEFINED_int8_t)
typedef signed char     int8_t;
//#define __DEFINED_int8_t
//#endif

//#if defined(__NEED_int16_t) && !defined(__DEFINED_int16_t)
typedef signed short    int16_t;
//#define __DEFINED_int16_t
//#endif

//#if defined(__NEED_int32_t) && !defined(__DEFINED_int32_t)
typedef signed int      int32_t;
//#define __DEFINED_int32_t
//#endif

//#if defined(__NEED_int64_t) && !defined(__DEFINED_int64_t)
typedef signed _Int64   int64_t;
//#define __DEFINED_int64_t
//#endif

//#if defined(__NEED_intmax_t) && !defined(__DEFINED_intmax_t)
typedef signed _Int64   intmax_t;
//#define __DEFINED_intmax_t
//#endif

//#if defined(__NEED_uint8_t) && !defined(__DEFINED_uint8_t)
typedef unsigned char   uint8_t;
//#define __DEFINED_uint8_t
//#endif

//#if defined(__NEED_uint16_t) && !defined(__DEFINED_uint16_t)
typedef unsigned short  uint16_t;
//#define __DEFINED_uint16_t
//#endif

//#if defined(__NEED_uint32_t) && !defined(__DEFINED_uint32_t)
typedef unsigned int    uint32_t;
//#define __DEFINED_uint32_t
//#endif

//#if defined(__NEED_uint64_t) && !defined(__DEFINED_uint64_t)
typedef unsigned _Int64 uint64_t;
//#define __DEFINED_uint64_t
//#endif

//#if defined(__NEED_uintmax_t) && !defined(__DEFINED_uintmax_t)
typedef unsigned _Int64 uintmax_t;
//#define __DEFINED_uintmax_t
//#endif

#if defined(__NEED_wctype_t) && !defined(__DEFINED_wctype_t)
typedef unsigned long wctype_t;
#define __DEFINED_wctype_t
#endif


#//if defined(__NEED_clockid_t) && !defined(__DEFINED_clockid_t)
typedef int clockid_t;
#define __DEFINED_clockid_t
//#endif

#if defined(__NEED_struct_timespec) && !defined(__DEFINED_struct_timespec)
struct timespec { time_t tv_sec; int :8*(sizeof(time_t)-sizeof(long))*(__BYTE_ORDER==4321); long tv_nsec; int :8*(sizeof(time_t)-sizeof(long))*(__BYTE_ORDER!=4321); };
#define __DEFINED_struct_timespec
#endif

#ifdef __cplusplus
#if defined(__NEED_pthread_t) && !defined(__DEFINED_pthread_t)
typedef unsigned long pthread_t;
#define __DEFINED_pthread_t
#endif

#endif

//#if defined(__NEED_pthread_mutexattr_t) && !defined(__DEFINED_pthread_mutexattr_t)
typedef struct { unsigned __attr; } __pthread_mutexattr_t;
#define __DEFINED_pthread_mutexattr_t
//#endif

#if defined(__NEED_locale_t) && !defined(__DEFINED_locale_t)
typedef struct __locale_struct * locale_t;
#define __DEFINED_locale_t
#endif

#if defined(__NEED_pthread_attr_t) && !defined(__DEFINED_pthread_attr_t)
typedef struct { union { int __i[sizeof(long)==8?14:9]; volatile int __vi[sizeof(long)==8?14:9]; unsigned long __s[sizeof(long)==8?7:9]; } __u; } pthread_attr_t;
#define __DEFINED_pthread_attr_t
#endif

//#if defined(__NEED_pthread_mutex_t) && !defined(__DEFINED_pthread_mutex_t)
typedef struct { union { int __i[sizeof(long)==8?10:6]; volatile int __vi[sizeof(long)==8?10:6]; volatile void *volatile __p[sizeof(long)==8?5:6]; } __u; } __pthread_mutex_t;
#define __DEFINED_pthread_mutex_t
//#endif

typedef struct { union { int __i[12]; volatile int __vi[12]; void *__p[12*sizeof(int)/sizeof(void*)]; } __u; } __pthread_cond_t;

typedef struct { unsigned __attr; } __pthread_condattr_t;

#if defined(__NEED_mtx_t) && !defined(__DEFINED_mtx_t)
typedef struct { union { int __i[sizeof(long)==8?10:6]; volatile int __vi[sizeof(long)==8?10:6]; volatile void *volatile __p[sizeof(long)==8?5:6]; } __u; } mtx_t;
#define __DEFINED_mtx_t
#endif


#undef _Addr
#undef _Int64
#undef _Reg
