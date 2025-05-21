# Compiler and flags
CC = musl-gcc
CFLAGS = -Wall -Wextra -fPIC -I. -D__NEED_struct_timespec

# Source files
SRCS = pthread_mutex_lock.c \
       pthread_mutex_timedlock.c \
       pthread_mutex_trylock.c \
       pthread_mutex_unlock.c \
       pthread_mutex_init.c \
	   pthread_self_glibc.c \
	   pthread_setcancelstate_glibc.c \
       pthread_cond_wait.c \
       pthread_cond_timedwait.c \
       pthread_cond_signal.c \
       pthread_cond_broadcast.c \
       pthread_cond_destroy.c \
       pthread_cond_init.c \
       __timedwait.c \
       __wait.c \
       vmlock.c \
       __syscall_cp.c \
       clock_gettime.c \
       syscall_ret.c \
	# vdso.c \

# Object files
OBJS = $(SRCS:.c=.o)

# Output library
TARGET = libmusl_mutex.a

# Default target
all: $(TARGET)

# Link shared library
$(TARGET): $(OBJS)
	ar rcs $@ $^

# Compile sources
%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

# Clean up
clean:
	rm -f $(OBJS) $(TARGET)

.PHONY: all clean
