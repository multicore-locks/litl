#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include "mutex_test_args.h"

__uint64_t shared_num   = 0;
pthread_mutex_t mutex;

void *incr_shared_res(void *iter_num) {
    int max_iterations = *(int *)iter_num;
    for (__uint64_t i = 0; i < max_iterations; i++) {
        pthread_mutex_lock(&mutex);
        shared_num += 1;
        //printf("shared_num current value: %d\n", shared_num);
        pthread_mutex_unlock(&mutex);
    }
    // pthread_mutex_unlock(&mutex);
}

int main(int argc, char *argv[]) {
	pthread_mutex_init(&mutex, NULL);
	
    mutex_test_args args = read_args(argc, argv);
    
    pthread_t *threads = calloc(args.thread_num, sizeof(pthread_t));
    for (unsigned i = 0; i < args.thread_num; i++) {
        pthread_create(&threads[i], NULL, incr_shared_res, &args.iter_num);
    }

    for (unsigned i = 0; i < args.thread_num; i++) {
        pthread_join(threads[i], NULL);
    }
    printf("shared_num value after threads work is: %d\n", shared_num);
    free(threads);
    return 0;
}
