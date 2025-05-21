#include <getopt.h>
#include <stdio.h>
#include "mutex_test_args.h"
#include <stdbool.h>

void check_args(mutex_test_args *args) {
    if (args->iter_num < 1) {
        printf("Wrong iteration number: %d, setting it to the default: 1\n", args->iter_num);
        args->iter_num = 1;
    }
    if (args->thread_num < 1) {
        printf("Wrong thread number: %d, setting it to the default: 1\n", args->thread_num);
        args->thread_num = 1;
    }
}

mutex_test_args read_args(int argc, char *argv[]) {
    struct option long_opts[] = {
        {"threads", required_argument, NULL, 't'},
        {"iterations", required_argument, NULL, 'i'},
        {NULL, 0, NULL, 0}};

    char *opts = "t:i";
    int opt;
    mutex_test_args args = {-1, -1};

	int long_index;
	opt = getopt_long(argc, argv, opts, long_opts, &long_index);

    while (opt != -1) {
        switch (opt) {
            case 't': {
                sscanf(optarg, "%d", &args.thread_num);
                break;
            }
            case 'i': {
                sscanf(optarg, "%d", &args.iter_num);
                break;
            }
        }
        opt = getopt_long(argc, argv, opts, long_opts, &long_index);
    }
    
    check_args(&args);

    return args;
}
