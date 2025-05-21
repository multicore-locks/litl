struct mutex_test_args {
    int thread_num;
    int iter_num;
} typedef mutex_test_args;

mutex_test_args read_args(int argc, char *argv[]);
