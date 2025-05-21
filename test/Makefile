LDFLAGS= -lpthread

all: test

test: test_program.o read_args.o
	gcc read_args.o test_program.o -o test_program $(LDFLAGS)

test_program.o: test_program.c
	gcc -c -ggdb test_program.c 

read_args.o: read_args.c mutex_test_args.h
	gcc -c read_args.c

clean:
	rm -rf *.o
