/* sum.c
    Test program for additional system calls.
    print the result of 'fibonacci' system call.
    print the result of 'sum_of_four_int' system call. */
#include <stdio.h>
#include <stdlib.h>
#include <syscall.h>

int
main (int argc, char **argv)
{
    int a,b,c,d;
    a = atoi(argv[1]);
    b = atoi(argv[2]);
    c = atoi(argv[3]);
    d = atoi(argv[4]);
    printf("%d %d\n", fibonacci(a), sum_of_four_int(a,b,c,d));

    return 0;
}
