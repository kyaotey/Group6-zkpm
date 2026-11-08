#include <stdio.h>
#include "exercises.h"

#define ARRAY_SIZE 5

/*
 * Exercise 2 (Fixed Version): Out-of-Bounds Remediation
 * Root Cause Fix:
 * Add explicit bounds verification (0 <= index < ARRAY_SIZE) before attempting
 * to read from the array. If the index is out of bounds, report the violation
 * safely and reject access instead of accessing undefined memory.
 */
int access_array(int index) {
    int array[ARRAY_SIZE] = {10, 20, 30, 40, 50};

    /* BOUNDS CHECK: Ensure index is within legitimate boundaries [0, 4] */
    if (index < 0 || index >= ARRAY_SIZE) {
        printf("[exercise2 - FIXED] Bounds Error: Requested index %d is out of bounds [0..%d]. Access blocked safely.\n",
               index, ARRAY_SIZE - 1);
        return -1; /* Return safe sentinel error code */
    }

    int value = array[index];
    printf("[exercise2 - FIXED] Valid access at index %d: %d\n", index, value);
    return value;
}

