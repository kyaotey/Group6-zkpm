#include <stdio.h>
#include "exercises.h"

/*
 * Exercise 2 (Buggy Version): Out-of-Bounds Read Vulnerability
 * The function creates an array of 5 integers (valid indices: 0 to 4).
 * It accesses array[index] directly without validating if index is in bounds.
 * Accessing index >= 5 causes an out-of-bounds read (stack/global buffer overflow).
 */
int access_array(int index) {
    int array[5] = {10, 20, 30, 40, 50};

    /* VULNERABILITY: No bounds checking before reading array[index] */
    int value = array[index];

    printf("[exercise2 - BUGGY] Array value at index %d: %d\n", index, value);
    return value;
}

