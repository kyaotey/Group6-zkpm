#include <stdio.h>
#include "exercises.h"

/*
 * Exercise 3 (Fixed Version): Uninitialized Memory Remediation
 * Root Cause Fix:
 * Explicitly initialize local variable to zero (0) upon declaration.
 * This guarantees deterministic behavior and eliminates read-before-write
 * undefined behavior.
 */
void print_uninitialized(void) {
    /* INITIALIZATION: Explicitly initialize local variable to 0 */
    int initialized_var = 0;

    printf("[exercise3 - FIXED] Initialized variable value: %d (deterministic & safe)\n", initialized_var);
}

