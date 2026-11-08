#include <stdio.h>
#include "exercises.h"

/*
 * Exercise 3 (Buggy Version): Uninitialized Memory Access
 * The local variable 'uninitialized_var' is declared but never initialized.
 * Reading from uninitialized automatic storage duration memory is Undefined Behavior
 * in C and will trigger MemorySanitizer / UndefinedBehaviorSanitizer.
 */
void print_uninitialized(void) {
    int uninitialized_var;

    /* VULNERABILITY: Reading garbage / uninitialized stack memory */
    printf("[exercise3 - BUGGY] Uninitialized variable value: %d\n", uninitialized_var);
}

