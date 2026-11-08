#include <stdio.h>
#include <string.h>
#include "exercises.h"

/*
 * Exercise 1 (Buggy Version): Buffer Overflow Vulnerability
 * The function allocates a fixed 10-byte buffer and uses the dangerous
 * strcpy() function without checking the length of the source string.
 * Any input of length >= 10 bytes will cause a stack-buffer-overflow.
 */
void copy_input(const char *input) {
    char buffer[10];

    /* VULNERABILITY: strcpy does not enforce destination buffer boundaries */
    strcpy(buffer, input);

    printf("[exercise1 - BUGGY] Copied into buffer: %s\n", buffer);
}

