#include <stdio.h>
#include <string.h>
#include "exercises.h"

/*
 * Exercise 1 (Fixed Version): Buffer Overflow Remediation
 * Root Cause Fix:
 * 1. Initialize buffer with zeros to avoid lingering junk bytes.
 * 2. Replace unbounded strcpy() with snprintf(), which strictly respects
 *    the destination buffer's capacity (sizeof(buffer) = 10 bytes).
 * 3. snprintf guarantees null-termination and prevents writes beyond 10 bytes.
 * 4. Checks return value to detect and handle truncation gracefully.
 */
void copy_input(const char *input) {
    char buffer[10] = {0};

    if (input == NULL) {
        printf("[exercise1 - FIXED] Error: NULL input passed.\n");
        return;
    }

    /* SAFE COPY: snprintf writes at most sizeof(buffer) bytes including '\0' */
    int written = snprintf(buffer, sizeof(buffer), "%s", input);

    if (written >= (int)sizeof(buffer)) {
        printf("[exercise1 - FIXED] Truncated (input was %d chars, safely capped to %zu): %s\n",
               written, sizeof(buffer) - 1, buffer);
    } else {
        printf("[exercise1 - FIXED] Safely copied (%d chars): %s\n", written, buffer);
    }
}

