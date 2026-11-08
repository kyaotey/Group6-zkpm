#ifndef EXERCISES_H
#define EXERCISES_H

/* Function prototypes for Week 3 Sanitizer Drill */

/**
 * Exercise 1: String copy function
 * @param input Pointer to null-terminated source string
 */
void copy_input(const char *input);

/**
 * Exercise 2: Array access function
 * @param index Index to read from internal array
 * @return Value at index, or -1 on boundary error
 */
int access_array(int index);

/**
 * Exercise 3: Uninitialized memory access demonstration
 */
void print_uninitialized(void);

#endif /* EXERCISES_H */

