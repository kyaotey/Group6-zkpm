#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "exercises.h"

static void test_empty_input(void) {
    printf("\n[TEST 1] Boundary Case: Empty Input (0 characters)\n");
    copy_input("");
    printf("[TEST 1] Passed safely.\n");
}

static void test_max_allowed(void) {
    printf("\n[TEST 2] Boundary Case: Maximum Allowed Length (9 characters + '\\0' fits 10-byte buffer)\n");
    copy_input("123456789");
    printf("[TEST 2] Passed safely.\n");
}

static void test_max_plus_one(void) {
    printf("\n[TEST 3] Boundary Case: Maximum Length + 1 (10 characters: triggers overflow on buggy version)\n");
    copy_input("1234567890");
    printf("[TEST 3] Passed safely.\n");
}

static void test_very_large_input(void) {
    printf("\n[TEST 4] Boundary Case: Very Large Input (1000 characters)\n");
    char large_buffer[1001];
    memset(large_buffer, 'A', 1000);
    large_buffer[1000] = '\0';
    copy_input(large_buffer);
    printf("[TEST 4] Passed safely.\n");
}

static void test_array_bounds(void) {
    printf("\n[TEST 5] Array Access Test: Valid index 2, then Out-of-Bounds index 10\n");
    printf("Accessing valid index 2:\n");
    access_array(2);
    printf("Accessing invalid index 10 (triggers sanitizer on buggy version):\n");
    access_array(10);
    printf("[TEST 5] Completed.\n");
}

static void test_uninitialized_memory(void) {
    printf("\n[TEST 6] Uninitialized Memory Test:\n");
    print_uninitialized();
    printf("[TEST 6] Completed.\n");
}

int main(int argc, char *argv[]) {
    int test_choice = 0;

    if (argc > 1) {
        test_choice = atoi(argv[1]);
    }

    printf("====================================================\n");
    printf("       WEEK 3 SANITIZER DRILL - BOUNDARY TESTS       \n");
    printf("====================================================\n");

    if (test_choice == 0) {
        /* Run all boundary tests sequentially */
        test_empty_input();
        test_max_allowed();
        test_max_plus_one();
        test_very_large_input();
        test_array_bounds();
        test_uninitialized_memory();
    } else {
        /* Allow targeting a specific test for loud sanitizer failure isolation */
        switch (test_choice) {
            case 1: test_empty_input(); break;
            case 2: test_max_allowed(); break;
            case 3: test_max_plus_one(); break;
            case 4: test_very_large_input(); break;
            case 5: test_array_bounds(); break;
            case 6: test_uninitialized_memory(); break;
            default:
                printf("Unknown test choice: %d. Valid choices are 1 through 6, or 0 for all.\n", test_choice);
                return 1;
        }
    }

    printf("\n====================================================\n");
    printf("              ALL SELECTED TESTS COMPLETED          \n");
    printf("====================================================\n");
    return 0;
}

