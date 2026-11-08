// rust_port.rs - Week 3 Sanitizer Drill: Rust Port of exercise1_fixed.c
//
// In Rust, memory safety and buffer boundary validation are guaranteed at compile time
// and runtime by the type system, ownership model, and checked slice indexing.

const MAX_BUFFER_CAPACITY: usize = 9; // Equivalent to C's 10-byte buffer (9 chars + '\0')

/// Safely copies an input string slice into a bounded String buffer.
/// If the input exceeds the buffer capacity, it truncates safely at UTF-8 char boundaries.
/// Unlike C's strcpy(), this is mathematically incapable of causing a buffer overflow.
pub fn copy_input(input: &str) -> String {
    let char_count = input.chars().count();

    if char_count > MAX_BUFFER_CAPACITY {
        // Safe truncation taking exact character count (UTF-8 safe)
        let truncated: String = input.chars().take(MAX_BUFFER_CAPACITY).collect();
        println!(
            "[rust_port] Input truncated ({} chars exceeds max {}): \"{}\"",
            char_count, MAX_BUFFER_CAPACITY, truncated
        );
        truncated
    } else {
        println!(
            "[rust_port] Safely copied ({} chars): \"{}\"",
            char_count, input
        );
        input.to_string()
    }
}

/// Optional demonstration of safe array indexing (port of exercise2_fixed.c)
pub fn access_array_safe(index: usize) -> Option<i32> {
    let array: [i32; 5] = [10, 20, 30, 40, 50];

    // Rust's .get() returns Option<&T> instead of executing unsafe memory reads
    match array.get(index) {
        Some(&val) => {
            println!("[rust_port] Array access index {}: {}", index, val);
            Some(val)
        }
        None => {
            println!(
                "[rust_port] Bounds check prevented out-of-bounds access at index {} (length: {})",
                index,
                array.len()
            );
            None
        }
    }
}

fn main() {
    println!("====================================================");
    println!("       RUST PORT: MEMORY-SAFE BOUNDARY DRILL        ");
    println!("====================================================\n");

    // Test 1: Empty input (0 characters)
    println!("--- Test 1: Empty Input (0 chars) ---");
    let result1 = copy_input("");
    assert_eq!(result1, "");

    // Test 2: Maximum allowed length (9 characters)
    println!("\n--- Test 2: Maximum Allowed Length (9 chars) ---");
    let result2 = copy_input("123456789");
    assert_eq!(result2, "123456789");

    // Test 3: Maximum length + 1 (10 characters: in C this overflows; in Rust it safely truncates)
    println!("\n--- Test 3: Maximum Length + 1 (10 chars) ---");
    let result3 = copy_input("1234567890");
    assert_eq!(result3, "123456789");

    // Test 4: Very large input (1000 characters)
    println!("\n--- Test 4: Very Large Input (1000 chars) ---");
    let large_input: String = "A".repeat(1000);
    let result4 = copy_input(&large_input);
    assert_eq!(result4.len(), 9);

    // Demonstration of Rust safe array bounds
    println!("\n--- Bonus: Safe Array Bounds Demonstration ---");
    access_array_safe(2);
    access_array_safe(10); // Safe handled rejection, never crashes or leaks memory

    println!("\n====================================================");
    println!("  ALL RUST TESTS PASSED WITH 100% MEMORY SAFETY!   ");
    println!("====================================================");
}

