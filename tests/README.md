#ML-KEM Test Suite

This directory contains the complete validation and robustness test infrastructure for the pure C implementation of ML-KEM (FIPS 203).

The goal of this test suite is not only correctness verification, but also practical validation of:

constant-time behavior,
malformed input handling,
memory safety,
race-condition resistance,
stress stability,
API robustness,
deterministic fallback behavior of ML-KEM decapsulation,
compiler-dependent behavior under optimization.

#The implementation is primarily validated on:

x86-64
GCC
Clang/LLVM

with configurable compiler selection through:

CC ?= gcc

Most tests are intentionally separated into independent categories to simplify debugging, maintenance, and security analysis.

#Test Categories
1. KAT End-to-End Decapsulation Tests

Directory:

test_decapsulation_end_to_end/

Purpose:

Full end-to-end verification of ML-KEM using official NIST known answer test vectors for key generation.
Verifies:
key generation,
encapsulation,
decapsulation,
shared secret agreement.

The test uses:

75 deterministic vector sets total:
25 × ML-KEM-512
25 × ML-KEM-768
25 × ML-KEM-1024

Validation compares the shared secret derived during decapsulation with the original shared secret produced during encapsulation.

2. KAT Key Generation Tests

Directory:

test_generation_keys/

Purpose:

Verification of deterministic ML-KEM key generation.

The test validates:

generated public keys,
generated secret keys,
deterministic seed handling.

Generated public keys are compared against official NIST reference vectors.

3. KAT Encapsulation Tests

Directory:

test_encapsulation/

Purpose:

Verification of deterministic encapsulation behavior.

The test validates:

ciphertext generation,
shared secret derivation,
deterministic randomness processing.

Generated ciphertexts are compared against official NIST reference vectors.

4. dudect Constant-Time Tests

Directory:

test_dudect_ml_kem/

Purpose:

Statistical timing-leakage detection using the official dudect framework.

The tests focus on secret-dependent code paths, including:

key generation,
encapsulation,
decapsulation,
modular arithmetic,
NTT operations,
SHAKE/SHA3 wrappers,
decryption internals,
constant-time secret selection logic.

These tests are designed to validate optimized production-style builds.

Recommended compilation flags:

CFLAGS = -O3 -std=c11 -Wall -Wextra

The dudect tests are intentionally separated from the main repository build flow.

Important

This directory must be copied into an official dudect source tree before compilation.

General workflow:

1. Download and build official dudect
2. Copy test_dudect_ml_kem/ into the dudect root directory
3. Build the tests inside dudect
4. Execute the generated binaries

dudect project:
https://github.com/oreparaz/dudect?utm_source=chatgpt.com

Why -O3 Is Used for dudect

The purpose of dudect is to test the timing behavior of the final optimized machine code.

Because of this:

constant-time tests are executed using aggressive compiler optimization,
while debugging and sanitizer-oriented tests usually use -O0 -g.

This separation is intentional.

5. API Input Validation Tests

Directory:
test_input_validation/

Purpose:

Validation of API robustness against intentionally malformed input.

The tests verify handling of:

NULL pointers,
invalid lengths,
invalid security levels,
corrupted parameters,
invalid buffer configurations.

The goal is to ensure:

predictable failure behavior,
absence of crashes,
absence of undefined behavior,
stable API handling.

6. Invalid Ciphertext / z-Path Tests

Directory:

test_invalid_ciphertext/

Purpose:

Verification of ML-KEM decapsulation behavior on malformed ciphertexts.

The tests intentionally corrupt ciphertexts and verify:

rejection behavior,
deterministic fallback secret derivation,
correctness of the ML-KEM z fallback path,
absence of accidental valid decapsulation.

Special attention is given to deterministic behavior:

identical malformed ciphertexts must produce identical fallback shared secrets.

7. Memory Leak Tests

Directory:

test_memory_leak/

Purpose:

Detection of:
memory leaks,
invalid frees,
heap corruption,
use-after-free,
stack corruption.

The tests are executed using:

AddressSanitizer (ASAN),
Valgrind.

Typical Valgrind flags:

--leak-check=full
--show-leak-kinds=all
--track-origins=yes
--verbose

These tests focus on:

repeated object creation/destruction,
repeated encapsulation/decapsulation,
stress allocation cycles.

8. Decapsulation Pool Stress Tests

Directory:

test_pool/

Purpose:

Validation of multithreaded decapsulation pool behavior under extreme contention.

The tests use:

large thread counts,
repeated concurrent decapsulation operations,
synchronized thread starts.

Validation targets:

race conditions,
pool corruption,
deadlocks,
memory safety,
thread safety.

Typical tooling:

ThreadSanitizer (TSAN),
AddressSanitizer (ASAN).

9. Massive Randomized Stress Tests

Directory:

test_randomized_stress/

Purpose:

Long-running randomized end-to-end validation.

The tests execute:

millions of complete ML-KEM operation cycles,
randomized encapsulation/decapsulation flows,
repeated object creation/destruction.

Goals:

detect rare edge-case failures,
validate long-term stability,
validate deterministic correctness,
detect hidden state corruption.

Compiler Support

The test suite is primarily validated using:

GCC
Clang/LLVM

Compiler selection is configurable through:

CC ?= gcc

Example:

make CC=clang


Optimization Strategy

Different test categories intentionally use different optimization levels.

Recommended for dudect
-O3

Reason:

validates optimized production-style machine code.
Recommended for sanitizer/debug tests
-O0 -g

Reason:

easier debugging,
cleaner sanitizer diagnostics,
improved stack traces.
Security Notes

Passing these tests does not mathematically prove security.

However, the suite is intended to provide strong practical engineering validation for:

correctness,
robustness,
memory safety,
concurrency behavior,
constant-time behavior on validated platforms.

The implementation and tests are primarily validated on:

x86-64,
GCC,
Clang.

Other architectures and compiler configurations may require additional validation.

External References
https://csrc.nist.gov/pubs/fips/203/final?utm_source=chatgpt.com
https://github.com/C2SP/CCTV/tree/main/ML-KEM
https://github.com/oreparaz/dudect?utm_source=chatgpt.com
https://llvm.org/?utm_source=chatgpt.com
https://gcc.gnu.org/?utm_source=chatgpt.com

