# ML-KEM Pool Stress Test

This directory contains a stress test for the ML-KEM decapsulation pool implementation. 
The goal of this test is to validate the behavior of the pool under heavy concurrent load and contention.
This test validates the behavior of the ML-KEM decapsulation pool under high contention.
Run:
    make
    ./test_pool

Sanitizers:
    make tsan
    make asan

---

## Overview

The test performs concurrent decapsulation using a shared pool of slots.

Configuration:

* Threads: 256
* Pool size: 16 slots
* Iterations per thread: 1,000,000
* Contention level: 16× over-subscription

All threads operate on the same valid ciphertext to isolate concurrency behavior from algorithmic variability.

---

## What is tested

This test focuses on:

* correctness of slot acquisition under contention
* absence of crashes or deadlocks
* stability of the decapsulation pipeline under load
* consistency of derived shared secrets across threads

Each thread repeatedly:

1. Attempts to acquire a slot
2. Performs `ml_kem_decaps_core`
3. Verifies the resulting shared secret
4. Handles `-EBUSY` by retrying

---

## Build (default)

```bash
make
```

This builds:

```bash
./test_pool
```

---

## Run

```bash
./test_pool
```

Expected output:

```text
Thread done, errors = 0
...
Test finished
```

---

## ThreadSanitizer (TSan)

Build:

```bash
gcc -O1 -g -pthread -fsanitize=thread \
    -I../userspace \
    TEST_pool.c \
    ../userspace/ml_kem.c \
    ../userspace/ml_kem_create_keys.c \
    ../userspace/ml_kem_decrypt.c \
    ../userspace/ml_kem_encaps.c \
    ../userspace/ml_kem_ntt_main.c \
    ../userspace/ml_kem_pool.c \
    ../userspace/ml_kem_sha3.c \
    ../userspace/ml_kem_shake.c \
    ../userspace/keccak1600.c \
    ../userspace/math_operations.c \
    -o test_pool_tsan
```

Run:

```bash
./test_pool_tsan
```

Expected:

* No ThreadSanitizer warnings
* No data race reports
* All threads complete with `errors = 0`

---

## AddressSanitizer + UBSan

Build:

```bash
gcc -O1 -g -pthread -fsanitize=address,undefined \
    -I../userspace \
    TEST_pool.c \
    ../userspace/ml_kem.c \
    ../userspace/ml_kem_create_keys.c \
    ../userspace/ml_kem_decrypt.c \
    ../userspace/ml_kem_encaps.c \
    ../userspace/ml_kem_ntt_main.c \
    ../userspace/ml_kem_pool.c \
    ../userspace/ml_kem_sha3.c \
    ../userspace/ml_kem_shake.c \
    ../userspace/keccak1600.c \
    ../userspace/math_operations.c \
    -o test_pool_asan
```

Run:

```bash
./test_pool_asan
```

Expected:

* No AddressSanitizer errors
* No UndefinedBehaviorSanitizer reports
* No crashes or memory violations

---

## Notes

* The test uses a single valid ciphertext for all threads to focus on concurrency behavior rather than input variability.
* This test does not attempt to prove formal race-freedom, but provides strong empirical evidence of correct synchronization.
* Sanitizer runs were performed under high contention and completed without warnings.

---

## Summary

Observed results:

* no data races detected (TSan)
* no memory safety issues detected (ASan)
* no undefined behavior detected (UBSan)
* no shared secret mismatches
* no crashes under heavy load

This indicates that the pool implementation behaves correctly under high concurrency and contention.
