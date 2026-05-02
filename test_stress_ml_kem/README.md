# ML-KEM Stress Test

## Overview

This test performs large-scale end-to-end validation of the ML-KEM implementation.

Each iteration includes a full lifecycle of the algorithm:

* key generation
* encapsulation
* decapsulation
* shared secret comparison
* memory cleanup

The goal is to verify correctness and stability of the implementation under intensive repeated execution.

---

## Purpose

This test is designed to:

* validate correctness beyond NIST Known Answer Tests (KAT)
* detect potential instability or rare edge-case failures
* stress-test memory allocation and cleanup logic
* simulate real-world repeated usage of the ML-KEM API

This is **not a formal verification tool**, but a practical reliability test.

---

## Configuration

The test behavior can be adjusted via the following parameters in the source code:

* `NUMBER_LOOPS` — number of full ML-KEM iterations (default: 1,000,000)
* `CURR_LVL` — security level (`ML_KEM_512`, `ML_KEM_768`, `ML_KEM_1024`)
* `ciphertext_len` — expected ciphertext size for the selected level

---

## How It Works

For each iteration:

1. A new ML-KEM context is created
2. A keypair is generated
3. Encapsulation is performed to derive a shared secret
4. Decapsulation is performed using the generated ciphertext
5. The two shared secrets are compared
6. All allocated resources are released

If any step fails or the shared secrets differ, the test terminates immediately.

---

## Output

* Progress is printed every 10,000 iterations
* On success, the test prints a final confirmation message
* On failure, an error message indicates the iteration and failure type

---

## Notes

* This test intentionally includes allocation and deallocation in each iteration
  to stress-test memory management and lifecycle handling

* The test is deterministic in structure but relies on internal randomness
  of the ML-KEM implementation

* Long execution time is expected for large iteration counts

---

## Limitations

* Does not verify constant-time behavior (see dudect tests)
* Does not replace formal verification or cryptographic validation
* Focuses on functional correctness and stability only

---

## Usage

Build and run using the provided `Makefile`:

```bash
make
./TEST_rand
```

---

## Summary

This stress test provides an additional layer of confidence in the correctness
and robustness of the ML-KEM implementation under heavy and repeated use.
