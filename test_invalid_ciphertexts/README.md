# ML-KEM Invalid Ciphertext Stress Test

This test validates the behavior of implicit rejection and deterministic fallback logic (`z`-based fallback) in the ML-KEM implementation.

The test performs repeated full-cycle operations:

* ML-KEM object creation
* Key generation
* Encapsulation
* Valid decapsulation
* Ciphertext corruption
* Repeated decapsulation of corrupted ciphertexts
* Memory cleanup

## What is tested

The test verifies that:

* valid ciphertexts produce identical shared secrets
* corrupted ciphertexts do NOT reproduce the original shared secret
* the same corrupted ciphertext always produces the same fallback secret
* decapsulation remains stable under repeated malformed ciphertext processing
* repeated allocation and cleanup do not produce crashes or sanitizer errors

## Build

```bash
make
```

## Run

```bash
make run
```

## Run with Valgrind

```bash
make valgrind
```

## Notes

* The test uses AddressSanitizer (`-fsanitize=address`)
* Default configuration runs 1,000,000 iterations
* This is a practical stress/integration test, not a formal cryptographic proof
* Intended for reliability validation and regression testing
