# ML-KEM Encapsulation Test

This directory contains a correctness test for the ML-KEM encapsulation path.

The purpose of this test is to verify that the implementation produces valid ciphertexts and shared secrets during encapsulation, using deterministic NIST-derived test vectors.

The test validates encapsulation for all supported ML-KEM parameter sets:

- ML-KEM-512
- ML-KEM-768
- ML-KEM-1024

For each parameter set, the test loads known vector data and compares the implementation output against the expected results.

## What this test verifies

This test verifies that:

- encapsulation successfully completes;
- the generated ciphertext matches the expected reference ciphertext;
- the generated shared secret matches the expected reference shared secret.

In other words, the implementation output is checked against known deterministic values derived from the official ML-KEM test-vector structure.

## Test logic

The test uses vector data stored in:

ML-KEM-encapDecap-FIPS203/internalProjection.json
this file got from(27.02.2026):
https://github.com/usnistgov/ACVP-Server/tree/master/gen-val/json-files/ML-KEM-encapDecap-FIPS203

For every vector entry, the test:
  1. loads the public key;
  2. performs encapsulation;
  3. compares the produced ciphertext with the expected ciphertext;
  4. compares the produced shared secret with the expected shared secret.

Both comparisons are performed byte-for-byte.

Build

  make

The default compiler is gcc, but another compiler may be selected:

  make CC=clang

Run

  ./test

Clean

  make clean

## Expected result

A successful execution prints progress messages for all tested vectors and parameter sets. If an error is detected, the test prints a message similar to:
Wrong ciphertext in vector <n> or Wrong shared secret in vector <n>
Such a result means that the encapsulation implementation produced data that does not match the expected ML-KEM reference behavior.

## Notes

This test validates functional correctness of encapsulation only. It does not validate:
constant-time behavior;
cache-timing resistance;
invalid-input handling;
concurrent execution safety;
memory-safety guarantees.

These properties are tested separately in other parts of the ML-KEM test suite.

