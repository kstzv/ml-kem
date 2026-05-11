# ML-KEM Decapsulation Test

This directory contains a correctness test for the ML-KEM decapsulation path.

The test performs a full ML-KEM flow:

1. create an ML-KEM object with a decapsulation pool;
2. run encapsulation using the generated public key;
3. run decapsulation using the generated private-key context;
4. compare the shared secret produced by encapsulation with the shared secret produced by decapsulation.

The test is executed for all three ML-KEM parameter sets:

- ML-KEM-512
- ML-KEM-768
- ML-KEM-1024

For each parameter set, the test processes 25 NIST-derived test-vector entries, for a total of 75 checks.

## What this test verifies

This test verifies that the implementation is able to complete the full encapsulation/decapsulation flow and recover the same 32-byte shared secret on both sides.

In other words, for each tested case:

K_encaps == K_decaps

If the values differ, the implementation reports an error for the corresponding vector and parameter set

# Test logic

The test reads seed data from:

ML-KEM-keyGen-FIPS203/internalProjection.json
this file got from(27.02.2026):
https://github.com/usnistgov/ACVP-Server/tree/master/gen-val/json-files/ML-KEM-keyGen-FIPS203

For each vector, it creates a new ML-KEM object, performs encapsulation, then decapsulation, and compares the resulting shared secrets.

The comparison uses memcmp() because this is a correctness test, not a constant-time leakage test.

Constant-time behavior is tested separately in the dedicated dudect tests.

Build

    make

The default compiler is gcc, but another compiler can be selected through CC:

    make CC=clang

Run

    ./test

Clean

    make clean

## Expected result

A successful run prints Done... messages for each tested vector and parameter set.

If a mismatch is detected, the test prints a message similar to:

Wrong! In <vector> vector, in ML-KEM-<level> level security!

Such a result means that the decapsulation path did not reconstruct the same shared secret as encapsulation and the implementation must be investigated.

Notes

This test is focused on functional correctness of decapsulation.

It does not replace:

    NIST KAT validation;
    constant-time testing;
    memory-safety testing;
    invalid-input testing;
    multithreaded pool stress testing.
