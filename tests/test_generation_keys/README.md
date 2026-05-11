# ML-KEM Key Generation Test

This directory contains a correctness test for ML-KEM key generation.

The purpose of this test is to verify that the implementation correctly generates ML-KEM key pairs according to the FIPS 203 specification and produces deterministic results when using NIST-derived test vectors.

The test validates key generation for all supported parameter sets:

- ML-KEM-512
- ML-KEM-768
- ML-KEM-1024

## What this test verifies

This test verifies that:

- key generation completes successfully;
- the generated secret key matches the expected reference data;
- the generated public key matches the expected reference data;
- the implementation correctly derives deterministic outputs from the provided seed material.

The generated keys are compared against known vector outputs derived from the ML-KEM reference test-vector structure.

## Test logic

The test loads deterministic vector data from:


ML-KEM-keyGen-FIPS203/internalProjection.json

For each vector entry, the test:

1.initializes the ML-KEM key-generation structures;

2.injects deterministic seed material;
   
3.performs key generation;
   
4.compares the produced public key against the expected reference value;

5.compares the produced secret key against the expected reference value.

All comparisons are performed byte-for-byte.

Build

    make

The default compiler is gcc, but another compiler may be selected:

    make CC=clang

Run

    ./test

Clean

    make clean

Expected result

A successful run prints progress information for all tested vectors and parameter sets. If a mismatch is detected, the test reports an error similar to:

Wrong public key in vector <n> or Wrong secret key in vector <n>

Such a result means that the generated ML-KEM key material does not match the expected deterministic reference behavior.

# Notes

This test validates functional correctness of ML-KEM key generation only.

It does not validate:

  1.constant-time behavior;
  
  2.side-channel resistance;
  
  3.memory-safety guarantees;
  
  4.multithreaded correctness;
  
  5.invalid-input handling.

These properties are tested separately in other parts of the ML-KEM test suite.
