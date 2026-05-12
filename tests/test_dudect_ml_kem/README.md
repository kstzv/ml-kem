Dudect Constant-Time Tests for ML-KEM
# Overview

This directory contains a collection of constant-time leakage tests for the ML-KEM implementation using the dudect framework.

Each subdirectory targets a separate module, primitive, or critical operation of the implementation in order to validate resistance against timing-based side-channel leakage.

 The tests focus primarily on:

- secret-dependent branching
  
- secret-dependent memory access

- compiler-induced timing variations

- constant-time arithmetic correctness

- correctness of constant-time masking/select operations


The overall goal of these tests is to increase confidence that the implementation behaves in a timing-independent manner on tested platforms and compiler configurations.

The tested implementation itself is based on the ML-KEM standard defined in FIPS 203

Core API and structures are defined in the public headers of the implementation.

# Directory Structure

Each subdirectory contains an isolated dudect test for a specific function or module.

Typical targets include:

 - key generation

 - encapsulation

 - decapsulation

 - decrypt routines

 - SHA3 / SHAKE wrappers

 - Keccak-f[1600]

 - NTT operations

 - modular arithmetic

 - constant-time selection logic

 - polynomial operations

Examples of tested modules from the implementation:

 - encapsulation routines
  
 - decapsulation and decrypt logic
  
 - SHAKE sponge implementation
  
 - SHA3 wrappers
  
 - Keccak-f[1600] permutation
  
 - NTT implementation
  
 - modular arithmetic and Barrett reduction

# General Test Structure

Most dudect tests inside this directory follow the same overall structure:

- Inclusion of required headers and implementation files
  
- Local pseudo-random generator functions
  
- Optional initialization / cleanup routines
  
- Allocation of test buffers and contexts
  
- Selection or wrapping of the tested function
  
- dudect prepare_inputs() implementation
  
- dudect do_one_computation() implementation
  
- Main test loop using dudect

This consistent structure helps isolate leakage sources and simplifies auditing and extension of the test suite.
