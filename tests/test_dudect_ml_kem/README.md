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

# Important Notes About dudect

dudect is a statistical leakage detection framework. A successful dudect run:

- does NOT mathematically prove absolute constant-time behavior
- does NOT guarantee resistance on all architectures or compilers
- DOES provide practical statistical evidence against observable timing leakage under the tested conditions

These tests are therefore intended as practical engineering validation rather than formal proof.

# Compiler Testing

The tests are intended to be executed under multiple compiler toolchains and optimization levels. Particular attention is given to:

- GCC
- Clang/LLVM

Typical optimization targets include:

 -O2
 
 -O3

This is important because compiler optimizations may alter the timing behavior of low-level constant-time code.

# What Is Considered Sensitive

The primary focus is on functions processing:

- secret keys
- temporary secrets
- decapsulation secrets
- shared secrets
- intermediate polynomial data
- rejection-sampling logic
- constant-time ciphertext validation
- constant-time fallback secret selection

Special attention is given to the decapsulation path and fallback logic used during invalid ciphertext handling.

# Example dudect Output

Typical dudect output may look similar to:

    meas:    1.00 M, max t: +1.32, max tau: 3.10e-03 For the moment, maybe constant time.

Lower absolute t-values generally indicate lower observable leakage under the tested conditions.

# Limitations

These tests were primarily executed on:

x86-64 systems
Linux userspace environments

Results may differ on:

- different architectures
- different microarchitectures
- embedded systems
- different compilers
- different optimization settings

Additional independent verification on other platforms is encouraged.

# Integration Notes

Most tests are intentionally isolated and may:

- duplicate portions of implementation code
- remove static qualifiers
- wrap internal functions
- expose internal routines for testing purposes

This is done intentionally to allow direct timing analysis of otherwise inaccessible internal operations.

# Security Goal

The goal of this test suite is to reduce the risk of:

- secret-dependent timing leakage
- compiler-induced timing regressions
- accidental non-constant-time behavior
- unsafe secret handling paths

while preserving:

- low-level implementation clarity
- explicit memory control
- portability
- compatibility with constrained environments

# Related Implementation

Main repository: 

https://github.com/kstzv/ml-kem
