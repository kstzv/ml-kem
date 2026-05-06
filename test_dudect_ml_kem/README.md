# Constant-Time / dudect Testing

## Current Coverage

The current dudect coverage includes testing of the primary secret-dependent execution paths of the ML-KEM implementation:

- Key generation module
- Encapsulation module
- Decryption module
- Decapsulation flow
- NTT/iNTT operations
- Polynomial arithmetic paths

The current testing focuses on detecting timing leaks in the primary secret-processing paths used by ML-KEM operations.

## Planned Future Coverage

The following components are planned for additional isolated dudect testing:

- Modular arithmetic operations
- Barrett reduction
- Modular multiplication
- Modular addition/subtraction
- SHA3-256 / SHA3-512
- SHAKE128 / SHAKE256

# ML-KEM dudect Tests

This directory contains dudect-based timing leakage tests for the ML-KEM implementation.

## Setup

1. Clone dudect:

```bash
git clone https://github.com/oreparaz/dudect.git

2. Build dudect:
make

3. Copy the directory:
test_dudect_ml_kem/ into the root dudect directory.

Expected layout:

dudect/
├── src/
├── examples/
├── test_dudect_ml_kem/
│   ├── test_decaps/
│   ├── test_math_operations/
│   ├── test_ml_kem_create_keys/
│   ├── test_ml_kem_decrypt/
│   ├── test_ml_kem_encaps/
│   ├── test_NTT/
│   └── userspace/
│
├── README.md
└── Makefile

4. Enter the required test directory and build using its local Makefile.

Example: cd test_dudect_ml_kem/test_decaps
make



