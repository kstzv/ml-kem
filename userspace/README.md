# ML-KEM Userspace Implementation

Userspace implementation of ML-KEM (FIPS 203) written in pure C.

This version serves as the primary implementation of this project of the project and is currently the most tested component.  
It shares the same architecture as the kernel version, but uses standard userspace primitives (`malloc`, `getrandom`, etc.).

> Status: beta.  
> NIST KAT tests for key generation and encapsulation are passing.  
> End-to-end decapsulation validated against internally generated vectors.

---

## Overview

This implementation provides a full ML-KEM pipeline in userspace:

- Key generation
- Encapsulation
- Decapsulation

Design priorities:

- minimal external dependencies
- explicit memory management
- architectural clarity
- portability
- minimal abstraction overhead

The code is structured to be:

- easy to audit
- easy to port (e.g. kernel / embedded)
- suitable for experimentation and research

---

## Architecture

The implementation is built around explicit context structures:

- `ml_kem_ctx` — persistent key material
- `ml_kem_temp` — temporary key generation buffers
- `ml_kem_encaps_ctx` — encapsulation context
- `ml_kem_decrypt_ctx` — decapsulation context
- `ml_kem_pool_decaps_ctx` — pool of reusable decapsulation slots

Key principles:

- strict separation of persistent and temporary data
- no hidden allocations in core logic
- explicit allocation / wipe / destroy lifecycle
- contiguous memory layout for performance and locality

---

## Features

- Pure C (C11)
- No external crypto libraries
- Own implementations of:
  - Keccak-f[1600]
  - SHA3-256 / SHA3-512 
  - SHAKE128 / SHAKE256
- Full ML-KEM pipeline:
  - Key generation
  - Encapsulation
  - Decapsulation
- Polynomial arithmetic:
  - NTT / inverse NTT
  - Barrett reduction
- Decapsulation pool:
  - lock-free slot acquisition
  - reduced allocation overhead

---


## Public API

Main entry points:

    struct ml_kem_pool_decaps_ctx *ml_kem_create_object(enum ml_kem_k level, size_t ml_kem_pool_count);

    void ml_kem_destroy_core(struct ml_kem_pool_decaps_ctx *ctx_pool);

    u8 *ml_kem_encaps_core(u8 *pk, enum ml_kem_k level, u8 *result);

    void ml_kem_ciphertext_destroy_core(u8 *ciphertext, enum ml_kem_k level);

    int ml_kem_decaps_core(struct ml_kem_pool_decaps_ctx *pool, u8 *ciphertext, size_t len_ciphertext, u8 *result, size_t len_result);

## Getting Started

Building:

    make
   

This produces:

   libmlkem.a

### Example

A complete usage example is available in:
   example/basic.c

Build the example:
   gcc example/basic.c libmlkem.a -I. -o basic

Run:
   ./basic

Expected output:
   ML-KEM object created
   ML-KEM object destroyed

### Integration

Include the public header:
   #include "ml_kem.h"

Compile your application and link against the library:
   gcc your_program.c libmlkem.a -I. -o your_program

The implementation currently targets:
- ISO C11
- GCC
- Clang

No external cryptographic libraries are required.


## License

This project is dual-licensed under:

- GNU General Public License v2.0
- MIT License

You may choose either license.

---

## 📬 Contact

- GitHub: kstzv(https://github.com/kstzv)
- Email: kstzavertaylo@gmail.com

