# Implementation of the ML-KEM 

Implementation of ML-KEM (FIPS 203) written in C11.

This directory contains the portable ML-KEM core implementation used as the foundation for all supported environment-specific ports.

All tests of this implementation are in /portable/tests
---

## Overview

This implementation provides the complete ML-KEM cryptographic core, including:

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

The implementation is divided into the following modules:

| File | Description |
|------|------------|
| `ml_kem.c` | Public API layer |
| `ml_kem_core_header.h` | Core definitions, constants, and structures |
| `ml_kem_create_keys.c` | Key generation |
| `ml_kem_encaps.c` | Encapsulation logic |
| `ml_kem_decrypt.c` | Decapsulation (decryption + re-encapsulation) |
| `ml_kem_ntt_main.c` | NTT and polynomial operations |
| `ml_kem_sha3.c` | SHA3-256 / SHA3-512 |
| `ml_kem_shake.c` | SHAKE128 / SHAKE256 |
| `keccak1600.c` | Keccak permutation |
| `ml_kem_pool.c` | Decapsulation pool implementation |

The implementation is built around explicit context structures:

- `ml_kem_ctx` — persistent key material
- `ml_kem_temp` — temporary key generation buffers
- `ml_kem_encaps_ctx` — encapsulation context
- `ml_kem_decrypt_ctx` — decryption context
- `ml_kem_decaps_ctx` — one slot context (decapsulation)
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
  - reusable slot contexts
  - lock-free slot acquisition
  - reduced allocation overhead
- Reusable decapsulation pool
- No runtime allocations during decapsulation
- Small stack footprint
- Constant-time oriented design

  
---

## Public API

Main entry points:

    struct ml_kem_pool_decaps_ctx *ml_kem_create_object(enum ml_kem_k level, size_t ml_kem_pool_count, ml_kem_entropy_fn entropy);

    void ml_kem_destroy_core(struct ml_kem_pool_decaps_ctx *ctx_pool);

    u8 *ml_kem_encaps_core(u8 *pk, enum ml_kem_k level, u8 *result, ml_kem_entropy_fn entropy);

    void ml_kem_ciphertext_destroy_core(u8 *ciphertext, enum ml_kem_k level);

    int ml_kem_decaps_core(struct ml_kem_pool_decaps_ctx *pool, u8 *ciphertext, size_t len_ciphertext, u8 *result, size_t len_result);
    
    int ml_kem_get_public_key(struct ml_kem_pool_decaps_ctx *pool, u8 *buffer_for_public_key, size_t size_buffer);

## Getting Started

This directory contains only the portable ML-KEM core implementation.

To build or integrate the library, use one of the available environment-specific ports located in:

portable/ports/

Each port provides its own build system, integration layer, and usage documentation.


## License

This project is dual-licensed under:

- GNU General Public License v2.0
- MIT License

You may choose either license.

---

## 📬 Contact

- GitHub: https://github.com/kstzv
- Email: kstzavertaylo@gmail.com

