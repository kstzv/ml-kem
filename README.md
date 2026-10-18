# Implementation of the ML-KEM 

Implementation of ML-KEM (FIPS 203) written in C11.

This directory contains the portable ML-KEM core implementation used as the foundation for all supported environment-specific ports.

All tests of this implementation are in `portable/tests/`.

## Security and Versioning

For security-sensitive applications, **it is strongly recommended to use the latest stable release** of this implementation.

Older versions may contain bugs or security vulnerabilities that have been identified and addressed in subsequent releases.

The latest stable release incorporates the most recent security fixes, corrections, and improvements. However, using the latest version does not guarantee the absence of vulnerabilities.

This implementation has not undergone a formal independent security audit

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

## Architecture and Recommended Reading Order

This implementation is organized primarily around the execution flow of ML-KEM and the explicit management of its memory resources, 
rather than around individual mathematical objects such as polynomials and polynomial vectors.

The recommended reading order is:

1. Memory creation and resource management (ml_kem_pool.c). Begin with the creation and organization of the memory required by an ML-KEM key and its associated operations. 
This module shows how reusable contexts and decapsulation slots are created, organized, acquired, and released. It defines the memory environment in which the main algorithmic phases execute.

2. Key creation. Follow the generation of the public and private key material and observe how the previously created memory is divided and reused during the process.

3. Encapsulation. Read the encapsulation procedure as a sequential transformation from the public key and fresh randomness to the ciphertext and shared secret. 
The internal encapsulation functionality is also reused later as part of decapsulation.

4. Decryption. Follow the internal decryption procedure separately. It recovers the candidate message from the ciphertext using the private key and provides 
the intermediate result required by the complete decapsulation flow.

5. Decapsulation in the public API. Complete decapsulation is assembled directly in the public API wrapper rather than implemented as another independent internal algorithmic module.
The wrapper combines the existing internal decryption and encapsulation functions: it decrypts the received ciphertext, reuses the encapsulation logic to reconstruct the expected ciphertext, 
performs the required verification and implicit rejection, and derives the final shared secret. 

Reading decapsulation at the API level therefore shows how the existing internal phases are composed into the complete standardized operation, 
while avoiding a duplicate implementation of encapsulation logic.

These modules are intended to be read as sequential data flows. They explicitly control the placement, lifetime, ownership, reuse, and transformation of intermediate values.

Lower-level modules provide reusable computational mechanisms invoked by the main execution phases:

 - NTT and polynomial arithmetic

 - SHA3 and SHAKE

 - Keccak-f[1600]

 - Modular arithmetic and reductions

 - Sampling and centered binomial distribution

For this reason, the implementation should generally be read from the resource-management layer into one of the high-level algorithmic phases, and then from input to output within that phase. 
Lower-level modules should be consulted when they are invoked by the execution flow.

This differs from implementations organized primarily around mathematical abstractions such as poly, polyvec, and indcpa. 
Here, mathematical primitives are separated when they form substantial reusable computational mechanisms, while simpler operations remain visible within the phase in which they are performed.

This organization is intentional. It supports explicit memory management, predictable data lifetimes, reusable operation contexts, bounded concurrency, reuse of complete internal phases, and direct inspection of the complete algorithmic flow.

---

## Source Modules and Contexts

The implementation is divided into the following modules:

| File | Description |
|------|------------|
| `ml_kem.c` | Public API layer |
| `ml_kem_core_header.h` | Core definitions, constants, and structures |
| `ml_kem_create_keys.c` | Key generation |
| `ml_kem_encaps.c` | Encapsulation logic |
| `ml_kem_decrypt.c` | Internal decryption stage used during decapsulation |
| `ml_kem_ntt_main.c` | NTT and polynomial operations |
| `ml_kem_sha3.c` | SHA3-256 / SHA3-512 |
| `ml_kem_shake.c` | SHAKE128 / SHAKE256 |
| `keccak1600.c` | Keccak permutation |
| `ml_kem_pool.c` | Decapsulation pool implementation |
| `ml_kem_encaps_pool.c` | Encapsulation pool implementation |

The implementation is built around explicit context structures:

- `ml_kem_ctx` — persistent key material
- `ml_kem_temp` — temporary key generation buffers
- `ml_kem_encaps_ctx` — encapsulation context
- `ml_kem_decrypt_ctx` — decryption context
- `ml_kem_decaps_ctx` — one slot context (decapsulation)
- `ml_kem_pool_decaps_ctx` — pool of reusable decapsulation slots
- `ml_kem_pool_encaps_ctx` — pools of reusable encapsulation slots (separate pools for ML-KEM-512, ML-KEM-768, and ML-KEM-1024)

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
- Encapsulation pool with reusable per-level slots
- No runtime allocations during decapsulation or pooled encapsulation
- Small stack footprint
- Constant-time oriented design

  
---

## Public API

The public API is declared in `ml_kem.h`. Main entry points:

```c
struct ml_kem_pool_decaps_ctx *ml_kem_create_object(
    enum ml_kem_k level, size_t ml_kem_pool_count,
    ml_kem_entropy_fn entropy);

void ml_kem_destroy_core(struct ml_kem_pool_decaps_ctx *ctx_pool);

struct ml_kem_pool_encaps_ctx *create_encaps_pool(
    size_t number_slots_512, size_t number_slots_768,
    size_t number_slots_1024);

void ml_kem_encaps_pool_destroy(struct ml_kem_pool_encaps_ctx *ctx);

int ml_kem_encaps_core(
    struct ml_kem_pool_encaps_ctx *ctx_pool,
    u8 *pk, size_t size_pk,
    u8 *buffer_ct, size_t size_ct,
    u8 *buffer_ss, size_t size_ss,
    ml_kem_entropy_fn entropy);

int ml_kem_decaps_core(
    struct ml_kem_pool_decaps_ctx *pool,
    u8 *ciphertext, size_t len_ciphertext,
    u8 *result, size_t len_result);

int ml_kem_get_public_key(
    struct ml_kem_pool_decaps_ctx *pool,
    u8 *buffer_for_public_key, size_t size_buffer);
```

`ml_kem_create_object()` creates a key pair and a reusable decapsulation pool for the selected security level. `create_encaps_pool()` optionally creates reusable encapsulation slots for one or more security levels. Pass `NULL` as the `ctx_pool` argument to `ml_kem_encaps_core()` to encapsulate without a preallocated encapsulation pool.

The `entropy` callback can be `NULL` to use the platform-provided random source. The public key and ciphertext buffer lengths must match the selected ML-KEM level; the shared-secret buffer must be 32 bytes.

## Getting Started

The portable ML-KEM core is located in portable/src/

To build or integrate the library, use one of the available environment-specific ports located in:

portable/ports/

Each port provides its own build system, integration layer, and usage documentation.

## Tests

The test suite for this implementation is located in
[`portable/tests/`](portable/tests/).

For information about the available tests, how to
build and run them, and any test-specific requirements,
refer to the README in that directory.

## License

This project is dual-licensed under:

- GNU General Public License v2.0
- MIT License

You may choose either license.

---

## 📬 Contact

- GitHub: https://github.com/kstzv
- Email: kstzavertaylo@gmail.com

