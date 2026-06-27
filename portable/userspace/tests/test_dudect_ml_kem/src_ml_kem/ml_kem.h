// SPDX-License-Identifier: GPL-2.0 OR MIT
// Copyright (c) 2026 K.S.Zavertailo

#ifndef ML_KEM_H
#define ML_KEM_H

#include "ml_kem_core_header.h"

// Public ML-KEM API
// This interface provides a minimal, allocation-aware API for:
//  - key encapsulation (client side)
//  - key decapsulation (server side, via slot pool)
// Design notes:
//  - All cryptographic operations follow ML-KEM (FIPS 203)
//  - Decapsulation uses a preallocated pool for concurrency and performance
//  - Sensitive data is internally wiped where applicable

// Create decapsulation pool object.
// Parameters:
//  level              - ML-KEM security level (ML_KEM_512 / 768 / 1024)
//  ml_kem_pool_count  - number of decapsulation slots in pool
//  entropy - callback used to obtain cryptographically secure random bytes. Pass NULL to use the operating system random source
// Returns:
//  Pointer to initialized pool context on success
//  NULL on allocation or initialization failure
// Notes:
//  - The pool holds all persistent and per-slot contexts
//  - Intended for repeated decapsulation operations
struct ml_kem_pool_decaps_ctx *ml_kem_create_object(enum ml_kem_k level, size_t ml_kem_pool_count, ml_kem_entropy_fn entropy);


// Destroy decapsulation pool object.
// Parameters:
//  ctx_pool - previously created pool context
// Behavior:
//  - Wipes sensitive data
//  - Frees all associated memory
// Safe to call with NULL.
void ml_kem_destroy_core(struct ml_kem_pool_decaps_ctx *ctx_pool);


// Perform encapsulation (client-side).
// Parameters:
//  pk      - public key (serialized, standard format)
//  level   - ML-KEM security level
// Returns:
//  Pointer to allocated ciphertext buffer on success
//  NULL on failure
// Notes:
//  - Caller is responsible for freeing ciphertext via
//    ml_kem_ciphertext_destroy_core()
//  - Result buffer is always zero-initialized before use
u8 *ml_kem_encaps_core(u8 *pk, enum ml_kem_k level, u8 *result, ml_kem_entropy_fn entropy);


// Destroy ciphertext buffer returned by encapsulation.
// Parameters:
//  ciphertext - ciphertext buffer returned by ml_kem_encaps_core()
//  level      - ML-KEM security level (used to determine size)
// Behavior:
//  - Wipes ciphertext contents
//  - Frees memory
// Safe to call with NULL.
void ml_kem_ciphertext_destroy_core(u8 *ciphertext, enum ml_kem_k level);


// Perform decapsulation (server-side).
// Parameters:
//  pool           - decapsulation pool object
//  ciphertext     - input ciphertext (serialized)
//  len_ciphertext - ciphertext length (must match level)
//  result         - output buffer (must be 32 bytes)
//  len_result     - size of result buffer
// Returns:
// 0 on success
//  -EINVAL on invalid input
// -EBUSY if no free slot is available (caller should retry)
// Notes:
//  - Thread-safe via slot pool (lock-free acquisition)
//  - Implements full ML-KEM decapsulation flow:
//      decrypt → re-encapsulate → verify → constant-time select
//  - Output is always written in constant time
int ml_kem_decaps_core(struct ml_kem_pool_decaps_ctx *pool, u8 *ciphertext, size_t len_ciphertext, u8 *result, size_t len_result);

// INTERNAL FUNCTION EXPOSED FOR TESTING
// The following function are normally declared as `static` in their respective compilation units
// It is exposed here ONLY for dudect-based constant-time analysis
// WARNING: 1. Not part of the public API; 2. Not intended for external use;
void ml_kem_decaps_ct_select_ss(struct ml_kem_pool_decaps_ctx *pool, u8 *ciphertext, size_t len_ciphertext, u8 *result, size_t curr_slot);

#endif
