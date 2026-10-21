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
struct ml_kem_general_keys_decaps_ctx *ml_kem_create_object(enum ml_kem_k level, size_t ml_kem_pool_count, ml_kem_entropy_fn entropy);

// This function creates a global key and decapsulation context based on a received message containing a private key. The message format must comply with the standard
// Parametrs:
	// 1. Pointer to buffer with message sk
	// 2. Buffer size from the previous parameter
	// 3. Buffer for maximum execution parallelism per key during decapsulation (if parallelism within the decapsulation stream is not required, specify 1 as the default)
// Return:
	// `struct ml_kem_general_keys_decaps_ctx *` structure of the global context for keys and decapsulation
struct ml_kem_general_keys_decaps_ctx *ml_kem_create_object_from_imported_sk(u8 *sk, size_t size_sk, size_t size_pool);

// Destroy decapsulation pool object.
// Parameters:
//  ctx_pool - previously created pool context
// Behavior:
//  - Wipes sensitive data
//  - Frees all associated memory
// Safe to call with NULL.
void ml_kem_destroy_core(struct ml_kem_general_keys_decaps_ctx *ctx_pool);

// Encapsulation core (client-side API)
// Parameters:
//  ctx_pool  - optional reusable encapsulation pool; NULL to use a temporary context
//  pk        - serialized public key used for encapsulation
//  size_pk   - size of the public key (must match the ML-KEM security level)
//  buffer_ct - output buffer for the generated ciphertext
//  size_ct   - size of the ciphertext buffer (must match the security level)
//  buffer_ss - output buffer for the derived 32-byte shared secret
//  size_ss   - size of the shared secret buffer (must be ML_KEM_SEED_BYTES)
//  entropy   - callback used to obtain cryptographically secure random bytes;
//              NULL to use the operating system random source
// Returns:
//  0 on success
//  -ML_KEM_EINVAL on invalid pointers, buffer sizes, or pool configuration
//  -ML_KEM_ENOMEM if temporary context allocation fails
//  -EBUSY if no free slot is available in the selected pool
//  Other error codes propagated from the encapsulation routine (e.g., entropy failure)
int ml_kem_encaps_core(struct ml_kem_pool_encaps_ctx *ctx_pool, u8 *pk, size_t size_pk, u8 *buffer_ct, size_t size_ct, u8 *buffer_ss, size_t size_ss, ml_kem_entropy_fn entropy);

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
int ml_kem_decaps_core(struct ml_kem_general_keys_decaps_ctx *pool, u8 *ciphertext, size_t len_ciphertext, u8 *result, size_t len_result);

// Gets the public key
// Parameters:
// -pool           			- initialized decapsulation pool (contains the PK within the structure hierarchy)
// -buffer_for_public_key   - buffer where the PK will be copied
// -size_buffer      		- size of the buffer (must conform to the ML-KEM security level)
int ml_kem_get_public_key(struct ml_kem_general_keys_decaps_ctx *pool, u8 *buffer_for_public_key, size_t size_buffer);

// Function for retrieving a private key in a standard-compliant format
// Parametrs:
	// 1. Structure of the global context for keys and decapsulation
	// 2. Pointer to buffer for message sk
	// 3. Buffer size from the previous parameter
// Return:
	// Type int, number of bytes written to the buffer or an error code
int ml_kem_get_sk(struct ml_kem_general_keys_decaps_ctx *ctx, u8 *buffer_for_sk, size_t size_buffer_for_sk);

// Create and initialize a reusable encapsulation pool
// Parameters:
//  number_slots_512  - number of slots for ML-KEM-512 (0 disables this level)
//  number_slots_768  - number of slots for ML-KEM-768 (0 disables this level)
//  number_slots_1024 - number of slots for ML-KEM-1024 (0 disables this level)
// Returns:
//  Pointer to the initialized encapsulation pool on success
//  Error result from err_create_encaps_pool() on failure (NULL in the userspace port)
struct ml_kem_pool_encaps_ctx *create_encaps_pool(size_t number_slots_512, size_t number_slots_768, size_t number_slots_1024);

// Destroy a reusable encapsulation pool and release its allocated memory.
// Parameters:
//  ctx - encapsulation pool created by create_encaps_pool()
// Returns:
//  Nothing (void)
void ml_kem_encaps_pool_destroy(struct ml_kem_pool_encaps_ctx *ctx);

#ifdef ML_KEM_DUDECT_TEST 

// INTERNAL FUNCTIONS EXPOSED FOR TESTING
// The following functions are normally declared as `static` in their respective compilation units
// It is exposed here ONLY for dudect-based constant-time analysis
// WARNING: 1. Not part of the public API; 2. Not intended for external use;

// Forward declarations of local function in this module
void ml_kem_decaps_ct_select_ss(struct ml_kem_general_keys_decaps_ctx *pool, u8 *ciphertext, size_t len_ciphertext, u8 *result, size_t curr_slot);

// Function for packing a secret vector
STATIC size_t get_s_vector(const u16 *secret, u8 *buffer, enum ml_kem_k k);

// Function for unpacking a secret vector
STATIC size_t unpack_s_vector(u16 *secret, u8 *buffer, enum ml_kem_k k);

#endif // ML_KEM_DUDECT_TEST

#endif

