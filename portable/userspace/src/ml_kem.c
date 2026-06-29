// SPDX-License-Identifier: GPL-2.0 OR MIT
// Copyright (c) 2026 K.S.Zavertailo

#include <stdlib.h>   // malloc, free
#include <string.h>   // memcpy
#include "ml_kem.h"

// Forward declarations of public API functions (redeclared for internal usage)
struct ml_kem_pool_decaps_ctx *ml_kem_create_object(enum ml_kem_k level, size_t ml_kem_pool_count, ml_kem_entropy_fn entropy);
void ml_kem_destroy_core(struct ml_kem_pool_decaps_ctx *ctx_pool);
u8 *ml_kem_encaps_core(u8 *pk, enum ml_kem_k level, u8 *result, ml_kem_entropy_fn entropy);
void ml_kem_ciphertext_destroy_core(u8 *ciphertext, enum ml_kem_k level);
int ml_kem_decaps_core(struct ml_kem_pool_decaps_ctx *pool, u8 *ciphertext, size_t len_ciphertext, u8 *result, size_t len_result);

// Forward declarations of local function in this module
STATIC void ml_kem_decaps_ct_select_ss(struct ml_kem_pool_decaps_ctx *pool, u8 *ciphertext, size_t len_ciphertext, u8 *result, size_t curr_slot);

// Full initialization routine:
//  - Generates ML-KEM keypair
//  - Allocates and initializes decapsulation pool
// Parameters:
//  level              - security level (ML_KEM_512 / 768 / 1024)
//  ml_kem_pool_count  - number of parallel decapsulation slots
//  entropy - callback used to obtain cryptographically secure random bytes. Pass NULL to use the operating system random source
// Returns:
//  Pointer to initialized pool context on success, NULL on failure.
// Notes:
//  - Pool defines maximum parallel decapsulation operations for a single keypair
//  - All key material is stored inside ctx_keys and shared across pool slots
struct ml_kem_pool_decaps_ctx *ml_kem_create_object(enum ml_kem_k level, size_t ml_kem_pool_count, ml_kem_entropy_fn entropy)
{
	// Validate security level
	if(level != ML_KEM_512 && level != ML_KEM_768 && level != ML_KEM_1024)
	{ return NULL; }
	
	// Validate pool size (parallelism bound)
	if(ml_kem_pool_count == 0 || ml_kem_pool_count > ML_KEM_MAX_POOL_SLOTS)
	{ return NULL; }
	
	// Key generation structures:
	// temp_keys - temporary (wiped after use)
	// ctx_keys  - persistent (stored inside pool)
	struct ml_kem_temp *temp_keys;
	struct ml_kem_ctx *ctx_keys;
	
	// Allocate persistent key context
	ctx_keys = ml_kem_ctx_alloc(level);
	if(!ctx_keys) { return NULL; }
	
	// Allocate temporary key generation context
	temp_keys = ml_kem_temp_alloc(level);
	if(!temp_keys) { goto error_exit; }
	
	// Generate keypair
	int ret = ml_kem_create_ctx_struct(temp_keys, ctx_keys, entropy);
	if(ret != 0) 
	{ 
		ml_kem_destroy_temp_struct(temp_keys); 
		goto error_exit; 
	}
	
	// Wipe and destroy temporary key material (no longer needed)
	ml_kem_destroy_temp_struct(temp_keys);
	
	// Allocate decapsulation pool (contains encaps + decrypt contexts per slot)
	struct ml_kem_pool_decaps_ctx *ctx_pool;
	ctx_pool = ml_kem_alloc_decaps_pool(level, ml_kem_pool_count, ctx_keys);
	if(!ctx_pool) { goto error_exit; }
	
	return ctx_pool;
	
	// Error path: destroy persistent keys
	error_exit:
		ml_kem_destroy_ctx_struct(ctx_keys);
		return NULL;
}

// Full destructor:
//  - Destroys decapsulation pool
//  - Securely wipes and frees all associated key material
// Parameters:
//  ctx_pool - pool returned by ml_kem_create_object()
// Notes:
//  - Safe to call with NULL
//  - Assumes all slots share the same key context
void ml_kem_destroy_core(struct ml_kem_pool_decaps_ctx *ctx_pool)
{
	if(!ctx_pool) { return; }
	
	struct ml_kem_ctx *keys;
	keys = ctx_pool->ml_kem_pool[0].decrypt_ctx->ctx;
	
	// Destroy pool (includes slot cleanup and memory release)
	ml_kem_pool_destroy(ctx_pool);
	
	// Destroy shared key material
	if(keys) { ml_kem_destroy_ctx_struct(keys); }
}

// Encapsulation wrapper (client-side, one-shot API)
// Parameters:
//  pk     - public key in serialized byte format (as defined by ML-KEM spec)
//  level  - security level (ML_KEM_512 / 768 / 1024)
//  result - output buffer (32 bytes) for shared secret (K_bar)
//  entropy - callback used to obtain cryptographically secure random bytes. Pass NULL to use the operating system random source
// Returns:
//  Pointer to newly allocated ciphertext buffer (serialized format),
//  or NULL on failure.
// Memory ownership:
//  - Returned ciphertext MUST be freed by caller using ml_kem_ciphertext_destroy_core()
//  - 'result' buffer is fully overwritten
// Notes:
//  - This is a high-level convenience wrapper over ml_kem_encapsulation()
//  - Internally allocates temporary context which is securely wiped before free
//  - No secret-dependent branching occurs in this wrapper
u8 *ml_kem_encaps_core(u8 *pk, enum ml_kem_k level, u8 *result, ml_kem_entropy_fn entropy)
{
	// Result pointer initialized to NULL (returned on failure)
	u8 *ciphertext;
	ciphertext = NULL;
	
	// Validate security level
	if(!(level == ML_KEM_512 || level == ML_KEM_768 || level == ML_KEM_1024))
	{ return ciphertext; }
	
	// Validate input pointers
	if(!pk || !result) { return ciphertext; }
	// Clear output buffer (defensive initialization)
	ml_kem_memzero(result, ML_KEM_SEED_BYTES);
		
	// Allocate encapsulation context
	struct ml_kem_encaps_ctx *ctx;
	ctx = ml_kem_alloc_encaps(pk, level);
	if(!ctx) { return ciphertext; }
	
	// Perform encapsulation (client mode: msg=NULL, hash_pk=NULL)
	ml_kem_encapsulation(ctx, NULL, NULL, entropy);
	if(!ctx) { goto exit; }
	
	// Allocate memory for final ciphertext
	ciphertext = malloc(ctx->ciphertext_len);
	if(!ciphertext) { goto exit; }
	// Initialize ciphertext buffer
	ml_kem_memzero(ciphertext, ctx->ciphertext_len);
	
	// Copy outputs:
	//  - shared secret (K_bar) → result buffer
	//  - serialized ciphertext → allocated buffer
	memcpy(result, ctx->K_bar, ML_KEM_SEED_BYTES);
	memcpy(ciphertext, ctx->ciphertext, ctx->ciphertext_len); 
	
	// Exit path:
	//  - on failure: ciphertext == NULL, result is zeroed
	//  - on success: ciphertext contains valid data
	exit:
		ml_kem_wipe_encaps(ctx);     // wipe sensitive data
		ml_kem_destroy_encaps(ctx);  // free context
		return ciphertext;
}

// Ciphertext destructor (client-side)
// Parameters:
//  ciphertext - buffer returned by ml_kem_encaps_core()
//  level      - security level used during encapsulation
// Behavior:
//  - Securely wipes ciphertext contents
//  - Frees allocated memory
// Notes:
//  - Safe to call with NULL
//  - Does nothing if level is invalid
//  - Ciphertext size depends on ML-KEM level
void ml_kem_ciphertext_destroy_core(u8 *ciphertext, enum ml_kem_k level)
{
	// Validate pointer
	if(!ciphertext) { return; }
	
	// Determine ciphertext length based on security level
	size_t len;
	if(level == ML_KEM_512) { len = LEN_CIPHERTEXT_512; }
	else if(level == ML_KEM_768) { len = LEN_CIPHERTEXT_768; }
	else if(level == ML_KEM_1024) { len = LEN_CIPHERTEXT_1024; }
	else { return; }
	
	// Secure wipe and free
	ml_kem_memzero(ciphertext, len);
	free(ciphertext);
}

// Decapsulation core (server-side API)
// Parameters:
//  pool           - initialized decapsulation pool (shared key + slot contexts)
//  ciphertext     - input ciphertext (serialized format)
//  len_ciphertext - length of ciphertext (must match level)
//  result         - output buffer (32 bytes) for shared secret
//  len_result     - size of result buffer (must be ML_KEM_SEED_BYTES)
// Returns:
//  0 on success
//  -EINVAL on invalid input
//  -EBUSY if no free slot is available (caller should retry)
// Behavior:
//  - Acquires a free slot from pool (lock-free, atomic)
//  - Performs decrypt → re-encapsulate → compare (per ML-KEM spec)
//  - Returns either real shared secret or fallback (z-based) value
//  - Ensures constant-time selection between valid/invalid paths
// Security notes:
//  - No secret-dependent branching in critical path
//  - Ciphertext comparison is done in constant time
//  - Final key selection uses bitwise masking (no branches)
//  - All sensitive buffers are wiped before releasing slot
int ml_kem_decaps_core(struct ml_kem_pool_decaps_ctx *pool, u8 *ciphertext, size_t len_ciphertext, u8 *result, size_t len_result)
{
	// Validate input pointers
	if (!ciphertext || !result) { return -EINVAL; }
	
	// Validate pool and slot array
	if(!pool || !pool->ml_kem_pool) { return -EINVAL; }
	
	// Validate internal pool memory regions (must be preallocated)
	if(!pool->ciphertexts_mem_ptr || !pool->public_key_msgs_mem_ptr || !pool->decrypt_mem_ptr || !pool->encaps_mem_ptr) { return -EINVAL; }
	
	// Validate output buffer size
	if(len_result != ML_KEM_SEED_BYTES) { return -EINVAL; }
	
	// Validate ciphertext length against pool configuration
	if(len_ciphertext != pool->ml_kem_pool[0].decrypt_ctx->ciphertext_len)
	{ return -EINVAL; }
	
	// Acquire a free slot (lock-free)
	size_t curr_slot = ML_KEM_MAX_POOL_SLOTS + 1;
	for(size_t i = 0; i < pool->ml_kem_pool_count; i++)
	{
		bool acquired;
		acquired = try_acquire_slot(&pool->ml_kem_pool[i].is_free);
		
		// Stop at first successfully acquired slot
		if(acquired) { curr_slot = i; break; }
	}
	
	// If no slot available → caller must retry later
	if(curr_slot == ML_KEM_MAX_POOL_SLOTS + 1) { return -EBUSY; }
	
	// Step 1: Decrypt ciphertext → recover message m
	ml_kem_decrypt(pool->ml_kem_pool[curr_slot].decrypt_ctx, ciphertext);
	
	// Step 2: Re-encapsulate using recovered m and stored h(pk)
	// This reconstructs expected ciphertext and shared secret
	ml_kem_encapsulation(pool->ml_kem_pool[curr_slot].encaps_ctx, pool->ml_kem_pool[curr_slot].decrypt_ctx->m, pool->ml_kem_pool[curr_slot].decrypt_ctx->ctx->h_pk, NULL);
	
	// Steps from 3 to 6 doing in this local functions. This functions must be CT
	ml_kem_decaps_ct_select_ss(pool, ciphertext, len_ciphertext, result, curr_slot);
	
	// Step 7: Wipe sensitive data in slot contexts
	ml_kem_wipe_encaps(pool->ml_kem_pool[curr_slot].encaps_ctx);
	ml_kem_wipe_decrypt(pool->ml_kem_pool[curr_slot].decrypt_ctx);
	
	// Release slot (atomic)
	atomic_store_explicit(&pool->ml_kem_pool[curr_slot].is_free, 1, memory_order_release);
	
	return 0;
}

// Function to check the coincidence of ciphertexts after decrypt and re-encaps	
STATIC void ml_kem_decaps_ct_select_ss(struct ml_kem_pool_decaps_ctx *pool, u8 *ciphertext, size_t len_ciphertext, u8 *result, size_t curr_slot)
{
	// Step 3: Precompute fallback shared secret (z || c) → SHAKE256
	// Used if ciphertext verification fails (CCA security requirement)
	u8 hash_z[ML_KEM_SEED_BYTES];
	memcpy(pool->ml_kem_pool[curr_slot].kdf_buf, pool->ml_kem_pool[curr_slot].decrypt_ctx->ctx->z, ML_KEM_SEED_BYTES);
	memcpy(pool->ml_kem_pool[curr_slot].kdf_buf + ML_KEM_SEED_BYTES, ciphertext, len_ciphertext);
	ml_kem_shake256(hash_z, ML_KEM_SEED_BYTES, pool->ml_kem_pool[curr_slot].kdf_buf, ML_KEM_SEED_BYTES + len_ciphertext);
	
	// Step 4: Constant-time ciphertext comparison
	u32 value = 0;

	for(size_t i = 0; i < len_ciphertext; i++)
	{
		u32 x = (u32)ciphertext[i];
		u32 y = (u32)pool->ml_kem_pool[curr_slot].encaps_ctx->ciphertext[i];
	
		value |= (x ^ y);
	}
	
	value = (value >> 16) | value;
	value = (value >> 8)  | value;
	value = (value >> 4)  | value;
	value = (value >> 2)  | value;
	value = (value >> 1)  | value;

	u32 fail = value & 1u;

	u8 mask = (u8)(0u - fail);
	u8 inv  = (u8)~mask;
	
	// Step 5: Constant-time selection of output key
	//  - if valid: return K_bar
	//  - if invalid: return fallback hash_z
	for (size_t i = 0; i < ML_KEM_SEED_BYTES; i++) 
	{
		result[i] = (pool->ml_kem_pool[curr_slot].encaps_ctx->K_bar[i] & inv) | (hash_z[i] & mask);
	}
	
	// Step 6: Wipe local buffers
	ml_kem_memzero(hash_z, ML_KEM_SEED_BYTES);
	ml_kem_memzero(pool->ml_kem_pool[curr_slot].kdf_buf, ML_KEM_SEED_BYTES + len_ciphertext);
}
	
	
	
