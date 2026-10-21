// SPDX-License-Identifier: GPL-2.0 OR MIT
// Copyright (c) 2026 K.S.Zavertailo

#include "ml_kem.h"

// Forward declarations of public API functions (redeclared for internal usage)
struct ml_kem_general_keys_decaps_ctx *ml_kem_create_object(enum ml_kem_k level, size_t ml_kem_pool_count, ml_kem_entropy_fn entropy);
struct ml_kem_general_keys_decaps_ctx *ml_kem_create_object_from_imported_sk(u8 *sk, size_t size_sk, size_t size_pool);
void ml_kem_destroy_core(struct ml_kem_general_keys_decaps_ctx *ctx_pool);
int ml_kem_encaps_core(struct ml_kem_pool_encaps_ctx *ctx_pool, u8 *pk, size_t size_pk, u8 *buffer_ct, size_t size_ct, u8 *buffer_ss, size_t size_ss, ml_kem_entropy_fn entropy);
int ml_kem_decaps_core(struct ml_kem_general_keys_decaps_ctx *pool, u8 *ciphertext, size_t len_ciphertext, u8 *result, size_t len_result);
int ml_kem_get_public_key(struct ml_kem_general_keys_decaps_ctx *pool, u8 *buffer_for_public_key, size_t size_buffer);
int ml_kem_get_sk(struct ml_kem_general_keys_decaps_ctx *ctx, u8 *buffer_for_sk, size_t size_buffer_for_sk);
struct ml_kem_pool_encaps_ctx *create_encaps_pool(size_t number_slots_512, size_t number_slots_768, size_t number_slots_1024);
void ml_kem_encaps_pool_destroy(struct ml_kem_pool_encaps_ctx *ctx);

// Forward declarations of local function in this module
STATIC void ml_kem_decaps_ct_select_ss(struct ml_kem_general_keys_decaps_ctx *pool, u8 *ciphertext, size_t len_ciphertext, u8 *result, size_t curr_slot);

// Function for packing a secret vector
STATIC size_t get_s_vector(const u16 *secret, u8 *buffer, enum ml_kem_k k);

// Function for unpacking a secret vector
STATIC size_t unpack_s_vector(u16 *secret, u8 *buffer, enum ml_kem_k k);

// Check coefs pk
STATIC bool ml_kem_validate_pk(const u8 *pk, size_t size_pk);

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
struct ml_kem_general_keys_decaps_ctx *ml_kem_create_object(enum ml_kem_k level, size_t ml_kem_pool_count, ml_kem_entropy_fn entropy)
{
	// Validate security level
	if(level != ML_KEM_512 && level != ML_KEM_768 && level != ML_KEM_1024)
	{ return err_create_keys(-ML_KEM_EINVAL); }
	
	// Validate pool size (parallelism bound)
	if(ml_kem_pool_count == 0 || ml_kem_pool_count > ML_KEM_MAX_POOL_SLOTS)
	{ return err_create_keys(-ML_KEM_EINVAL); }
	
	// Key generation structures:
	// temp_keys - temporary (wiped after use)
	// ctx_keys  - persistent (stored inside pool)
	struct ml_kem_temp *temp_keys;
	struct ml_kem_ctx *ctx_keys;
	
	// Allocate persistent key context
	ctx_keys = ml_kem_ctx_alloc(level);
	if(!ctx_keys) { return err_create_keys(-ML_KEM_ENOMEM); }
	
	int ret;
	
	// Allocate temporary key generation context
	temp_keys = ml_kem_temp_alloc(level);
	if(!temp_keys) { ret = -ML_KEM_ENOMEM; goto error_exit; }
	
	// Generate keypair
	ret = ml_kem_create_ctx_struct(temp_keys, ctx_keys, entropy);
	if(ret != 0) 
	{ 
		ml_kem_destroy_temp_struct(temp_keys); 
		goto error_exit; 
	}
	
	// Wipe and destroy temporary key material (no longer needed)
	ml_kem_destroy_temp_struct(temp_keys);
	
	// Allocate decapsulation pool (contains encaps + decrypt contexts per slot)
	struct ml_kem_general_keys_decaps_ctx *ctx_pool;
	ctx_pool = ml_kem_alloc_decaps_pool(level, ml_kem_pool_count, ctx_keys);
	if(!ctx_pool) { ret = -ML_KEM_ENOMEM; goto error_exit; }
	
	return ctx_pool;
	
	// Error path: destroy persistent keys
	error_exit:
		ml_kem_destroy_ctx_struct(ctx_keys);
		return err_create_keys(ret);
}

// This function creates a global key and decapsulation context based on a received message containing a private key. The message format must comply with the standard
// Parametrs:
	// 1. Pointer to buffer with message sk
	// 2. Buffer size from the previous parameter
	// 3. Buffer for maximum execution parallelism per key during decapsulation (if parallelism within the decapsulation stream is not required, specify 1 as the default)
// Return:
	// `struct ml_kem_general_keys_decaps_ctx *` structure of the global context for keys and decapsulation
struct ml_kem_general_keys_decaps_ctx *ml_kem_create_object_from_imported_sk(u8 *sk, size_t size_sk, size_t size_pool)
{
	// Check size pool
	if(size_pool == 0 || size_pool > ML_KEM_MAX_POOL_SLOTS) { return err_create_object_from_imported_sk(-ML_KEM_EINVAL); }
	
	if(!sk) { return err_create_object_from_imported_sk(-ML_KEM_EINVAL); }
	
	// Determination of the security level
	enum ml_kem_k k;
	size_t size_pk;
	if(size_sk == LEN_SK_512)
	{
		k = ML_KEM_512;
		size_pk = RES_PUBL_PART_LVL_512;
	}else if(size_sk == LEN_SK_768)
	{
		k = ML_KEM_768;
		size_pk = RES_PUBL_PART_LVL_768;
	}else if(size_sk == LEN_SK_1024)
	{
		k = ML_KEM_1024;
		size_pk = RES_PUBL_PART_LVL_1024;
	}else { return err_create_object_from_imported_sk(-ML_KEM_EINVAL); }
	
	// Memory allocation for keys
	struct ml_kem_ctx *ctx_keys;
	ctx_keys = ml_kem_ctx_alloc(k);
	if(!ctx_keys) { return err_create_object_from_imported_sk(-ML_KEM_ENOMEM); }
	
	// Get secret vector
	size_t buff_ctr = unpack_s_vector(ctx_keys->secret, sk, k);
	
	// Copy pk messege
	memcpy(ctx_keys->public_key_msg, sk + buff_ctr, size_pk);
	buff_ctr += size_pk;
	
	// Copy seed matrix
	memcpy(ctx_keys->seed_rho, ctx_keys->public_key_msg + (size_pk - ML_KEM_SEED_BYTES), ML_KEM_SEED_BYTES);
	
	// Copy hash pk
	memcpy(ctx_keys->h_pk, sk + buff_ctr, ML_KEM_SEED_BYTES);
	buff_ctr += ML_KEM_SEED_BYTES;
	
	// Copy z
	memcpy(ctx_keys->z, sk + buff_ctr, ML_KEM_SEED_BYTES);
	buff_ctr += ML_KEM_SEED_BYTES;
	
	ctx_keys->k = k;
	ctx_keys->public_key_msg_len = size_pk;
	
	// Check hash in sk messege
	u8 computed_hash[ML_KEM_SEED_BYTES];
	ml_kem_sha3_256(computed_hash, ctx_keys->public_key_msg, size_pk);
	if(memcmp(computed_hash, ctx_keys->h_pk, ML_KEM_SEED_BYTES) != 0)
	{
		ml_kem_memzero(computed_hash, sizeof(computed_hash));
		ml_kem_destroy_ctx_struct(ctx_keys);
		return err_create_object_from_imported_sk(-ML_KEM_EINVAL);
	}
	ml_kem_memzero(computed_hash, ML_KEM_SEED_BYTES);
	
	// Check coefficients in pk
	if(ml_kem_validate_pk(ctx_keys->public_key_msg, ctx_keys->public_key_msg_len) == 0)
	{
		ml_kem_destroy_ctx_struct(ctx_keys);
		return err_create_object_from_imported_sk(-ML_KEM_EINVAL);
	}

	// Create pool(global context)
	struct ml_kem_general_keys_decaps_ctx *global_ctx;
	global_ctx = ml_kem_alloc_decaps_pool(k, size_pool, ctx_keys);
	if(!global_ctx) { ml_kem_destroy_ctx_struct(ctx_keys); return err_create_object_from_imported_sk(-ML_KEM_ENOMEM); }
	
	return global_ctx;
}

// Full destructor:
//  - Destroys decapsulation pool
//  - Securely wipes and frees all associated key material
// Parameters:
//  ctx_pool - pool returned by ml_kem_create_object()
// Notes:
//  - Safe to call with NULL
//  - Assumes all slots share the same key context
void ml_kem_destroy_core(struct ml_kem_general_keys_decaps_ctx *ctx_pool)
{
	if(!ctx_pool) { return; }
	
	struct ml_kem_ctx *keys;
	keys = ctx_pool->ml_kem_pool[0].decrypt_ctx->ctx;
	
	// Destroy pool (includes slot cleanup and memory release)
	ml_kem_pool_destroy(ctx_pool);
	
	// Destroy shared key material
	if(keys) { ml_kem_destroy_ctx_struct(keys); }
}

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
// Behavior:
//  - Selects the ML-KEM security level from public key, ciphertext, and secret sizes
//  - Uses a newly allocated context when ctx_pool is NULL
//  - Otherwise acquires a reusable slot in the pool corresponding to the selected level
//  - Copies the ciphertext and shared secret to caller-provided buffers on success
//  - Wipes working data and destroys the temporary context or releases the pool slot
// Notes:
//  - The caller must provide valid buffers with the specified sizes
//  - In pool mode, the selected security level must have an initialized subpool
int ml_kem_encaps_core(struct ml_kem_pool_encaps_ctx *ctx_pool, u8 *pk, size_t size_pk, u8 *buffer_ct, size_t size_ct, u8 *buffer_ss, size_t size_ss, ml_kem_entropy_fn entropy)
{
	// Validate mandatory input and output pointers
	if(!pk || !buffer_ct || !buffer_ss) { return err_encaps(-ML_KEM_EINVAL); }
	
	// Prepare context and pool slot selection
	enum ml_kem_k level;
	struct ml_kem_encaps_ctx *ctx = NULL;
	struct ml_kem_encaps_slot *slot = NULL;
	size_t curr_slot = ML_KEM_MAX_POOL_SLOTS + 1;
	// Standalone mode: determine the level and allocate a temporary context
	if(!ctx_pool)
	{
		if(size_pk == RES_PUBL_PART_LVL_512 && size_ct == LEN_CIPHERTEXT_512 && size_ss == ML_KEM_SEED_BYTES) { level = ML_KEM_512; }
		else if(size_pk == RES_PUBL_PART_LVL_768 && size_ct == LEN_CIPHERTEXT_768 && size_ss == ML_KEM_SEED_BYTES) { level = ML_KEM_768; }
		else if(size_pk == RES_PUBL_PART_LVL_1024 && size_ct == LEN_CIPHERTEXT_1024 && size_ss == ML_KEM_SEED_BYTES) { level = ML_KEM_1024; }
		else { return err_encaps(-ML_KEM_EINVAL); }
		
		ctx = ml_kem_alloc_encaps(pk, level);
		if(!ctx) { return err_encaps(-ML_KEM_ENOMEM); }
	}else
	{
		// Pool mode: select the matching set of reusable encapsulation slots
		size_t size_pool; 
		if(size_pk == RES_PUBL_PART_LVL_512 && size_ct == LEN_CIPHERTEXT_512 && size_ss == ML_KEM_SEED_BYTES) 
		{ 
			slot = ctx_pool->ml_kem_pool_512;
			size_pool = ctx_pool->ml_kem_pool_count_512; 
		}else if(size_pk == RES_PUBL_PART_LVL_768 && size_ct == LEN_CIPHERTEXT_768 && size_ss == ML_KEM_SEED_BYTES) 
		{ 
			slot = ctx_pool->ml_kem_pool_768;
			size_pool = ctx_pool->ml_kem_pool_count_768; 
		} else if(size_pk == RES_PUBL_PART_LVL_1024 && size_ct == LEN_CIPHERTEXT_1024 && size_ss == ML_KEM_SEED_BYTES) 
		{ 
			slot = ctx_pool->ml_kem_pool_1024;
			size_pool = ctx_pool->ml_kem_pool_count_1024; 
		}else { return err_encaps(-ML_KEM_EINVAL); }
		
		// Reject an absent or incorrectly sized subpool
		if(!slot || size_pool == 0 || size_pool > ML_KEM_MAX_POOL_SLOTS) { return err_encaps(-ML_KEM_EINVAL); }
		// Acquire a free slot (lock-free)
		for(size_t i = 0; i < size_pool; i++)
		{
			bool acquired;
			acquired = ml_kem_try_acquire_slot(&slot[i].is_free);
			if(acquired) { curr_slot = i; break; }
		}
		
		// If no slot available → caller must retry later
		if(curr_slot == ML_KEM_MAX_POOL_SLOTS + 1) { return err_encaps(-EBUSY); }
		
		// Use the acquired context with the public key supplied for this operation
		ctx = slot[curr_slot].encaps_ctx;
		memcpy(ctx->public_key_msg, pk, size_pk);
	}
	
	// Perform encapsulation (client mode: msg=NULL, hash_pk=NULL)
	int ret = 0;
	ml_kem_encapsulation(ctx, NULL, NULL, entropy);
	if(ctx->err != 0) { ret = err_encaps(ctx->err); goto exit; } 
	
	// Write both output values only after successful encapsulation
	memcpy(buffer_ss, ctx->K_bar, ML_KEM_SEED_BYTES);
	memcpy(buffer_ct, ctx->ciphertext, size_ct);
	
	// Common cleanup path for both success and encapsulation failure
	exit:
		// Wipe temporary cryptographic data before releasing resources
		ml_kem_wipe_encaps(ctx);
		if(!ctx_pool) 
		{ 
			// Standalone mode: free the temporary context
			ml_kem_destroy_encaps(ctx); 
		}else 
		{ 
			// Pool mode: make the acquired slot available for subsequent calls
			ml_kem_release_slot(&slot[curr_slot].is_free); 
			ctx = NULL; 
			slot = NULL; 
		}
		return ret;
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
int ml_kem_decaps_core(struct ml_kem_general_keys_decaps_ctx *pool, u8 *ciphertext, size_t len_ciphertext, u8 *result, size_t len_result)
{
	// Validate input pointers
	if (!ciphertext || !result) { return err_decaps(-EINVAL); }
	
	// Validate pool and slot array
	if(!pool || !pool->ml_kem_pool) { return err_decaps(-EINVAL); }
	
	// Validate internal pool memory regions (must be preallocated)
	if(!pool->ciphertexts_mem_ptr || !pool->public_key_msgs_mem_ptr || !pool->decrypt_mem_ptr || !pool->encaps_mem_ptr) { return err_decaps(-EINVAL); }
	
	// Validate output buffer size
	if(len_result != ML_KEM_SEED_BYTES) { return err_decaps(-EINVAL); }
	
	// Validate ciphertext length against pool configuration
	if(len_ciphertext != pool->ml_kem_pool[0].decrypt_ctx->ciphertext_len)
	{ return err_decaps(-EINVAL); }
	
	// Acquire a free slot (lock-free)
	size_t curr_slot = ML_KEM_MAX_POOL_SLOTS + 1;
	for(size_t i = 0; i < pool->ml_kem_pool_count; i++)
	{
		bool acquired;
		acquired = ml_kem_try_acquire_slot(&pool->ml_kem_pool[i].is_free);
		
		// Stop at first successfully acquired slot
		if(acquired) { curr_slot = i; break; }
	}
	
	// If no slot available → caller must retry later
	if(curr_slot == ML_KEM_MAX_POOL_SLOTS + 1) { return err_decaps(-EBUSY); }
	
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
	ml_kem_release_slot(&pool->ml_kem_pool[curr_slot].is_free);
	
	return 0;
}
	
// Gets the public key
// Parameters:
// -pool           			- initialized decapsulation pool (contains the PK within the structure hierarchy)
// -buffer_for_public_key   - buffer where the PK will be copied
// -size_buffer      		- size of the buffer (must conform to the ML-KEM security level)
int ml_kem_get_public_key(struct ml_kem_general_keys_decaps_ctx *pool, u8 *buffer_for_public_key, size_t size_buffer)
{
	// Validate pool and slot array
	if(!pool || !pool->ml_kem_pool) { return err_get_pk(-EINVAL); }
	
	// Validate internal pool memory regions (must be preallocated)
	if(!pool->ciphertexts_mem_ptr || !pool->public_key_msgs_mem_ptr || !pool->decrypt_mem_ptr || !pool->encaps_mem_ptr) { return err_get_pk(-EINVAL); }
	
	// Validate buffer ptr
	if(!buffer_for_public_key) { return err_get_pk(-EINVAL); }
	
	// Validate size of buffer
	if(pool->ml_kem_pool[0].decrypt_ctx->ctx->public_key_msg_len != size_buffer) { return err_get_pk(-EINVAL); }
	
	// Copy key to buffer
	memcpy(buffer_for_public_key, pool->ml_kem_pool[0].decrypt_ctx->ctx->public_key_msg, pool->ml_kem_pool[0].decrypt_ctx->ctx->public_key_msg_len);
	
	return 0;
}

// Function for retrieving a private key in a standard-compliant format
// Parametrs:
	// 1. Structure of the global context for keys and decapsulation
	// 2. Pointer to buffer for message sk
	// 3. Buffer size from the previous parameter
// Return:
	// Type int, number of bytes written to the buffer or an error code
int ml_kem_get_sk(struct ml_kem_general_keys_decaps_ctx *ctx, u8 *buffer_for_sk, size_t size_buffer_for_sk)
{
	// Check got parametrs
	if(!ctx || !ctx->ml_kem_pool || !ctx->ml_kem_pool->decrypt_ctx || !ctx->ml_kem_pool->decrypt_ctx->ctx 
		|| !ctx->ml_kem_pool->decrypt_ctx->ctx->secret || !ctx->ml_kem_pool->decrypt_ctx->ctx->public_key_msg || !buffer_for_sk) { return err_get_sk(-ML_KEM_EINVAL); }
	
	if(ctx->ml_kem_pool->decrypt_ctx->ctx->k != ML_KEM_512 && ctx->ml_kem_pool->decrypt_ctx->ctx->k != ML_KEM_768 &&
		ctx->ml_kem_pool->decrypt_ctx->ctx->k != ML_KEM_1024) { return err_get_sk(-ML_KEM_EINVAL); }
	
	if(ctx->ml_kem_pool->decrypt_ctx->ctx->k == ML_KEM_512 
		&& (size_buffer_for_sk < LEN_SK_512 
			|| ctx->ml_kem_pool->decrypt_ctx->ctx->public_key_msg_len != RES_PUBL_PART_LVL_512)) { return err_get_sk(-ML_KEM_EINVAL); }
	else if(ctx->ml_kem_pool->decrypt_ctx->ctx->k == ML_KEM_768 
		&& (size_buffer_for_sk < LEN_SK_768
			|| ctx->ml_kem_pool->decrypt_ctx->ctx->public_key_msg_len != RES_PUBL_PART_LVL_768)) { return err_get_sk(-ML_KEM_EINVAL); }
	else if(ctx->ml_kem_pool->decrypt_ctx->ctx->k == ML_KEM_1024 
		&& (size_buffer_for_sk < LEN_SK_1024
			|| ctx->ml_kem_pool->decrypt_ctx->ctx->public_key_msg_len != RES_PUBL_PART_LVL_1024)) { return err_get_sk(-ML_KEM_EINVAL); }
	
	// Get secret vector
	size_t buff_ctr = 0;
	buff_ctr = get_s_vector(ctx->ml_kem_pool->decrypt_ctx->ctx->secret, buffer_for_sk, ctx->ml_kem_pool->decrypt_ctx->ctx->k);
	// Copy pk in bytes format and seed matrix
	memcpy(buffer_for_sk + buff_ctr, ctx->ml_kem_pool->decrypt_ctx->ctx->public_key_msg, ctx->ml_kem_pool->decrypt_ctx->ctx->public_key_msg_len);
	buff_ctr += ctx->ml_kem_pool->decrypt_ctx->ctx->public_key_msg_len;
	// Copy hash pk
	memcpy(buffer_for_sk + buff_ctr, ctx->ml_kem_pool->decrypt_ctx->ctx->h_pk, ML_KEM_SEED_BYTES);
	buff_ctr += ML_KEM_SEED_BYTES;
	// Copy z
	memcpy(buffer_for_sk + buff_ctr, ctx->ml_kem_pool->decrypt_ctx->ctx->z, ML_KEM_SEED_BYTES);
	buff_ctr += ML_KEM_SEED_BYTES;
	
	return (int)buff_ctr;
}

// Create and initialize a reusable encapsulation pool.
// Parameters:
//  number_slots_512  - number of slots for ML-KEM-512 (0 disables this level)
//  number_slots_768  - number of slots for ML-KEM-768 (0 disables this level)
//  number_slots_1024 - number of slots for ML-KEM-1024 (0 disables this level)
// Returns:
//  Pointer to the initialized encapsulation pool on success
//  Error result from err_create_encaps_pool() on failure (NULL in the userspace port)
// Behavior:
//  - Creates separate reusable encapsulation slots for the requested security levels
//  - Allocates per-slot contexts and working buffers for polynomial and byte operations
//  - Initializes atomic slot availability flags through the pool setup routine
//  - Destroys the partially initialized pool if any setup step fails
// Notes:
//  - At least one security level must have a non-zero number of slots
//  - Each security level supports at most ML_KEM_MAX_POOL_SLOTS slots
//  - The caller must destroy the returned pool using ml_kem_encaps_pool_destroy()
struct ml_kem_pool_encaps_ctx *create_encaps_pool(size_t number_slots_512, size_t number_slots_768, size_t number_slots_1024)
{
	// Reject an empty pool configuration
	if(number_slots_512 == 0 && number_slots_768 == 0 && number_slots_1024 == 0) { return err_create_encaps_pool(-ML_KEM_EINVAL); }
	// Validate the maximum number of slots for each security level
	else if(number_slots_512 > ML_KEM_MAX_POOL_SLOTS 
		|| number_slots_768 > ML_KEM_MAX_POOL_SLOTS 
			|| number_slots_1024 > ML_KEM_MAX_POOL_SLOTS) { return err_create_encaps_pool(-ML_KEM_EINVAL); }
			
	// Allocate and zero-initialize the pool descriptor
	struct ml_kem_pool_encaps_ctx *ctx;
	ctx = ml_kem_alloc(sizeof(struct ml_kem_pool_encaps_ctx));
	if(!ctx) { return err_create_encaps_pool(-ML_KEM_ENOMEM); }
	ml_kem_memzero(ctx, sizeof(struct ml_kem_pool_encaps_ctx));
	int ret = 0;
	
	// Initialize the ML-KEM-512 subpool if requested
	if(number_slots_512 != 0)
	{
		// Allocate slot descriptors, contexts, and initialize slot availability
		ret = ml_kem_create_all_structs(ctx, ML_KEM_512, number_slots_512);
		if(ret != 0) {  ml_kem_encaps_pool_destroy(ctx); return err_create_encaps_pool(-ML_KEM_ENOMEM); }
		
		// Allocate and assign per-slot u16 polynomial buffers
		ret = ml_kem_assign_encaps_pool_u16_buffers(ctx, ML_KEM_512, number_slots_512);
		if(ret != 0) { ml_kem_encaps_pool_destroy(ctx); return err_create_encaps_pool(-ML_KEM_ENOMEM); }
		
		// Allocate and assign public key, ciphertext, and XOF byte buffers
		ret = ml_kem_assign_encaps_pool_u8_buffers(ctx, ML_KEM_512, number_slots_512);
		if(ret != 0) { ml_kem_encaps_pool_destroy(ctx); return err_create_encaps_pool(-ML_KEM_ENOMEM); }
	}
	
	// Initialize the ML-KEM-768 subpool if requested
	if(number_slots_768 != 0)
	{
		// Allocate slot descriptors, contexts, and initialize slot availability
		ret = ml_kem_create_all_structs(ctx, ML_KEM_768, number_slots_768);
		if(ret != 0) { ml_kem_encaps_pool_destroy(ctx); return err_create_encaps_pool(-ML_KEM_ENOMEM); }
		
		// Allocate and assign per-slot u16 polynomial buffers
		ret = ml_kem_assign_encaps_pool_u16_buffers(ctx, ML_KEM_768, number_slots_768);
		if(ret != 0) { ml_kem_encaps_pool_destroy(ctx); return err_create_encaps_pool(-ML_KEM_ENOMEM); }
		
		// Allocate and assign public key, ciphertext, and XOF byte buffers
		ret = ml_kem_assign_encaps_pool_u8_buffers(ctx, ML_KEM_768, number_slots_768);
		if(ret != 0) { ml_kem_encaps_pool_destroy(ctx); return err_create_encaps_pool(-ML_KEM_ENOMEM); }
	}
	
	// Initialize the ML-KEM-1024 subpool if requested
	if(number_slots_1024 != 0)
	{
		// Allocate slot descriptors, contexts, and initialize slot availability
		ret = ml_kem_create_all_structs(ctx, ML_KEM_1024, number_slots_1024);
		if(ret != 0) { ml_kem_encaps_pool_destroy(ctx); return err_create_encaps_pool(-ML_KEM_ENOMEM); }
		
		// Allocate and assign per-slot u16 polynomial buffers
		ret = ml_kem_assign_encaps_pool_u16_buffers(ctx, ML_KEM_1024, number_slots_1024);
		if(ret != 0) { ml_kem_encaps_pool_destroy(ctx); return err_create_encaps_pool(-ML_KEM_ENOMEM); }
		
		// Allocate and assign public key, ciphertext, and XOF byte buffers
		ret = ml_kem_assign_encaps_pool_u8_buffers(ctx, ML_KEM_1024, number_slots_1024);
		if(ret != 0) { ml_kem_encaps_pool_destroy(ctx); return err_create_encaps_pool(-ML_KEM_ENOMEM); }
	}
	
	// Return the initialized pool with all requested subpools ready for reuse
	return ctx;
}

// Destroy a reusable encapsulation pool and release its allocated memory.
// Parameters:
//  ctx - encapsulation pool created by create_encaps_pool()
// Returns:
//  Nothing (void)
// Behavior:
//  - Releases the allocated resources of the ML-KEM-512, ML-KEM-768, and ML-KEM-1024 subpools
//  - Wipes encapsulation contexts and contiguous u16/u8 working buffers before freeing them
//  - Frees slot descriptor arrays and the main pool structure
//  - Checks each allocation pointer to support partially initialized pools
// Notes:
//  - Safe to call with NULL
//  - The caller must ensure no other thread is using the pool during destruction
//  - Slot descriptors and the main pool structure are freed without explicit zeroization
void ml_kem_encaps_pool_destroy(struct ml_kem_pool_encaps_ctx *ctx)
{
	// No resources to release if the pool pointer is NULL
	if(!ctx) { return; }
	
	// Destroy the ML-KEM-512 subpool
	// Wipe and free its contiguous array of encapsulation contexts
	if(ctx->ml_kem_pool_512 && ctx->ml_kem_pool_512->encaps_ctx) 
	{ 
		ml_kem_memzero(ctx->ml_kem_pool_512->encaps_ctx, sizeof(struct ml_kem_encaps_ctx) * ctx->ml_kem_pool_count_512);
		ml_kem_free(ctx->ml_kem_pool_512->encaps_ctx); 
	}
	
	// Free the slot descriptor array
	if(ctx->ml_kem_pool_512) { ml_kem_free(ctx->ml_kem_pool_512); }
	
	// Wipe and free the contiguous u16 polynomial working buffers
	if(ctx->all_u16_mem_512) 
	{ 
		ml_kem_memzero(ctx->all_u16_mem_512, (sizeof(u16) * (ML_KEM_512 * 3 + 2) * ML_KEM_N) * ctx->ml_kem_pool_count_512);
		ml_kem_free(ctx->all_u16_mem_512); 
	}
	
	// Wipe and free the public key, ciphertext, and XOF byte buffers
	if(ctx->all_u8_mem_512) 
	{ 
		ml_kem_memzero(ctx->all_u8_mem_512, (RES_PUBL_PART_LVL_512 + LEN_CIPHERTEXT_512 + ML_KEM_MATRIX_XOF_BYTES) * ctx->ml_kem_pool_count_512);
		ml_kem_free(ctx->all_u8_mem_512); 
	}
	
	// Destroy the ML-KEM-768 subpool
	// Wipe and free its contiguous array of encapsulation contexts
	if(ctx->ml_kem_pool_768 && ctx->ml_kem_pool_768->encaps_ctx) 
	{ 
		ml_kem_memzero(ctx->ml_kem_pool_768->encaps_ctx, sizeof(struct ml_kem_encaps_ctx) * ctx->ml_kem_pool_count_768);
		ml_kem_free(ctx->ml_kem_pool_768->encaps_ctx); 
	}
	
	// Free the slot descriptor array
	if(ctx->ml_kem_pool_768) { ml_kem_free(ctx->ml_kem_pool_768); }
	
	// Wipe and free the contiguous u16 polynomial working buffers
	if(ctx->all_u16_mem_768) 
	{ 
		ml_kem_memzero(ctx->all_u16_mem_768, (sizeof(u16) * (ML_KEM_768 * 3 + 2) * ML_KEM_N) * ctx->ml_kem_pool_count_768);
		ml_kem_free(ctx->all_u16_mem_768); 
	}
	
	// Wipe and free the public key, ciphertext, and XOF byte buffers
	if(ctx->all_u8_mem_768) 
	{ 
		ml_kem_memzero(ctx->all_u8_mem_768, (RES_PUBL_PART_LVL_768 + LEN_CIPHERTEXT_768 + ML_KEM_MATRIX_XOF_BYTES) * ctx->ml_kem_pool_count_768);
		ml_kem_free(ctx->all_u8_mem_768);
	}
	
	// Destroy the ML-KEM-1024 subpool
	// Wipe and free its contiguous array of encapsulation contexts
	if(ctx->ml_kem_pool_1024 && ctx->ml_kem_pool_1024->encaps_ctx) 
	{ 
		ml_kem_memzero(ctx->ml_kem_pool_1024->encaps_ctx, sizeof(struct ml_kem_encaps_ctx) * ctx->ml_kem_pool_count_1024);
		ml_kem_free(ctx->ml_kem_pool_1024->encaps_ctx); 
	}
	
	// Free the slot descriptor array
	if(ctx->ml_kem_pool_1024) { ml_kem_free(ctx->ml_kem_pool_1024); }
	
	// Wipe and free the contiguous u16 polynomial working buffers
	if(ctx->all_u16_mem_1024) 
	{ 
		ml_kem_memzero(ctx->all_u16_mem_1024, (sizeof(u16) * (ML_KEM_1024 * 3 + 2) * ML_KEM_N) * ctx->ml_kem_pool_count_1024);
		ml_kem_free(ctx->all_u16_mem_1024); 
	}
	
	// Wipe and free the public key, ciphertext, and XOF byte buffers
	if(ctx->all_u8_mem_1024) 
	{ 
		ml_kem_memzero(ctx->all_u8_mem_1024, (RES_PUBL_PART_LVL_1024 + LEN_CIPHERTEXT_1024 + ML_KEM_MATRIX_XOF_BYTES) * ctx->ml_kem_pool_count_1024);
		ml_kem_free(ctx->all_u8_mem_1024); 
	}
	
	// Release the main pool descriptor after all subpools are destroyed
	ml_kem_free(ctx);
}

// Function to check the coincidence of ciphertexts after decrypt and re-encaps	
STATIC void ml_kem_decaps_ct_select_ss(struct ml_kem_general_keys_decaps_ctx *pool, u8 *ciphertext, size_t len_ciphertext, u8 *result, size_t curr_slot)
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
	for (size_t i = 0; i < ML_KEM_SEED_BYTES; i++) { result[i] = pool->ml_kem_pool[curr_slot].encaps_ctx->K_bar[i] & inv; }

	for (size_t i = 0; i < ML_KEM_SEED_BYTES; i++) { result[i] |= hash_z[i] & mask; }
	
	// Step 6: Wipe local buffers
	ml_kem_memzero(hash_z, ML_KEM_SEED_BYTES);
	ml_kem_memzero(pool->ml_kem_pool[curr_slot].kdf_buf, ML_KEM_SEED_BYTES + len_ciphertext);
}

// Function for packing a secret vector
STATIC size_t get_s_vector(const u16 *secret, u8 *buffer, enum ml_kem_k k)
{
    size_t buff_ctr = 0;

    for(size_t i = 0; i < k * ML_KEM_N; i += 2)
    {
        u16 c0 = secret[i];
        u16 c1 = secret[i + 1];

        buffer[buff_ctr++] = (u8)c0;
        buffer[buff_ctr++] = (u8)((c0 >> 8) | (c1 << 4));
        buffer[buff_ctr++] = (u8)(c1 >> 4);
    }

    return buff_ctr;
}

// Function for unpacking a secret vector
STATIC size_t unpack_s_vector(u16 *secret, u8 *buffer, enum ml_kem_k k)
{
	size_t buff_ctr = 0;
	size_t i = 0;
	
	while(i < k * ML_KEM_N)
	{
		u8 a = buffer[buff_ctr++];
        u8 b = buffer[buff_ctr++];
        u8 c = buffer[buff_ctr++];
		
		secret[i] = (u16)a;
        secret[i] |= (u16)(b & 0x0F) << 8;
        secret[i] = ml_kem_ct_sub_if_ge(secret[i]);
        i++;
        
		secret[i] = (u16)(b >> 4);
        secret[i] |= (u16)c << 4;
        secret[i] = ml_kem_ct_sub_if_ge(secret[i]);
        i++;
	}
	return buff_ctr;
}

// Check coefs pk
STATIC bool ml_kem_validate_pk(const u8 *pk, size_t size_pk)
{
    size_t len = size_pk - ML_KEM_SEED_BYTES;
    bool res = true; 

    for(size_t i = 0; i < len; i += 3)
    {
        u8 a = pk[i];
        u8 b = pk[i + 1];
        u8 c = pk[i + 2];

        u16 coef1 = (u16)a | ((u16)(b & 0x0F) << 8);
        u16 coef2 = (u16)(b >> 4) | ((u16)c << 4);

        if(coef1 >= ML_KEM_Q || coef2 >= ML_KEM_Q) { res = false; }
    }

    return res;
}

// For export in Linux kernel
#ifdef LINUX_KERNEL

#include <linux/export.h>

EXPORT_SYMBOL_GPL(ml_kem_create_object);
EXPORT_SYMBOL_GPL(ml_kem_create_object_from_imported_sk);
EXPORT_SYMBOL_GPL(ml_kem_destroy_core);
EXPORT_SYMBOL_GPL(ml_kem_encaps_core);
EXPORT_SYMBOL_GPL(ml_kem_decaps_core);
EXPORT_SYMBOL_GPL(ml_kem_get_public_key);
EXPORT_SYMBOL_GPL(ml_kem_get_sk);
EXPORT_SYMBOL_GPL(create_encaps_pool);
EXPORT_SYMBOL_GPL(ml_kem_encaps_pool_destroy);

#endif











