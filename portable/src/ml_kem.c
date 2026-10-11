// SPDX-License-Identifier: GPL-2.0 OR MIT
// Copyright (c) 2026 K.S.Zavertailo

#include "ml_kem.h"

// Forward declarations of public API functions (redeclared for internal usage)
struct ml_kem_pool_decaps_ctx *ml_kem_create_object(enum ml_kem_k level, size_t ml_kem_pool_count, ml_kem_entropy_fn entropy);
void ml_kem_destroy_core(struct ml_kem_pool_decaps_ctx *ctx_pool);
int ml_kem_encaps_core(struct ml_kem_pool_encaps_ctx *ctx_pool, u8 *pk, size_t size_pk, u8 *buffer_ct, size_t size_ct, u8 *buffer_ss, size_t size_ss, ml_kem_entropy_fn entropy);
int ml_kem_decaps_core(struct ml_kem_pool_decaps_ctx *pool, u8 *ciphertext, size_t len_ciphertext, u8 *result, size_t len_result);
int ml_kem_get_public_key(struct ml_kem_pool_decaps_ctx *pool, u8 *buffer_for_public_key, size_t size_buffer);
struct ml_kem_pool_encaps_ctx *create_encaps_pool(size_t number_slots_512, size_t number_slots_768, size_t number_slots_1024);
void ml_kem_encaps_pool_destroy(struct ml_kem_pool_encaps_ctx *ctx);

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
	struct ml_kem_pool_decaps_ctx *ctx_pool;
	ctx_pool = ml_kem_alloc_decaps_pool(level, ml_kem_pool_count, ctx_keys);
	if(!ctx_pool) { ret = -ML_KEM_ENOMEM; goto error_exit; }
	
	return ctx_pool;
	
	// Error path: destroy persistent keys
	error_exit:
		ml_kem_destroy_ctx_struct(ctx_keys);
		return err_create_keys(ret);
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

// Моя примітка: слід англійською не забути її описати
int ml_kem_encaps_core(struct ml_kem_pool_encaps_ctx *ctx_pool, u8 *pk, size_t size_pk, u8 *buffer_ct, size_t size_ct, u8 *buffer_ss, size_t size_ss, ml_kem_entropy_fn entropy)
{
	if(!pk || !buffer_ct || !buffer_ss) { return err_encaps(-ML_KEM_EINVAL); }
	
	enum ml_kem_k level;
	struct ml_kem_encaps_ctx *ctx = NULL;
	struct ml_kem_encaps_slot *slot = NULL;
	size_t curr_slot = ML_KEM_MAX_POOL_SLOTS + 1;
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
		
		ctx = slot[curr_slot].encaps_ctx;
		memcpy(ctx->public_key_msg, pk, size_pk);
	}
	
	// Perform encapsulation (client mode: msg=NULL, hash_pk=NULL)
	int ret = 0;
	ml_kem_encapsulation(ctx, NULL, NULL, entropy);
	if(ctx->err != 0) { ret = err_encaps(ctx->err); goto exit; } 
	
	memcpy(buffer_ss, ctx->K_bar, ML_KEM_SEED_BYTES);
	memcpy(buffer_ct, ctx->ciphertext, size_ct);
	
	exit:
		ml_kem_wipe_encaps(ctx);
		if(!ctx_pool) 
		{ 
			ml_kem_destroy_encaps(ctx); 
		}else 
		{ 
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
int ml_kem_decaps_core(struct ml_kem_pool_decaps_ctx *pool, u8 *ciphertext, size_t len_ciphertext, u8 *result, size_t len_result)
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
	for (size_t i = 0; i < ML_KEM_SEED_BYTES; i++) { result[i] = pool->ml_kem_pool[curr_slot].encaps_ctx->K_bar[i] & inv; }

	for (size_t i = 0; i < ML_KEM_SEED_BYTES; i++) { result[i] |= hash_z[i] & mask; }
	
	// Step 6: Wipe local buffers
	ml_kem_memzero(hash_z, ML_KEM_SEED_BYTES);
	ml_kem_memzero(pool->ml_kem_pool[curr_slot].kdf_buf, ML_KEM_SEED_BYTES + len_ciphertext);
}
	
// Gets the public key
// Parameters:
// -pool           			- initialized decapsulation pool (contains the PK within the structure hierarchy)
// -buffer_for_public_key   - buffer where the PK will be copied
// -size_buffer      		- size of the buffer (must conform to the ML-KEM security level)
int ml_kem_get_public_key(struct ml_kem_pool_decaps_ctx *pool, u8 *buffer_for_public_key, size_t size_buffer)
{
	// Validate pool and slot array
	if(!pool || !pool->ml_kem_pool) { return err_decaps(-EINVAL); }
	
	// Validate internal pool memory regions (must be preallocated)
	if(!pool->ciphertexts_mem_ptr || !pool->public_key_msgs_mem_ptr || !pool->decrypt_mem_ptr || !pool->encaps_mem_ptr) { return err_decaps(-EINVAL); }
	
	// Validate buffer ptr
	if(!buffer_for_public_key) { return err_get_pk(-EINVAL); }
	
	// Validate size of buffer
	if(pool->ml_kem_pool[0].decrypt_ctx->ctx->public_key_msg_len != size_buffer) { return err_get_pk(-EINVAL); }
	
	// Copy key to buffer
	memcpy(buffer_for_public_key, pool->ml_kem_pool[0].decrypt_ctx->ctx->public_key_msg, pool->ml_kem_pool[0].decrypt_ctx->ctx->public_key_msg_len);
	
	return 0;
}

// Моя примітка: створення пулу інкапсуляцій (в фінальному релізі буде додано ноармальнй опис в коментарях) 
struct ml_kem_pool_encaps_ctx *create_encaps_pool(size_t number_slots_512, size_t number_slots_768, size_t number_slots_1024)
{
	if(number_slots_512 == 0 && number_slots_768 == 0 && number_slots_1024 == 0) { return err_create_encaps_pool(-ML_KEM_EINVAL); }
	else if(number_slots_512 > ML_KEM_MAX_POOL_SLOTS 
		|| number_slots_768 > ML_KEM_MAX_POOL_SLOTS 
			|| number_slots_1024 > ML_KEM_MAX_POOL_SLOTS) { return err_create_encaps_pool(-ML_KEM_EINVAL); }
			
	struct ml_kem_pool_encaps_ctx *ctx;
	ctx = ml_kem_alloc(sizeof(struct ml_kem_pool_encaps_ctx));
	if(!ctx) { return err_create_encaps_pool(-ML_KEM_ENOMEM); }
	ml_kem_memzero(ctx, sizeof(struct ml_kem_pool_encaps_ctx));
	int ret = 0;
	
	if(number_slots_512 != 0)
	{
		ret = ml_kem_create_all_structs(ctx, ML_KEM_512, number_slots_512);
		if(ret != 0) {  ml_kem_encaps_pool_destroy(ctx); return err_create_encaps_pool(-ML_KEM_ENOMEM); }
		
		ret = ml_kem_assign_encaps_pool_u16_buffers(ctx, ML_KEM_512, number_slots_512);
		if(ret != 0) { ml_kem_encaps_pool_destroy(ctx); return err_create_encaps_pool(-ML_KEM_ENOMEM); }
		
		ret = ml_kem_assign_encaps_pool_u8_buffers(ctx, ML_KEM_512, number_slots_512);
		if(ret != 0) { ml_kem_encaps_pool_destroy(ctx); return err_create_encaps_pool(-ML_KEM_ENOMEM); }
	}
	
	if(number_slots_768 != 0)
	{
		ret = ml_kem_create_all_structs(ctx, ML_KEM_768, number_slots_768);
		if(ret != 0) { ml_kem_encaps_pool_destroy(ctx); return err_create_encaps_pool(-ML_KEM_ENOMEM); }
		
		ret = ml_kem_assign_encaps_pool_u16_buffers(ctx, ML_KEM_768, number_slots_768);
		if(ret != 0) { ml_kem_encaps_pool_destroy(ctx); return err_create_encaps_pool(-ML_KEM_ENOMEM); }
		
		ret = ml_kem_assign_encaps_pool_u8_buffers(ctx, ML_KEM_768, number_slots_768);
		if(ret != 0) { ml_kem_encaps_pool_destroy(ctx); return err_create_encaps_pool(-ML_KEM_ENOMEM); }
	}
	
	if(number_slots_1024 != 0)
	{
		ret = ml_kem_create_all_structs(ctx, ML_KEM_1024, number_slots_1024);
		if(ret != 0) { ml_kem_encaps_pool_destroy(ctx); return err_create_encaps_pool(-ML_KEM_ENOMEM); }
		
		ret = ml_kem_assign_encaps_pool_u16_buffers(ctx, ML_KEM_1024, number_slots_1024);
		if(ret != 0) { ml_kem_encaps_pool_destroy(ctx); return err_create_encaps_pool(-ML_KEM_ENOMEM); }
		
		ret = ml_kem_assign_encaps_pool_u8_buffers(ctx, ML_KEM_1024, number_slots_1024);
		if(ret != 0) { ml_kem_encaps_pool_destroy(ctx); return err_create_encaps_pool(-ML_KEM_ENOMEM); }
	}
	
	return ctx;
}

// Моя примітка: деструктор пулу інкапсуляцій (в фінальному релізі буде додано ноармальнй опис в коментарях) 
void ml_kem_encaps_pool_destroy(struct ml_kem_pool_encaps_ctx *ctx)
{
	if(!ctx) { return; }
	
	// Delete all 512 level mem
	if(ctx->ml_kem_pool_512 && ctx->ml_kem_pool_512->encaps_ctx) 
	{ 
		ml_kem_memzero(ctx->ml_kem_pool_512->encaps_ctx, sizeof(struct ml_kem_encaps_ctx) * ctx->ml_kem_pool_count_512);
		ml_kem_free(ctx->ml_kem_pool_512->encaps_ctx); 
	}
	
	if(ctx->ml_kem_pool_512) { ml_kem_free(ctx->ml_kem_pool_512); }
	
	if(ctx->all_u16_mem_512) 
	{ 
		ml_kem_memzero(ctx->all_u16_mem_512, (sizeof(u16) * (ML_KEM_512 * 3 + 2) * ML_KEM_N) * ctx->ml_kem_pool_count_512);
		ml_kem_free(ctx->all_u16_mem_512); 
	}
	
	if(ctx->all_u8_mem_512) 
	{ 
		ml_kem_memzero(ctx->all_u8_mem_512, (RES_PUBL_PART_LVL_512 + LEN_CIPHERTEXT_512 + ML_KEM_MATRIX_XOF_BYTES) * ctx->ml_kem_pool_count_512);
		ml_kem_free(ctx->all_u8_mem_512); 
	}
	
	// Delete all 768 level mem
	if(ctx->ml_kem_pool_768 && ctx->ml_kem_pool_768->encaps_ctx) 
	{ 
		ml_kem_memzero(ctx->ml_kem_pool_768->encaps_ctx, sizeof(struct ml_kem_encaps_ctx) * ctx->ml_kem_pool_count_768);
		ml_kem_free(ctx->ml_kem_pool_768->encaps_ctx); 
	}
	
	if(ctx->ml_kem_pool_768) { ml_kem_free(ctx->ml_kem_pool_768); }
	
	if(ctx->all_u16_mem_768) 
	{ 
		ml_kem_memzero(ctx->all_u16_mem_768, (sizeof(u16) * (ML_KEM_768 * 3 + 2) * ML_KEM_N) * ctx->ml_kem_pool_count_768);
		ml_kem_free(ctx->all_u16_mem_768); 
	}
	
	if(ctx->all_u8_mem_768) 
	{ 
		ml_kem_memzero(ctx->all_u8_mem_768, (RES_PUBL_PART_LVL_768 + LEN_CIPHERTEXT_768 + ML_KEM_MATRIX_XOF_BYTES) * ctx->ml_kem_pool_count_768);
		ml_kem_free(ctx->all_u8_mem_768);
	}
	
	// Delete all 1024 level mem
	if(ctx->ml_kem_pool_1024 && ctx->ml_kem_pool_1024->encaps_ctx) 
	{ 
		ml_kem_memzero(ctx->ml_kem_pool_1024->encaps_ctx, sizeof(struct ml_kem_encaps_ctx) * ctx->ml_kem_pool_count_1024);
		ml_kem_free(ctx->ml_kem_pool_1024->encaps_ctx); 
	}
	
	if(ctx->ml_kem_pool_1024) { ml_kem_free(ctx->ml_kem_pool_1024); }
	
	if(ctx->all_u16_mem_1024) 
	{ 
		ml_kem_memzero(ctx->all_u16_mem_1024, (sizeof(u16) * (ML_KEM_1024 * 3 + 2) * ML_KEM_N) * ctx->ml_kem_pool_count_1024);
		ml_kem_free(ctx->all_u16_mem_1024); 
	}
	
	if(ctx->all_u8_mem_1024) 
	{ 
		ml_kem_memzero(ctx->all_u8_mem_1024, (RES_PUBL_PART_LVL_1024 + LEN_CIPHERTEXT_1024 + ML_KEM_MATRIX_XOF_BYTES) * ctx->ml_kem_pool_count_1024);
		ml_kem_free(ctx->all_u8_mem_1024); 
	}
	
	ml_kem_free(ctx);
}

// For export in Linux kernel
#ifdef LINUX_KERNEL

#include <linux/export.h>

EXPORT_SYMBOL_GPL(ml_kem_create_object);
EXPORT_SYMBOL_GPL(ml_kem_destroy_core);
EXPORT_SYMBOL_GPL(ml_kem_get_public_key);
EXPORT_SYMBOL_GPL(ml_kem_encaps_core);
EXPORT_SYMBOL_GPL(ml_kem_decaps_core);
EXPORT_SYMBOL_GPL(create_encaps_pool);
EXPORT_SYMBOL_GPL(ml_kem_encaps_pool_destroy);

#endif











