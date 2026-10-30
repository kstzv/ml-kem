// SPDX-License-Identifier: GPL-2.0 OR MIT
// Copyright (c) 2026 K.S.Zavertailo

// File #9 - decapsulation pool management

#include "ml_kem_core_header.h"

// Cross-module function declarations
struct ml_kem_general_keys_decaps_ctx *ml_kem_alloc_decaps_pool(enum ml_kem_k level, size_t ml_kem_pool_count, struct ml_kem_ctx *private_keys);
void ml_kem_pool_destroy(struct ml_kem_general_keys_decaps_ctx *head_pool);
bool try_acquire_slot(ml_kem_atomic_t *is_free);

// Static (internal) helpers
STATIC struct ml_kem_general_keys_decaps_ctx *ml_kem_alloc_head_decaps_pool(size_t ml_kem_pool_count);
STATIC u16 *ml_kem_get_mem_two_bytes_ptrs_encaps(struct ml_kem_encaps_ctx *ctx, u16 *two_bytes_ptrs, enum ml_kem_k level);
STATIC u16 *ml_kem_get_mem_two_bytes_ptrs_decrypt(struct ml_kem_decrypt_ctx *ctx, u16 *two_bytes_ptrs, enum ml_kem_k level);
#if FULL_MATRIX
STATIC u16 *get_full_matrix(struct ml_kem_ctx *ctx_keys, struct ml_kem_general_keys_decaps_ctx *ctx_global);
#endif

// Allocate and initialize the entire decapsulation pool.
// This is the main entry point that prepares all memory required for parallel decapsulation.
struct ml_kem_general_keys_decaps_ctx *ml_kem_alloc_decaps_pool(enum ml_kem_k level, size_t ml_kem_pool_count, struct ml_kem_ctx *private_keys)
{
	// Validate input parameters:
	// - security level must be within defined ML-KEM levels
	// - pool size must be non-zero and within allowed bounds
	if((level < ML_KEM_512 || ML_KEM_1024 < level) || ml_kem_pool_count > ML_KEM_MAX_POOL_SLOTS || ml_kem_pool_count == 0)
	{ return NULL; }
	
	// Determine sizes of variable-length buffers depending on security level
	// (public key message and ciphertext sizes differ across ML-KEM variants)
	size_t ciphertext_len, public_key_msg_len;
	if(level == ML_KEM_512){ public_key_msg_len = RES_PUBL_PART_LVL_512; ciphertext_len = LEN_CIPHERTEXT_512; }
	else if(level == ML_KEM_768) { public_key_msg_len = RES_PUBL_PART_LVL_768; ciphertext_len = LEN_CIPHERTEXT_768; }
	else if(level == ML_KEM_1024) { public_key_msg_len = RES_PUBL_PART_LVL_1024; ciphertext_len = LEN_CIPHERTEXT_1024; }
	
	// Allocate pool header + slot descriptors
	struct ml_kem_general_keys_decaps_ctx *head_pool;
	head_pool = ml_kem_alloc_head_decaps_pool(ml_kem_pool_count);
	if(!head_pool) { return NULL; }
	
	// Store global parameters in pool header
	head_pool->ciphertext_len = ciphertext_len;
	head_pool->public_key_msg_len = public_key_msg_len;
	
	// Allocate array of encapsulation contexts (one per slot)
	struct ml_kem_encaps_ctx *encaps;
	encaps = ml_kem_alloc(sizeof(struct ml_kem_encaps_ctx) * ml_kem_pool_count);
	if(!encaps) { goto first_error_exit; }
	ml_kem_memzero(encaps, sizeof(struct ml_kem_encaps_ctx) * ml_kem_pool_count);
	head_pool->encaps_mem_ptr = encaps;
	
	// Allocate array of decryption contexts (one per slot)
	struct ml_kem_decrypt_ctx *decrypt;
	decrypt = ml_kem_alloc(sizeof(struct ml_kem_decrypt_ctx) * ml_kem_pool_count);
	if(!decrypt) { goto second_error_exit; }
	ml_kem_memzero(decrypt, sizeof(struct ml_kem_decrypt_ctx) * ml_kem_pool_count);
	head_pool->decrypt_mem_ptr = decrypt;
	
	// Allocate shared buffer for ciphertexts:
	// each slot uses two buffers (one for decrypt, one for re-encapsulation)
	u8 *ciphertexts;
	ciphertexts = ml_kem_alloc(ciphertext_len * 2 * ml_kem_pool_count);
	if(!ciphertexts) { goto third_error_exit; }
	ml_kem_memzero(ciphertexts, ciphertext_len * 2 * ml_kem_pool_count);
	head_pool->ciphertexts_mem_ptr = ciphertexts;
	
	// Allocate buffer for public key messages (used by encapsulation contexts)
	u8 *public_key_msgs;
	public_key_msgs = ml_kem_alloc(public_key_msg_len * ml_kem_pool_count);
	if(!public_key_msgs) { goto fourth_error_exit; }
	ml_kem_memzero(public_key_msgs, public_key_msg_len * ml_kem_pool_count);
	head_pool->public_key_msgs_mem_ptr = public_key_msgs;
	
	// Allocate buffer for raw XOF output (used during polynomial generation)
	u8 *raw_bytes;
	raw_bytes = ml_kem_alloc((ML_KEM_MATRIX_XOF_BYTES + ML_KEM_KECCAK_STATE_BYTES) * ml_kem_pool_count);
	if(!raw_bytes) { goto fifth_error_exit; }
	ml_kem_memzero(raw_bytes, (ML_KEM_MATRIX_XOF_BYTES + ML_KEM_KECCAK_STATE_BYTES) * ml_kem_pool_count);
	head_pool->raw_bytes_mem_ptr = raw_bytes;
	
	// Allocate contiguous memory for all u16-based working buffers (polynomials, vectors, etc.)
	// Layout is computed based on ML-KEM parameters and reused across all contexts
	size_t two_bytes_ptrs_total;
	two_bytes_ptrs_total = ((4 * level * ML_KEM_N) + (4 * ML_KEM_N)) * ml_kem_pool_count;
	u16 *two_bytes_ptrs;
	two_bytes_ptrs = ml_kem_alloc(two_bytes_ptrs_total * sizeof(u16));
	if(!two_bytes_ptrs) { goto sixth_error_exit; }
	head_pool->two_bytes_ptrs_total = two_bytes_ptrs_total * sizeof(u16);
	ml_kem_memzero(two_bytes_ptrs, head_pool->two_bytes_ptrs_total);
	head_pool->two_bytes_mem_ptrs = two_bytes_ptrs;
	
	// Initialize each slot:
	// - bind contexts
	// - assign memory slices
	// - copy public key
	// - setup per-slot buffers
	for(size_t i = 0; i < ml_kem_pool_count; i++)
	{
		struct ml_kem_decrypt_ctx *d = &decrypt[i];
		struct ml_kem_encaps_ctx  *e = &encaps[i];

		head_pool->ml_kem_pool[i].decrypt_ctx = d;
		head_pool->ml_kem_pool[i].encaps_ctx  = e;

		// Bind persistent private key context
		d->ctx = private_keys;
		d->ciphertext_len = ciphertext_len;
		d->ciphertext = ciphertexts + (2 * i + 0) * ciphertext_len;

		// Setup encapsulation context (used for re-encryption during decapsulation)
		e->ciphertext_len = ciphertext_len;
		e->public_key_msg_len = public_key_msg_len;
		e->ciphertext = ciphertexts + (2 * i + 1) * ciphertext_len;
		e->public_key_msg = public_key_msgs + i * public_key_msg_len;
		memcpy(e->public_key_msg, private_keys->public_key_msg, public_key_msg_len);
		e->k = level;
		e->raw_bytes = raw_bytes + i * (ML_KEM_MATRIX_XOF_BYTES + ML_KEM_KECCAK_STATE_BYTES);
		sha3_ctx_get_mem(&e->sha3, (u64 *)(e->raw_bytes + ML_KEM_MATRIX_XOF_BYTES), ML_KEM_KECCAK_STATE_BYTES/sizeof(u64));
		shake_ctx_get_mem(&e->shake, (u64 *)(e->raw_bytes + ML_KEM_MATRIX_XOF_BYTES), ML_KEM_KECCAK_STATE_BYTES/sizeof(u64));
		e->err = 0;
		
		// Assign u16 working memory regions for both contexts
		two_bytes_ptrs = ml_kem_get_mem_two_bytes_ptrs_encaps(e, two_bytes_ptrs, level);
		two_bytes_ptrs = ml_kem_get_mem_two_bytes_ptrs_decrypt(d, two_bytes_ptrs, level);
		
		// After public_key pointer is assigned
		ml_kem_unpack_pk_t_u16(e);
	}
	
	#if FULL_MATRIX
	u16 *full_matrix;
	full_matrix = get_full_matrix(head_pool->ml_kem_pool[0].decrypt_ctx->ctx, head_pool);
	if(!full_matrix) { goto seventh_exit; }
	
	for(size_t i = 0; i < ml_kem_pool_count; i++) { head_pool->ml_kem_pool[i].encaps_ctx->full_matrix = full_matrix; }
	#endif
	
	return head_pool;
	
	// Error handling with reverse-order cleanup 
	#if FULL_MATRIX
	seventh_exit:
		ml_kem_free(two_bytes_ptrs);
	#endif
	sixth_error_exit:
		ml_kem_free(raw_bytes);
	fifth_error_exit:
		ml_kem_free(public_key_msgs);
	fourth_error_exit:
		ml_kem_free(ciphertexts);
	third_error_exit:
		ml_kem_free(decrypt);
	second_error_exit:
		ml_kem_free(encaps);
	first_error_exit:
		ml_kem_free(head_pool->ml_kem_pool);
		ml_kem_free(head_pool);
		return NULL;
}

// Assign contiguous u16 memory regions to all pointer fields of the encapsulation context.
// The function "slices" a pre-allocated linear buffer into logically separate arrays.

// Memory layout (in order):
//   public_key  -> k polynomials
//   u           -> k polynomials (vector of size k)
//   v           -> 1 polynomial
//   y           -> k polynomials (temporary secret)
//   poly        -> 1 polynomial (temporary buffer)

// Important:
// - All buffers are taken from a single contiguous block to improve locality and reduce allocations
// - Pointer arithmetic must strictly match the ML-KEM structure layout
// - The function returns the updated pointer for further allocation chaining
STATIC u16 *ml_kem_get_mem_two_bytes_ptrs_encaps(struct ml_kem_encaps_ctx *ctx, u16 *two_bytes_ptrs, enum ml_kem_k level)
{
	// public_key: unpacked t vector (k polynomials)
	ctx->public_key = two_bytes_ptrs;
	two_bytes_ptrs += ML_KEM_N * level;
	
	// u: vector of k polynomials (used for u computation in encapsulation)
	ctx->u = two_bytes_ptrs;
	two_bytes_ptrs += ML_KEM_N * level;
	
	// v: single polynomial (encodes message component)
	ctx->v = two_bytes_ptrs;
	two_bytes_ptrs += ML_KEM_N;
	
	// y: temporary secret vector (k polynomials, derived from seed)
	ctx->y = two_bytes_ptrs;
	two_bytes_ptrs += ML_KEM_N * level;
	
	// poly: temporary working polynomial buffer
	ctx->poly = two_bytes_ptrs;
	two_bytes_ptrs += ML_KEM_N;
	
	// Return pointer to the next free position in the buffer
	return two_bytes_ptrs;
}

// Assign contiguous u16 memory regions to all pointer fields of the decryption context.
// This is a reduced layout compared to encapsulation (only required buffers are allocated).

// Memory layout (in order):
//   u     -> k polynomials (received from ciphertext)
//   v     -> 1 polynomial
//   poly  -> 1 polynomial (temporary buffer)

// Notes:
// - Uses the same shared linear buffer as encapsulation contexts
// - Designed to minimize memory footprint for decapsulation
// - Must stay consistent with how ciphertext is unpacked and processed
STATIC u16 *ml_kem_get_mem_two_bytes_ptrs_decrypt(struct ml_kem_decrypt_ctx *ctx, u16 *two_bytes_ptrs, enum ml_kem_k level)
{
	// u: vector of k polynomials extracted from ciphertext
	ctx->u = two_bytes_ptrs;
	two_bytes_ptrs += ML_KEM_N * level;
	
	// v: single polynomial extracted from ciphertext
	ctx->v = two_bytes_ptrs;
	two_bytes_ptrs += ML_KEM_N;
	
	// poly: temporary working polynomial buffer
	ctx->poly = two_bytes_ptrs;
	two_bytes_ptrs += ML_KEM_N;
	
	// Return pointer to the next free position in the buffer
	return two_bytes_ptrs;
}

// Allocate and initialize the pool head structure along with slot descriptors.
// This function only allocates the "skeleton" of the pool (no heavy buffers yet).
// All large memory regions are assigned later in ml_kem_alloc_decaps_pool().
STATIC struct ml_kem_general_keys_decaps_ctx *ml_kem_alloc_head_decaps_pool(size_t ml_kem_pool_count)
{
	// Allocate pool head structure
	struct ml_kem_general_keys_decaps_ctx *head_pool;
	head_pool = ml_kem_alloc(sizeof(struct ml_kem_general_keys_decaps_ctx));
	if(!head_pool) { return NULL; }
	
	// Allocate array of slot descriptors (each slot = encaps + decrypt pair)
	head_pool->ml_kem_pool = ml_kem_alloc(sizeof(struct ml_kem_decaps_ctx) * ml_kem_pool_count);
	if(!head_pool->ml_kem_pool) { ml_kem_free(head_pool); return NULL; }
	
	// Initialize global pool metadata and pointers
	head_pool->ml_kem_pool_count = ml_kem_pool_count;
	head_pool->two_bytes_ptrs_total = 0;
	head_pool->two_bytes_mem_ptrs = NULL;
	head_pool->raw_bytes_mem_ptr = NULL;
	head_pool->ciphertexts_mem_ptr = NULL;
	head_pool->public_key_msgs_mem_ptr = NULL;
	head_pool->decrypt_mem_ptr = NULL;
	head_pool->encaps_mem_ptr = NULL;

	// Initialize each slot:
	// - mark as free (atomic flag = 1)
	// - clear context pointers (will be assigned later)
	for(size_t i = 0; i < ml_kem_pool_count; i++)
	{
		ml_kem_atomic_init_slot(&head_pool->ml_kem_pool[i].is_free);
		head_pool->ml_kem_pool[i].decrypt_ctx = NULL;
		head_pool->ml_kem_pool[i].encaps_ctx = NULL;
	}
	
	return head_pool;
}

#if FULL_MATRIX
STATIC u16 *get_full_matrix(struct ml_kem_ctx *ctx_keys, struct ml_kem_general_keys_decaps_ctx *ctx_global)
{
	if(!ctx_keys || !ctx_global) { return NULL; }
	
	u16 *matrix;
	matrix = ml_kem_alloc(ctx_keys->k * ctx_keys->k * ML_KEM_N * sizeof(u16));
	if(!matrix) { return NULL; }
	
	u8 local_seed_m[ML_KEM_SEED_BYTES + 2];
	memcpy(local_seed_m, ctx_keys->seed_rho, ML_KEM_SEED_BYTES);
	for(u8 i = 0; i < ctx_keys->k; i++)
	{
		for(u8 j = 0; j < ctx_keys->k; j++)
		{
			local_seed_m[32] = i;
			local_seed_m[33] = j;
			
			// Expand seed using SHAKE128 to obtain raw bytes for matrix polynomial
			shake_ctx_zero(&ctx_global->ml_kem_pool[0].encaps_ctx->shake);
			shake_ctx_init(&ctx_global->ml_kem_pool[0].encaps_ctx->shake, local_seed_m, ML_KEM_SEED_BYTES + 2, 
				ctx_global->ml_kem_pool[0].encaps_ctx->raw_bytes, ML_KEM_MATRIX_XOF_BYTES);
				
			int poly_counter = 0;
			do{
				shake128(&ctx_global->ml_kem_pool[0].encaps_ctx->shake);
				poly_counter += ml_kem_gen_polynomial_for_matrix((matrix + (i * ctx_keys->k + j) * ML_KEM_N) + poly_counter, 
					ctx_global->ml_kem_pool[0].encaps_ctx->raw_bytes, ML_KEM_MATRIX_XOF_BYTES, (int)ML_KEM_N - poly_counter);
					
				if(poly_counter >= ML_KEM_N) { break; }
			}while(poly_counter < ML_KEM_N);
			
		}
	}
	
	ctx_global->full_matrix_ptr = matrix;
	return matrix;
}
#endif
	

// Destroy the entire pool and securely wipe all associated memory.
// This includes:
// - all shared buffers
// - all per-slot contexts
// - slot descriptors and the pool head itself
//
// Important:
// - Sensitive data is explicitly zeroed before freeing (best-effort secure wipe)
// - Order of cleanup matches allocation dependencies
void ml_kem_pool_destroy(struct ml_kem_general_keys_decaps_ctx *head_pool)
{
	// Validate input pointer
	if(!head_pool) { return; }
	
	// Wipe and free all u16-based working buffers (polynomials, vectors, etc.)
	if(head_pool->two_bytes_mem_ptrs)
	{
		ml_kem_memzero(head_pool->two_bytes_mem_ptrs, head_pool->two_bytes_ptrs_total);
		ml_kem_free(head_pool->two_bytes_mem_ptrs);
	}
	
	// Wipe and free raw XOF byte buffers used in encapsulation
	if(head_pool->raw_bytes_mem_ptr)
	{
		ml_kem_memzero(head_pool->raw_bytes_mem_ptr, head_pool->ml_kem_pool_count * (ML_KEM_MATRIX_XOF_BYTES + ML_KEM_KECCAK_STATE_BYTES));
		ml_kem_free(head_pool->raw_bytes_mem_ptr);
	}
	
	// Wipe and free ciphertext buffers (used by both decrypt and re-encapsulation paths)
	if(head_pool->ciphertexts_mem_ptr)
	{
		ml_kem_memzero(head_pool->ciphertexts_mem_ptr, 2 * head_pool->ml_kem_pool_count * head_pool->ciphertext_len);
		ml_kem_free(head_pool->ciphertexts_mem_ptr);
	}
	
	// Wipe and free public key message buffers (encapsulation contexts)
	if(head_pool->public_key_msgs_mem_ptr)
	{
		ml_kem_memzero(head_pool->public_key_msgs_mem_ptr, head_pool->ml_kem_pool_count * head_pool->public_key_msg_len);
		ml_kem_free(head_pool->public_key_msgs_mem_ptr);
	}
	
	// Wipe and free all decryption context structures
	if(head_pool->decrypt_mem_ptr)
	{
		ml_kem_memzero(head_pool->decrypt_mem_ptr, sizeof(struct ml_kem_decrypt_ctx) * head_pool->ml_kem_pool_count);
		ml_kem_free(head_pool->decrypt_mem_ptr);
	}
	
	// Wipe and free all encapsulation context structures
	if(head_pool->encaps_mem_ptr)
	{
		ml_kem_memzero(head_pool->encaps_mem_ptr, sizeof(struct ml_kem_encaps_ctx) * head_pool->ml_kem_pool_count);
		ml_kem_free(head_pool->encaps_mem_ptr);
	}
	
	// Free slot descriptors
	if(head_pool->ml_kem_pool) { ml_kem_free(head_pool->ml_kem_pool); }
	
	#if FULL_MATRIX
	ml_kem_free(head_pool->full_matrix_ptr);
	#endif
	
	// Finally free the pool head itself
	ml_kem_free(head_pool);
	
	// All resources have been released
}
 
 
 
 
 
 
 
 

