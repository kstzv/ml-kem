// SPDX-License-Identifier: GPL-2.0 OR MIT
// Copyright (c) 2026 K.S.Zavertailo

// File #10 - decapsulation pool management

#include <string.h>
#include <stdlib.h>
#include "ml_kem_core_header.h"

// Cross-module function declarations
struct ml_kem_pool_decaps_ctx *ml_kem_alloc_decaps_pool(enum ml_kem_k level, size_t ml_kem_pool_count, struct ml_kem_ctx *private_keys);
void ml_kem_pool_destroy(struct ml_kem_pool_decaps_ctx *head_pool);
bool try_acquire_slot(atomic_int *is_free);

// Static (internal) helpers
static struct ml_kem_pool_decaps_ctx *ml_kem_alloc_head_decaps_pool(size_t ml_kem_pool_count);
static u16 *ml_kem_get_mem_two_bytes_ptrs_encaps(struct ml_kem_encaps_ctx *ctx, u16 *two_bytes_ptrs, enum ml_kem_k level);
static u16 *ml_kem_get_mem_two_bytes_ptrs_decrypt(struct ml_kem_decrypt_ctx *ctx, u16 *two_bytes_ptrs, enum ml_kem_k level);

// Allocate and initialize the entire decapsulation pool.
// This is the main entry point that prepares all memory required for parallel decapsulation.
struct ml_kem_pool_decaps_ctx *ml_kem_alloc_decaps_pool(enum ml_kem_k level, size_t ml_kem_pool_count, struct ml_kem_ctx *private_keys)
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
	struct ml_kem_pool_decaps_ctx *head_pool;
	head_pool = ml_kem_alloc_head_decaps_pool(ml_kem_pool_count);
	if(!head_pool) { return NULL; }
	
	// Store global parameters in pool header
	head_pool->ciphertext_len = ciphertext_len;
	head_pool->public_key_msg_len = public_key_msg_len;
	
	// Allocate array of encapsulation contexts (one per slot)
	struct ml_kem_encaps_ctx *encaps;
	encaps = malloc(sizeof(struct ml_kem_encaps_ctx) * ml_kem_pool_count);
	if(!encaps) { goto first_error_exit; }
	ml_kem_memzero(encaps, sizeof(struct ml_kem_encaps_ctx) * ml_kem_pool_count);
	head_pool->encaps_mem_ptr = encaps;
	
	// Allocate array of decryption contexts (one per slot)
	struct ml_kem_decrypt_ctx *decrypt;
	decrypt = malloc(sizeof(struct ml_kem_decrypt_ctx) * ml_kem_pool_count);
	if(!decrypt) { goto second_error_exit; }
	ml_kem_memzero(decrypt, sizeof(struct ml_kem_decrypt_ctx) * ml_kem_pool_count);
	head_pool->decrypt_mem_ptr = decrypt;
	
	// Allocate shared buffer for ciphertexts:
	// each slot uses two buffers (one for decrypt, one for re-encapsulation)
	u8 *ciphertexts;
	ciphertexts = malloc(ciphertext_len * 2 * ml_kem_pool_count);
	if(!ciphertexts) { goto third_error_exit; }
	ml_kem_memzero(ciphertexts, ciphertext_len * 2 * ml_kem_pool_count);
	head_pool->ciphertexts_mem_ptr = ciphertexts;
	
	// Allocate buffer for public key messages (used by encapsulation contexts)
	u8 *public_key_msgs;
	public_key_msgs = malloc(public_key_msg_len * ml_kem_pool_count);
	if(!public_key_msgs) { goto fourth_error_exit; }
	ml_kem_memzero(public_key_msgs, public_key_msg_len * ml_kem_pool_count);
	head_pool->public_key_msgs_mem_ptr = public_key_msgs;
	
	// Allocate buffer for raw XOF output (used during polynomial generation)
	u8 *raw_bytes;
	raw_bytes = malloc(ML_KEM_MATRIX_XOF_BYTES * ml_kem_pool_count);
	if(!raw_bytes) { goto fifth_error_exit; }
	ml_kem_memzero(raw_bytes, ML_KEM_MATRIX_XOF_BYTES * ml_kem_pool_count);
	head_pool->raw_bytes_mem_ptr = raw_bytes;
	
	// Allocate contiguous memory for all u16-based working buffers (polynomials, vectors, etc.)
	// Layout is computed based on ML-KEM parameters and reused across all contexts
	size_t two_bytes_ptrs_total;
	two_bytes_ptrs_total = ((4 * level * ML_KEM_N) + (4 * ML_KEM_N)) * ml_kem_pool_count;
	u16 *two_bytes_ptrs;
	two_bytes_ptrs = malloc(two_bytes_ptrs_total * sizeof(u16));
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
		e->raw_bytes = raw_bytes + i * ML_KEM_MATRIX_XOF_BYTES;
		
		// Assign u16 working memory regions for both contexts
		two_bytes_ptrs = ml_kem_get_mem_two_bytes_ptrs_encaps(e, two_bytes_ptrs, level);
		two_bytes_ptrs = ml_kem_get_mem_two_bytes_ptrs_decrypt(d, two_bytes_ptrs, level);
		
		// After public_key pointer is assigned
		ml_kem_unpack_pk_t_u16(e);
	}
	
	return head_pool;
	
	// Error handling with reverse-order cleanup 
	sixth_error_exit:
		free(raw_bytes);
	fifth_error_exit:
		free(public_key_msgs);
	fourth_error_exit:
		free(ciphertexts);
	third_error_exit:
		free(decrypt);
	second_error_exit:
		free(encaps);
	first_error_exit:
		free(head_pool->ml_kem_pool);
		free(head_pool);
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
static u16 *ml_kem_get_mem_two_bytes_ptrs_encaps(struct ml_kem_encaps_ctx *ctx, u16 *two_bytes_ptrs, enum ml_kem_k level)
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
static u16 *ml_kem_get_mem_two_bytes_ptrs_decrypt(struct ml_kem_decrypt_ctx *ctx, u16 *two_bytes_ptrs, enum ml_kem_k level)
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
static struct ml_kem_pool_decaps_ctx *ml_kem_alloc_head_decaps_pool(size_t ml_kem_pool_count)
{
	// Allocate pool head structure
	struct ml_kem_pool_decaps_ctx *head_pool;
	head_pool = malloc(sizeof(struct ml_kem_pool_decaps_ctx));
	if(!head_pool) { return NULL; }
	
	// Allocate array of slot descriptors (each slot = encaps + decrypt pair)
	head_pool->ml_kem_pool = malloc(sizeof(struct ml_kem_decaps_ctx) * ml_kem_pool_count);
	if(!head_pool->ml_kem_pool) { free(head_pool); return NULL; }
	
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
		atomic_init(&head_pool->ml_kem_pool[i].is_free, 1);
		head_pool->ml_kem_pool[i].decrypt_ctx = NULL;
		head_pool->ml_kem_pool[i].encaps_ctx = NULL;
	}
	
	return head_pool;
}

// Destroy the entire pool and securely wipe all associated memory.
// This includes:
// - all shared buffers
// - all per-slot contexts
// - slot descriptors and the pool head itself
//
// Important:
// - Sensitive data is explicitly zeroed before freeing (best-effort secure wipe)
// - Order of cleanup matches allocation dependencies
void ml_kem_pool_destroy(struct ml_kem_pool_decaps_ctx *head_pool)
{
	// Validate input pointer
	if(!head_pool) { return; }
	
	// Wipe and free all u16-based working buffers (polynomials, vectors, etc.)
	if(head_pool->two_bytes_mem_ptrs)
	{
		ml_kem_memzero(head_pool->two_bytes_mem_ptrs, head_pool->two_bytes_ptrs_total);
		free(head_pool->two_bytes_mem_ptrs);
	}
	
	// Wipe and free raw XOF byte buffers used in encapsulation
	if(head_pool->raw_bytes_mem_ptr)
	{
		ml_kem_memzero(head_pool->raw_bytes_mem_ptr, head_pool->ml_kem_pool_count * ML_KEM_MATRIX_XOF_BYTES);
		free(head_pool->raw_bytes_mem_ptr);
	}
	
	// Wipe and free ciphertext buffers (used by both decrypt and re-encapsulation paths)
	if(head_pool->ciphertexts_mem_ptr)
	{
		ml_kem_memzero(head_pool->ciphertexts_mem_ptr, 2 * head_pool->ml_kem_pool_count * head_pool->ciphertext_len);
		free(head_pool->ciphertexts_mem_ptr);
	}
	
	// Wipe and free public key message buffers (encapsulation contexts)
	if(head_pool->public_key_msgs_mem_ptr)
	{
		ml_kem_memzero(head_pool->public_key_msgs_mem_ptr, head_pool->ml_kem_pool_count * head_pool->public_key_msg_len);
		free(head_pool->public_key_msgs_mem_ptr);
	}
	
	// Wipe and free all decryption context structures
	if(head_pool->decrypt_mem_ptr)
	{
		ml_kem_memzero(head_pool->decrypt_mem_ptr, sizeof(struct ml_kem_decrypt_ctx) * head_pool->ml_kem_pool_count);
		free(head_pool->decrypt_mem_ptr);
	}
	
	// Wipe and free all encapsulation context structures
	if(head_pool->encaps_mem_ptr)
	{
		ml_kem_memzero(head_pool->encaps_mem_ptr, sizeof(struct ml_kem_encaps_ctx) * head_pool->ml_kem_pool_count);
		free(head_pool->encaps_mem_ptr);
	}
	
	// Free slot descriptors
	if(head_pool->ml_kem_pool) { free(head_pool->ml_kem_pool); }
	
	// Finally free the pool head itself
	free(head_pool);
	
	// All resources have been released
}
	
// Attempt to atomically acquire a free slot.
// Returns true if the slot was successfully acquired, false otherwise.
//
// Semantics:
// - expected value = 1 (slot is free)
// - new value = 0 (slot is now occupied)
// - uses atomic CAS to avoid race conditions between threads
bool try_acquire_slot(atomic_int *is_free)
{
    int expected = 1;

    return atomic_compare_exchange_strong(is_free, &expected, 0);
}
 
 
 
 
 
 
 
 

