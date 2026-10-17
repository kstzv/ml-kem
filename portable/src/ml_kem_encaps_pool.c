// SPDX-License-Identifier: GPL-2.0 OR MIT
// Copyright (c) 2026 K.S.Zavertailo

// File #10 - encapsulation pool management

// This module prepares reusable encapsulation contexts for ML-KEM-512,
// ML-KEM-768, and ML-KEM-1024. Each security level has its own slot array.
// Working buffers are allocated in contiguous regions and assigned to slots.
// Allocation and initialization are performed before encapsulation operations.
#include "ml_kem_core_header.h"

// Cross-module functions used by create_encaps_pool() to initialize each subpool.
int ml_kem_create_all_structs(struct ml_kem_pool_encaps_ctx *ctx, enum ml_kem_k k, size_t number_slots);
int ml_kem_assign_encaps_pool_u16_buffers(struct ml_kem_pool_encaps_ctx *ctx, enum ml_kem_k k, size_t number_slots);
int ml_kem_assign_encaps_pool_u8_buffers(struct ml_kem_pool_encaps_ctx *ctx, enum ml_kem_k k, size_t number_slots);

// Allocate and initialize slot descriptors and encapsulation context structures.
// Parameters:
//  ctx          - zero-initialized encapsulation pool descriptor
//  k            - ML-KEM security level (ML_KEM_512 / 768 / 1024)
//  number_slots - number of slots to create for the selected security level
// Returns:
//  0 on success
//  1 if allocation fails or the security level is unsupported
// Behavior:
//  - Allocates an array of slot descriptors and an array of encapsulation contexts
//  - Stores the arrays and slot count in the matching security-level subpool
//  - Links each slot to its context and initializes its atomic availability flag
//  - Sets the security level and expected public key/ciphertext sizes per context
// Notes:
//  - ctx must be valid and number_slots must be a valid, non-zero slot count
//  - Polynomial and byte working buffers are assigned by separate routines
//  - The caller owns the initialized subpool and handles its eventual destruction
int ml_kem_create_all_structs(struct ml_kem_pool_encaps_ctx *ctx, enum ml_kem_k k, size_t number_slots)
{
	// Allocate slot descriptors (each slot holds a context pointer and an atomic flag)
	struct ml_kem_encaps_slot *first_slot;
	first_slot = ml_kem_alloc(sizeof(struct ml_kem_encaps_slot) * number_slots);
	if(!first_slot) { return 1; }
	
	// Allocate and zero-initialize one encapsulation context per slot
	struct ml_kem_encaps_ctx *encapses;
	encapses = ml_kem_alloc(sizeof(struct ml_kem_encaps_ctx) * number_slots);
	if(!encapses) { ml_kem_free(first_slot); return 1; }
	ml_kem_memzero(encapses, sizeof(struct ml_kem_encaps_ctx) * number_slots);
	
	// Select the subpool fields and serialized data sizes for the requested level
	size_t public_key_msg_len;
	size_t ciphertext_len;
	if(k == ML_KEM_512) 
	{ 
		ctx->ml_kem_pool_512 = first_slot;	
		ctx->ml_kem_pool_count_512 = number_slots;
		
		public_key_msg_len = RES_PUBL_PART_LVL_512;
		ciphertext_len = LEN_CIPHERTEXT_512;
	}else if(k == ML_KEM_768)
	{
		ctx->ml_kem_pool_768 = first_slot;
		ctx->ml_kem_pool_count_768 = number_slots;
		
		public_key_msg_len = RES_PUBL_PART_LVL_768;
		ciphertext_len = LEN_CIPHERTEXT_768;
	}else if(k == ML_KEM_1024)
	{
		ctx->ml_kem_pool_1024 = first_slot;
		ctx->ml_kem_pool_count_1024 = number_slots;
		
		public_key_msg_len = RES_PUBL_PART_LVL_1024;
		ciphertext_len = LEN_CIPHERTEXT_1024;
	} else { ml_kem_free(first_slot); ml_kem_free(encapses); return 1; }
	
	// Connect each slot with its context and initialize its metadata and atomic flag
	for(size_t i = 0; i < number_slots; i++)
	{
		first_slot[i].encaps_ctx = &encapses[i];
		ml_kem_atomic_init_slot(&first_slot[i].is_free);
		encapses[i].k = k;
		encapses[i].ciphertext_len = ciphertext_len;
		encapses[i].public_key_msg_len = public_key_msg_len;
	}
	
	return 0;
}

// Allocate and assign contiguous u16 working buffers for an encapsulation subpool.
// Parameters:
//  ctx          - pool descriptor with the selected subpool already initialized
//  k            - ML-KEM security level (ML_KEM_512 / 768 / 1024)
//  number_slots - number of slots in the selected subpool
// Returns:
//  0 on success
//  1 if allocation fails or the security level is unsupported
// Behavior:
//  - Allocates and clears one contiguous u16 memory block for all selected slots
//  - Stores the allocation base pointer in the corresponding pool field
//  - Assigns disjoint slices of that block to each encapsulation context
// Memory layout (per slot, in order):
//  [ public_key (k*N) | u (k*N) | v (N) | y (k*N) | poly (N) ]
//  Total: (3*k + 2) * ML_KEM_N coefficients of type u16 per slot
// Notes:
//  - Requires a valid ctx and preinitialized slots for the selected level
//  - The allocation is owned by the pool, not by the individual contexts
//  - The entire memory block is released by ml_kem_encaps_pool_destroy()
int ml_kem_assign_encaps_pool_u16_buffers(struct ml_kem_pool_encaps_ctx *ctx, enum ml_kem_k k, size_t number_slots)
{
	// Allocate and clear polynomial storage for every slot in the subpool
	u16 *work_mem_two_bytes;
	work_mem_two_bytes = ml_kem_alloc((sizeof(u16) * (k * 3 + 2) * ML_KEM_N) * number_slots);
	if(!work_mem_two_bytes) { return 1; }
	ml_kem_memzero(work_mem_two_bytes, (sizeof(u16) * (k * 3 + 2) * ML_KEM_N) * number_slots);
	
	// Register the allocation base and select the matching slot array
	struct ml_kem_encaps_slot *first_slot;
	if(k == ML_KEM_512)
	{
		first_slot = ctx->ml_kem_pool_512;
		ctx->all_u16_mem_512 = work_mem_two_bytes;
	}else if(k == ML_KEM_768)
	{
		first_slot = ctx->ml_kem_pool_768;
		ctx->all_u16_mem_768 = work_mem_two_bytes;
	}else if(k == ML_KEM_1024)
	{
		first_slot = ctx->ml_kem_pool_1024;
		ctx->all_u16_mem_1024 = work_mem_two_bytes;
	} else { ml_kem_free(work_mem_two_bytes); return 1; }
	
	// Partition the allocation into non-overlapping working regions per slot
	for(size_t i = 0; i < number_slots; i++)
	{
		// Unpacked public key vector t: k polynomials
		first_slot[i].encaps_ctx->public_key = work_mem_two_bytes;
		work_mem_two_bytes += (k * ML_KEM_N);
		
		// Ciphertext vector u: k polynomials
		first_slot[i].encaps_ctx->u = work_mem_two_bytes;
		work_mem_two_bytes += (k * ML_KEM_N);
		
		// Ciphertext polynomial v: one polynomial
		first_slot[i].encaps_ctx->v = work_mem_two_bytes;
		work_mem_two_bytes += ML_KEM_N;
		
		// Ephemeral secret vector y: k polynomials
		first_slot[i].encaps_ctx->y = work_mem_two_bytes;
		work_mem_two_bytes += (k * ML_KEM_N);
		
		// Temporary working polynomial: one polynomial
		first_slot[i].encaps_ctx->poly = work_mem_two_bytes;
		work_mem_two_bytes += ML_KEM_N;
	}
	
	return 0;
}

// Allocate and assign contiguous byte buffers for an encapsulation subpool.
// Parameters:
//  ctx          - pool descriptor with the selected subpool already initialized
//  k            - ML-KEM security level (ML_KEM_512 / 768 / 1024)
//  number_slots - number of slots in the selected subpool
// Returns:
//  0 on success
//  1 if allocation fails or the security level is unsupported
// Behavior:
//  - Selects public key and ciphertext sizes for the requested security level
//  - Allocates and clears one contiguous byte buffer for all selected slots
//  - Stores the allocation base pointer in the corresponding pool field
//  - Assigns public key, ciphertext, and raw XOF output regions to each slot
// Memory layout (per slot, in order):
//  [ public_key_msg (size_pk) | ciphertext (size_ct) | raw_bytes (ML_KEM_MATRIX_XOF_BYTES) ]
// Notes:
//  - Requires a valid ctx and preinitialized slots for the selected level
//  - All three regions are slices of one pool-owned allocation
//  - The entire memory block is released by ml_kem_encaps_pool_destroy()
int ml_kem_assign_encaps_pool_u8_buffers(struct ml_kem_pool_encaps_ctx *ctx, enum ml_kem_k k, size_t number_slots)
{
	// Determine serialized buffer sizes and locate the selected slot array
	size_t size_pk, size_ct;
	struct ml_kem_encaps_slot *first_slot;
	if(k == ML_KEM_512)
	{
		size_ct = LEN_CIPHERTEXT_512;
		size_pk = RES_PUBL_PART_LVL_512;
		first_slot = ctx->ml_kem_pool_512;
	}else if(k == ML_KEM_768)
	{
		size_ct = LEN_CIPHERTEXT_768;
		size_pk = RES_PUBL_PART_LVL_768;
		first_slot = ctx->ml_kem_pool_768;
	}else if(k == ML_KEM_1024)
	{
		size_ct = LEN_CIPHERTEXT_1024;
		size_pk = RES_PUBL_PART_LVL_1024;
		first_slot = ctx->ml_kem_pool_1024;
	}else { return 1; }
	
	
	
	// Allocate and zero-initialize the byte storage for all slots
	u8 *work_mem_two_bytes;
	work_mem_two_bytes = ml_kem_alloc((size_pk + size_ct + (size_t)ML_KEM_MATRIX_XOF_BYTES) * number_slots);
	if(!work_mem_two_bytes) { return 1; }
	ml_kem_memzero(work_mem_two_bytes, (size_pk + size_ct + (size_t)ML_KEM_MATRIX_XOF_BYTES) * number_slots);
	// Preserve the allocation base in the pool for later cleanup
	if(k == ML_KEM_512) { ctx->all_u8_mem_512 = work_mem_two_bytes; }
	else if(k == ML_KEM_768) { ctx->all_u8_mem_768 = work_mem_two_bytes; }
	else if(k == ML_KEM_1024) { ctx->all_u8_mem_1024 = work_mem_two_bytes; }
	
	// Divide the shared allocation into separate byte regions for each slot
	for(size_t i = 0; i < number_slots; i++)
	{
		// Serialized public key used by this encapsulation context
		first_slot[i].encaps_ctx->public_key_msg = work_mem_two_bytes;
		work_mem_two_bytes += size_pk;
		
		// Output ciphertext buffer for this slot
		first_slot[i].encaps_ctx->ciphertext = work_mem_two_bytes;
		work_mem_two_bytes += size_ct;
		
		// Temporary SHAKE/XOF output buffer used during polynomial generation
		first_slot[i].encaps_ctx->raw_bytes = work_mem_two_bytes;
		work_mem_two_bytes += ML_KEM_MATRIX_XOF_BYTES;
	}
	
	return 0;
}









