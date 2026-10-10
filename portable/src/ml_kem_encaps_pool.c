// SPDX-License-Identifier: GPL-2.0 OR MIT
// Copyright (c) 2026 K.S.Zavertailo

// File #10 - encapsulation pool management

#include "ml_kem_core_header.h"

int ml_kem_create_all_structs(struct ml_kem_pool_encaps_ctx *ctx, enum ml_kem_k k, size_t number_slots);
int ml_kem_assign_encaps_pool_u16_buffers(struct ml_kem_pool_encaps_ctx *ctx, enum ml_kem_k k, size_t number_slots);
int ml_kem_assign_encaps_pool_u8_buffers(struct ml_kem_pool_encaps_ctx *ctx, enum ml_kem_k k, size_t number_slots);

int ml_kem_create_all_structs(struct ml_kem_pool_encaps_ctx *ctx, enum ml_kem_k k, size_t number_slots)
{
	struct ml_kem_encaps_slot *first_slot;
	first_slot = ml_kem_alloc(sizeof(struct ml_kem_encaps_slot) * number_slots);
	if(!first_slot) { return 1; }
	
	struct ml_kem_encaps_ctx *encapses;
	encapses = ml_kem_alloc(sizeof(struct ml_kem_encaps_ctx) * number_slots);
	if(!encapses) { ml_kem_free(first_slot); return 1; }
	ml_kem_memzero(encapses, sizeof(struct ml_kem_encaps_ctx) * number_slots);
	
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
	}
	
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

int ml_kem_assign_encaps_pool_u16_buffers(struct ml_kem_pool_encaps_ctx *ctx, enum ml_kem_k k, size_t number_slots)
{
	u16 *work_mem_two_bytes;
	work_mem_two_bytes = ml_kem_alloc((sizeof(u16) * (k * 3 + 2) * ML_KEM_N) * number_slots);
	if(!work_mem_two_bytes) { return 1; }
	ml_kem_memzero(work_mem_two_bytes, (sizeof(u16) * (k * 3 + 2) * ML_KEM_N) * number_slots);
	
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
	
	for(size_t i = 0; i < number_slots; i++)
	{
		first_slot[i].encaps_ctx->public_key = work_mem_two_bytes;
		work_mem_two_bytes += (k * ML_KEM_N);
		
		first_slot[i].encaps_ctx->u = work_mem_two_bytes;
		work_mem_two_bytes += (k * ML_KEM_N);
		
		first_slot[i].encaps_ctx->v = work_mem_two_bytes;
		work_mem_two_bytes += ML_KEM_N;
		
		first_slot[i].encaps_ctx->y = work_mem_two_bytes;
		work_mem_two_bytes += (k * ML_KEM_N);
		
		first_slot[i].encaps_ctx->poly = work_mem_two_bytes;
		work_mem_two_bytes += ML_KEM_N;
	}
	
	return 0;
}

int ml_kem_assign_encaps_pool_u8_buffers(struct ml_kem_pool_encaps_ctx *ctx, enum ml_kem_k k, size_t number_slots)
{
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
	
	
	
	u8 *work_mem_two_bytes;
	work_mem_two_bytes = ml_kem_alloc((size_pk + size_ct + (size_t)ML_KEM_MATRIX_XOF_BYTES) * number_slots);
	if(!work_mem_two_bytes) { return 1; }
	ml_kem_memzero(work_mem_two_bytes, (size_pk + size_ct + (size_t)ML_KEM_MATRIX_XOF_BYTES) * number_slots);
	if(k == ML_KEM_512) { ctx->all_u8_mem_512 = work_mem_two_bytes; }
	else if(k == ML_KEM_768) { ctx->all_u8_mem_768 = work_mem_two_bytes; }
	else if(k == ML_KEM_1024) { ctx->all_u8_mem_1024 = work_mem_two_bytes; }
	
	for(size_t i = 0; i < number_slots; i++)
	{
		first_slot[i].encaps_ctx->public_key_msg = work_mem_two_bytes;
		work_mem_two_bytes += size_pk;
		
		first_slot[i].encaps_ctx->ciphertext = work_mem_two_bytes;
		work_mem_two_bytes += size_ct;
		
		first_slot[i].encaps_ctx->raw_bytes = work_mem_two_bytes;
		work_mem_two_bytes += ML_KEM_MATRIX_XOF_BYTES;
	}
	
	return 0;
}









