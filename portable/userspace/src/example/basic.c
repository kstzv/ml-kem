// SPDX-License-Identifier: GPL-2.0 OR MIT
// Copyright (c) 2026 K.S.Zavertailo
#include "ml_kem.h"
#include <stdio.h>
#include <string.h>

int main()
{
	// Create keys and pool
    struct ml_kem_pool_decaps_ctx *ctx;
    ctx = ml_kem_create_object(ML_KEM_768, 4);
    if (!ctx) { fprintf(stderr, "Failed to create ML-KEM context\n"); return 1; }
    printf("ML-KEM object created\n");
    
    // Pointer for ciphertext and buffer for shared secret
    u8 *ciphertext;
    u8 shared_secret[ML_KEM_SEED_BYTES];
    u8 public_key_msg[ctx->ml_kem_pool[0].decrypt_ctx->ctx->public_key_msg_len];
    memcpy(public_key_msg, ctx->ml_kem_pool[0].decrypt_ctx->ctx->public_key_msg, 
		ctx->ml_kem_pool[0].decrypt_ctx->ctx->public_key_msg_len);
    
    // Encapsutation
    ciphertext = ml_kem_encaps_core(public_key_msg, ML_KEM_768, shared_secret);
    if (!ciphertext)
	{ 
		fprintf(stderr, "Failed to encapsulate\n"); 
		ml_kem_destroy_core(ctx); 
		return 1;
	}
    
    // Decapsulation
    u8 shared_secret_decaps[ML_KEM_SEED_BYTES];
    int ret = ml_kem_decaps_core(ctx, ciphertext, LEN_CIPHERTEXT_768, shared_secret_decaps, ML_KEM_SEED_BYTES);
    if(ret != 0) { fprintf(stderr, "Failed to decaps ML-KEM context\n"); return 1; }
    
    if (memcmp(shared_secret, shared_secret_decaps, ML_KEM_SEED_BYTES) != 0)
	{ fprintf(stderr, "Shared secrets mismatch\n"); return 1; }
    
    // Destructors for Encapsutation, Pool and Keys
    ml_kem_ciphertext_destroy_core(ciphertext, ML_KEM_768);
    ml_kem_destroy_core(ctx);
    
    printf("ML-KEM object destroyed\n");

    return 0;
}
