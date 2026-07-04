// SPDX-License-Identifier: GPL-2.0 OR MIT
// Copyright (c) 2026 K.S.Zavertailo
#include "ml_kem.h"
#include <stdio.h>
#include <string.h>

const size_t size_pk = 1184; // 800 - L512; 1184 - L768; 1568 - L1024

int main()
{
	// Create keys and pool
    struct ml_kem_pool_decaps_ctx *ctx;
    ctx = ml_kem_create_object(ML_KEM_768, 4, NULL);
    if (!ctx) { fprintf(stderr, "Failed to create ML-KEM context\n"); return 1; }
    printf("ML-KEM object created\n");
    
    u8 the_pk_buffer[size_pk];
    int ret = ml_kem_get_public_key(ctx, the_pk_buffer, size_pk);
    if(ret != 0) { fprintf(stderr, "Failed to get pk\n"); return 1; }
    
    // Pointer for ciphertext and buffer for shared secret
    u8 *ciphertext;
    u8 shared_secret[ML_KEM_SEED_BYTES];
    
    // Encapsutation
    ciphertext = ml_kem_encaps_core(the_pk_buffer, ML_KEM_768, shared_secret, NULL);
    if (!ciphertext)
	{ 
		fprintf(stderr, "Failed to encapsulate\n"); 
		ml_kem_destroy_core(ctx); 
		return 1;
	}
    
    // Decapsulation
    u8 shared_secret_decaps[ML_KEM_SEED_BYTES];
    ret = ml_kem_decaps_core(ctx, ciphertext, LEN_CIPHERTEXT_768, shared_secret_decaps, ML_KEM_SEED_BYTES);
    if(ret != 0) { fprintf(stderr, "Failed to decaps ML-KEM context\n"); return 1; }
    
    if (memcmp(shared_secret, shared_secret_decaps, ML_KEM_SEED_BYTES) != 0)
	{ fprintf(stderr, "Shared secrets mismatch\n"); return 1; }
    
    // Destructors for Encapsutation, Pool and Keys
    ml_kem_ciphertext_destroy_core(ciphertext, ML_KEM_768);
    ml_kem_destroy_core(ctx);
    
    printf("ML-KEM object destroyed\n");

    return 0;
}
