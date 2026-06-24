#include <stdio.h>
#include <string.h>
#include "ml_kem.h"

// This test performs large-scale end-to-end validation of the ML-KEM implementation.
// Each iteration includes:
//   - key generation
//   - encapsulation
//   - decapsulation
//   - comparison of derived shared secrets
// The goal of this test is to increase confidence in the correctness of the implementation,
// in addition to NIST Known Answer Tests (KAT).
// By default, NUMBER_LOOPS is set to 1,000,000 iterations.
// To test different security levels, modify:
//   - CURR_LVL
//   - ciphertext_len
// To change the number of iterations, adjust NUMBER_LOOPS accordingly.

#define NUMBER_LOOPS 1000000                      // Number of iterations
enum ml_kem_k CURR_LVL = ML_KEM_1024;             // Level of sequrity
const size_t ciphertext_len = LEN_CIPHERTEXT_1024;// Size of ciphertext

// Massives for shared secrets
u8 shared_secret_in_encaps[ML_KEM_SEED_BYTES];
u8 shared_secret_in_decaps[ML_KEM_SEED_BYTES];

int main()
{
	// The main loop
	for(size_t i = 0; i < NUMBER_LOOPS; i++)
	{
		// zeroing before using
		for(size_t j = 0; j < ML_KEM_SEED_BYTES; j++)
		{
			shared_secret_in_encaps[j] = 0;
			shared_secret_in_decaps[j] = 0;
		}
		
		// create pool and keys
		struct ml_kem_pool_decaps_ctx *ctx_key; 
		ctx_key = ml_kem_create_object(CURR_LVL, 1);
		if(!ctx_key) { printf("ml_kem_create_object() failed at iteration %zu\n", i); return -1; }
		
		// encapsulation - get first shared secret
		u8 *ciphertext;
		ciphertext = ml_kem_encaps_core(ctx_key->ml_kem_pool[0].decrypt_ctx->ctx->public_key_msg, CURR_LVL, shared_secret_in_encaps);
		if(!ciphertext) 
		{ 
			ml_kem_destroy_core(ctx_key);
			printf("ml_kem_encaps_core() failed at iteration %zu\n", i); 
			return -1; 
		}
		
		// dencapsulation - get second shared secret
		int ret = ml_kem_decaps_core(ctx_key, ciphertext, ciphertext_len, shared_secret_in_decaps, ML_KEM_SEED_BYTES);
		if(ret != 0) 
		{ 
			printf("Error in ml_kem_decaps_core(), iterations number %zu\n", i);
			ml_kem_ciphertext_destroy_core(ciphertext, CURR_LVL);
			ml_kem_destroy_core(ctx_key); 
			return -1;
		}
		
		// comparison two shared secrets
		if(memcmp(shared_secret_in_encaps, shared_secret_in_decaps, ML_KEM_SEED_BYTES) != 0)
		{
			printf("Different shared secrets in iteration %zu\n", i);
			ml_kem_ciphertext_destroy_core(ciphertext, CURR_LVL);
			ml_kem_destroy_core(ctx_key);
			return -1;
		}
		
		// Clean memory
		ml_kem_ciphertext_destroy_core(ciphertext, CURR_LVL);
		ml_kem_destroy_core(ctx_key);
		
		// printf("Progress: %zu\n", i); - if you need to review each iteration
		
		// Info about progress
		if ((i % 10000) == 0) { printf("Progress: %zu\n", i); }
	}
	
	// Result info messege
	printf("Everything is correct in this test, thank you for attention.....\n");
	
	return 0;
}
