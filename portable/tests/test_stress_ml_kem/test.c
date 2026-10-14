
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
// To test different security levels, modify CURR_LVL.
// To change the number of iterations, adjust NUMBER_LOOPS accordingly.

#define NUMBER_LOOPS 1000000                      // Number of iterations
enum ml_kem_k CURR_LVL = ML_KEM_1024;             // Security level

// Arrays for shared secrets
u8 shared_secret_in_encaps[ML_KEM_SEED_BYTES];
u8 shared_secret_in_decaps[ML_KEM_SEED_BYTES];

int main(void)
{
    // Determine the exact public key and ciphertext lengths for the selected security level.
    size_t public_key_len;
    size_t ciphertext_len;
    
    if(CURR_LVL == ML_KEM_512)
    {
		public_key_len = RES_PUBL_PART_LVL_512;
        ciphertext_len = LEN_CIPHERTEXT_512;
	}else if(CURR_LVL == ML_KEM_768)
	{
		public_key_len = RES_PUBL_PART_LVL_768;
        ciphertext_len = LEN_CIPHERTEXT_768;
	}else if(CURR_LVL == ML_KEM_1024)
	{
		public_key_len = RES_PUBL_PART_LVL_1024;
        ciphertext_len = LEN_CIPHERTEXT_1024;
	}else {  printf("Unsupported ML-KEM security level\n"); return -1; }

    // Caller-owned output buffers, large enough for any supported security level.
    u8 public_key[RES_PUBL_PART_LVL_1024];
    u8 ciphertext[LEN_CIPHERTEXT_1024];

    // The main loop
    for (size_t i = 0; i < NUMBER_LOOPS; i++)
    {
        // Zeroing before using
        for (size_t j = 0; j < ML_KEM_SEED_BYTES; j++)
        {
            shared_secret_in_encaps[j] = 0;
            shared_secret_in_decaps[j] = 0;
        }

        // Create pool and keys
        struct ml_kem_pool_decaps_ctx *ctx_key;
        ctx_key = ml_kem_create_object(CURR_LVL, 1, NULL);
        if (!ctx_key) 
        {
            printf("ml_kem_create_object() failed at iteration %zu\n", i);
            return -1;
        }

        // Extract the public key through the public API
        int ret = ml_kem_get_public_key(ctx_key, public_key, public_key_len);
        if (ret != 0)
        {
            printf("ml_kem_get_public_key() failed at iteration %zu: %d\n", i, ret);
            ml_kem_destroy_core(ctx_key);
            return -1;
        }

        // Encapsulation - get first shared secret
        // NULL selects standalone encapsulation; ciphertext is written into our buffer.
        ret = ml_kem_encaps_core(NULL, public_key, public_key_len, ciphertext, ciphertext_len, shared_secret_in_encaps, ML_KEM_SEED_BYTES, NULL);
        if (ret != 0)
        {
            ml_kem_destroy_core(ctx_key);
            printf("ml_kem_encaps_core() failed at iteration %zu: %d\n", i, ret);
            return -1;
        }

        // Decapsulation - get second shared secret
        ret = ml_kem_decaps_core(ctx_key, ciphertext, ciphertext_len, shared_secret_in_decaps, ML_KEM_SEED_BYTES);
        if (ret != 0)
        {
            printf("Error in ml_kem_decaps_core(), iteration number %zu: %d\n", i, ret);
            ml_kem_destroy_core(ctx_key);
            return -1;
        }

        // Compare two shared secrets
        if (memcmp(shared_secret_in_encaps, shared_secret_in_decaps, ML_KEM_SEED_BYTES) != 0)
        {
            printf("Different shared secrets in iteration %zu\n", i);
            ml_kem_destroy_core(ctx_key);
            return -1;
        }

        // Clean memory: ciphertext is caller-owned and must not be freed.
        ml_kem_destroy_core(ctx_key);

        // printf("Progress: %zu\n", i); - if you need to review each iteration

        // Info about progress
        if ((i % 10000) == 0) { printf("Progress: %zu\n", i); }
    }

    // Result info message
    printf("Everything is correct in this test, thank you for attention.....\n");

    return 0;
}

