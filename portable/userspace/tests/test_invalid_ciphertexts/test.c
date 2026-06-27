#include <stdio.h>
#include <string.h>
#include "ml_kem.h"

// Number of iterations
#define LOOPS 100000

// Number of slots in the decapsulation pool
#define SLOTS 2

// Start value for PRNG
u8 pseudo = 0xA5;

int main(void)
{
    // Main test loop
    for(size_t i = 0; i < LOOPS; i++)
    {
        // Create ML-KEM object
        struct ml_kem_pool_decaps_ctx *ctx;
        ctx = ml_kem_create_object(ML_KEM_768, SLOTS, NULL);
        if(!ctx)
        {
            printf("create failed\n");
            return -1;
        }

        // Temp buffers and pointer for shared secrets and ciphertext
        u8 result_enc[32];
        u8 result_dec[32];
        u8 result_bad_1[32];
        u8 result_bad_2[32];
        u8 *ciphertext;

        // Encaps
        ciphertext = ml_kem_encaps_core(ctx->ml_kem_pool[0].encaps_ctx->public_key_msg, ML_KEM_768, result_enc, NULL);
        if(!ciphertext)
        {
            printf("encaps failed\n");
            ml_kem_destroy_core(ctx);
            return -1;
        }

        // Valid decapsulation
        int ret = ml_kem_decaps_core(ctx, ciphertext, LEN_CIPHERTEXT_768, result_dec, 32);
        if(ret != 0)
        {
            printf("valid decaps failed\n");
            ml_kem_ciphertext_destroy_core(ciphertext, ML_KEM_768);
            ml_kem_destroy_core(ctx);
            return -1;
        }

        // Check valid shared secret
        if(memcmp(result_enc, result_dec, 32) != 0)
        {
			ml_kem_ciphertext_destroy_core(ciphertext, ML_KEM_768);
            ml_kem_destroy_core(ctx);
            printf("valid shared secret mismatch\n");
            return -1;
        }

		// Ciphertext corruption in this iteration
		pseudo = (u8)(pseudo * 33u + 17u);
		size_t random_pos = i % LEN_CIPHERTEXT_768;
		u8 old = ciphertext[random_pos];
		u8 value = pseudo;

		// Ensure ciphertext byte is really changed 
		while(value == old)
		{
			pseudo = (u8)(pseudo * 33u + 17u);
			value = pseudo;
		}

		ciphertext[random_pos] = value;

        // First decapsulation of corrupted ciphertext
        ret = ml_kem_decaps_core(ctx, ciphertext, LEN_CIPHERTEXT_768, result_bad_1, 32);
        if(ret != 0)
        {
            printf("corrupted decaps #1 failed\n");
            ml_kem_ciphertext_destroy_core(ciphertext, ML_KEM_768);
            ml_kem_destroy_core(ctx);
            return -1;
        }

        // Second decapsulation of corrupted ciphertext
        ret = ml_kem_decaps_core(ctx, ciphertext, LEN_CIPHERTEXT_768, result_bad_2, 32);
        if(ret != 0)
        {
            printf("corrupted decaps #2 failed\n");
            ml_kem_ciphertext_destroy_core(ciphertext, ML_KEM_768);
            ml_kem_destroy_core(ctx);
            return -1;
        }

        // Corrupted ciphertext must NOT produce valid secret
        if(memcmp(result_enc, result_bad_1, 32) == 0)
        {
			ml_kem_ciphertext_destroy_core(ciphertext, ML_KEM_768);
            ml_kem_destroy_core(ctx);
            printf("implicit rejection failed\n");
            return -1;
        }

        // Same corrupted ciphertext must produce same fallback secret
        if(memcmp(result_bad_1, result_bad_2, 32) != 0)
        {
			ml_kem_ciphertext_destroy_core(ciphertext, ML_KEM_768);
            ml_kem_destroy_core(ctx);
            printf("z fallback mismatch\n");
            return -1;
        }

        // Destroy objects
        ml_kem_ciphertext_destroy_core(ciphertext, ML_KEM_768);
        ml_kem_destroy_core(ctx);
        
        // Info about progress
		if ((i % 10000) == 0) { printf("Progress: %zu\n", i); }
    }
    
    // Result info messege
	printf("Everything is correct in this test, thank you for attention.....\n");

    printf("done\n");
    return 0;
}
