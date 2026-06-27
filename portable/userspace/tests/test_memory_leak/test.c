#include <stdio.h>
#include <string.h>
#include "ml_kem.h"

// Number of iterations
#define LOOPS 1000

// Number of slots in the decapsulation pool
#define SLOTS 2

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
            return 1;
        }

		// Temp buffers and pointer for shared secrets and ciphertext
        u8 result_enc[32];
        u8 result_dec[32];
        u8 *ciphertext;

		// Encaps
        ciphertext = ml_kem_encaps_core(ctx->ml_kem_pool[0].encaps_ctx->public_key_msg, ML_KEM_768, result_enc, NULL);
        if(!ciphertext)
        {
            printf("encaps failed\n");
            ml_kem_destroy_core(ctx);
            return 1;
        }

		// Decaps
        int ret = ml_kem_decaps_core(ctx, ciphertext, LEN_CIPHERTEXT_768, result_dec, 32);
        if(ret != 0)
        {
            printf("decaps failed\n");
            ml_kem_ciphertext_destroy_core(ciphertext, ML_KEM_768);
            ml_kem_destroy_core(ctx);
            return 1;
        }

		// Check shares secrets
        if(memcmp(result_enc, result_dec, 32) != 0)
        {
            printf("shared secret mismatch\n");
            return 1;
        }

		// Ruin objects
        ml_kem_ciphertext_destroy_core(ciphertext, ML_KEM_768);
        ml_kem_destroy_core(ctx);
    }

    printf("done\n");
    return 0;
}
