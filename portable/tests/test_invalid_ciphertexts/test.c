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
    for(size_t i = 0; i < LOOPS; i++)
    {
        int ret = -1;

        struct ml_kem_pool_decaps_ctx *ctx;
        ctx = ml_kem_create_object(ML_KEM_768, SLOTS, NULL);
        if(!ctx)
        {
            printf("create failed\n");
            return -1;
        }

        u8 public_key[RES_PUBL_PART_LVL_768];
        u8 ciphertext[LEN_CIPHERTEXT_768];

        u8 result_enc[32];
        u8 result_dec[32];
        u8 result_bad_1[32];
        u8 result_bad_2[32];

        // Get public key
        ret = ml_kem_get_public_key(
            ctx, public_key, sizeof(public_key)
        );
        if(ret != 0)
        {
            printf("get public key failed\n");
            goto error_exit;
        }

        // Encapsulation
        ret = ml_kem_encaps_core(
            NULL,
            public_key,
            sizeof(public_key),
            ciphertext,
            sizeof(ciphertext),
            result_enc,
            sizeof(result_enc),
            NULL
        );
        if(ret != 0)
        {
            printf("encaps failed\n");
            goto error_exit;
        }

        // Valid decapsulation
        ret = ml_kem_decaps_core(
            ctx, ciphertext, sizeof(ciphertext),
            result_dec, sizeof(result_dec)
        );
        if(ret != 0)
        {
            printf("valid decaps failed\n");
            goto error_exit;
        }

        // Check valid shared secret
        if(memcmp(result_enc, result_dec, 32) != 0)
        {
            printf("valid shared secret mismatch\n");
            ret = -1;
            goto error_exit;
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
        ret = ml_kem_decaps_core(
            ctx, ciphertext, sizeof(ciphertext),
            result_bad_1, sizeof(result_bad_1)
        );
        if(ret != 0)
        {
            printf("corrupted decaps #1 failed\n");
            goto error_exit;
        }

        // Second decapsulation of corrupted ciphertext
        ret = ml_kem_decaps_core(
            ctx, ciphertext, sizeof(ciphertext),
            result_bad_2, sizeof(result_bad_2)
        );
        if(ret != 0)
        {
            printf("corrupted decaps #2 failed\n");
            goto error_exit;
        }

        // Corrupted ciphertext must NOT produce valid secret
        if(memcmp(result_enc, result_bad_1, 32) == 0)
        {
            printf("implicit rejection failed\n");
            ret = -1;
            goto error_exit;
        }

        // Same corrupted ciphertext must produce same fallback secret
        if(memcmp(result_bad_1, result_bad_2, 32) != 0)
        {
            printf("z fallback mismatch\n");
            ret = -1;
            goto error_exit;
        }

        // Successful iteration
        ret = 0;

        error_exit:
            ml_kem_destroy_core(ctx);

        if(ret != 0) { return -1; }

        if((i % 10000) == 0)
        {
            printf("Progress: %zu\n", i);
        }
    }

    printf("Everything is correct in this test, thank you for attention.....\n");
    printf("done\n");

    return 0;
}

