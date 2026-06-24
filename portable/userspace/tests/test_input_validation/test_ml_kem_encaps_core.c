#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include "ml_kem.h"

// Number of iterations
#define LOOPS 1000

int main(void)
{
	srand((unsigned)time(NULL));

	// Result buffers
	u8 result_512[32];
	u8 result_768[32];
	u8 result_1024[32];

	// Main test loop
	for(size_t i = 0; i < LOOPS; i++)
	{
		// Create valid ML-KEM objects
		struct ml_kem_pool_decaps_ctx *ctx_512;
		struct ml_kem_pool_decaps_ctx *ctx_768;
		struct ml_kem_pool_decaps_ctx *ctx_1024;

		ctx_512 = ml_kem_create_object(ML_KEM_512, 2);
		if(ctx_512 == NULL)
		{
			printf("Error: create ML_KEM_512\n");
			return -1;
		}

		ctx_768 = ml_kem_create_object(ML_KEM_768, 2);
		if(ctx_768 == NULL)
		{
			printf("Error: create ML_KEM_768\n");
			return -1;
		}

		ctx_1024 = ml_kem_create_object(ML_KEM_1024, 2);
		if(ctx_1024 == NULL)
		{
			printf("Error: create ML_KEM_1024\n");
			return -1;
		}

		// -----------------------------------------------------------------
		// VALID TESTS
		// -----------------------------------------------------------------

		u8 *ct_512;
		u8 *ct_768;
		u8 *ct_1024;

		ct_512 = ml_kem_encaps_core(
			ctx_512->ml_kem_pool[0].encaps_ctx->public_key_msg,
			ML_KEM_512,
			result_512
		);

		if(ct_512 == NULL)
		{
			printf("Error: encaps ML_KEM_512\n");
			return -1;
		}

		ct_768 = ml_kem_encaps_core(
			ctx_768->ml_kem_pool[0].encaps_ctx->public_key_msg,
			ML_KEM_768,
			result_768
		);

		if(ct_768 == NULL)
		{
			printf("Error: encaps ML_KEM_768\n");
			return -1;
		}

		ct_1024 = ml_kem_encaps_core(
			ctx_1024->ml_kem_pool[0].encaps_ctx->public_key_msg,
			ML_KEM_1024,
			result_1024
		);

		if(ct_1024 == NULL)
		{
			printf("Error: encaps ML_KEM_1024\n");
			return -1;
		}

		// -----------------------------------------------------------------
		// INVALID TESTS
		// -----------------------------------------------------------------

		u8 *wrong_ct;

		// NULL public key
		wrong_ct = ml_kem_encaps_core(
			NULL,
			ML_KEM_768,
			result_768
		);

		if(wrong_ct != NULL)
		{
			printf("Error: NULL pk accepted\n");
			return -1;
		}

		// NULL result buffer
		wrong_ct = ml_kem_encaps_core(
			ctx_768->ml_kem_pool[0].encaps_ctx->public_key_msg,
			ML_KEM_768,
			NULL
		);

		if(wrong_ct != NULL)
		{
			printf("Error: NULL result accepted\n");
			return -1;
		}

		// Invalid level
		wrong_ct = ml_kem_encaps_core(
			ctx_768->ml_kem_pool[0].encaps_ctx->public_key_msg,
			999,
			result_768
		);

		if(wrong_ct != NULL)
		{
			printf("Error: invalid level accepted\n");
			return -1;
		}

		// -----------------------------------------------------------------
		// CLEANUP
		// -----------------------------------------------------------------

		ml_kem_ciphertext_destroy_core(ct_512, ML_KEM_512);
		ml_kem_ciphertext_destroy_core(ct_768, ML_KEM_768);
		ml_kem_ciphertext_destroy_core(ct_1024, ML_KEM_1024);

		ml_kem_destroy_core(ctx_512);
		ml_kem_destroy_core(ctx_768);
		ml_kem_destroy_core(ctx_1024);

		// Progress output
		if(i % 10 == 0)
		{
			printf("Progress %zu.....\n", i);
		}
	}

	// Result info message
	printf("Everything is correct in this test, thank you for attention.....\n");

	printf("done\n");

	return 0;
}













