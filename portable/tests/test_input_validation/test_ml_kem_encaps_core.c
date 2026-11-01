// SPDX-License-Identifier: GPL-2.0 OR MIT
// Copyright (c) 2026 K.S.Zavertailo

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
	
	u8 ct_512[LEN_CIPHERTEXT_512];
	u8 ct_768[LEN_CIPHERTEXT_768];
	u8 ct_1024[LEN_CIPHERTEXT_1024];
	
	u8 pk_512[RES_PUBL_PART_LVL_512];
	u8 pk_768[RES_PUBL_PART_LVL_768];
	u8 pk_1024[RES_PUBL_PART_LVL_1024];

	// Main test loop
	for(size_t i = 0; i < LOOPS; i++)
	{
		int ret = 0;
		// Create valid ML-KEM objects
		struct ml_kem_general_keys_decaps_ctx *ctx_512;
		ctx_512 = ml_kem_create_object(ML_KEM_512, 2, NULL);
		if(ctx_512 == NULL)
		{
			printf("Error: create ML_KEM_512\n");
			return -1;
		}

		struct ml_kem_general_keys_decaps_ctx *ctx_768;
		ctx_768 = ml_kem_create_object(ML_KEM_768, 2, NULL);
		if(ctx_768 == NULL)
		{
			printf("Error: create ML_KEM_768\n");
			ret = -1;
			goto ex_1;
		}

		struct ml_kem_general_keys_decaps_ctx *ctx_1024;
		ctx_1024 = ml_kem_create_object(ML_KEM_1024, 2, NULL);
		if(ctx_1024 == NULL)
		{
			printf("Error: create ML_KEM_1024\n");
			ret = -1;
			goto ex_2;
		}
		
		ret = ml_kem_get_public_key(ctx_512, pk_512, RES_PUBL_PART_LVL_512);
		if(ret != 0) { printf("Error: get pk ML_KEM_512\n"); goto ex_3; }
		
		ret = ml_kem_get_public_key(ctx_768, pk_768, RES_PUBL_PART_LVL_768);
		if(ret != 0) { printf("Error: get pk ML_KEM_768\n"); goto ex_3; }
		
		ret = ml_kem_get_public_key(ctx_1024, pk_1024, RES_PUBL_PART_LVL_1024);
		if(ret != 0) { printf("Error: get pk ML_KEM_1024\n"); goto ex_3; }

		// -----------------------------------------------------------------
		// VALID TESTS
		// -----------------------------------------------------------------

		ret = ml_kem_encaps_core(NULL, pk_512, RES_PUBL_PART_LVL_512, ct_512, LEN_CIPHERTEXT_512, result_512, 32, NULL);
		if(ret != 0)
		{
			printf("Error: encaps ML_KEM_512\n");
			goto ex_3;
		}

		ret = ml_kem_encaps_core(NULL, pk_768, RES_PUBL_PART_LVL_768, ct_768, LEN_CIPHERTEXT_768, result_768, 32, NULL);
		if(ret != 0)
		{
			printf("Error: encaps ML_KEM_768\n");
			goto ex_3;
		}

		ret = ml_kem_encaps_core(NULL, pk_1024, RES_PUBL_PART_LVL_1024, ct_1024, LEN_CIPHERTEXT_1024, result_1024, 32, NULL);
		if(ret != 0)
		{
			printf("Error: encaps ML_KEM_1024\n");
			goto ex_3;
		}

		// -----------------------------------------------------------------
		// INVALID TESTS
		// -----------------------------------------------------------------

		ret = ml_kem_encaps_core(NULL, NULL, RES_PUBL_PART_LVL_1024, ct_1024, LEN_CIPHERTEXT_1024, result_1024, 32, NULL);
		if(ret == 0) { printf("Error: wrong pk accepted\n"); ret = -1; goto ex_3; }
		ret = 0;
		
		ret = ml_kem_encaps_core(NULL, pk_1024, 12, ct_1024, LEN_CIPHERTEXT_1024, result_1024, 32, NULL);
		if(ret == 0) { printf("Error: wrong pk accepted\n"); ret = -1; goto ex_3; }
		ret = 0;
		
		ret = ml_kem_encaps_core(NULL, pk_1024, RES_PUBL_PART_LVL_1024, NULL, LEN_CIPHERTEXT_1024, result_1024, 32, NULL);
		if(ret == 0) { printf("Error: wrong ct accepted\n"); ret = -1; goto ex_3; }
		ret = 0;
		
		ret = ml_kem_encaps_core(NULL, pk_1024, RES_PUBL_PART_LVL_1024, ct_1024, 54655, result_1024, 32, NULL);
		if(ret == 0) { printf("Error: wrong ct accepted\n"); ret = -1; goto ex_3; }
		ret = 0;
		
		ret = ml_kem_encaps_core(NULL, pk_1024, RES_PUBL_PART_LVL_1024, ct_1024, LEN_CIPHERTEXT_1024, NULL, 32, NULL);
		if(ret == 0) { printf("Error: wrong ss accepted\n"); ret = -1; goto ex_3; }
		ret = 0;
		
		ret = ml_kem_encaps_core(NULL, pk_1024, RES_PUBL_PART_LVL_1024, ct_1024, LEN_CIPHERTEXT_1024, result_1024, 122, NULL);
		if(ret == 0) { printf("Error: wrong ss accepted\n"); ret = -1; goto ex_3; }
		ret = 0;

		// -----------------------------------------------------------------
		// CLEANUP
		// -----------------------------------------------------------------
		
		ex_3:
			ml_kem_destroy_core(ctx_1024);
		ex_2:
			ml_kem_destroy_core(ctx_768);
		ex_1:
			ml_kem_destroy_core(ctx_512);
		
		if(ret != 0) { return -1; }

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


























