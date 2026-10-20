#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include "ml_kem.h"

// Number of iterations
#define LOOPS 1000

#define SIZE_POOL 10

int main(void)
{
	int ret = 0;
	
	srand((unsigned)time(NULL));
   
    struct ml_kem_general_keys_decaps_ctx *ctx_512;
    ctx_512 = ml_kem_create_object(ML_KEM_512, SIZE_POOL, NULL);
    if(!ctx_512) { printf("Error in ml_kem_create_object() for ML_KEM_512\n"); return -1; }
    
    struct ml_kem_general_keys_decaps_ctx *ctx_768;
    ctx_768 = ml_kem_create_object(ML_KEM_768, SIZE_POOL, NULL);
    if(!ctx_768) { printf("Error in ml_kem_create_object() for ML_KEM_768\n"); ret = -1; goto ex_1; }
    
    struct ml_kem_general_keys_decaps_ctx *ctx_1024;
    ctx_1024 = ml_kem_create_object(ML_KEM_1024, SIZE_POOL, NULL);
    if(!ctx_1024) { printf("Error in ml_kem_create_object() for ML_KEM_1024\n"); ret = -1; goto ex_2; }
    
    u8 result[32];
    size_t temp;
    
    u8 ct_512[LEN_CIPHERTEXT_512];
	u8 ct_768[LEN_CIPHERTEXT_768];
	u8 ct_1024[LEN_CIPHERTEXT_1024];
	
	u8 pk_512[RES_PUBL_PART_LVL_512];
	u8 pk_768[RES_PUBL_PART_LVL_768];
	u8 pk_1024[RES_PUBL_PART_LVL_1024];
    
    for(size_t i = 0; i < LOOPS; i++)
    {
		ret = ml_kem_get_public_key(ctx_512, pk_512, RES_PUBL_PART_LVL_512);
		if(ret != 0) { printf("Error: get pk ML_KEM_512\n"); goto ex_3; }
		
		ret = ml_kem_encaps_core(NULL, pk_512, RES_PUBL_PART_LVL_512, ct_512, LEN_CIPHERTEXT_512, result, 32, NULL);
		if(ret != 0) { printf("Error in ml_kem_encaps_core() for ML_KEM_512\n"); goto ex_3; }
		
		ret = ml_kem_decaps_core(ctx_512, ct_512, LEN_CIPHERTEXT_512, result, 32);
		if(ret != 0) { printf("Error in ml_kem_decaps_core() for ML_KEM_512\n"); goto ex_3; }
		
		ret = ml_kem_decaps_core(NULL, ct_512, LEN_CIPHERTEXT_512, result, 32);
		if(ret == 0) { printf("Error: got wrong first parametr in ml_kem_decaps_core() for ML_KEM_512\n"); ret = -1; goto ex_3; }
		
		ret = ml_kem_decaps_core(ctx_512, NULL, LEN_CIPHERTEXT_512, result, 32);
		if(ret == 0) { printf("Error: got wrong second parametr in ml_kem_decaps_core() for ML_KEM_512\n"); ret = -1; goto ex_3; }
		
		temp = rand();
		if(temp == LEN_CIPHERTEXT_512) { temp++; }
		ret = ml_kem_decaps_core(ctx_512, ct_512, temp, result, 32);
		if(ret == 0) { printf("Error: got wrong third parametr in ml_kem_decaps_core() for ML_KEM_512\n"); ret = -1; goto ex_3; }
		
		ret = ml_kem_decaps_core(ctx_512, ct_512, LEN_CIPHERTEXT_512, NULL, 32);
		if(ret == 0) { printf("Error: got wrong fourth parametr in ml_kem_decaps_core() for ML_KEM_512\n"); ret = -1; goto ex_3; }
		
		temp = rand();
		if(temp == 32) { temp++; }
		ret = ml_kem_decaps_core(ctx_512, ct_512, LEN_CIPHERTEXT_512, result, temp);
		if(ret == 0) { printf("Error: got wrong fiveth parametr in ml_kem_decaps_core() for ML_KEM_512\n"); ret = -1; goto ex_3; }
	}
    
    // Result info messege
	printf("Everything is correct in first loop in this test.....\n");
	
	for(size_t i = 0; i < LOOPS; i++)
    {
		ret = ml_kem_get_public_key(ctx_768, pk_768, RES_PUBL_PART_LVL_768);
		if(ret != 0) { printf("Error: get pk ML_KEM_768\n"); goto ex_3; }
		
		ret = ml_kem_encaps_core(NULL, pk_768, RES_PUBL_PART_LVL_768, ct_768, LEN_CIPHERTEXT_768, result, 32, NULL);
		if(ret != 0) { printf("Error in ml_kem_encaps_core() for ML_KEM_1024\n"); goto ex_3; }
		
		ret = ml_kem_decaps_core(ctx_768, ct_768, LEN_CIPHERTEXT_768, result, 32);
		if(ret != 0) { printf("Error in ml_kem_decaps_core() for ML_KEM_768\n"); goto ex_3; }
		
		ret = ml_kem_decaps_core(NULL, ct_768, LEN_CIPHERTEXT_768, result, 32);
		if(ret == 0) { printf("Error: got wrong first parametr in ml_kem_decaps_core() for ML_KEM_768\n"); ret = -1; goto ex_3; }
		
		ret = ml_kem_decaps_core(ctx_768, NULL, LEN_CIPHERTEXT_768, result, 32);
		if(ret == 0) { printf("Error: got wrong second parametr in ml_kem_decaps_core() for ML_KEM_768\n"); ret = -1; goto ex_3; }
		
		temp = rand();
		if(temp == LEN_CIPHERTEXT_768) { temp++; }
		ret = ml_kem_decaps_core(ctx_768, ct_768, temp, result, 32);
		if(ret == 0) { printf("Error: got wrong third parametr in ml_kem_decaps_core() for ML_KEM_768\n"); ret = -1; goto ex_3; }
		
		ret = ml_kem_decaps_core(ctx_768, ct_768, LEN_CIPHERTEXT_768, NULL, 32);
		if(ret == 0) { printf("Error: got wrong fourth parametr in ml_kem_decaps_core() for ML_KEM_768\n"); ret = -1; goto ex_3; }
		
		temp = rand();
		if(temp == 32) { temp++; }
		ret = ml_kem_decaps_core(ctx_768, ct_768, LEN_CIPHERTEXT_768, result, temp);
		if(ret == 0) { printf("Error: got wrong fiveth parametr in ml_kem_decaps_core() for ML_KEM_768\n"); ret = -1; goto ex_3; }
	}
	
	// Result info messege
	printf("Everything is correct in second loop in this test.....\n");
	
	for(size_t i = 0; i < LOOPS; i++)
    {
		ret = ml_kem_get_public_key(ctx_1024, pk_1024, RES_PUBL_PART_LVL_1024);
		if(ret != 0) { printf("Error: get pk ML_KEM_1024\n"); goto ex_3; }
		
		ret = ml_kem_encaps_core(NULL, pk_1024, RES_PUBL_PART_LVL_1024, ct_1024, LEN_CIPHERTEXT_1024, result, 32, NULL);
		if(ret != 0) { printf("Error in ml_kem_encaps_core() for ML_KEM_1024\n"); goto ex_3; }
		
		ret = ml_kem_decaps_core(ctx_1024, ct_1024, LEN_CIPHERTEXT_1024, result, 32);
		if(ret != 0) { printf("Error in ml_kem_decaps_core() for ML_KEM_1024\n"); goto ex_3; }
		
		ret = ml_kem_decaps_core(NULL, ct_1024, LEN_CIPHERTEXT_1024, result, 32);
		if(ret == 0) { printf("Error: got wrong first parametr in ml_kem_decaps_core() for ML_KEM_1024\n"); ret = -1; goto ex_3; }
		
		ret = ml_kem_decaps_core(ctx_1024, NULL, LEN_CIPHERTEXT_1024, result, 32);
		if(ret == 0) { printf("Error: got wrong second parametr in ml_kem_decaps_core() for ML_KEM_1024\n"); ret = -1; goto ex_3; }
		
		temp = rand();
		if(temp == LEN_CIPHERTEXT_1024) { temp++; }
		ret = ml_kem_decaps_core(ctx_1024, ct_1024, temp, result, 32);
		if(ret == 0) { printf("Error: got wrong third parametr in ml_kem_decaps_core() for ML_KEM_1024\n"); ret = -1; goto ex_3; }
		
		ret = ml_kem_decaps_core(ctx_1024, ct_1024, LEN_CIPHERTEXT_1024, NULL, 32);
		if(ret == 0) { printf("Error: got wrong fourth parametr in ml_kem_decaps_core() for ML_KEM_1024\n"); ret = -1; goto ex_3; }
		
		temp = rand();
		if(temp == 32) { temp++; }
		ret = ml_kem_decaps_core(ctx_1024, ct_1024, LEN_CIPHERTEXT_1024, result, temp);
		if(ret == 0) { printf("Error: got wrong fiveth parametr in ml_kem_decaps_core() for ML_KEM_1024\n"); ret = -1; goto ex_3; }
		ret = 0;
	}
	
	// Result info messege
	printf("Everything is correct in third loop in this test.....\n");
	
	ex_3:
		ml_kem_destroy_core(ctx_1024);
	ex_2:
		ml_kem_destroy_core(ctx_768);
	ex_1:
		ml_kem_destroy_core(ctx_512);
		
	
	// Result info messege
	if(ret == 0) { printf("Thank you for attention.....\n"); }

    printf("done\n");
    return ret;
}













