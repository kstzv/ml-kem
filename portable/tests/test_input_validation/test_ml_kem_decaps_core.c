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
	srand((unsigned)time(NULL));
	
    struct ml_kem_pool_decaps_ctx *ctx_512;
    struct ml_kem_pool_decaps_ctx *ctx_768;
    struct ml_kem_pool_decaps_ctx *ctx_1024;
    
    ctx_512 = ml_kem_create_object(ML_KEM_512, SIZE_POOL, NULL);
    if(!ctx_512) { printf("Error in ml_kem_create_object() for ML_KEM_512\n"); return -1; }
    
    ctx_768 = ml_kem_create_object(ML_KEM_768, SIZE_POOL, NULL);
    if(!ctx_768) { printf("Error in ml_kem_create_object() for ML_KEM_768\n"); return -1; }
    
    ctx_1024 = ml_kem_create_object(ML_KEM_1024, SIZE_POOL, NULL);
    if(!ctx_1024) { printf("Error in ml_kem_create_object() for ML_KEM_1024\n"); return -1; }
    
    u8 result[32];
    size_t ret;
    size_t temp;
    
    for(size_t i = 0; i < LOOPS; i++)
    {
		u8 *ciphertext;
		
		ciphertext = ml_kem_encaps_core(ctx_512->ml_kem_pool[0].decrypt_ctx->ctx->public_key_msg, ML_KEM_512, result, NULL);
		if(!ciphertext) { printf("Error in ml_kem_encaps_core() for ML_KEM_512\n"); return -1; }
		
		ret = ml_kem_decaps_core(ctx_512, ciphertext, LEN_CIPHERTEXT_512, result, 32);
		if(ret != 0) { printf("Error in ml_kem_decaps_core() for ML_KEM_512\n"); return -1; }
		
		ret = ml_kem_decaps_core(NULL, ciphertext, LEN_CIPHERTEXT_512, result, 32);
		if(ret == 0) { printf("Error: got wrong first parametr in ml_kem_decaps_core() for ML_KEM_512\n"); return -1; }
		
		ret = ml_kem_decaps_core(ctx_512, NULL, LEN_CIPHERTEXT_512, result, 32);
		if(ret == 0) { printf("Error: got wrong second parametr in ml_kem_decaps_core() for ML_KEM_512\n"); return -1; }
		
		temp = rand();
		if(temp == LEN_CIPHERTEXT_512) { temp++; }
		ret = ml_kem_decaps_core(ctx_512, ciphertext, temp, result, 32);
		if(ret == 0) { printf("Error: got wrong third parametr in ml_kem_decaps_core() for ML_KEM_512\n"); return -1; }
		
		ret = ml_kem_decaps_core(ctx_512, ciphertext, LEN_CIPHERTEXT_512, NULL, 32);
		if(ret == 0) { printf("Error: got wrong fourth parametr in ml_kem_decaps_core() for ML_KEM_512\n"); return -1; }
		
		temp = rand();
		if(temp == 32) { temp++; }
		ret = ml_kem_decaps_core(ctx_512, ciphertext, LEN_CIPHERTEXT_512, result, temp);
		if(ret == 0) { printf("Error: got wrong fiveth parametr in ml_kem_decaps_core() for ML_KEM_512\n"); return -1; }
		
		ml_kem_ciphertext_destroy_core(ciphertext, ML_KEM_512);
	}
    
    // Result info messege
	printf("Everything is correct in first loop in this test.....\n");
	
	for(size_t i = 0; i < LOOPS; i++)
    {
		u8 *ciphertext;
		
		ciphertext = ml_kem_encaps_core(ctx_768->ml_kem_pool[0].decrypt_ctx->ctx->public_key_msg, ML_KEM_768, result, NULL);
		if(!ciphertext) { printf("Error in ml_kem_encaps_core() for ML_KEM_768\n"); return -1; }
		
		ret = ml_kem_decaps_core(ctx_768, ciphertext, LEN_CIPHERTEXT_768, result, 32);
		if(ret != 0) { printf("Error in ml_kem_decaps_core() for ML_KEM_768\n"); return -1; }
		
		ret = ml_kem_decaps_core(NULL, ciphertext, LEN_CIPHERTEXT_768, result, 32);
		if(ret == 0) { printf("Error: got wrong first parametr in ml_kem_decaps_core() for ML_KEM_768\n"); return -1; }
		
		ret = ml_kem_decaps_core(ctx_768, NULL, LEN_CIPHERTEXT_768, result, 32);
		if(ret == 0) { printf("Error: got wrong second parametr in ml_kem_decaps_core() for ML_KEM_768\n"); return -1; }
		
		temp = rand();
		if(temp == LEN_CIPHERTEXT_768) { temp++; }
		ret = ml_kem_decaps_core(ctx_768, ciphertext, temp, result, 32);
		if(ret == 0) { printf("Error: got wrong third parametr in ml_kem_decaps_core() for ML_KEM_768\n"); return -1; }
		
		ret = ml_kem_decaps_core(ctx_768, ciphertext, LEN_CIPHERTEXT_768, NULL, 32);
		if(ret == 0) { printf("Error: got wrong fourth parametr in ml_kem_decaps_core() for ML_KEM_768\n"); return -1; }
		
		temp = rand();
		if(temp == 32) { temp++; }
		ret = ml_kem_decaps_core(ctx_768, ciphertext, LEN_CIPHERTEXT_768, result, temp);
		if(ret == 0) { printf("Error: got wrong fiveth parametr in ml_kem_decaps_core() for ML_KEM_768\n"); return -1; }
		
		ml_kem_ciphertext_destroy_core(ciphertext, ML_KEM_768);
	}
	
	// Result info messege
	printf("Everything is correct in second loop in this test.....\n");
	
	for(size_t i = 0; i < LOOPS; i++)
    {
		u8 *ciphertext;
		
		ciphertext = ml_kem_encaps_core(ctx_1024->ml_kem_pool[0].decrypt_ctx->ctx->public_key_msg, ML_KEM_1024, result, NULL);
		if(!ciphertext) { printf("Error in ml_kem_encaps_core() for ML_KEM_1024\n"); return -1; }
		
		ret = ml_kem_decaps_core(ctx_1024, ciphertext, LEN_CIPHERTEXT_1024, result, 32);
		if(ret != 0) { printf("Error in ml_kem_decaps_core() for ML_KEM_1024\n"); return -1; }
		
		ret = ml_kem_decaps_core(NULL, ciphertext, LEN_CIPHERTEXT_1024, result, 32);
		if(ret == 0) { printf("Error: got wrong first parametr in ml_kem_decaps_core() for ML_KEM_1024\n"); return -1; }
		
		ret = ml_kem_decaps_core(ctx_1024, NULL, LEN_CIPHERTEXT_1024, result, 32);
		if(ret == 0) { printf("Error: got wrong second parametr in ml_kem_decaps_core() for ML_KEM_1024\n"); return -1; }
		
		temp = rand();
		if(temp == LEN_CIPHERTEXT_1024) { temp++; }
		ret = ml_kem_decaps_core(ctx_1024, ciphertext, temp, result, 32);
		if(ret == 0) { printf("Error: got wrong third parametr in ml_kem_decaps_core() for ML_KEM_1024\n"); return -1; }
		
		ret = ml_kem_decaps_core(ctx_1024, ciphertext, LEN_CIPHERTEXT_1024, NULL, 32);
		if(ret == 0) { printf("Error: got wrong fourth parametr in ml_kem_decaps_core() for ML_KEM_1024\n"); return -1; }
		
		temp = rand();
		if(temp == 32) { temp++; }
		ret = ml_kem_decaps_core(ctx_1024, ciphertext, LEN_CIPHERTEXT_1024, result, temp);
		if(ret == 0) { printf("Error: got wrong fiveth parametr in ml_kem_decaps_core() for ML_KEM_1024\n"); return -1; }
		
		ml_kem_ciphertext_destroy_core(ciphertext, ML_KEM_1024);
	}
	
	// Result info messege
	printf("Everything is correct in second loop in this test.....\n");
	
	ml_kem_destroy_core(ctx_512);
	ml_kem_destroy_core(ctx_768);
	ml_kem_destroy_core(ctx_1024);
	
	// Result info messege
	printf("Thank you for attention.....\n");

    printf("done\n");
    return 0;
}













