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
	
    // Main test loop
	for(size_t i = 0; i < LOOPS; i++)
	{
		struct ml_kem_pool_decaps_ctx *ctx_512;
		struct ml_kem_pool_decaps_ctx *ctx_768;
		struct ml_kem_pool_decaps_ctx *ctx_1024;
		
		struct ml_kem_pool_decaps_ctx *ctx_wrong;
		
		size_t temp;
		
		temp = (rand()%128) + 1;
		ctx_512 = ml_kem_create_object(2, temp);
		if(ctx_512 == NULL) { printf("Error: in ML_KEM_512"); return -1; }
		
		temp = (rand()%128) + 1;
		ctx_768 = ml_kem_create_object(3, temp);
		if(ctx_768 == NULL) { printf("Error: in ML_KEM_768"); return -1; }
		
		temp = (rand()%128) + 1;
		ctx_1024 = ml_kem_create_object(4, temp);
		if(ctx_1024 == NULL) { printf("Error: in ML_KEM_1024"); return -1; }
		
		size_t wrong_level = 0;
		
		temp = rand();
		wrong_level = rand();
		while(temp >= 128 && (wrong_level > 1 && wrong_level <= 4))
		{
			temp = rand();
			wrong_level = rand();
			if(temp >= 128 && (wrong_level > 1 && wrong_level <= 4)) { break; }
		}
		
		ctx_wrong = ml_kem_create_object(wrong_level, temp);
		if(ctx_wrong != NULL) 
		{ 
			printf("Error: It got wrong datas!"); 
			ml_kem_destroy_core(ctx_wrong); 
			return -1; 
		}
		
		ml_kem_destroy_core(ctx_512); 
		ml_kem_destroy_core(ctx_768); 
		ml_kem_destroy_core(ctx_1024);
		
		if(i%10 == 0) { printf("Progress %zu.....\n", i); }
	} 
    
    // Result info messege
	printf("Everything is correct in this test, thank you for attention.....\n");

    printf("done\n");
    return 0;
}













