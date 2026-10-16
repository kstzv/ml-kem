#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <sched.h>
#include "ml_kem.h"

#define NUMBER_THREADS 20

#define SIZE_LOOP_512  100
#define SIZE_LOOP_768  100
#define SIZE_LOOP_1024 100

#define SIZE_POOL_512  8
#define SIZE_POOL_768  8
#define SIZE_POOL_1024 8

u8 ct[LEN_CIPHERTEXT_1024];
u8 pk[RES_PUBL_PART_LVL_1024];
u8 ss[ML_KEM_SEED_BYTES];

struct decaps_thread_args {
    struct ml_kem_pool_decaps_ctx *pool;
    u8 *ciphertext;
    size_t ciphertext_len;
    const u8 *ss_from_encaps;
    size_t number_loops;
    int status;
};

struct encaps_thread_args {
    struct ml_kem_pool_encaps_ctx *pool;
    struct ml_kem_pool_decaps_ctx *decaps_pool;
    u8 ciphertext[LEN_CIPHERTEXT_1024];
    size_t ciphertext_len;
    u8 *pk;
    size_t pk_size;
    size_t number_loops;
    int status;
};

void *encaps_pool_worker(void *encaps_arg)
{
    struct encaps_thread_args *arg = encaps_arg;

    u8 ss_encaps[ML_KEM_SEED_BYTES];
    u8 ss_decaps[ML_KEM_SEED_BYTES];

    for (size_t i = 0; i < arg->number_loops; i++)
    {
        int ret;

        // Encapsulation
        do {
            ret = ml_kem_encaps_core(arg->pool, arg->pk, arg->pk_size, arg->ciphertext, arg->ciphertext_len, ss_encaps, ML_KEM_SEED_BYTES, NULL);

            if (ret == -ML_KEM_EBUSY) { sched_yield(); }

        } while (ret == -ML_KEM_EBUSY);

        if (ret != 0) { goto error; }

        // Verify through decapsulation
        do {
            ret = ml_kem_decaps_core(arg->decaps_pool, arg->ciphertext, arg->ciphertext_len, ss_decaps, ML_KEM_SEED_BYTES);

            if (ret == -ML_KEM_EBUSY) { sched_yield(); }

        } while (ret == -ML_KEM_EBUSY);

        if (ret != 0 || memcmp(ss_encaps, ss_decaps, ML_KEM_SEED_BYTES) != 0) { goto error; }
    }

    arg->status = 0;
    return NULL;

	error:
		arg->status = 1;
		return NULL;
}

void *decaps_pool_worker(void *decaps_arg)
{
	struct decaps_thread_args *arg = decaps_arg;
	u8 ss[ML_KEM_SEED_BYTES];
	
	for(size_t i = 0; i < arg->number_loops; i++)
	{
		int ret = 0;
		do{
			ret = ml_kem_decaps_core(arg->pool, arg->ciphertext, arg->ciphertext_len, ss, ML_KEM_SEED_BYTES);
			if (ret == -ML_KEM_EBUSY) { sched_yield(); }
		}while(ret == -ML_KEM_EBUSY);
		
		if (ret != 0 || memcmp(ss, arg->ss_from_encaps, ML_KEM_SEED_BYTES) != 0) { arg->status = 1; return NULL; }
	}
	
	arg->status = 0;
    return NULL;
}

int func_test_decaps(enum ml_kem_k level)
{
	size_t size_pk, size_ct, number_pool, number_loops;
	if(level == ML_KEM_512)
	{
		size_ct = LEN_CIPHERTEXT_512;
		size_pk = RES_PUBL_PART_LVL_512;
		number_pool = SIZE_POOL_512;
		number_loops = SIZE_LOOP_512;
	}else if(level == ML_KEM_768)
	{
		size_ct = LEN_CIPHERTEXT_768;
		size_pk = RES_PUBL_PART_LVL_768;
		number_pool = SIZE_POOL_768;
		number_loops = SIZE_LOOP_768;
	}else if(level == ML_KEM_1024)
	{
		size_ct = LEN_CIPHERTEXT_1024;
		size_pk = RES_PUBL_PART_LVL_1024;
		number_pool = SIZE_POOL_1024;
		number_loops = SIZE_LOOP_1024;
	} else { return -5; }
	
	int created_threads = 0;
	int ret = 0;
	pthread_t threads[NUMBER_THREADS];
	struct decaps_thread_args ctx_decaps[NUMBER_THREADS];
	struct ml_kem_pool_decaps_ctx *decaps_pool_ctx = ml_kem_create_object(level, number_pool, NULL);
	if(!decaps_pool_ctx) { ret = -1; goto exit; }
	
	u8 pk[RES_PUBL_PART_LVL_1024];
	ret = ml_kem_get_public_key(decaps_pool_ctx, pk, size_pk);
	if(ret != 0) { ret = -2; goto exit; }
	
	u8 ct[NUMBER_THREADS][LEN_CIPHERTEXT_1024];
	u8 ss[NUMBER_THREADS][ML_KEM_SEED_BYTES];
	
	for(size_t i = 0; i < NUMBER_THREADS; i++)
	{
		ret = ml_kem_encaps_core(NULL, pk, size_pk, ct[i], size_ct, ss[i], ML_KEM_SEED_BYTES, NULL);
		if(ret != 0) { ret = -6; break; }
		
		ctx_decaps[i].ciphertext = ct[i];
		ctx_decaps[i].ciphertext_len = size_ct;
		ctx_decaps[i].number_loops = number_loops;
		ctx_decaps[i].pool = decaps_pool_ctx;
		ctx_decaps[i].ss_from_encaps = ss[i];
		ctx_decaps[i].status = -1;
		
		if(pthread_create(&threads[i], NULL, decaps_pool_worker, &ctx_decaps[i]) != 0) { ret = -3; break; }
		created_threads++;
	}
	
	for (int i = 0; i < created_threads; i++) 
	{
		if(pthread_join(threads[i], NULL) != 0) { abort(); }

		if (ctx_decaps[i].status != 0 && ret == 0) { ret = -4; }
	}
	
	if(ret == 0) { ret = created_threads; }
	
	exit:
		ml_kem_destroy_core(decaps_pool_ctx);
		return ret;
}
		

int func_test_encaps(enum ml_kem_k level)
{
	size_t size_pk, size_ct, number_pool, number_loops;
	if(level == ML_KEM_512)
	{
		size_ct = LEN_CIPHERTEXT_512;
		size_pk = RES_PUBL_PART_LVL_512;
		number_pool = SIZE_POOL_512;
		number_loops = SIZE_LOOP_512;
	}else if(level == ML_KEM_768)
	{
		size_ct = LEN_CIPHERTEXT_768;
		size_pk = RES_PUBL_PART_LVL_768;
		number_pool = SIZE_POOL_768;
		number_loops = SIZE_LOOP_768;
	}else if(level == ML_KEM_1024)
	{
		size_ct = LEN_CIPHERTEXT_1024;
		size_pk = RES_PUBL_PART_LVL_1024;
		number_pool = SIZE_POOL_1024;
		number_loops = SIZE_LOOP_1024;
	}else { return -5; }
	
	int created_threads = 0;
	int ret = 0;
	pthread_t threads[NUMBER_THREADS];
	struct encaps_thread_args ctx_encaps[NUMBER_THREADS];
	struct ml_kem_pool_decaps_ctx *decaps_pool_ctx = ml_kem_create_object(level, number_pool, NULL);
	struct ml_kem_pool_encaps_ctx *encaps_pool_ctx = create_encaps_pool(SIZE_POOL_512, SIZE_POOL_768, SIZE_POOL_1024);
	if(!decaps_pool_ctx || !encaps_pool_ctx) { ret = -1; goto exit; }
	
	u8 pk[RES_PUBL_PART_LVL_1024];
	ret = ml_kem_get_public_key(decaps_pool_ctx, pk, size_pk);
	if(ret != 0) { ret = -2; goto exit; }
	
	for(size_t i = 0; i < NUMBER_THREADS; i++)
	{
		ctx_encaps[i].ciphertext_len = size_ct;
		ctx_encaps[i].decaps_pool = decaps_pool_ctx;
		ctx_encaps[i].number_loops = number_loops;
		ctx_encaps[i].pk = pk;
		ctx_encaps[i].pk_size = size_pk;
		ctx_encaps[i].pool = encaps_pool_ctx;
		ctx_encaps[i].status = -1;
		
		if(pthread_create(&threads[i], NULL, encaps_pool_worker, &ctx_encaps[i]) != 0) { ret = -3; break; }
		created_threads++;
	}
	
	for (int i = 0; i < created_threads; i++) 
	{
		if(pthread_join(threads[i], NULL) != 0) { abort(); }

		if (ctx_encaps[i].status != 0 && ret == 0) { ret = -4; }
	}
	
	if(ret == 0) { ret = created_threads; }
	
	exit:
		ml_kem_encaps_pool_destroy(encaps_pool_ctx);
		ml_kem_destroy_core(decaps_pool_ctx);
		return ret;
}

#define SLOT_DECAPS_POOL_LIFE_CYCLE 	 40
#define SLOT_ENCAPS_POOL_LIFE_CYCLE_512  20
#define SLOT_ENCAPS_POOL_LIFE_CYCLE_768  25
#define SLOT_ENCAPS_POOL_LIFE_CYCLE_1024 30
#define NUMBER_LOOPS_FOR_POOL_LIFE_CYCLE 1000

int func_test_pool_lifecycle(enum ml_kem_k level_decaps, size_t slots_decaps, size_t slots_encaps_512, size_t slots_encaps_768, size_t slots_encaps_1024, size_t number_loops)
{
    for(size_t i = 0; i < number_loops; i++)
    {
        int success = 0;

        struct ml_kem_pool_decaps_ctx *ctx_dec = NULL;
        struct ml_kem_pool_encaps_ctx *ctx_enc = NULL;

        ctx_dec = ml_kem_create_object(level_decaps, slots_decaps, NULL);
        if(!ctx_dec) { goto cleanup; }

        ctx_enc = create_encaps_pool(slots_encaps_512, slots_encaps_768, slots_encaps_1024);
        if(!ctx_enc) { goto cleanup; }

        success = 1;

        cleanup:
            ml_kem_encaps_pool_destroy(ctx_enc);
            ml_kem_destroy_core(ctx_dec);

        if(!success) { return -1; }
    }

    return 0;
}

int main()
{
	int ret = 0;
	printf("\n512 level encaps pool test...\n");
	ret = func_test_encaps(ML_KEM_512);
	if(ret < 0) 
	{
		printf("\n512 level encaps pool test ERROR: %i\n", ret);
		return -1;
	}else { printf("\n512 level encaps pool test with %i threads: SUCCESS\n", ret); }
	printf("\n...............\n");
	
	printf("\n768 level encaps pool test...\n");
	ret = func_test_encaps(ML_KEM_768);
	if(ret < 0) 
	{
		printf("\n768 level encaps pool test ERROR: %i\n", ret);
		return -1;
	}else { printf("\n768 level encaps pool test with %i threads: SUCCESS\n", ret); }
	printf("\n...............\n");
	
	printf("\n1024 level encaps pool test...\n");
	ret = func_test_encaps(ML_KEM_1024);
	if(ret < 0) 
	{
		printf("\n1024 level encaps pool test ERROR: %i\n", ret);
		return -1;
	}else { printf("\n1024 level encaps pool test with %i threads: SUCCESS\n", ret); }
	printf("\n...............\n");
	
	printf("\n512 level decaps pool test...\n");
	ret = func_test_decaps(ML_KEM_512);
	if(ret < 0) 
	{
		printf("\n512 level decaps pool test ERROR: %i\n", ret);
		return -1;
	}else { printf("\n512 level decaps pool test with %i threads: SUCCESS\n", ret); }
	printf("\n...............\n");	
	
	printf("\n768 level decaps pool test...\n");
	ret = func_test_decaps(ML_KEM_768);
	if(ret < 0) 
	{
		printf("\n768 level decaps pool test ERROR: %i\n", ret);
		return -1;
	}else { printf("\n768 level decaps pool test with %i threads: SUCCESS\n", ret); }
	printf("\n...............\n");
	
	printf("\n1024 level decaps pool test...\n");
	ret = func_test_decaps(ML_KEM_1024);
	if(ret < 0) 
	{
		printf("\n1024 level decaps pool test ERROR: %i\n", ret);
		return -1;
	}else { printf("\n1024 level decaps pool test with %i threads: SUCCESS\n", ret); }
	printf("\n...............\n");
	
	printf("\ntest mem in pools lifecycles...\n");
	ret = func_test_pool_lifecycle(ML_KEM_512, SLOT_DECAPS_POOL_LIFE_CYCLE, SLOT_ENCAPS_POOL_LIFE_CYCLE_512, SLOT_ENCAPS_POOL_LIFE_CYCLE_768, SLOT_ENCAPS_POOL_LIFE_CYCLE_1024, NUMBER_LOOPS_FOR_POOL_LIFE_CYCLE);
	if(ret < 0) 
	{
		printf("\ntest mem in pools lifecycles ERROR: %i\n", ret);
		return -1;
	}else { printf("\ntest mem in pools lifecycles with %d iterations: SUCCESS\n", NUMBER_LOOPS_FOR_POOL_LIFE_CYCLE); }
	printf("\n...............\n");
	
	return 0;
}





















