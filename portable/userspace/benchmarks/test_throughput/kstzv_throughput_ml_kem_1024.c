// SPDX-License-Identifier: GPL-2.0 OR MIT
// Copyright (c) 2026 K.S.Zavertailo
#include <stdio.h>
#include <string.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <time.h>
#include "ml_kem.h"

// Benchmark parameters and shared input/output buffers
#define NUMBER_ITERATIONS 100000
#define NUMBER_THREADS 16

u8 shared_secrets[NUMBER_ITERATIONS][ML_KEM_SEED_BYTES];
u8 ciphertexts[NUMBER_ITERATIONS][LEN_CIPHERTEXT_1024];

atomic_size_t current_index = 0;

// Arguments passed to each worker thread
struct thread_args {
    struct ml_kem_pool_decaps_ctx *ctx_keys;
};

// Worker thread: performs decapsulation and verifies shared secrets
void *worker(void *arg)
{
    struct thread_args *args = arg;

    u8 decaps_shared_secret[ML_KEM_SEED_BYTES];

    while(1)
    {
        size_t idx = atomic_fetch_add(&current_index, 1);

        if(idx >= NUMBER_ITERATIONS) { break; }

        int ret = ml_kem_decaps_core(args->ctx_keys, ciphertexts[idx], LEN_CIPHERTEXT_1024, decaps_shared_secret, ML_KEM_SEED_BYTES);
        if(ret != 0)
        {
            printf("Decapsulation error\n");
            exit(EXIT_FAILURE);
        }

        ret = memcmp(decaps_shared_secret, shared_secrets[idx], ML_KEM_SEED_BYTES);
        if(ret != 0)
        {
            printf("Shared secret mismatch\n");
            exit(EXIT_FAILURE);
        }
    }

    return NULL;
}

int main()
{
	// Create keys
	struct ml_kem_pool_decaps_ctx  *ctx_keys;
	ctx_keys = ml_kem_create_object(ML_KEM_1024, NUMBER_THREADS);
	if(!ctx_keys) { printf("Error in ml_kem_create_object()\n"); return -1; }
	
	// Create ciphertexts
	u8 *temp_ciphertext;
	for(size_t i = 0; i < NUMBER_ITERATIONS; i++)
	{
		temp_ciphertext = ml_kem_encaps_core(ctx_keys->ml_kem_pool[0].decrypt_ctx->ctx->public_key_msg, ML_KEM_1024, shared_secrets[i]);
		if(!temp_ciphertext) { printf("Error in ml_kem_encaps_core()\n"); ml_kem_destroy_core(ctx_keys); return -1; }
		
		memcpy(ciphertexts[i], temp_ciphertext, LEN_CIPHERTEXT_1024);
		ml_kem_ciphertext_destroy_core(temp_ciphertext, ML_KEM_1024);
		temp_ciphertext = NULL;
	}
	
	pthread_t threads[NUMBER_THREADS];
	struct thread_args args;
	args.ctx_keys = ctx_keys;
	
	atomic_store(&current_index, 0);
	int ret;
	
	struct timespec start;
	struct timespec end;
	
	// Create threads
	for(size_t i = 0; i < NUMBER_THREADS; i++)
	{
		ret = pthread_create(&threads[i], NULL, worker, &args);
		if(ret != 0)
		{
			printf("pthread_create failed\n");
			ml_kem_destroy_core(ctx_keys);
			return -1;
		}
	}
	
	// Measure decapsulation phase
	clock_gettime(CLOCK_MONOTONIC, &start);
	for(size_t i = 0; i < NUMBER_THREADS; i++)
	{
		ret = pthread_join(threads[i], NULL);
		if(ret != 0) 
		{
			printf("pthread_join failed\n");
			ml_kem_destroy_core(ctx_keys);
			return -1;
		}
	}
	clock_gettime(CLOCK_MONOTONIC, &end);
	
	// Print benchmark result
	double elapsed = (end.tv_sec - start.tv_sec) + (end.tv_nsec - start.tv_nsec) / 1000000000.0;
	double throughput = NUMBER_ITERATIONS / elapsed;
	
	printf("Time: %.6f sec\n", elapsed);
	printf("Throughput: %.2f decaps/sec\n", throughput);
	
	printf("It is OK.....\n");
	ml_kem_destroy_core(ctx_keys);
		
	return 0;
}
