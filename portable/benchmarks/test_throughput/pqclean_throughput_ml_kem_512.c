// SPDX-License-Identifier: GPL-2.0 OR MIT
// Copyright (c) 2026 K.S.Zavertailo
#include <stdio.h>
#include <string.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <time.h>
#include "api.h"

// Benchmark parameters and shared input/output buffers
#define NUMBER_ITERATIONS 100000
#define NUMBER_THREADS 16

uint8_t shared_secrets[NUMBER_ITERATIONS][PQCLEAN_MLKEM512_CLEAN_CRYPTO_BYTES];
uint8_t ciphertexts[NUMBER_ITERATIONS][PQCLEAN_MLKEM512_CLEAN_CRYPTO_CIPHERTEXTBYTES];

atomic_size_t current_index = 0;

// Arguments passed to each worker thread
struct thread_args {
    uint8_t *secret;
};

// Worker thread: performs decapsulation and verifies shared secrets
void *worker(void *arg)
{
    struct thread_args *args = arg;

    uint8_t decaps_shared_secret[PQCLEAN_MLKEM512_CLEAN_CRYPTO_BYTES];

    while(1)
    {
        size_t idx = atomic_fetch_add(&current_index, 1);

        if(idx >= NUMBER_ITERATIONS) { break; }

        int ret = PQCLEAN_MLKEM512_CLEAN_crypto_kem_dec(decaps_shared_secret, ciphertexts[idx], args->secret);
        if(ret != 0)
        {
            printf("Decapsulation error\n");
            exit(EXIT_FAILURE);
        }

        ret = memcmp(decaps_shared_secret, shared_secrets[idx], PQCLEAN_MLKEM512_CLEAN_CRYPTO_BYTES);
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
	pthread_t threads[NUMBER_THREADS];
	uint8_t secret[PQCLEAN_MLKEM512_CLEAN_CRYPTO_SECRETKEYBYTES];
	uint8_t pk[PQCLEAN_MLKEM512_CLEAN_CRYPTO_PUBLICKEYBYTES];
	struct thread_args args;
	args.secret = secret;
	
	atomic_store(&current_index, 0);
	int ret;
	
	struct timespec start;
	struct timespec end;
	
	// Create keys
	ret = PQCLEAN_MLKEM512_CLEAN_crypto_kem_keypair(pk, secret);
	if(ret != 0) { printf("Error in create keys\n"); return -1; }
	
	// Create ciphertexts
	for(size_t i = 0; i < NUMBER_ITERATIONS; i++)
	{
		ret = PQCLEAN_MLKEM512_CLEAN_crypto_kem_enc(ciphertexts[i], shared_secrets[i], pk);
		if(ret != 0) { printf("Error in encaps\n"); return -1; }
	}
	
	// Create threads
	for(size_t i = 0; i < NUMBER_THREADS; i++)
	{
		ret = pthread_create(&threads[i], NULL, worker, &args);
		if(ret != 0)
		{
			printf("pthread_create failed\n");
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
		
	return 0;
}
