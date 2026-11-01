// SPDX-License-Identifier: GPL-2.0 OR MIT
// Copyright (c) 2026 K.S.Zavertailo
// Encapsulation throughput benchmark: 100000 encapsulations, 16 threads.
// Only the parallel encapsulation phase is timed; verification is afterward.
#include <stdio.h>
#include <string.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <time.h>
#include "ml_kem.h"

#ifndef NUMBER_ITERATIONS
#define NUMBER_ITERATIONS 100000
#endif
#ifndef NUMBER_THREADS
#define NUMBER_THREADS 16
#endif

static u8 ciphertexts[NUMBER_ITERATIONS][LEN_CIPHERTEXT_768];
static u8 shared_secrets[NUMBER_ITERATIONS][ML_KEM_SEED_BYTES];
static atomic_size_t current_index = ATOMIC_VAR_INIT(0);

// Prevent workers from running before CLOCK_MONOTONIC starts.
static pthread_mutex_t start_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t ready_cond = PTHREAD_COND_INITIALIZER;
static pthread_cond_t start_cond = PTHREAD_COND_INITIALIZER;
static size_t ready_threads = 0;
static int start_released = 0;
static int cancel_start = 0;

static int wait_for_start(void)
{
    pthread_mutex_lock(&start_mutex);
    ready_threads++;
    pthread_cond_signal(&ready_cond);
    
    while (!start_released) { pthread_cond_wait(&start_cond, &start_mutex); }
    
    int cancelled = cancel_start;
    pthread_mutex_unlock(&start_mutex);
    return cancelled;
}

static void release_start(int cancel)
{
    pthread_mutex_lock(&start_mutex);
    cancel_start = cancel;
    start_released = 1;
    pthread_cond_broadcast(&start_cond);
    pthread_mutex_unlock(&start_mutex);
}

static int launch_and_measure(pthread_t threads[NUMBER_THREADS], void *(*worker)(void *), void *args, double *elapsed)
{
    size_t created = 0;
    for (; created < NUMBER_THREADS; created++) 
    {
        if (pthread_create(&threads[created], NULL, worker, args) != 0) 
        {
            fprintf(stderr, "pthread_create failed\n");
            release_start(1);
            for (size_t i = 0; i < created; i++) { pthread_join(threads[i], NULL); }
            return -1;
        }
    }

    pthread_mutex_lock(&start_mutex);
    while (ready_threads != NUMBER_THREADS) { pthread_cond_wait(&ready_cond, &start_mutex); }

    struct timespec start, end;
    if (clock_gettime(CLOCK_MONOTONIC, &start) != 0) 
    {
        pthread_mutex_unlock(&start_mutex);
        release_start(1);
        for (size_t i = 0; i < created; i++) { pthread_join(threads[i], NULL); }
        return -1;
    }
    start_released = 1;
    pthread_cond_broadcast(&start_cond);
    pthread_mutex_unlock(&start_mutex);

    for (size_t i = 0; i < NUMBER_THREADS; i++) 
    {
        if (pthread_join(threads[i], NULL) != 0) 
        {
            // Avoid freeing worker-owned resources if a join fails.
            fprintf(stderr, "pthread_join failed\n");
            exit(EXIT_FAILURE);
        }
    }
    if (clock_gettime(CLOCK_MONOTONIC, &end) != 0) { return -1; }
    *elapsed = (double)(end.tv_sec - start.tv_sec) + (double)(end.tv_nsec - start.tv_nsec) / 1000000000.0;
    return 0;
}

struct thread_args {
    struct ml_kem_pool_encaps_ctx *encaps_pool;
    u8 *pk;
};

static void *worker(void *arg)
{
    struct thread_args *args = (struct thread_args *)arg;
    if (wait_for_start()) { return NULL; }

    while (1) 
    {
        size_t idx = atomic_fetch_add_explicit(&current_index, 1, memory_order_relaxed);
        if (idx >= NUMBER_ITERATIONS) { break; }

        int ret = ml_kem_encaps_core(args->encaps_pool, args->pk, RES_PUBL_PART_LVL_768, ciphertexts[idx], LEN_CIPHERTEXT_768, shared_secrets[idx], ML_KEM_SEED_BYTES, NULL);
        if (ret != 0) 
        {
            fprintf(stderr, "Encapsulation error: %d (index %zu)\n", ret, idx);
            exit(EXIT_FAILURE);
        }
    }
    return NULL;
}

int main()
{
    // Key generation and pool initialization are deliberately NOT timed.
    struct ml_kem_general_keys_decaps_ctx *ctx_keys = ml_kem_create_object(ML_KEM_768, 1, NULL);
    if (!ctx_keys) 
    {
        fprintf(stderr, "ml_kem_create_object failed\n");
        return EXIT_FAILURE;
    }

    u8 pk[RES_PUBL_PART_LVL_768];
    if (ml_kem_get_public_key(ctx_keys, pk, sizeof(pk)) != 0) 
    {
        fprintf(stderr, "ml_kem_get_public_key failed\n");
        ml_kem_destroy_core(ctx_keys);
        return EXIT_FAILURE;
    }

    struct ml_kem_pool_encaps_ctx *encaps_pool = create_encaps_pool(0, NUMBER_THREADS, 0);
    if (!encaps_pool) 
    {
        fprintf(stderr, "create_encaps_pool failed\n");
        ml_kem_destroy_core(ctx_keys);
        return EXIT_FAILURE;
    }

    pthread_t threads[NUMBER_THREADS];
    struct thread_args args = { .encaps_pool = encaps_pool, .pk = pk };
    double elapsed = 0.0;
    if (launch_and_measure(threads, worker, &args, &elapsed) != 0) 
    {
        fprintf(stderr, "Thread start/timing failed\n");
        ml_kem_encaps_pool_destroy(encaps_pool);
        ml_kem_destroy_core(ctx_keys);
        return EXIT_FAILURE;
    }

    printf("Time: %.6f sec\n", elapsed);
    printf("Throughput: %.2f encaps/sec\n", (double)NUMBER_ITERATIONS / elapsed);

    // Verify every encapsulation using the matching secret key OUTSIDE the timed phase.
    u8 decaps_shared_secret[ML_KEM_SEED_BYTES];
    for (size_t i = 0; i < NUMBER_ITERATIONS; i++) 
    {
        int ret = ml_kem_decaps_core(ctx_keys, ciphertexts[i], LEN_CIPHERTEXT_768, decaps_shared_secret, sizeof(decaps_shared_secret));
        if (ret != 0 || memcmp(decaps_shared_secret, shared_secrets[i], sizeof(decaps_shared_secret)) != 0) 
        {
            fprintf(stderr, "Decapsulation verification failed at index %zu\n", i);
            ml_kem_encaps_pool_destroy(encaps_pool);
            ml_kem_destroy_core(ctx_keys);
            return EXIT_FAILURE;
        }
    }

    printf("It is OK.....\n");
    ml_kem_encaps_pool_destroy(encaps_pool);
    ml_kem_destroy_core(ctx_keys);
    return EXIT_SUCCESS;
}
