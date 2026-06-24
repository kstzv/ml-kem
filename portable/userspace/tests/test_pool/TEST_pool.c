#define _POSIX_C_SOURCE 200809L

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sched.h>
#include <ml_kem.h>

// High-contention stress test configuration
// THREADS: total number of concurrent worker threads
// ITERATIONS: number of decapsulation attempts per thread

#define THREADS 256
#define ITERATIONS 1000000

// Per-thread arguments
// All threads share: the same decapsulation pool; the same valid ciphertext; the same expected shared secret
// This isolates concurrency behavior from input variability

struct thread_arg {
    struct ml_kem_pool_decaps_ctx *pool;
    u8 *ciphertext;
    size_t ciphertext_len;
    u8 *expected_secret;
};

// Barrier used to synchronize thread start
pthread_barrier_t barrier;

// Worker thread routine
// Each thread: waits for synchronized start; repeatedly attempts decapsulation; verifies correctness of the derived shared secret
// -EBUSY is expected under contention and is treated as a retry signal

void *worker(void *arg)
{
    struct thread_arg *t = (struct thread_arg *)arg;
    u8 result[ML_KEM_SEED_BYTES];

	// Ensure all threads start at approximately the same time
    pthread_barrier_wait(&barrier);

    int errors = 0;

    for (int i = 0; i < ITERATIONS; i++) {
		
		// Periodically yield CPU to increase scheduling variability and improve contention patterns
        if ((i & 1023) == 0) { sched_yield(); }

        int ret = ml_kem_decaps_core(t->pool, t->ciphertext, t->ciphertext_len, result, ML_KEM_SEED_BYTES);

		// Slot was busy — expected under high contention. Simply retry without counting as an error.
        if (ret == -EBUSY) { continue; }

		// Any other non-zero return value is considered a failure
        if (ret != 0)  { errors++; continue; }

		// Validate correctness of the derived shared secret. Any mismatch indicates corruption or race-related issue
        if (memcmp(result, t->expected_secret, ML_KEM_SEED_BYTES) != 0) 
        {
            printf("MISMATCH!\n");
            errors++;
        }
    }

    printf("Thread done, errors = %d\n", errors);
    return NULL;
}

int main(void)
{
    enum ml_kem_k level = ML_KEM_1024;
    size_t pool_size = 16;

    pthread_barrier_init(&barrier, NULL, THREADS);

	// Create decapsulation pool. Pool size is intentionally smaller than thread count to induce heavy contention
    struct ml_kem_pool_decaps_ctx *pool = ml_kem_create_object(level, pool_size);

    if (!pool) {
        printf("Pool creation failed\n");
        pthread_barrier_destroy(&barrier);
        return 1;
    }

	// Generate a valid ciphertext and corresponding shared secret. This single ciphertext is reused by all threads to isolate
	// Concurrency effects from input variability
    u8 shared_secret[ML_KEM_SEED_BYTES];
    u8 *ciphertext = ml_kem_encaps_core(pool->ml_kem_pool[0].decrypt_ctx->ctx->public_key_msg, level, shared_secret);

    if (!ciphertext) {
        printf("Encaps failed\n");
        ml_kem_destroy_core(pool);
        pthread_barrier_destroy(&barrier);
        return 1;
    }
    
	// Extract ciphertext length from pool context
    size_t ciphertext_len = pool->ml_kem_pool[0].decrypt_ctx->ciphertext_len;

    pthread_t threads[THREADS];
    struct thread_arg arg = { // Shared argument for all threads. Safe because all fields are read-only during execution
        .pool = pool,
        .ciphertext = ciphertext,
        .ciphertext_len = ciphertext_len,
        .expected_secret = shared_secret
    };

	// Spawn worker threads
    for (int i = 0; i < THREADS; i++) 
    {
        pthread_create(&threads[i], NULL, worker, &arg);
    }
	
	// Wait for all threads to complete
    for (int i = 0; i < THREADS; i++) 
    {
        pthread_join(threads[i], NULL);
    }

	// Cleanup resources
    ml_kem_ciphertext_destroy_core(ciphertext, level);
    ml_kem_destroy_core(pool);
    pthread_barrier_destroy(&barrier);

    printf("Test finished\n");
    return 0;
}
