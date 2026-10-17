#define _POSIX_C_SOURCE 200809L

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sched.h>
#include <errno.h>
#include <ml_kem.h>

#ifndef THREADS
#define THREADS 256
#endif
#ifndef ITERATIONS
#define ITERATIONS 1000000
#endif
#ifndef POOL_SIZE
#define POOL_SIZE 16
#endif

// A condition-variable start gate also lets us cancel all workers safely
// when thread creation fails (a fixed-size pthread_barrier_t cannot).
struct start_gate {
    pthread_mutex_t mutex;
    pthread_cond_t cond;
    int released;
    int cancelled;
};

struct thread_arg {
    struct ml_kem_pool_encaps_ctx *pool;
    const u8 *public_key;
    struct start_gate *gate;
    size_t successes;
    size_t busy;
    size_t errors;
    u8 last_ciphertext[LEN_CIPHERTEXT_1024];
    u8 last_secret[ML_KEM_SEED_BYTES];
};

static void *worker(void *opaque)
{
    struct thread_arg *a = opaque;
    u8 ciphertext[LEN_CIPHERTEXT_1024];
    u8 secret[ML_KEM_SEED_BYTES];

    pthread_mutex_lock(&a->gate->mutex);
    while (!a->gate->released)
        pthread_cond_wait(&a->gate->cond, &a->gate->mutex);
    int cancelled = a->gate->cancelled;
    pthread_mutex_unlock(&a->gate->mutex);
    if (cancelled) return NULL;

    for (size_t i = 0; i < (size_t)ITERATIONS; ++i) {
        if ((i & 1023u) == 0) sched_yield();

        int ret = ml_kem_encaps_core(a->pool, (u8 *)a->public_key,
                                     RES_PUBL_PART_LVL_1024,
                                     ciphertext, sizeof(ciphertext),
                                     secret, sizeof(secret), NULL);
        if (ret == -EBUSY) {
            ++a->busy;
            continue;
        }
        if (ret != 0) {
            ++a->errors;
            continue;
        }

        ++a->successes;
        memcpy(a->last_ciphertext, ciphertext, sizeof(ciphertext));
        memcpy(a->last_secret, secret, sizeof(secret));
    }
    return NULL;
}

int main(void)
{
    int exit_code = EXIT_FAILURE;
    pthread_t threads[THREADS];
    struct thread_arg *args = NULL;
    size_t created = 0;
    struct ml_kem_pool_decaps_ctx *decaps = NULL;
    struct ml_kem_pool_encaps_ctx *encaps = NULL;
    struct start_gate gate;
    u8 pk[RES_PUBL_PART_LVL_1024];
    size_t total_success = 0, total_busy = 0, total_errors = 0;

    if (pthread_mutex_init(&gate.mutex, NULL) != 0) return EXIT_FAILURE;
    if (pthread_cond_init(&gate.cond, NULL) != 0) {
        pthread_mutex_destroy(&gate.mutex);
        return EXIT_FAILURE;
    }
    gate.released = 0;
    gate.cancelled = 0;

    decaps = ml_kem_create_object(ML_KEM_1024, POOL_SIZE, NULL);
    if (!decaps) { fprintf(stderr, "Decapsulation object creation failed\n"); goto cleanup; }
    if (ml_kem_get_public_key(decaps, pk, sizeof(pk)) != 0) {
        fprintf(stderr, "Public key extraction failed\n");
        goto cleanup;
    }
    encaps = create_encaps_pool(0, 0, POOL_SIZE);
    if (!encaps) { fprintf(stderr, "Encapsulation pool creation failed\n"); goto cleanup; }

    args = calloc(THREADS, sizeof(*args));
    if (!args) { perror("calloc"); goto cleanup; }

    for (size_t i = 0; i < THREADS; ++i) {
        args[i].pool = encaps;
        args[i].public_key = pk;
        args[i].gate = &gate;
        int err = pthread_create(&threads[i], NULL, worker, &args[i]);
        if (err != 0) {
            fprintf(stderr, "pthread_create failed at thread %zu: %s\n", i, strerror(err));
            pthread_mutex_lock(&gate.mutex);
            gate.cancelled = 1;
            gate.released = 1;
            pthread_cond_broadcast(&gate.cond);
            pthread_mutex_unlock(&gate.mutex);
            goto join_workers;
        }
        ++created;
    }

    pthread_mutex_lock(&gate.mutex);
    gate.released = 1;
    pthread_cond_broadcast(&gate.cond);
    pthread_mutex_unlock(&gate.mutex);

join_workers:
    for (size_t i = 0; i < created; ++i) {
        int err = pthread_join(threads[i], NULL);
        if (err != 0) { fprintf(stderr, "pthread_join failed: %s\n", strerror(err)); abort(); }
    }
    if (gate.cancelled) goto cleanup;

    // Workers only compete for encapsulation slots. Verify the LAST successful
    // ciphertext/secret from each worker after all threads have completed.
    // Other tests should cover broader cryptographic correctness.
    for (size_t i = 0; i < created; ++i) {
        total_success += args[i].successes;
        total_busy += args[i].busy;
        total_errors += args[i].errors;
        // A thread can legitimately receive only EBUSY under severe
        // contention; require progress across the entire run, not per thread.
        if (args[i].successes == 0) continue;
        u8 recovered[ML_KEM_SEED_BYTES];
        int ret = ml_kem_decaps_core(decaps, args[i].last_ciphertext,
                                     sizeof(args[i].last_ciphertext),
                                     recovered, sizeof(recovered));
        if (ret != 0 || memcmp(recovered, args[i].last_secret, sizeof(recovered)) != 0) {
            fprintf(stderr, "Thread %zu: final encapsulation/decapsulation mismatch (ret=%d)\n", i, ret);
            ++total_errors;
        }
    }

    printf("Encapsulation pool stress test: %d threads, %d slots, %d attempts/thread\n",
           THREADS, POOL_SIZE, ITERATIONS);
    printf("Successes: %zu; busy: %zu; errors: %zu\n",
           total_success, total_busy, total_errors);
    if (total_errors == 0 && total_success > 0) {
        puts("SUCCESS");
        exit_code = EXIT_SUCCESS;
    } else {
        puts("FAILURE");
    }

cleanup:
    free(args);
    ml_kem_encaps_pool_destroy(encaps);
    ml_kem_destroy_core(decaps);
    pthread_cond_destroy(&gate.cond);
    pthread_mutex_destroy(&gate.mutex);
    return exit_code;
}
