// Multithreaded ML-KEM encapsulation/decapsulation pool stress tests.
// This test exercises concurrent pool access, shared secret agreement,
// repeated pool creation/destruction, and error handling under contention.
// Intended for execution with externally enabled compiler sanitizers.
// Sanitizer instrumentation and checks are controlled by the build/runtime,
// not by the test itself.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <sched.h>
#include "ml_kem.h"

// Number of concurrent worker threads used in each pool stress test.
// The worker count exceeds each pool size to exercise slot contention.
#define NUMBER_THREADS 20

// Number of operations performed by each worker for each ML-KEM level.
#define SIZE_LOOP_512  100
#define SIZE_LOOP_768  100
#define SIZE_LOOP_1024 100

// Number of reusable slots in the encapsulation/decapsulation stress pools.
#define SIZE_POOL_512  8
#define SIZE_POOL_768  8
#define SIZE_POOL_1024 8

// Per-thread arguments for repeated decapsulation of a fixed ciphertext.
// Each worker has its own ciphertext/expected-secret pair while all workers
// share the same decapsulation pool.
struct decaps_thread_args {
    // Shared pool containing the keypair and reusable decapsulation slots
    struct ml_kem_general_keys_decaps_ctx *pool;
    // Worker-specific ciphertext to be decapsulated repeatedly
    u8 *ciphertext;
    // Actual ciphertext length for the selected ML-KEM level
    size_t ciphertext_len;
    // Expected shared secret produced during initial encapsulation
    const u8 *ss_from_encaps;
    // Number of decapsulation attempts that must succeed
    size_t number_loops;
    // Worker result: 0 on success, 1 on failure, -1 before completion
    int status;
};

// Per-thread arguments for encapsulation followed by decapsulation.
// Threads share both pools and the read-only public key, but keep separate
// ciphertext storage and completion status.
struct encaps_thread_args {
    // Shared reusable encapsulation pool
    struct ml_kem_pool_encaps_ctx *pool;
    // Shared decapsulation pool used to verify each ciphertext
    struct ml_kem_general_keys_decaps_ctx *decaps_pool;
    // Per-thread ciphertext buffer sized for the largest ML-KEM variant
    u8 ciphertext[LEN_CIPHERTEXT_1024];
    // Ciphertext length for the selected security level
    size_t ciphertext_len;
    // Shared public key supplied by the parent thread
    u8 *pk;
    // Serialized public key size for the selected security level
    size_t pk_size;
    // Number of encapsulation/decapsulation round trips
    size_t number_loops;
    // Worker result: 0 on success, 1 on failure, -1 before completion
    int status;
};

// Worker for concurrent encapsulation pool testing.
// Parameters:
//  encaps_arg - pointer to a preinitialized encaps_thread_args structure
// Returns:
//  NULL; execution status is written to arg->status
// Behavior:
//  - Acquires a reusable encapsulation slot and generates ciphertext/shared secret
//  - Decapsulates the ciphertext using the matching keypair
//  - Verifies that the resulting shared secrets are identical
//  - Retries slot acquisition after -ML_KEM_EBUSY, yielding the CPU
// Notes:
//  - Both pools and the public key must remain valid until this thread exits
//  - Busy-slot retries have no timeout; a permanently busy pool can stall a worker
void *encaps_pool_worker(void *encaps_arg)
{
    struct encaps_thread_args *arg = encaps_arg;

    // Keep each shared secret in thread-local stack storage
    u8 ss_encaps[ML_KEM_SEED_BYTES];
    u8 ss_decaps[ML_KEM_SEED_BYTES];

    // Perform the configured number of complete encapsulation/decapsulation cycles
    for (size_t i = 0; i < arg->number_loops; i++)
    {
        int ret;

        // Generate a new ciphertext and shared secret using the shared encapsulation pool
        // Encapsulation
        do {
            ret = ml_kem_encaps_core(arg->pool, arg->pk, arg->pk_size, arg->ciphertext, arg->ciphertext_len, ss_encaps, ML_KEM_SEED_BYTES, NULL);

            // Yield on pool saturation and retry instead of treating contention as failure
            if (ret == -ML_KEM_EBUSY) { sched_yield(); }

        } while (ret == -ML_KEM_EBUSY);

        // Abort this worker if encapsulation fails for any reason other than busy slots
        if (ret != 0) { goto error; }

        // Recover the shared secret from the generated ciphertext
        // Verify through decapsulation
        do {
            ret = ml_kem_decaps_core(arg->decaps_pool, arg->ciphertext, arg->ciphertext_len, ss_decaps, ML_KEM_SEED_BYTES);

            // Decapsulation also uses a bounded slot pool shared by all workers
            if (ret == -ML_KEM_EBUSY) { sched_yield(); }

        } while (ret == -ML_KEM_EBUSY);

        // Any API error or mismatched shared secret fails the round-trip test
        if (ret != 0 || memcmp(ss_encaps, ss_decaps, ML_KEM_SEED_BYTES) != 0) { goto error; }
    }

    // Report successful completion of all requested iterations
    arg->status = 0;
    return NULL;

    // Common error exit: worker status is observed after pthread_join()
	error:
		arg->status = 1;
		return NULL;
}

// Worker for concurrent decapsulation pool testing.
// Parameters:
//  decaps_arg - pointer to a preinitialized decaps_thread_args structure
// Returns:
//  NULL; execution status is written to arg->status
// Behavior:
//  - Repeatedly decapsulates the worker's fixed ciphertext
//  - Retries while the shared decapsulation pool reports -ML_KEM_EBUSY
//  - Compares every resulting shared secret against the expected value
// Notes:
//  - Ciphertext and expected secret are prepared before the thread starts
//  - The parent thread retains all input storage until after pthread_join()
void *decaps_pool_worker(void *decaps_arg)
{
	struct decaps_thread_args *arg = decaps_arg;
	// Local output buffer prevents concurrent writes to a shared secret buffer
	u8 ss[ML_KEM_SEED_BYTES];
	
	// Exercise repeated acquisition and release of decapsulation slots
	for(size_t i = 0; i < arg->number_loops; i++)
	{
		int ret = 0;
		// Retry when all decapsulation slots are currently occupied
		do{
			ret = ml_kem_decaps_core(arg->pool, arg->ciphertext, arg->ciphertext_len, ss, ML_KEM_SEED_BYTES);
			if (ret == -ML_KEM_EBUSY) { sched_yield(); }
		}while(ret == -ML_KEM_EBUSY);
		
		// Fail if decapsulation returns an error or produces a different secret
		if (ret != 0 || memcmp(ss, arg->ss_from_encaps, ML_KEM_SEED_BYTES) != 0) { arg->status = 1; return NULL; }
	}
	
	// All iterations completed with the expected shared secret
	arg->status = 0;
    return NULL;
}

// Test concurrent decapsulation for one ML-KEM security level.
// Parameters:
//  level - security level (ML_KEM_512 / 768 / 1024)
// Returns:
//  Number of successfully completed worker threads on success
//  -1 if the decapsulation pool cannot be created
//  -2 if the public key cannot be obtained
//  -3 if a worker thread cannot be created
//  -4 if a worker reports a decapsulation or secret comparison failure
//  -5 if the security level is unsupported
//  -6 if initial standalone encapsulation fails
// Behavior:
//  - Creates one shared decapsulation pool and retrieves its public key
//  - Generates one independent ciphertext/shared secret pair per worker
//  - Starts concurrent workers that repeatedly decapsulate their own ciphertext
//  - Joins all successfully created workers before destroying the pool
// Notes:
//  - Worker count exceeds the number of pool slots to exercise contention
//  - A pthread_join() failure invokes abort() rather than returning a code
int func_test_decaps(enum ml_kem_k level)
{
	// Select public key size, ciphertext size, pool capacity, and loop count
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
	
	// Allocate thread handles and per-thread argument structures on the stack
	int created_threads = 0;
	int ret = 0;
	pthread_t threads[NUMBER_THREADS];
	struct decaps_thread_args ctx_decaps[NUMBER_THREADS];
	// Create one keypair with a reusable decapsulation pool for all workers
	struct ml_kem_general_keys_decaps_ctx *decaps_pool_ctx = ml_kem_create_object(level, number_pool, NULL);
	if(!decaps_pool_ctx) { ret = -1; goto exit; }
	
	// Retrieve the matching serialized public key into the maximum-sized buffer
	u8 pk[RES_PUBL_PART_LVL_1024];
	ret = ml_kem_get_public_key(decaps_pool_ctx, pk, size_pk);
	if(ret != 0) { ret = -2; goto exit; }
	
	// Each worker receives a separate ciphertext and expected shared secret
	u8 ct[NUMBER_THREADS][LEN_CIPHERTEXT_1024];
	u8 ss[NUMBER_THREADS][ML_KEM_SEED_BYTES];
	
	// Prepare each test vector and launch its decapsulation worker
	for(size_t i = 0; i < NUMBER_THREADS; i++)
	{
		// Generate the test ciphertext using standalone (non-pool) encapsulation
		ret = ml_kem_encaps_core(NULL, pk, size_pk, ct[i], size_ct, ss[i], ML_KEM_SEED_BYTES, NULL);
		if(ret != 0) { ret = -6; break; }
		
		// Bind this worker to its own test vector and the shared pool
		ctx_decaps[i].ciphertext = ct[i];
		ctx_decaps[i].ciphertext_len = size_ct;
		ctx_decaps[i].number_loops = number_loops;
		ctx_decaps[i].pool = decaps_pool_ctx;
		ctx_decaps[i].ss_from_encaps = ss[i];
		ctx_decaps[i].status = -1;
		
		// Track only threads actually created so partial startup can be joined safely
		if(pthread_create(&threads[i], NULL, decaps_pool_worker, &ctx_decaps[i]) != 0) { ret = -3; break; }
		created_threads++;
	}
	
	// Wait for launched workers and collect their completion status
	for (int i = 0; i < created_threads; i++) 
	{
		if(pthread_join(threads[i], NULL) != 0) { abort(); }

		if (ctx_decaps[i].status != 0 && ret == 0) { ret = -4; }
	}
	
	// On success, return the number of worker threads that completed
	if(ret == 0) { ret = created_threads; }
	
	// Release the shared pool only after all launched workers have exited
	exit:
		ml_kem_destroy_core(decaps_pool_ctx);
		return ret;
}
		

// Test concurrent encapsulation and round-trip verification for one level.
// Parameters:
//  level - security level (ML_KEM_512 / 768 / 1024)
// Returns:
//  Number of successfully completed worker threads on success
//  -1 if one of the pools cannot be created
//  -2 if the public key cannot be obtained
//  -3 if a worker thread cannot be created
//  -4 if a worker reports an encapsulation/decapsulation verification failure
//  -5 if the security level is unsupported
// Behavior:
//  - Creates a decapsulation pool for the selected level
//  - Creates an encapsulation pool with subpools for all three levels
//  - Shares both pools and the public key between concurrent worker threads
//  - Checks every generated shared secret by decapsulating its ciphertext
//  - Joins all successfully created threads before destroying either pool
// Notes:
//  - The selected encapsulation subpool has fewer slots than worker threads
//  - The parent-owned public key remains valid until all workers have joined
//  - A pthread_join() failure invokes abort() rather than returning a code
int func_test_encaps(enum ml_kem_k level)
{
	// Select the buffer sizes and stress-test parameters for this security level
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
	
	// Prepare thread handles, worker arguments, and shared pool objects
	int created_threads = 0;
	int ret = 0;
	pthread_t threads[NUMBER_THREADS];
	struct encaps_thread_args ctx_encaps[NUMBER_THREADS];
	// Create a matching keypair/decapsulation pool and all encapsulation subpools
	struct ml_kem_general_keys_decaps_ctx *decaps_pool_ctx = ml_kem_create_object(level, number_pool, NULL);
	struct ml_kem_pool_encaps_ctx *encaps_pool_ctx = create_encaps_pool(SIZE_POOL_512, SIZE_POOL_768, SIZE_POOL_1024);
	if(!decaps_pool_ctx || !encaps_pool_ctx) { ret = -1; goto exit; }
	
	// Copy the public key once; all workers read from this same buffer
	u8 pk[RES_PUBL_PART_LVL_1024];
	ret = ml_kem_get_public_key(decaps_pool_ctx, pk, size_pk);
	if(ret != 0) { ret = -2; goto exit; }
	
	// Launch workers that independently perform encapsulation/decapsulation round trips
	for(size_t i = 0; i < NUMBER_THREADS; i++)
	{
		// Provide each worker with pool references and fixed test parameters
		ctx_encaps[i].ciphertext_len = size_ct;
		ctx_encaps[i].decaps_pool = decaps_pool_ctx;
		ctx_encaps[i].number_loops = number_loops;
		ctx_encaps[i].pk = pk;
		ctx_encaps[i].pk_size = size_pk;
		ctx_encaps[i].pool = encaps_pool_ctx;
		ctx_encaps[i].status = -1;
		
		// Record only successfully created threads for later joining
		if(pthread_create(&threads[i], NULL, encaps_pool_worker, &ctx_encaps[i]) != 0) { ret = -3; break; }
		created_threads++;
	}
	
	// Wait for all started workers and check their result flags
	for (int i = 0; i < created_threads; i++) 
	{
		if(pthread_join(threads[i], NULL) != 0) { abort(); }

		if (ctx_encaps[i].status != 0 && ret == 0) { ret = -4; }
	}
	
	// Return the number of completed worker threads on success
	if(ret == 0) { ret = created_threads; }
	
	// Destroy both pools only after all started worker threads have exited
	exit:
		ml_kem_encaps_pool_destroy(encaps_pool_ctx);
		ml_kem_destroy_core(decaps_pool_ctx);
		return ret;
}

// Pool lifecycle stress-test parameters.
// Repeated allocation and destruction is intended to expose lifetime and
// cleanup defects when the binary is executed under memory sanitizers.
#define SLOT_DECAPS_POOL_LIFE_CYCLE 	 40
#define SLOT_ENCAPS_POOL_LIFE_CYCLE_512  20
#define SLOT_ENCAPS_POOL_LIFE_CYCLE_768  25
#define SLOT_ENCAPS_POOL_LIFE_CYCLE_1024 30
#define NUMBER_LOOPS_FOR_POOL_LIFE_CYCLE 1000

// Test repeated creation and destruction of ML-KEM pool objects.
// Parameters:
//  level_decaps       - security level of the decapsulation keypair and pool
//  slots_decaps       - number of reusable decapsulation slots
//  slots_encaps_512   - number of ML-KEM-512 encapsulation slots
//  slots_encaps_768   - number of ML-KEM-768 encapsulation slots
//  slots_encaps_1024  - number of ML-KEM-1024 encapsulation slots
//  number_loops       - number of create/destroy cycles
// Returns:
//  0 if all pool allocation and destruction cycles complete
//  -1 if either pool creation fails in any iteration
// Behavior:
//  - Allocates a decapsulation pool and an encapsulation pool each iteration
//  - Destroys both pools through a common cleanup path, including partial setup
//  - Repeats the lifecycle to exercise allocation and deallocation paths
// Notes:
//  - This function does not perform cryptographic operations on the pools
//  - Memory and lifetime violations are reported by external sanitizer tooling
int func_test_pool_lifecycle(enum ml_kem_k level_decaps, size_t slots_decaps, size_t slots_encaps_512, size_t slots_encaps_768, size_t slots_encaps_1024, size_t number_loops)
{
    // Repeat complete pool lifecycles to stress allocation and cleanup
    for(size_t i = 0; i < number_loops; i++)
    {
        int success = 0;

        // Initialize pointers so cleanup is valid even after failed creation
        struct ml_kem_general_keys_decaps_ctx *ctx_dec = NULL;
        struct ml_kem_pool_encaps_ctx *ctx_enc = NULL;

        // Create the decapsulation pool and its associated key material
        ctx_dec = ml_kem_create_object(level_decaps, slots_decaps, NULL);
        if(!ctx_dec) { goto cleanup; }

        // Create the independently configured encapsulation subpools
        ctx_enc = create_encaps_pool(slots_encaps_512, slots_encaps_768, slots_encaps_1024);
        if(!ctx_enc) { goto cleanup; }

        // Both objects were created successfully in this iteration
        success = 1;

        // Always destroy any objects created before leaving this iteration
        cleanup:
            ml_kem_encaps_pool_destroy(ctx_enc);
            ml_kem_destroy_core(ctx_dec);

        // Stop at the first failed allocation cycle
        if(!success) { return -1; }
    }

    return 0;
}

// Entry point for the complete pool stress-test suite.
// Returns:
//  0 if all test groups complete successfully
//  -1 if any test group reports failure
// Behavior:
//  - Runs encapsulation pool tests for ML-KEM-512, ML-KEM-768, and ML-KEM-1024
//  - Runs decapsulation pool tests for the same three levels
//  - Runs repeated pool creation/destruction testing
//  - Prints a result for each group and exits on the first failure
// Notes:
//  - Sanitizer instrumentation must be configured when compiling/running
//  - Successful completion does not by itself prove absence of memory or data races
int main()
{
	int ret = 0;
	// Concurrent encapsulation round-trip tests for all three security levels
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
	
	// Concurrent decapsulation tests using pre-generated ciphertexts
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
	
	// Repeated allocation/destruction test for pools of multiple sizes
	printf("\ntest mem in pools lifecycles...\n");
	ret = func_test_pool_lifecycle(ML_KEM_512, SLOT_DECAPS_POOL_LIFE_CYCLE, SLOT_ENCAPS_POOL_LIFE_CYCLE_512, SLOT_ENCAPS_POOL_LIFE_CYCLE_768, SLOT_ENCAPS_POOL_LIFE_CYCLE_1024, NUMBER_LOOPS_FOR_POOL_LIFE_CYCLE);
	if(ret < 0) 
	{
		printf("\ntest mem in pools lifecycles ERROR: %i\n", ret);
		return -1;
	}else { printf("\ntest mem in pools lifecycles with %d iterations: SUCCESS\n", NUMBER_LOOPS_FOR_POOL_LIFE_CYCLE); }
	printf("\n...............\n");
	
	// All test groups finished without reporting a failure
	return 0;
}





















