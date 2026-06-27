#include <stdint.h>
#include <stddef.h>
#include <string.h>

#define randombit dudect_randombit_internal
#define randombytes dudect_randombytes_internal

#define DUDECT_IMPLEMENTATION
#include "dudect.h"

#undef randombit
#undef randombytes

#include "ml_kem_core_header.h"
#include "ml_kem.h"

// IMPORTANT: In ml_kem.c temporarily remove static:
// void ml_kem_decaps_ct_select_ss(struct ml_kem_pool_decaps_ctx *pool, u8 *ciphertext, size_t len_ciphertext, u8 *result, size_t curr_slot);
// or place this test in the same translation unit under #ifdef.
void ml_kem_decaps_ct_select_ss(struct ml_kem_pool_decaps_ctx *pool, u8 *ciphertext, size_t len_ciphertext, u8 *result, size_t curr_slot);


// Deterministic RNG for dudect                                     
static u64 dudect_rng_state = 0x123456789ABCDEF0ULL;

static u64 dudect_xorshift64(void)
{
    u64 x = dudect_rng_state;

    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;

    dudect_rng_state = x;
    return x;
}

u8 randombit(void)
{
    return (u8)(dudect_xorshift64() & 1u);
}

void randombytes(u8 *x, size_t how_much)
{
    for (size_t i = 0; i < how_much; i++) {
        x[i] = (u8)dudect_xorshift64();
    }
}

// Test configuration                                               

// We test ML-KEM-1024 because it has the largest ciphertext
// And therefore the largest comparison loop.
#define TEST_CIPHERTEXT_LEN LEN_CIPHERTEXT_1024

// Input format:
// class 0: ciphertext == encaps_ctx->ciphertext
// class 1: ciphertext != encaps_ctx->ciphertext
// This directly tests whether the comparison and secret
// selection path leaks timing information.
#define INPUT_SIZE TEST_CIPHERTEXT_LEN

// Minimal structures and buffers                                   
static struct ml_kem_pool_decaps_ctx *pool_head;
enum ml_kem_k LVL = ML_KEM_1024;

static u8 ciphertext_reference[TEST_CIPHERTEXT_LEN];
static u8 ciphertext_input[TEST_CIPHERTEXT_LEN];

static u8 result_buf[ML_KEM_SEED_BYTES];

// Prevent compiler optimization 
static volatile u8 dudect_sink = 0;

// Initialization                                                    
static void init_ctx(void)
{
	pool_head = ml_kem_create_object(LVL, 1, NULL);

     // Fixed non-zero values. These are NOT dudect classes
    randombytes(ciphertext_reference, sizeof(ciphertext_reference));
    randombytes(pool_head->ml_kem_pool[0].encaps_ctx->K_bar, ML_KEM_SEED_BYTES);

    pool_head->ml_kem_pool[0].encaps_ctx->ciphertext = ciphertext_reference;
}

static void exit_ctx(void)
{
	ml_kem_destroy_core(pool_head);
}

// Dudect input generation                                         
void prepare_inputs(dudect_config_t *c, u8 *input_data, u8 *classes)
{
    for (size_t i = 0; i < c->number_measurements; i++) {

        u8 *input = input_data + (i * c->chunk_size);

        classes[i] = randombit();

        if (classes[i] == 0) {

             // VALID ciphertext: identical to reconstructed ciphertext
            memcpy(input, ciphertext_reference, TEST_CIPHERTEXT_LEN);
        } else 
        {

             // INVALID ciphertext: random ciphertext 
            randombytes(input, TEST_CIPHERTEXT_LEN);

             // Ensure at least one byte differs
            memcpy(input, ciphertext_reference, TEST_CIPHERTEXT_LEN);
            input[0] ^= 0x01;
        }
    }
}

// One measurement                                                  
u8 do_one_computation(u8 *data)
{
    memcpy(ciphertext_input, data, TEST_CIPHERTEXT_LEN);

    memset(result_buf, 0, sizeof(result_buf));

    ml_kem_decaps_ct_select_ss(pool_head, ciphertext_input, TEST_CIPHERTEXT_LEN, result_buf, 0);

     // Prevent optimizer from removing computation.
    dudect_sink ^= result_buf[0];
    dudect_sink ^= result_buf[7];
    dudect_sink ^= result_buf[19];

    return dudect_sink;
}

// Run test programm in dudect
int main(void)
{
    dudect_ctx_t ctx;
    dudect_config_t config;
    dudect_state_t state;

    init_ctx();

    config.chunk_size = INPUT_SIZE;
    config.number_measurements = 50000;

    dudect_init(&ctx, &config);

    do {
        state = dudect_main(&ctx);
    } while (state == DUDECT_NO_LEAKAGE_EVIDENCE_YET);
    
    exit_ctx();

    dudect_free(&ctx);

    return 0;
}

