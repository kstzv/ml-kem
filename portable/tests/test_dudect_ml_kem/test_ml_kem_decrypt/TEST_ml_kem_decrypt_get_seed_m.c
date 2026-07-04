#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdio.h>

#define randombit dudect_randombit_internal
#define randombytes dudect_randombytes_internal

#define DUDECT_IMPLEMENTATION
#include "dudect.h"

#undef randombit
#undef randombytes

#include "ml_kem_core_header.h"
#include "ml_kem.h"

// Deterministic RNG для dudect
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
/* ======================================= */

// Get size input data for the test
#define LEVEL ML_KEM_1024
#define POLY_SIZE (sizeof(u16) * ML_KEM_N)
#define INPUT_SIZE (POLY_SIZE)

// Structs keys and decrypt
static struct ml_kem_pool_decaps_ctx *ctx = NULL;

// To prevent the compiler from throwing out calculations
static volatile u8 dudect_sink = 0;

// forward declaration 
void ml_kem_decrypt_get_seed_m(struct ml_kem_decrypt_ctx *ctx_decry);

// Create all needes struct and datas
static int init_ctx(void)
{
	ctx = ml_kem_create_object(LEVEL, 1, NULL);
	if(!ctx) 
	{
		printf("Error in ml_kem_create_object()\n");
		return -1;
	}

    return 0;
}

// Destroy all created objects
static void destroy_ctx(void)
{
    if(ctx)
    {
		ml_kem_destroy_core(ctx);
	}
}

// Filling in the appropriate fields before each iteration dudect
// dudect classification:
// class 0 → poly = fixed
// class 1 → poly = random
void prepare_inputs(dudect_config_t *c, u8 *input_data, u8 *classes)
{
    for (size_t i = 0; i < c->number_measurements; i++) {
        u8 *input = input_data + i * c->chunk_size;

        classes[i] = randombit();

        if (classes[i] == 0) {
            memset(input, 0x00, POLY_SIZE);
        } else {
            randombytes(input, POLY_SIZE);
        }
    }
}

// Run in dudect function for test
u8 do_one_computation(u8 *data)
{
	// Zeroing and copyng testing info in testing variables
    ml_kem_wipe_decrypt(ctx->ml_kem_pool[0].decrypt_ctx);
    memcpy(ctx->ml_kem_pool[0].decrypt_ctx->poly, data, POLY_SIZE);

    // Function for test
    ml_kem_decrypt_get_seed_m(ctx->ml_kem_pool[0].decrypt_ctx);

    // Protection against optimization
    dudect_sink ^= ctx->ml_kem_pool[0].decrypt_ctx->m[0];
    dudect_sink ^= ctx->ml_kem_pool[0].decrypt_ctx->m[7];
    dudect_sink ^= ctx->ml_kem_pool[0].decrypt_ctx->m[15];

    return dudect_sink;
}

// Run test programm in dudect
int main(void)
{
    dudect_ctx_t ctx;
    dudect_config_t config;
    dudect_state_t state;

    if (init_ctx() != 0) {
        fprintf(stderr, "init_ctx failed\n");
        return 1;
    }

    config.chunk_size = INPUT_SIZE;
    config.number_measurements = 50000;

    dudect_init(&ctx, &config);

    do {
        state = dudect_main(&ctx);
    } while (state == DUDECT_NO_LEAKAGE_EVIDENCE_YET);

    dudect_free(&ctx);
    destroy_ctx();

    return 0;
}
