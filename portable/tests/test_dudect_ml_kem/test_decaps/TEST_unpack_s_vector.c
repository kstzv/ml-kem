
#include <stdint.h>
#include <stddef.h>
#include <string.h>

#define randombit dudect_randombit_internal
#define randombytes dudect_randombytes_internal

#define DUDECT_IMPLEMENTATION
#include "dudect.h"

#undef randombit
#undef randombytes

#include "ml_kem.h"

// Deterministic RNG for dudect
static u64 dudect_rng_state = 0x123456789ABCDEF0ULL;

static u64 dudect_xorshift64(void)
{
    u64 x = dudect_rng_state;
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    return dudect_rng_state = x;
}

u8 randombit(void)
{
    return (u8)(dudect_xorshift64() & 1u);
}

void randombytes(u8 *x, size_t how_much)
{
    for(size_t i = 0; i < how_much; i++)
        x[i] = (u8)dudect_xorshift64();
}

/* =============================================================== */

#define TEST_LEVEL ML_KEM_1024
#define NUM_COEFFS (ML_KEM_N * TEST_LEVEL)
#define INPUT_SIZE (NUM_COEFFS * 3 / 2)

static u16 secret[NUM_COEFFS];

static volatile u8 dudect_sink = 0;

// class 0 -> fixed packed vector
// class 1 -> random packed bytes
void prepare_inputs(dudect_config_t *c, u8 *input_data, u8 *classes)
{
    for(size_t i = 0; i < c->number_measurements; i++)
    {
        u8 *input = input_data + i * c->chunk_size;
        classes[i] = randombit();

        if(classes[i] == 0)
        {
            memset(input, 0, c->chunk_size);
        }
        else
        {
            randombytes(input, c->chunk_size);
        }
    }
}

// dudect target function
u8 do_one_computation(u8 *data)
{
    memset(secret, 0, sizeof(secret));

    // Target function
    size_t consumed = unpack_s_vector(secret, data, TEST_LEVEL);

    // Prevent dead-code elimination
    u8 acc = (u8)consumed;

    for(size_t i = 0; i < NUM_COEFFS; i++)
    {
        acc ^= (u8)secret[i];
        acc ^= (u8)(secret[i] >> 8);
    }

    dudect_sink ^= acc;
    return dudect_sink;
}

int main(void)
{
    dudect_ctx_t ctx;
    dudect_config_t config;
    dudect_state_t state;

    config.chunk_size = INPUT_SIZE;
    config.number_measurements = 50000;

    dudect_init(&ctx, &config);

    do {
        state = dudect_main(&ctx);
    } while(state == DUDECT_NO_LEAKAGE_EVIDENCE_YET);

    dudect_free(&ctx);
    return 0;
}



