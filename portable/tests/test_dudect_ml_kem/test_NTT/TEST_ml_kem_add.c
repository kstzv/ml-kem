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

// input split: first || second 
static u16 first_poly[ML_KEM_N];
static u16 second_poly[ML_KEM_N];
static u16 result_poly[ML_KEM_N];

// prevent optimization 
static volatile u8 dudect_sink = 0;

static u64 rng_class_state = 0x123456789ABCDEF0ULL;
static u64 rng_data_state  = 0xFEDCBA9876543210ULL;

static u64 rng_next(u64 *state)
{
    u64 x = *state;

    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;

    return *state = x;
}

void prepare_inputs(dudect_config_t *c, u8 *input_data, u8 *classes)
{
    for(size_t i = 0; i < c->number_measurements; i++)
    {
        u8 *input = input_data + i * c->chunk_size;

        classes[i] = (u8)(rng_next(&rng_class_state) & 1u);

        for(size_t j = 0; j < 2 * ML_KEM_N; j++)
        {
            u16 value = (u16)(
                rng_next(&rng_data_state) % ML_KEM_Q
            );

            if(classes[i] == 0)
                value = 0;

            memcpy(input + j * sizeof(u16),
                   &value, sizeof(value));
        }
    }
}

// Run in dudect function for test
u8 do_one_computation(u8 *data)
{
    const size_t half = sizeof(u16) * ML_KEM_N;

    memcpy(first_poly, data, half);
    memcpy(second_poly, data + half, half);

    ml_kem_add(result_poly, first_poly, second_poly);

    dudect_sink = (u8)result_poly[0];

    return dudect_sink;
}

// Run test programm in dudect
int main(void)
{
    dudect_ctx_t ctx;
    dudect_config_t config;
    dudect_state_t state;

    // IMPORTANT: double input size
    config.chunk_size = 2 * sizeof(u16) * ML_KEM_N;
    config.number_measurements = 50000;

    dudect_init(&ctx, &config);

    do {
        state = dudect_main(&ctx);
    } while (state == DUDECT_NO_LEAKAGE_EVIDENCE_YET);

    dudect_free(&ctx);
    return 0;
}
