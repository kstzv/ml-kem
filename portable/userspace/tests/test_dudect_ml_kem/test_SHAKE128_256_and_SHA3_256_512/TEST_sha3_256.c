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
    for(size_t i = 0; i < how_much; i++) {
        x[i] = (u8)dudect_xorshift64();
    }
}
/* =============================================================== */

// SHA3 input size.
// 64 bytes is large enough to:
//  - exercise absorb logic normally
//  - avoid tiny degenerate cases
//  - stay below SHA3-256 rate (136 bytes)
#define INPUT_SIZE 64

// Output buffer for SHA3-256 
static u8 sha3_out[32];

// Prevent compiler optimization
static volatile u8 dudect_sink = 0;

// class 0 -> fixed input
// class 1 -> random input
void prepare_inputs(dudect_config_t *c, u8 *input_data, u8 *classes)
{
    for(size_t i = 0; i < c->number_measurements; i++)
    {
        u8 *input = input_data + i * c->chunk_size;

        classes[i] = randombit();

        if(classes[i] == 0)
        {
            memset(input, 0x00, c->chunk_size);
        }else
        {
            randombytes(input, c->chunk_size);
        }
    }
}

// dudect target function
u8 do_one_computation(u8 *data)
{
    // clear previous output
    memset(sha3_out, 0, sizeof(sha3_out));

    // target function
    ml_kem_sha3_256(sha3_out, data, INPUT_SIZE);

    // Reduce output to one byte, preventing dead-code elimination.
    u8 acc = 0;

    for(size_t i = 0; i < sizeof(sha3_out); i++)
    {
        acc ^= sha3_out[i];
    }

    dudect_sink ^= acc;

    return dudect_sink;
}

// Run dudect
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
