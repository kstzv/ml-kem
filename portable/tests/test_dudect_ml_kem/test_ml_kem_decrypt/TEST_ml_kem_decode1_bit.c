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

// Deterministic RNG для dudect
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
    for (size_t i = 0; i < how_much; i++) {
        x[i] = (u8)dudect_xorshift64();
    }
}
/* ================================= */


// Get size input data for the test
#define INPUT_SIZE sizeof(u16)

// To prevent the compiler from throwing out calculations
static volatile u8 dudect_sink = 0;

// Filling in the appropriate fields before each iteration dudect
// dudect classification:
// dudect classification:
// class 0: w ∈ [833, 2496]
// class 1: w ∉ [833, 2496]
// These regions are used to verify that ml_kem_decode1_bit()
// Correctly handles the ML-KEM decoding thresholds and that
// Compiler optimizations do not introduce secret-dependent timing
void prepare_inputs(dudect_config_t *c, uint8_t *input_data, uint8_t *classes)
{
    for (size_t i = 0; i < c->number_measurements; i++) {

        u16 *w = (u16 *)(input_data + i * c->chunk_size);

        classes[i] = randombit();

        if (classes[i] == 0) {
            // valid region
            *w = 833 + (dudect_xorshift64() % (2496 - 833 + 1));
        } else {
            // invalid region
            if (randombit()) {
                *w = dudect_xorshift64() % 833;
            } else {
                *w = 2497 + (dudect_xorshift64() % (65535 - 2497));
            }
        }
    }
}

// Run in dudect function for test
u8 do_one_computation(u8 *data)
{
    u16 w;
    memcpy(&w, data, sizeof(w));

    u8 r = ml_kem_decode1_bit(w);

    dudect_sink ^= r;

    return dudect_sink;
}

// Run test programm in dudect
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
    } while (state == DUDECT_NO_LEAKAGE_EVIDENCE_YET);

    dudect_free(&ctx);
    return 0;
}
