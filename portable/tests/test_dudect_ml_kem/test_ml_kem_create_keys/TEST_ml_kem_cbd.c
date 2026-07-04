#include <stdint.h>
#include <stddef.h>

#define randombit dudect_randombit_internal
#define randombytes dudect_randombytes_internal

#define DUDECT_IMPLEMENTATION
#include "dudect.h"

#undef randombit
#undef randombytes

#include "ml_kem_core_header.h"
#include <string.h>

// Custom deterministic RNG for dudect
// NOTE: This RNG is deterministic and used ONLY for dudect testing.
// It is NOT cryptographically secure
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
/* ================================================================ */


// Declaring function required for the test
void ml_kem_gen_polynomial_for_cbd(u16 *poly, const u8 *stream, const u8 eta);

// 128 байт → eta = 2
#define INPUT_SIZE (ML_KEM_N / 4)
// For 192 байт → eta = 3
// #define INPUT_SIZE (ML_KEM_N * 3 / 4)

static u16 poly[ML_KEM_N];

// To prevent the compiler from throwing out calculations
static volatile u8 dudect_sink = 0;


// Filling in the appropriate fields before each iteration dudect
// dudect classification:
// class 0 → fixed input
// class 1 → random input
void prepare_inputs(dudect_config_t *c, u8 *input_data, u8 *classes)
{
    for (size_t i = 0; i < c->number_measurements; i++) {
        u8 *input = input_data + i * c->chunk_size;
        classes[i] = randombit();

        if (classes[i] == 0) {
            memset(input, 0x00, c->chunk_size);
        } else {
            randombytes(input, c->chunk_size);
        }
    }
}

// Run in dudect function for test
u8 do_one_computation(u8 *data)
{
    memset(poly, 0, sizeof(poly));

	// Function for test
    // eta = 2
    ml_kem_gen_polynomial_for_cbd(poly, data, 2);

    // === for testing eta = 3
    // ml_kem_gen_polynomial_for_cbd(poly, data, 3);

    // Protection against optimization
    u8 acc = 0;
    for (size_t i = 0; i < ML_KEM_N; i++) {
        acc ^= (u8)poly[i];
        acc ^= (u8)(poly[i] >> 8);
    }

    dudect_sink ^= acc;
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
