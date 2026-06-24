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
void ml_kem_create_vector_poly(struct ml_kem_temp *temp);

#define INPUT_SIZE ML_KEM_SEED_BYTES // size test data == seed

// Declaring an encapsulation structure
static struct ml_kem_temp temp;

// To prevent the compiler from throwing out calculations
static volatile u8 dudect_sink = 0;

// Create temp struct in generations keys
static void init_temp(void)
{
    static u8 raw_bytes[ML_KEM_VECTOR_XOF_BYTES_L2];
    static u16 secret[ML_KEM_N * ML_KEM_512];

    memset(&temp, 0, sizeof(temp));

    temp.k = ML_KEM_512;
    temp.eta = ML_KEM_CBD_ETA_3;
    temp.number_raw_bytes_vectors = ML_KEM_VECTOR_XOF_BYTES_L2;
    temp.raw_bytes = raw_bytes;
    temp.secret = secret;
}

// Filling in the appropriate fields before each iteration dudect
// dudect classification:
// class 0 -> fixed secret
// class 1 -> random secret
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
    memset(temp.raw_bytes, 0, temp.number_raw_bytes_vectors);
    memset(temp.secret, 0, sizeof(u16) * ML_KEM_N * temp.k);

    memcpy(temp.seed_sigma, data, ML_KEM_SEED_BYTES);

	// Function for test
    ml_kem_create_vector_poly(&temp);

    // Protection against optimization
    dudect_sink ^= (u8)(temp.secret[0] & 0xFF);
    return dudect_sink;
}

// Run test programm in dudect
int main(void)
{
    dudect_ctx_t ctx;
    dudect_config_t config;
    dudect_state_t state;

    init_temp();

    config.chunk_size = INPUT_SIZE;
    config.number_measurements = 50000;

    dudect_init(&ctx, &config);

    do {
        state = dudect_main(&ctx);
    } while (state == DUDECT_NO_LEAKAGE_EVIDENCE_YET);

    dudect_free(&ctx);
    return 0;
}
