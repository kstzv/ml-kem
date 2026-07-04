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
// ================================================================

// Declaring functions required for the test
void ml_kem_create_temp_secret_y(struct ml_kem_encaps_ctx *ctx, u8 *seed);
void ml_kem_create_v(struct ml_kem_encaps_ctx *ctx, u8 *seed);

#define INPUT_SIZE (ML_KEM_SEED_BYTES * 2) // 32 байти r + 32 байти seed_m 

// Declaring an encapsulation structure object and buffers for its fields
static struct ml_kem_encaps_ctx kem_ctx;
static u8  raw_bytes_buf[ML_KEM_MATRIX_XOF_BYTES];
static u16 u_buf[ML_KEM_N * ML_KEM_1024];
static u16 v_buf[ML_KEM_N];
static u16 pk_buf[ML_KEM_N * ML_KEM_1024];
static u16 y_buf[ML_KEM_N * ML_KEM_1024];
static u16 poly_buf[ML_KEM_N];

// To prevent the compiler from throwing out calculations
static volatile u8 dudect_sink = 0;

// Filling in the structure fields
static void init_ctx(void)
{
    memset(&kem_ctx, 0, sizeof(kem_ctx));

    kem_ctx.k          = ML_KEM_1024;
    kem_ctx.raw_bytes  = raw_bytes_buf;
    kem_ctx.u          = u_buf;      
    kem_ctx.v          = v_buf;
    kem_ctx.public_key = pk_buf;
    kem_ctx.y          = y_buf;
    kem_ctx.poly       = poly_buf;

     // We make the public key fixed and NOT zero to avoid an overly artificial degenerate case.
     // This is public data, so it shouldn't be a dudect class
    for (size_t i = 0; i < ML_KEM_N * kem_ctx.k; i++) {
        kem_ctx.public_key[i] = (u16)(dudect_xorshift64() % ML_KEM_Q);
    }

    memset(kem_ctx.seed_rho, 0xA5, ML_KEM_SEED_BYTES); /* тут не використовується create_v, але хай валідно */
}

// Filling in the appropriate fields before each iteration dudect
// dudect classification:
// class 0 -> fixed secret
// class 1 -> random secret
// Format input:
//   [0..31]  = r_seed
//   [32..63] = seed_m
void prepare_inputs(dudect_config_t *c, u8 *input_data, u8 *classes)
{
    static const u8 fixed_r[ML_KEM_SEED_BYTES] = {0};
    static const u8 fixed_m[ML_KEM_SEED_BYTES] = {0};

    for (size_t i = 0; i < c->number_measurements; i++) {
        u8 *input = input_data + i * c->chunk_size;
        classes[i] = randombit();

        if (classes[i] == 0) {
            memcpy(input, fixed_r, ML_KEM_SEED_BYTES);
            memcpy(input + ML_KEM_SEED_BYTES, fixed_m, ML_KEM_SEED_BYTES);
        } else {
            randombytes(input, c->chunk_size);
        }
    }
}

// Run in dudect function for test
u8 do_one_computation(u8 *data)
{
    u8 *r_seed = data;
    u8 *m_seed = data + ML_KEM_SEED_BYTES;

    memset(kem_ctx.raw_bytes, 0, sizeof(raw_bytes_buf));
    memset(kem_ctx.v,         0, sizeof(v_buf));
    memset(kem_ctx.y,         0, sizeof(y_buf));
    memset(kem_ctx.poly,      0, sizeof(poly_buf));
    memset(kem_ctx.seed_m,    0, ML_KEM_SEED_BYTES);

    memcpy(kem_ctx.seed_m, m_seed, ML_KEM_SEED_BYTES);

    ml_kem_create_temp_secret_y(&kem_ctx, r_seed);

    // Function for test
    ml_kem_create_v(&kem_ctx, r_seed);

	// Protection against optimization
    dudect_sink ^= (u8)(kem_ctx.v[0] & 0xFF);
    dudect_sink ^= (u8)(kem_ctx.v[17] & 0xFF);
    dudect_sink ^= (u8)(kem_ctx.v[129] & 0xFF);

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

    dudect_free(&ctx);
    return 0;
}
