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
    for(size_t i = 0; i < how_much; i++) {
        x[i] = (u8)dudect_xorshift64();
    }
}
// ================================================================

// Test target
u16 ml_kem_ct_sub_if_ge(u16 x);


// Prevent optimization
static volatile u16 dudect_sink = 0;


// Input classes
// class 0: x < q
// class 1: x >= q
void prepare_inputs(dudect_config_t *c, u8 *input_data, u8 *classes)
{
    for(size_t i = 0; i < c->number_measurements; i++)
    {
        u16 *input = (u16 *)(input_data + i * c->chunk_size);

        classes[i] = randombit();

        if(classes[i] == 0)
        {
             // [0 ; q-1]
            *input = (u16)(dudect_xorshift64() % ML_KEM_Q);
        }else
        {
             // [q ; 2q-1]
            *input = (u16)(ML_KEM_Q + (dudect_xorshift64() % ML_KEM_Q));
        }
    }
}

// One computation
u8 do_one_computation(u8 *data)
{
    u16 x = *(u16 *)data;

    u16 r = ml_kem_ct_sub_if_ge(x);

    dudect_sink ^= r;

    return (u8)dudect_sink;
}

// Run test programm in dudect
int main(void)
{
    dudect_ctx_t ctx;
    dudect_config_t config;
    dudect_state_t state;

    config.chunk_size = sizeof(u16);
    config.number_measurements = 50000;

    dudect_init(&ctx, &config);

    do {
        state = dudect_main(&ctx);
    } while(state == DUDECT_NO_LEAKAGE_EVIDENCE_YET);

    dudect_free(&ctx);

    return 0;
}
	
	
	
	
	
	
	
	
	
	
	
