// SPDX-License-Identifier: GPL-2.0 OR MIT
// Copyright (c) 2026 K.S.Zavertailo

// File #7 — implementation of SHAKE128 / SHAKE256 wrappers
//
// This file implements the sponge construction on top of Keccak-f[1600]
// and is used in ML-KEM for:
//  - noise generation
//  - matrix A expansion
//  - secret vector derivation

#include "ml_kem_core_header.h"



int shake_ctx_get_mem(struct shake_ctx *ctx, u64 *state, size_t size_mem);
void shake_ctx_init(struct shake_ctx *ctx, const u8 *in, size_t inlen, u8 *out, size_t outlen);
void shake_ctx_zero(struct shake_ctx *ctx);
void shake128(struct shake_ctx *ctx);
void shake256(struct shake_ctx *ctx);

void shake_absorb(struct shake_ctx *ctx);
static void shake_finalize(struct shake_ctx *ctx);
static void shake_squeeze(struct shake_ctx *ctx);

int shake_ctx_get_mem(struct shake_ctx *ctx, u64 *state, size_t size_mem)
{
	if(!ctx || !state || size_mem != 25) { return -1; }
	ctx->state = state;
    ctx->rate = 0;
    ctx->pos = 0;
    ctx->in = NULL;
    ctx->inlen = 0;
    ctx->out = NULL;
    ctx->outlen = 0;
	return 0;
}

void shake_ctx_init(struct shake_ctx *ctx, const u8 *in, size_t inlen, u8 *out, size_t outlen)
{
    ctx->rate = 0;
    ctx->pos = 0;

    ctx->in = in;
    ctx->inlen = inlen;

    ctx->out = out;
    ctx->outlen = outlen;
}

// Clear the 1600-bit Keccak state and reset the context
void shake_ctx_zero(struct shake_ctx *ctx)
{
    if (ctx == NULL || ctx->state == NULL) { return; }

    // 25 lanes x 8 bytes
    volatile u8 *p = (volatile u8 *)ctx->state;
    size_t len = 200;
    while (len--) { *p++ = 0; }
    ctx->in = NULL;
    ctx->inlen = 0;
    ctx->out = NULL;
    ctx->outlen = 0;
    ctx->pos = 0;
    ctx->rate = 0;
}

void shake128(struct shake_ctx *ctx)
{
    ctx->rate = 168;

    // Continue squeezing an already finalized state
    if (ctx->pos != 0) 
    {
        shake_squeeze(ctx);
        return;
    }

    shake_absorb(ctx);
    shake_finalize(ctx);

    ctx->pos = 0;

    shake_squeeze(ctx);
}

void shake256(struct shake_ctx *ctx)
{
    ctx->rate = 136;

    // Continue squeezing an already finalized state
    if (ctx->pos != 0) 
    {
        shake_squeeze(ctx);
        return;
    }

    shake_absorb(ctx);
    shake_finalize(ctx);

    ctx->pos = 0;

    shake_squeeze(ctx);
}

// Absorb input into the rate portion of the Keccak state
void shake_absorb(struct shake_ctx *ctx)
{
    u8 *s = (u8 *)ctx->state;

    while (ctx->inlen > 0)
    {
        size_t n = ctx->rate - ctx->pos;

        if (n > ctx->inlen) { n = ctx->inlen; }

        for (size_t i = 0; i < n; i++) { s[ctx->pos + i] ^= ctx->in[i]; }

        ctx->pos += n;
        ctx->in += n;
        ctx->inlen -= n;

        // Permute after absorbing a complete rate block
        if (ctx->pos == ctx->rate)
        {
            keccak_f1600(ctx->state);
            ctx->pos = 0;
        }
    }
}

// Apply SHAKE domain separation and pad10*1 padding
static void shake_finalize(struct shake_ctx *ctx)
{
    u8 *s = (u8 *)ctx->state;

    s[ctx->pos] ^= 0x1F;     // SHAKE domain separator
    s[ctx->rate - 1] ^= 0x80;// Final padding bit

    keccak_f1600(ctx->state);
}

// Extract output from the rate portion, permuting as needed
static void shake_squeeze(struct shake_ctx *ctx)
{
    u8 *s = (u8 *)ctx->state;

    size_t local_outlen = ctx->outlen;
    u8 *local_ptr_out = ctx->out;

    while (local_outlen > 0)
    {
        // Generate the next output block when the rate is exhausted
        if (ctx->pos == ctx->rate)
        {
            keccak_f1600(ctx->state);
            ctx->pos = 0;
        }

        size_t n = ctx->rate - ctx->pos;

        if (n > local_outlen) { n = local_outlen; }

        for (size_t i = 0; i < n; i++) { local_ptr_out[i] = s[ctx->pos + i]; }

        ctx->pos += n;
        local_ptr_out += n;
        local_outlen -= n;
    }
}

