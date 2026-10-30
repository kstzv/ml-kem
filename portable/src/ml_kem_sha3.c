// SPDX-License-Identifier: GPL-2.0 OR MIT
// Copyright (c) 2026 K.S.Zavertailo

// File #6 - ml_kem_sha3.c – local implementation of SHA3-256 / SHA3-512 for ML-KEM

// SHA3 implementation shares the same Keccak-f[1600]
// Permutation as SHAKE but uses SHA3 domain separation.
// This file is used in ML-KEM for:
//  - public key hashing
//  - seed expansion
//  - auxiliary cryptographic operations

#include "ml_kem_core_header.h"

int sha3_ctx_get_mem(struct sha3_ctx *ctx, u64 *state, size_t size_mem);
void sha3_ctx_init(struct sha3_ctx *ctx, const u8 *in, size_t inlen, u8 *out);
void sha3_256(struct sha3_ctx *ctx);
void sha3_512(struct sha3_ctx *ctx);

static void sha3_absorb(struct sha3_ctx *ctx);
static void sha3_finalize(struct sha3_ctx *ctx);
static void sha3_squeeze(struct sha3_ctx *ctx, u8 outlen);

int sha3_ctx_get_mem(struct sha3_ctx *ctx, u64 *state, size_t size_mem)
{
	if(!ctx || !state || size_mem != 25) { return -1; }
	ctx->state = state;
    ctx->rate = 0;
    ctx->pos = 0;
    ctx->in = NULL;
    ctx->inlen = 0;
    ctx->out = NULL;
	return 0;
}

void sha3_ctx_init(struct sha3_ctx *ctx, const u8 *in, size_t inlen, u8 *out)
{
	// 25 lanes x 8 bytes
    volatile u8 *p = (volatile u8 *)ctx->state;
    size_t len = 200;
    while (len--) { *p++ = 0; }
    
    ctx->rate = 0;
    ctx->pos = 0;
	
    ctx->in = in;
    ctx->inlen = inlen;
    ctx->out = out;
}

void sha3_256(struct sha3_ctx *ctx)
{
    ctx->rate = 136;
    ctx->pos = 0;

    sha3_absorb(ctx);
    sha3_finalize(ctx);
    sha3_squeeze(ctx, 32);
}

void sha3_512(struct sha3_ctx *ctx)
{
    ctx->rate = 72;
    ctx->pos = 0;

    sha3_absorb(ctx);
    sha3_finalize(ctx);
    sha3_squeeze(ctx, 64);
}

// Absorb input into the rate portion of the Keccak state
static void sha3_absorb(struct sha3_ctx *ctx)
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

// Apply sha3 domain separation and pad10*1 padding
static void sha3_finalize(struct sha3_ctx *ctx)
{
    u8 *s = (u8 *)ctx->state;

    s[ctx->pos] ^= 0x06;     // SHA3 domain separator
    s[ctx->rate - 1] ^= 0x80;// Final padding bit

    keccak_f1600(ctx->state);
}

// Extract output from the rate portion, permuting as needed
static void sha3_squeeze(struct sha3_ctx *ctx, uint8_t outlen)
{
    const u8 *s = (const u8 *)ctx->state;

    for (size_t i = 0; i < outlen; i++)
    {
        ctx->out[i] = s[i];
    }
}


