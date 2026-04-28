// SPDX-License-Identifier: GPL-2.0 OR MIT
// Copyright (c) 2026 K.S.Zavertailo

// File №7 - ml_kem_sha3.c – local implementation of SHA3-256 / SHA3-512 for ML-KEM

#include "ml_kem_core_header.h"  

struct ml_kem_sha3_ctx 
{
	u64    st[25];   // 25 * 8 = 200 bytes of state
	size_t rate;     // rate size in bytes (SHA3-256: 136, SHA3-512: 72)
	size_t pos;      // position inside the current rate block (in bytes)
};

// Cross-file function declarations
void ml_kem_sha3_256(u8 out[32], const u8 *in, size_t inlen);
void ml_kem_sha3_512(u8 out[64], const u8 *in, size_t inlen);

// Forward declarations of static functions
static void ml_kem_sha3_init(struct ml_kem_sha3_ctx *ctx, size_t rate);
static void ml_kem_sha3_absorb(struct ml_kem_sha3_ctx *ctx, const u8 *in, size_t inlen);
static void ml_kem_sha3_finalize(struct ml_kem_sha3_ctx *ctx, u8 delim);
static void ml_kem_sha3_squeeze(struct ml_kem_sha3_ctx *ctx, u8 *out, size_t outlen);

// Context initialization 
static void ml_kem_sha3_init(struct ml_kem_sha3_ctx *ctx, size_t rate)
{
	memzero_explicit(ctx, sizeof(*ctx));
	ctx->rate = rate;
	ctx->pos  = 0;
}

 // Absorption of input bytes (without padding).
 // Byte is mapped in little-endian inside a 64-bit word:
 // st[pos/8] ^= (u64)byte << ((pos % 8) * 8)
static void ml_kem_sha3_absorb(struct ml_kem_sha3_ctx *ctx, const u8 *in, size_t inlen)
{
	size_t i;

	for (i = 0; i < inlen; i++) {
		size_t idx   = ctx->pos >> 3;          		// index of the 64-bit word
		unsigned int shift = (ctx->pos & 7U) * 8U;

		ctx->st[idx] ^= (u64)in[i] << shift;
		ctx->pos++;

		// Once rate bytes are filled — apply Keccak-f1600
		if (ctx->pos == ctx->rate) {
			keccak_f1600_ct(ctx->st);
			ctx->pos = 0;
		}
	}
}

 // Finalization: add domain separation (delim, e.g. 0x06),
 // then 0x80 into the last byte of the rate block.
 // After that, perform one more keccak_f1600_ct().
 
 // This is the standard pad10*1 with domain:
 // SHA3-256/512: delim = 0x06
 // SHAKE:        delim = 0x1F
static void ml_kem_sha3_finalize(struct ml_kem_sha3_ctx *ctx, u8 delim)
{
	size_t idx;
	unsigned int shift;

	// XOR domain byte at the current position
	idx   = ctx->pos >> 3;
	shift = (ctx->pos & 7U) * 8U;
	ctx->st[idx] ^= (u64)delim << shift;

	// XOR 0x80 into the last byte of the rate block
	idx   = (ctx->rate - 1) >> 3;
	shift = ((ctx->rate - 1) & 7U) * 8U;
	ctx->st[idx] ^= (u64)0x80 << shift;

	// Final permutation before output
	keccak_f1600_ct(ctx->st);
	ctx->pos = 0;
}

 // Squeeze: extract outlen bytes from the state,
 // calling keccak_f1600_ct again if needed (next rounds)
static void ml_kem_sha3_squeeze(struct ml_kem_sha3_ctx *ctx, u8 *out, size_t outlen)
{
	size_t i;

	for (i = 0; i < outlen; i++) {
		if (ctx->pos == ctx->rate) {
			keccak_f1600_ct(ctx->st);
			ctx->pos = 0;
		}

		size_t idx   = ctx->pos >> 3;
		unsigned int shift = (ctx->pos & 7U) * 8U;

		out[i] = (u8)((ctx->st[idx] >> shift) & 0xFFU);
		ctx->pos++;
	}
}

// One-shot SHA3-256: rate = 136, output = 32 bytes, delim = 0x06 
void ml_kem_sha3_256(u8 out[32], const u8 *in, size_t inlen)
{
	struct ml_kem_sha3_ctx ctx;

	ml_kem_sha3_init(&ctx, 136);         // r = 1088 bits = 136 bytes
	ml_kem_sha3_absorb(&ctx, in, inlen);
	ml_kem_sha3_finalize(&ctx, 0x06);    // domain separation for SHA3
	ml_kem_sha3_squeeze(&ctx, out, 32);

	memzero_explicit(&ctx, sizeof(ctx));
}

// One-shot SHA3-512: rate = 72, output = 64 bytes, delim = 0x06
void ml_kem_sha3_512(u8 out[64], const u8 *in, size_t inlen)
{
	struct ml_kem_sha3_ctx ctx;

	ml_kem_sha3_init(&ctx, 72);      		 // r = 576 bits = 72 bytes
	ml_kem_sha3_absorb(&ctx, in, inlen);
	ml_kem_sha3_finalize(&ctx, 0x06);
	ml_kem_sha3_squeeze(&ctx, out, 64);

	memzero_explicit(&ctx, sizeof(ctx));
}


