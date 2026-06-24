// SPDX-License-Identifier: GPL-2.0 OR MIT
// Copyright (c) 2026 K.S.Zavertailo

// File #6 - ml_kem_sha3.c – local implementation of SHA3-256 / SHA3-512 for ML-KEM

// SHA3 implementation shares the same Keccak-f[1600]
// Permutation as SHAKE but uses SHA3 domain separation.
// This file is used in ML-KEM for:
//  - public key hashing
//  - seed expansion
//  - auxiliary cryptographic operations

#include <string.h>
#include "ml_kem_core_header.h"

struct ml_kem_sha3_ctx {
	u64 st[25];
	size_t rate;
	size_t pos;
};

void ml_kem_sha3_256(u8 out[32], const u8 *in, size_t inlen);
void ml_kem_sha3_512(u8 out[64], const u8 *in, size_t inlen);

static inline u64 ml_kem_sha3_load64_le(const u8 *src)
{
	return ((u64)src[0]      ) |
	       ((u64)src[1] <<  8) |
	       ((u64)src[2] << 16) |
	       ((u64)src[3] << 24) |
	       ((u64)src[4] << 32) |
	       ((u64)src[5] << 40) |
	       ((u64)src[6] << 48) |
	       ((u64)src[7] << 56);
}

static inline void ml_kem_sha3_store64_le(u8 *dst, u64 x)
{
	dst[0] = (u8)(x);
	dst[1] = (u8)(x >>  8);
	dst[2] = (u8)(x >> 16);
	dst[3] = (u8)(x >> 24);
	dst[4] = (u8)(x >> 32);
	dst[5] = (u8)(x >> 40);
	dst[6] = (u8)(x >> 48);
	dst[7] = (u8)(x >> 56);
}

static void ml_kem_sha3_init(struct ml_kem_sha3_ctx *ctx, size_t rate)
{
	ml_kem_memzero(ctx, sizeof(*ctx));
	ctx->rate = rate;
}

static void ml_kem_sha3_absorb(struct ml_kem_sha3_ctx *ctx, const u8 *in, size_t inlen)
{
	size_t i;
	const size_t rate = ctx->rate;

	/* Full rate blocks. Rare for current ML-KEM SHA3 calls, but correct. */
	while (inlen >= rate) {
		for (i = 0; i < rate / 8; i++)
			ctx->st[i] ^= ml_kem_sha3_load64_le(in + 8 * i);

		keccak_f1600_ct(ctx->st);
		in += rate;
		inlen -= rate;
	}

	/* Remaining partial block. First consume full lanes. */
	for (i = 0; i < inlen / 8; i++)
		ctx->st[i] ^= ml_kem_sha3_load64_le(in + 8 * i);

	ctx->pos = 8 * i;
	in += ctx->pos;
	inlen -= ctx->pos;

	/* Tail: at most 7 bytes. */
	for (i = 0; i < inlen; i++) {
		const size_t pos = ctx->pos;

		ctx->st[pos >> 3] ^= (u64)in[i] << (8 * (pos & 7U));
		ctx->pos = pos + 1;
	}
}

// Apply SHA3 domain separation (0x06) and final padding
static void ml_kem_sha3_finalize(struct ml_kem_sha3_ctx *ctx, u8 delim)
{
	const size_t pos = ctx->pos;

	ctx->st[pos >> 3] ^= (u64)delim << (8 * (pos & 7U));
	ctx->st[(ctx->rate - 1) >> 3] ^= (u64)0x80 << (8 * ((ctx->rate - 1) & 7U));

	keccak_f1600_ct(ctx->st);
	ctx->pos = 0;
}

static void ml_kem_sha3_squeeze(struct ml_kem_sha3_ctx *ctx, u8 *out, size_t outlen)
{
	while (outlen > 0) {
		if (ctx->pos == ctx->rate) {
			keccak_f1600_ct(ctx->st);
			ctx->pos = 0;
		}

		if ((ctx->pos & 7U) == 0 && outlen >= 8 && ctx->pos + 8 <= ctx->rate) {
			ml_kem_sha3_store64_le(out, ctx->st[ctx->pos >> 3]);
			ctx->pos += 8;
			out += 8;
			outlen -= 8;
			continue;
		}

		*out++ = (u8)(ctx->st[ctx->pos >> 3] >> (8 * (ctx->pos & 7U)));
		ctx->pos++;
		outlen--;
	}
}

// SHA3-256: rate = 136 bytes, output = 32 bytes
void ml_kem_sha3_256(u8 out[32], const u8 *in, size_t inlen)
{
	struct ml_kem_sha3_ctx ctx;

	ml_kem_sha3_init(&ctx, 136);
	ml_kem_sha3_absorb(&ctx, in, inlen);
	ml_kem_sha3_finalize(&ctx, 0x06);
	ml_kem_sha3_squeeze(&ctx, out, 32);

	ml_kem_memzero(&ctx, sizeof(ctx));
}

// SHA3-512: rate = 72 bytes, output = 64 bytes
void ml_kem_sha3_512(u8 out[64], const u8 *in, size_t inlen)
{
	struct ml_kem_sha3_ctx ctx;

	ml_kem_sha3_init(&ctx, 72);
	ml_kem_sha3_absorb(&ctx, in, inlen);
	ml_kem_sha3_finalize(&ctx, 0x06);
	ml_kem_sha3_squeeze(&ctx, out, 64);

	ml_kem_memzero(&ctx, sizeof(ctx));
}


