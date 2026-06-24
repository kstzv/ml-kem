// SPDX-License-Identifier: GPL-2.0 OR MIT
// Copyright (c) 2026 K.S.Zavertailo

// File #8 — implementation of SHAKE128 / SHAKE256 wrappers
//
// This file implements the sponge construction on top of Keccak-f[1600]
// and is used in ML-KEM for:
//  - noise generation
//  - matrix A expansion
//  - secret vector derivation
//
// IMPORTANT:
//  - the code contains no secret-dependent branching
//  - all counters and indices are public
//  - no division or modulo operations on secret data
//  - fully constant-time from a cryptographic perspective

// SPDX-License-Identifier: GPL-2.0 OR MIT
// Copyright (c) 2026 K.S.Zavertailo

// File #8 — implementation of SHAKE128 / SHAKE256 wrappers
//
// Optimized one-shot sponge wrappers for ML-KEM.
// Main optimization vs the previous version:
//  - absorb full 64-bit little-endian lanes instead of byte-by-byte loops
//  - squeeze full 64-bit lanes instead of byte-by-byte loops
//  - keep the same Keccak-f[1600], domain separation and wipe behavior

#include <string.h>
#include "ml_kem_core_header.h"

struct ml_kem_sponge {
	u64 st[25];
	size_t rate;
	size_t pos;
	u8 delim;
	bool squeezing;
};

void ml_kem_shake128(u8 *out, size_t outlen, const u8 *in, size_t inlen);
void ml_kem_shake256(u8 *out, size_t outlen, const u8 *in, size_t inlen);

static inline u64 ml_kem_load64_le(const u8 *src)
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

static inline void ml_kem_store64_le(u8 *dst, u64 x)
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

static void ml_kem_sponge_init(struct ml_kem_sponge *S, size_t rate, u8 delim)
{
	memset(S, 0, sizeof(*S));
	S->rate = rate;
	S->delim = delim;
}

static void ml_kem_sponge_absorb(struct ml_kem_sponge *S, const u8 *in, size_t inlen)
{
	size_t i;
	const size_t rate = S->rate;

	/* Fast path: absorb complete rate blocks as 64-bit little-endian lanes. */
	while (inlen >= rate) {
		for (i = 0; i < rate / 8; i++)
			S->st[i] ^= ml_kem_load64_le(in + 8 * i);

		keccak_f1600_ct(S->st);
		in += rate;
		inlen -= rate;
	}

	/* Remaining partial block. First consume full lanes. */
	for (i = 0; i < inlen / 8; i++)
		S->st[i] ^= ml_kem_load64_le(in + 8 * i);

	S->pos = 8 * i;
	in += S->pos;
	inlen -= S->pos;

	/* Tail: at most 7 bytes. */
	for (i = 0; i < inlen; i++) {
		const size_t pos = S->pos;

		S->st[pos >> 3] ^= (u64)in[i] << (8 * (pos & 7U));
		S->pos = pos + 1;
	}
}

static void ml_kem_sponge_finalize(struct ml_kem_sponge *S)
{
	const size_t pos = S->pos;

	S->st[pos >> 3] ^= (u64)S->delim << (8 * (pos & 7U));
	S->st[(S->rate - 1) >> 3] ^= (u64)0x80 << (8 * ((S->rate - 1) & 7U));

	keccak_f1600_ct(S->st);
	S->pos = 0;
	S->squeezing = true;
}

static void ml_kem_sponge_squeeze(struct ml_kem_sponge *S, u8 *out, size_t outlen)
{
	while (outlen > 0) {
		if (S->pos == S->rate) {
			keccak_f1600_ct(S->st);
			S->pos = 0;
		}

		/* Fast path: output complete aligned 64-bit lanes. */
		if ((S->pos & 7U) == 0 && outlen >= 8 && S->pos + 8 <= S->rate) {
			ml_kem_store64_le(out, S->st[S->pos >> 3]);
			S->pos += 8;
			out += 8;
			outlen -= 8;
			continue;
		}

		*out++ = (u8)(S->st[S->pos >> 3] >> (8 * (S->pos & 7U)));
		S->pos++;
		outlen--;
	}
}

void ml_kem_shake128(u8 *out, size_t outlen, const u8 *in, size_t inlen)
{
	struct ml_kem_sponge S;

	ml_kem_sponge_init(&S, 168, 0x1F);
	ml_kem_sponge_absorb(&S, in, inlen);
	ml_kem_sponge_finalize(&S);
	ml_kem_sponge_squeeze(&S, out, outlen);

	ml_kem_memzero(&S, sizeof(S));
}

void ml_kem_shake256(u8 *out, size_t outlen, const u8 *in, size_t inlen)
{
	struct ml_kem_sponge S;

	ml_kem_sponge_init(&S, 136, 0x1F);
	ml_kem_sponge_absorb(&S, in, inlen);
	ml_kem_sponge_finalize(&S);
	ml_kem_sponge_squeeze(&S, out, outlen);

	ml_kem_memzero(&S, sizeof(S));
}

