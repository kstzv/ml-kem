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

#include <string.h>
#include "ml_kem_core_header.h"

// Keccak sponge structure (used for SHAKE128/256 and SHA3)
struct ml_kem_sponge {
	u64 st[25];    // 1600-bit Keccak state (25 lanes × 64 bits)
	size_t rate;   // Rate in bytes (SHAKE128: 168, SHAKE256: 136)
	size_t pos;    // Current position within rate portion
	u8 delim;      // Domain separation byte (SHAKE: 0x1F, SHA3: 0x06)
	bool squeezing;// Phase flag: false = absorb, true = squeeze
};

// Public SHAKE wrappers used across ML-KEM modules
void ml_kem_shake128(u8 *out, size_t outlen, const u8 *in, size_t inlen);
void ml_kem_shake256(u8 *out, size_t outlen, const u8 *in, size_t inlen);

// Internal sponge construction functions
static void ml_kem_sponge_squeeze(struct ml_kem_sponge *S, u8 *out, size_t outlen);
static void ml_kem_sponge_finalize(struct ml_kem_sponge *S);
static void ml_kem_sponge_absorb(struct ml_kem_sponge *S, const u8 *in, size_t inlen);
static void ml_kem_sponge_init(struct ml_kem_sponge *S, size_t rate, u8 delim);

// -----------------------------------------------------------------------------
// Sponge initialization
// -----------------------------------------------------------------------------
//
// Here we:
//  - zero the entire Keccak state (1600 bits)
//  - set the rate (number of bytes processed per round)
//  - set the delimiter (domain separation for SHAKE)
//  - reset position and squeezing flag
//
static void ml_kem_sponge_init(struct ml_kem_sponge *S, size_t rate, u8 delim)
{
	memset(S, 0, sizeof(*S)); // Fully zero state and metadata

	S->rate = rate;           // Sponge rate:
	                          // 168 bytes — SHAKE128
	                          // 136 bytes — SHAKE256

	S->delim = delim;         // Domain separation byte (0x1F for SHAKE)
	S->pos = 0;               // Current position within rate
	S->squeezing = false;     // Start in absorb mode
}

// -----------------------------------------------------------------------------
// Sponge absorb phase
// -----------------------------------------------------------------------------
//
// This function incrementally absorbs input bytes into the Keccak state.
// Data is XORed byte-by-byte into 64-bit lanes.
//
// Addressing scheme:
//  - pos / 8  -> index of 64-bit lane
//  - pos % 8  -> byte offset within lane
//
// IMPORTANT:
//  - pos is a public counter
//  - indices and shifts do not depend on secret data
//
static void ml_kem_sponge_absorb(struct ml_kem_sponge *S, const u8 *in, size_t inlen)
{
	size_t i;

	// Iterate over all input bytes
	for (i = 0; i < inlen; i++)
	{
		size_t pos = S->pos;

		// pos >> 3 == pos / 8
		// selects the 64-bit lane index
		size_t idx = pos >> 3;

		// (pos & 7) << 3 == (pos % 8) * 8
		// selects byte offset within the lane
		size_t sh  = (pos & 7) << 3;

		// Byte-wise XOR absorption into the state
		S->st[idx] ^= (u64)in[i] << sh;

		// Advance position
		S->pos = pos + 1;

		// If rate is filled — apply Keccak-f[1600]
		if (S->pos == S->rate)
		{
			keccak_f1600_ct(S->st);
			S->pos = 0;
		}
	}
}

// -----------------------------------------------------------------------------
// Sponge finalize phase
// -----------------------------------------------------------------------------
//
// Applies SHAKE padding (pad10*1):
//  - XOR delimiter at current position
//  - XOR 1 into MSB of the last rate byte
//  - perform final Keccak-f[1600]
//
static void ml_kem_sponge_finalize(struct ml_kem_sponge *S)
{
	size_t pos = S->pos;
	size_t idx = pos >> 3;
	size_t sh  = (pos & 7) << 3;

	// Write domain separation byte
	S->st[idx] ^= (u64)S->delim << sh;

	// Apply final padding bit (MSB of last rate byte)
	S->st[(S->rate - 1) >> 3] ^= 1ULL << 63;

	// Final Keccak permutation
	keccak_f1600_ct(S->st);

	// Prepare for squeeze phase
	S->pos = 0;
	S->squeezing = true;
}

// -----------------------------------------------------------------------------
// Sponge squeeze phase
// -----------------------------------------------------------------------------
//
// Extracts bytes from the Keccak state.
// When rate is exhausted — applies Keccak-f[1600] again.
//
static void ml_kem_sponge_squeeze(struct ml_kem_sponge *S, u8 *out, size_t outlen)
{
	size_t i;

	for (i = 0; i < outlen; i++)
	{
		size_t pos = S->pos;
		size_t idx = pos >> 3;
		size_t sh  = (pos & 7) << 3;

		// Extract one byte from the state
		out[i] = (u8)(S->st[idx] >> sh);

		S->pos = pos + 1;

		// If rate is exhausted — apply permutation
		if (S->pos == S->rate)
		{
			keccak_f1600_ct(S->st);
			S->pos = 0;
		}
	}
}

// -----------------------------------------------------------------------------
// SHAKE128 wrapper
// -----------------------------------------------------------------------------
//
// Used for:
//  - matrix A generation
//  - secret vector derivation in ML-KEM
//
void ml_kem_shake128(u8 *out, size_t outlen, const u8 *in, size_t inlen)
{
	struct ml_kem_sponge S;

	ml_kem_sponge_init(&S, 168, 0x1F);
	ml_kem_sponge_absorb(&S, in, inlen);
	ml_kem_sponge_finalize(&S);
	ml_kem_sponge_squeeze(&S, out, outlen);

	// Mandatory state wipe
	ml_kem_memzero(&S, sizeof(S));
}

// -----------------------------------------------------------------------------
// SHAKE256 wrapper
// -----------------------------------------------------------------------------
//
// Used for:
//  - noise and secret generation
//  - higher security requirements
//
void ml_kem_shake256(u8 *out, size_t outlen, const u8 *in, size_t inlen)
{
	struct ml_kem_sponge S;

	ml_kem_sponge_init(&S, 136, 0x1F);
	ml_kem_sponge_absorb(&S, in, inlen);
	ml_kem_sponge_finalize(&S);
	ml_kem_sponge_squeeze(&S, out, outlen);

	ml_kem_memzero(&S, sizeof(S));
}

