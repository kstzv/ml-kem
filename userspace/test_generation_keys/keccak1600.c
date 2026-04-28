// SPDX-License-Identifier: GPL-2.0 OR MIT
// Copyright (c) 2026 K.S.Zavertailo

// File №9 - keccak_f1600_ct.c implementation
#include "ml_kem_core_header.h"

#define KECCAKF_ROUNDS 24

// Forward declaration of the Keccak-f[1600] permutation function
void keccak_f1600_ct(u64 state[25]);

// 64-bit left rotation
static inline u64 rotl64(u64 x, unsigned int y)
{
	return (x << y) | (x >> (64 - y));
}

// Round constants
static const u64 keccakf_rndc[KECCAKF_ROUNDS] = {
	0x0000000000000001ULL, 0x0000000000008082ULL,
	0x800000000000808aULL, 0x8000000080008000ULL,
	0x000000000000808bULL, 0x0000000080000001ULL,
	0x8000000080008081ULL, 0x8000000000008009ULL,
	0x000000000000008aULL, 0x0000000000000088ULL,
	0x0000000080008009ULL, 0x000000008000000aULL,
	0x000000008000808bULL, 0x800000000000008bULL,
	0x8000000000008089ULL, 0x8000000000008003ULL,
	0x8000000000008002ULL, 0x8000000000000080ULL,
	0x000000000000800aULL, 0x800000008000000aULL,
	0x8000000080008081ULL, 0x8000000000008080ULL,
	0x0000000080000001ULL, 0x8000000080008008ULL
};

// Rotation offsets for the Rho step
static const unsigned int keccakf_rotc[24] = {
	1,  3,  6, 10, 15, 21,
	28, 36, 45, 55,  2, 14,
	27, 41, 56,  8, 25, 43,
	62, 18, 39, 61, 20, 44
};

// Lane permutation indices for the Pi step
static const unsigned int keccakf_piln[24] = {
	10, 7, 11, 17, 18, 3,
	5, 16, 8, 21, 24, 4,
	15, 23, 19, 13, 12, 2,
	20, 14, 22, 9,  6,  1
};


 // keccak_f1600_ct - Keccak-f[1600] permutation (24 rounds)
 // @state: array of 25 64-bit lanes (200 bytes), processed in-place
 // Properties:
 //  - no data-dependent branching
 //  - no secret-dependent memory access or indexing
 //  - uses only XOR, AND, NOT, OR, rotations, and fixed-bound loops
 //
 // Important:
 //  - No byte-order (endianness) handling is done here.
 //  - Little-endian conversion must be handled in absorb/squeeze (SHAKE/SHA3 layer).
void keccak_f1600_ct(u64 state[25])
{
	int round;
	int i, y;
	u64 bc[5];
	u64 t;

	for (round = 0; round < KECCAKF_ROUNDS; round++) {
		// θ (Theta) step
		bc[0] = state[0] ^ state[5] ^ state[10] ^ state[15] ^ state[20];
		bc[1] = state[1] ^ state[6] ^ state[11] ^ state[16] ^ state[21];
		bc[2] = state[2] ^ state[7] ^ state[12] ^ state[17] ^ state[22];
		bc[3] = state[3] ^ state[8] ^ state[13] ^ state[18] ^ state[23];
		bc[4] = state[4] ^ state[9] ^ state[14] ^ state[19] ^ state[24];

		t = bc[4] ^ rotl64(bc[1], 1);
		state[0]  ^= t;
		state[5]  ^= t;
		state[10] ^= t;
		state[15] ^= t;
		state[20] ^= t;

		t = bc[0] ^ rotl64(bc[2], 1);
		state[1]  ^= t;
		state[6]  ^= t;
		state[11] ^= t;
		state[16] ^= t;
		state[21] ^= t;

		t = bc[1] ^ rotl64(bc[3], 1);
		state[2]  ^= t;
		state[7]  ^= t;
		state[12] ^= t;
		state[17] ^= t;
		state[22] ^= t;

		t = bc[2] ^ rotl64(bc[4], 1);
		state[3]  ^= t;
		state[8]  ^= t;
		state[13] ^= t;
		state[18] ^= t;
		state[23] ^= t;

		t = bc[3] ^ rotl64(bc[0], 1);
		state[4]  ^= t;
		state[9]  ^= t;
		state[14] ^= t;
		state[19] ^= t;
		state[24] ^= t;

		// ρ (Rho) + π (Pi) steps
		t = state[1];
		for (i = 0; i < 24; i++) {
			unsigned int j = keccakf_piln[i];
			u64 tmp = state[j];

			state[j] = rotl64(t, keccakf_rotc[i]);
			t = tmp;
		}

		// χ (Chi) step
		for (y = 0; y < 25; y += 5) {
			u64 a0 = state[y + 0];
			u64 a1 = state[y + 1];
			u64 a2 = state[y + 2];
			u64 a3 = state[y + 3];
			u64 a4 = state[y + 4];

			state[y + 0] = a0 ^ ((~a1) & a2);
			state[y + 1] = a1 ^ ((~a2) & a3);
			state[y + 2] = a2 ^ ((~a3) & a4);
			state[y + 3] = a3 ^ ((~a4) & a0);
			state[y + 4] = a4 ^ ((~a0) & a1);
		}

		// ι (Iota) step
		state[0] ^= keccakf_rndc[round];
	}
}

