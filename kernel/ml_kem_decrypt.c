// SPDX-License-Identifier: GPL-2.0 OR MIT
// Copyright (c) 2026 K.S.Zavertailo

// File #4: Decryption (decrypt) — part of ML-KEM decapsulation

#include <linux/slab.h>
#include "ml_kem_core_header.h"

// Cross-module function declarations
void ml_kem_wipe_decrypt(struct ml_kem_decrypt_ctx *ctx_decry);
void ml_kem_decrypt(struct ml_kem_decrypt_ctx *ctx_decry, u8 *ciphertext);

// Internal (static) helpers
static void ml_kem_decrypt_get_poly(struct ml_kem_decrypt_ctx *ctx_decry);
static void ml_kem_decrypt_get_seed_m(struct ml_kem_decrypt_ctx *ctx_decry);
static inline u8 ml_kem_decode1_bit(u16 w);
static inline u16 ml_kem_decompress_one_coeff(u16 y, u8 d_u);
static void ml_kem_decompress_one_poly(u16 *poly, u8 *compress_poly, const u8 d);
static void ml_kem_decompress(struct ml_kem_decrypt_ctx *ctx);

// Secure wipe of decryption context
void ml_kem_wipe_decrypt(struct ml_kem_decrypt_ctx *ctx_decry)
{
	// Validate input pointer
	if(!ctx_decry) { return; }

	// Zeroize polynomial buffers (u, v and temporary poly share the same allocation)
	if(ctx_decry->u) { memzero_explicit(ctx_decry->u, sizeof(u16) * (ctx_decry->ctx->k + 2) * ML_KEM_N); }
	
	// Zeroize stored ciphertext
	if(ctx_decry->ciphertext) { memzero_explicit(ctx_decry->ciphertext, ctx_decry->ciphertext_len); }
	
	// Zeroize recovered message seed (m)
	memzero_explicit(ctx_decry->m, 32);
}

// Main decryption routine (part of global decapsulation, paired with encapsulation)
void ml_kem_decrypt(struct ml_kem_decrypt_ctx *ctx_decry, u8 *ciphertext)
{
	// Copy input ciphertext into internal buffer
	memcpy(ctx_decry->ciphertext, ciphertext, ctx_decry->ciphertext_len);
	
	// Decompress ciphertext into polynomial vectors (u, v)
	ml_kem_decompress(ctx_decry);
	
	// Compute resulting polynomial: v - <u, s>
	ml_kem_decrypt_get_poly(ctx_decry);
	
	// Extract final message seed (m) from resulting polynomial
	ml_kem_decrypt_get_seed_m(ctx_decry);
}
	
// Compute resulting polynomial from ML-KEM decryption formula
// Result: poly = v - sum(u_i * s_i)
static void ml_kem_decrypt_get_poly(struct ml_kem_decrypt_ctx *ctx_decry)
{
	// Clear temporary buffer used for accumulation
	memzero_explicit(ctx_decry->poly, sizeof(u16) * ML_KEM_N);
	
	// Compute inner product <u, s> in NTT domain
	for(size_t i = 0; i < ctx_decry->ctx->k; i++)
	{
		// Transform current u polynomial to NTT domain
		ml_kem_ntt_fips203(ctx_decry->u + i * ML_KEM_N);
		
		// Point-wise multiply with corresponding secret key polynomial s_i
		// Result is written back into u buffer (no longer needed afterward)
		ml_kem_multiply(ctx_decry->u + i * ML_KEM_N, ctx_decry->u + i * ML_KEM_N, ctx_decry->ctx->secret + i * ML_KEM_N);
		
		// Accumulate into result polynomial (inner product of vectors)
		ml_kem_add(ctx_decry->poly, ctx_decry->poly, ctx_decry->u + i * ML_KEM_N);
	}
	
	// Convert accumulated result back to coefficient domain
	ml_kem_intt_fips203(ctx_decry->poly);
	
	// Final step: compute v - <u, s> coefficient-wise modulo q
	for(int i = 0; i < ML_KEM_N; i++)
	{
		ctx_decry->poly[i] = ml_kem_sub_mod(ctx_decry->v[i], ctx_decry->poly[i]);
	}
	// ctx_decry->poly now contains the decrypted polynomial
}

// Extract final 32-byte message seed (m) from decrypted polynomial
static void ml_kem_decrypt_get_seed_m(struct ml_kem_decrypt_ctx *ctx_decry)
{
	// Clear output buffer
	memzero_explicit(ctx_decry->m, 32);

	// Each coefficient encodes 1 bit → reconstruct 256-bit message
	for (int i = 0; i < 256; i++) 
	{
		u8 bit = ml_kem_decode1_bit(ctx_decry->poly[i]);
		ctx_decry->m[i >> 3] |= bit << (i & 7);
	}
}
	
// Extract a single bit from polynomial coefficient
// Thresholds explanation (ML-KEM modulus q = 3329):
//   833  ≈ q / 4
//   2496 ≈ 3q / 4
// Bit is interpreted as:
//   1 → if coefficient is in central region
//   0 → if coefficient is near 0 or near q
// Note:
//   This implementation relies on arithmetic to avoid branches,
//   but constant-time behavior depends on compiler optimizations.
//   May require future hardening (e.g., via assembly or verified CT pattern).
static inline u8 ml_kem_decode1_bit(u16 w)
{
    u32 lo = (u32)w - 833u;
    u32 hi = 2496u - (u32)w;

    u32 overflow_lo = lo >> 31;     // 1 if w < 833  (borrow occurred)
    u32 overflow_hi = hi >> 31;     // 1 if w > 2496 (borrow occurred)

    u32 out_of_range = overflow_lo | overflow_hi;
    return (u8)(1u & ~out_of_range);
}

// Decompression formula for a single coefficient
// Maps d-bit compressed value back into Z_q domain
static inline u16 ml_kem_decompress_one_coeff(u16 y, u8 d_u)
{
    return (y * ML_KEM_Q + (1U << (d_u - 1))) >> d_u;
}

// Decompress a single polynomial from packed bitstream
// Input:
//   compress_poly - packed coefficients (bitstream)
//   d             - number of bits per coefficient
// Output:
//   poly          - decompressed polynomial in Z_q
// Implementation notes:
//   - Uses a bit-buffer to extract d-bit values
//   - Ensures no bit loss across byte boundaries
//   - Mask is preselected for valid d values (4,5,10,11)
static void ml_kem_decompress_one_poly(u16 *poly, u8 *compress_poly, const u8 d)
{
	// Number of bits in one byte
	const u8 bits_in_byte = 8;
	// Bit buffer for streaming extraction
	u32 buffer = 0;
	// Number of valid bits currently in buffer
	u8 number_bits_buff = 0;
	
	// Counters for output coefficients and input bytes
	int poly_counter = 0;
	int bytes_counter = 0;

	// Bitmask for extracting d-bit values (prevalidated set of d)
	u16 mask;
	switch (d)
	{
		case 4:  mask = 0x000F; break;
		case 5:  mask = 0x001F; break;
		case 10: mask = 0x03FF; break;
		case 11: mask = 0x07FF; break;
	}

	// Extract coefficients one by one
	while (poly_counter < ML_KEM_N)
	{
		// Fill buffer until we have enough bits
		while (number_bits_buff < d)
		{
			buffer |= (u32)compress_poly[bytes_counter] << number_bits_buff;
			bytes_counter++;
			number_bits_buff += bits_in_byte;
		}

		// Extract one d-bit coefficient 
		poly[poly_counter] = (u16)buffer & mask;
		poly[poly_counter] =
			ml_kem_decompress_one_coeff(poly[poly_counter], d);
		poly_counter++;

		// Shift buffer to discard used bits 
		buffer >>= d;
		number_bits_buff -= d;
	}
}

// Main decompression routine for ciphertext
// Reconstructs:
//   - vector u (k polynomials)
//   - polynomial v
// Layout in ciphertext:
//   [ u_0 | u_1 | ... | u_{k-1} | v ]
// Compression parameters depend on security level
static void ml_kem_decompress(struct ml_kem_decrypt_ctx *ctx_decry)
{
	// Select compression parameters based on security level
	u8 d_u, d_v;
	if(ctx_decry->ctx->k == ML_KEM_1024)
	{
		d_u = 11;
		d_v = 5;
	}else
	{
		d_u = 10;
		d_v = 4;
	}
	
	// Number of compressed bytes per polynomial in u
	int bytes_conter_u = ML_KEM_N * d_u / 8;
	
	// Sequentially decompress u polynomials
	size_t poss = 0;
	size_t i = 0;
	while(i < ctx_decry->ctx->k && poss < ctx_decry->ciphertext_len)
	{
		ml_kem_decompress_one_poly(ctx_decry->u + i * ML_KEM_N, ctx_decry->ciphertext + poss, d_u);
		poss += bytes_conter_u;
		i++;
	}
	
	// Decompress single polynomial v (no loop needed)
	ml_kem_decompress_one_poly(ctx_decry->v, ctx_decry->ciphertext + poss, d_v);
}
	

	
	
	
	
	
	
	
	
	
	
