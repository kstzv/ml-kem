// SPDX-License-Identifier: GPL-2.0 OR MIT
// Copyright (c) 2026 K.S.Zavertailo

// File #3: ML-KEM encapsulation module

#include <sys/random.h>
#include <stdlib.h>
#include <string.h>
#include "ml_kem_core_header.h"

// External (cross-file) function declarations
struct ml_kem_encaps_ctx *ml_kem_alloc_encaps(u8 *public_key_msg, enum ml_kem_k k);
void ml_kem_wipe_encaps(struct ml_kem_encaps_ctx *ctx);
void ml_kem_destroy_encaps(struct ml_kem_encaps_ctx *ctx);
void ml_kem_encapsulation(struct ml_kem_encaps_ctx *ctx, u8 *msg, u8 *hash_pk, ml_kem_entropy_fn entropy);
void ml_kem_unpack_pk_t_u16(struct ml_kem_encaps_ctx *ctx);

// Internal (file-local) helper functions
static void ml_kem_create_temp_secret_y(struct ml_kem_encaps_ctx *ctx, u8 *seed);
static int  ml_kem_create_u(struct ml_kem_encaps_ctx *ctx, u8 *seed);
static void ml_kem_create_v(struct ml_kem_encaps_ctx *ctx, u8 *seed);
static void ml_kem_compress_ciphertext(struct ml_kem_encaps_ctx *ctx);
static inline u16 ml_kem_compress(u16 x, u8 d);
static void ml_kem_compress_and_pack(u8 *out, const u16 *coeffs, size_t n, u8 d);

// Allocate and initialize encapsulation context.
// This function prepares all buffers required for ML-KEM encapsulation,
// including:
//  - unpacked public key (u16 representation)
//  - temporary secret vector (y)
//  - intermediate polynomials
//  - final ciphertext buffer
// Memory layout is optimized by allocating a single large buffer for
// multiple u16 arrays and splitting it via pointer arithmetic.
// Parameters:
//   public_key_msg - serialized public key (byte format, per FIPS 203)
//   k              - security level (ML_KEM_512 / 768 / 1024)
// Returns:
//   Pointer to initialized context on success, NULL on failure.
struct ml_kem_encaps_ctx *ml_kem_alloc_encaps(u8 *public_key_msg, enum ml_kem_k k)
{
	// Validate security level
	if (ML_KEM_512 > k || ML_KEM_1024 < k) { return NULL; }

	// Allocate main context structure
	struct ml_kem_encaps_ctx *ctx;
	ctx = malloc(sizeof(struct ml_kem_encaps_ctx));
	if (!ctx) { return NULL; }
	ml_kem_memzero(ctx, sizeof(struct ml_kem_encaps_ctx));

	// Set parameters depending on security level
	if (k == ML_KEM_512)
	{
		ctx->k = k;
		ctx->public_key_msg_len = RES_PUBL_PART_LVL_512;
		ctx->ciphertext_len     = LEN_CIPHERTEXT_512;
	}
	else if (k == ML_KEM_768)
	{
		ctx->k = k;
		ctx->public_key_msg_len = RES_PUBL_PART_LVL_768;
		ctx->ciphertext_len     = LEN_CIPHERTEXT_768;
	}
	else if (k == ML_KEM_1024)
	{
		ctx->k = k;
		ctx->public_key_msg_len = RES_PUBL_PART_LVL_1024;
		ctx->ciphertext_len     = LEN_CIPHERTEXT_1024;
	}

	 // Allocate contiguous buffer for all u16 polynomial data:
	 // Layout:
	 //   [u | v | public_key | y | poly]
	ctx->u = malloc(sizeof(u16) * ML_KEM_N * (3 * ctx->k + 2));
	if (!ctx->u) { goto first_error_exit; }
	ml_kem_memzero(ctx->u, sizeof(u16) * ML_KEM_N * (3 * ctx->k + 2));
	ctx->v          = ctx->u + ML_KEM_N * ctx->k;
	ctx->public_key = ctx->v + ML_KEM_N;
	ctx->y          = ctx->public_key + ML_KEM_N * ctx->k;
	ctx->poly       = ctx->y + ML_KEM_N * ctx->k;

	// Allocate buffer for final ciphertext
	ctx->ciphertext = malloc(ctx->ciphertext_len);
	if (!ctx->ciphertext) { goto second_error_exit; }
	ml_kem_memzero(ctx->ciphertext, ctx->ciphertext_len);

	 // Allocate buffer for serialized public key + extra space
	 // For XOF-generated raw bytes (used during matrix expansion)
	ctx->public_key_msg = malloc(ctx->public_key_msg_len + ML_KEM_MATRIX_XOF_BYTES);
	if (!ctx->public_key_msg) { goto third_error_exit; }
	ml_kem_memzero(ctx->public_key_msg, ctx->public_key_msg_len + ML_KEM_MATRIX_XOF_BYTES);

	// Assign raw_bytes buffer
	ctx->raw_bytes = ctx->public_key_msg + ctx->public_key_msg_len;

	// Copy provided public key if present
	if (public_key_msg != NULL)
	{
		memcpy(ctx->public_key_msg, public_key_msg, ctx->public_key_msg_len);
	}

	return ctx;

	// Error handling
	third_error_exit:
		free(ctx->ciphertext);
	second_error_exit:
		free(ctx->u);
	first_error_exit:
		free(ctx);
	return NULL;
}

// Wipe (zeroize) sensitive data stored in encapsulation context
void ml_kem_wipe_encaps(struct ml_kem_encaps_ctx *ctx)
{
	// Validate input pointer
	if(!ctx) { return; }
	
	// Zeroize ciphertext buffer if allocated
	if(ctx->ciphertext) { ml_kem_memzero(ctx->ciphertext, ctx->ciphertext_len); }
	
	// Zeroize XOF raw bytes buffer (used for matrix generation)
	// Note: public_key_msg itself is not wiped here as it is non-secret
	if(ctx->public_key_msg)
	{
		ml_kem_memzero(ctx->raw_bytes, ML_KEM_MATRIX_XOF_BYTES);
	}
	
	// Zeroize main polynomial buffer containing:
	// u, v, unpacked public key, temporary secret y, and working polynomial
	if(ctx->u)
	{
		ml_kem_memzero(ctx->u, sizeof(u16) * ML_KEM_N * (2 * ctx->k + 2));
	}
	
	// Zeroize internal seed and shared secret buffers
	ml_kem_memzero(ctx->seed_rho, ML_KEM_SEED_BYTES);
	ml_kem_memzero(ctx->seed_m,   ML_KEM_SEED_BYTES);
	ml_kem_memzero(ctx->K_bar,    ML_KEM_SEED_BYTES);
}

// Destroy encapsulation context and free all associated memory
void ml_kem_destroy_encaps(struct ml_kem_encaps_ctx *ctx)
{
	// Validate input pointer
	if(!ctx) { return; }
	
	// Free ciphertext buffer
	if(ctx->ciphertext) { free(ctx->ciphertext); }
	
	// Free serialized public key buffer (also contains raw_bytes region)
	if(ctx->public_key_msg)
	{
		free(ctx->public_key_msg);
		ctx->public_key_msg = NULL;
		ctx->raw_bytes = NULL;
	}
	
	// Free main polynomial buffer and reset derived pointers
	if(ctx->u)
	{
		free(ctx->u);
		ctx->u = NULL;
		ctx->poly = NULL;
		ctx->v = NULL;
		ctx->public_key = NULL;
		ctx->y = NULL;
	}
	
	// Free context structure itself
	free(ctx);
}
	
// Main ML-KEM encapsulation routine.
// Usage model:
//  - Client side: msg == NULL and hash_pk == NULL → generate fresh randomness
//  - Server side (during decapsulation): both msg and hash_pk must be provided
//  - entropy parameter - callback used to obtain cryptographically secure random bytes. NULL if using the operating system's random data source
// NOTE: msg and hash_pk must either both be valid or both be NULL.
void ml_kem_encapsulation(struct ml_kem_encaps_ctx *ctx, u8 *msg, u8 *hash_pk, ml_kem_entropy_fn entropy)
{
	// Validate consistency of (msg, hash_pk) pair:
	// either both provided (decapsulation flow) or both NULL (encapsulation flow)
	if((msg && !hash_pk) || (!msg && hash_pk)) { return; }
	
	// Buffers:
	// first_seed_encaps = (m || H(pk))
	// result_seeds      = (K_bar || r)
	u8 first_seed_encaps[ML_KEM_SEED_BYTES * 2];
	u8 result_seeds[ML_KEM_SEED_BYTES * 2];
	
	/* In the test versions for encaps generations seeds not use
	// Branch depends only on caller role (client vs server),
	// not on secret data → does not violate constant-time requirements
	if(msg && hash_pk)
	{
		// Server-side path (during decapsulation):
		// reuse provided m and H(pk)
		memcpy(ctx->seed_m, msg, ML_KEM_SEED_BYTES);
		memcpy(first_seed_encaps, msg, ML_KEM_SEED_BYTES);
		memcpy(first_seed_encaps + ML_KEM_SEED_BYTES, hash_pk, ML_KEM_SEED_BYTES);
	}
	else
	{
		// Client-side path:
		// generate fresh random m and compute H(pk)
		if(entropy == NULL)
		{
			if(ml_kem_entropy(first_seed_encaps, ML_KEM_SEED_BYTES) != 0) { return; }
		}else
		{
			if(entropy(first_seed_encaps, ML_KEM_SEED_BYTES) != 0) { return; }
		}

		memcpy(ctx->seed_m, first_seed_encaps, ML_KEM_SEED_BYTES);

		// Compute H(pk)
		ml_kem_sha3_256(first_seed_encaps + ML_KEM_SEED_BYTES, ctx->public_key_msg, ctx->public_key_msg_len);
	}
	*/
	
	// Copying seeds in the test version - from a global array into which seeds are read from a JSON file
	memcpy(ctx->seed_m, mass_m, ML_KEM_SEED_BYTES);
	memcpy(first_seed_encaps, mass_m, ML_KEM_SEED_BYTES);
	// Public key hashing up to 32 bytes of the second half of the raw data for the final hash in the test version
	ml_kem_sha3_256(first_seed_encaps + ML_KEM_SEED_BYTES, ctx->public_key_msg, ctx->public_key_msg_len);
		
	// Derive (K_bar || r) = SHA3-512(m || H(pk))
    ml_kem_sha3_512(result_seeds, first_seed_encaps, ML_KEM_SEED_BYTES * 2);

    // Clear intermediate buffer
    ml_kem_memzero(first_seed_encaps, sizeof(first_seed_encaps));
  
    // Extract shared secret K_bar and randomness r
    memcpy(ctx->K_bar, result_seeds, ML_KEM_SEED_BYTES); // shared secret
    u8 *r = result_seeds + ML_KEM_SEED_BYTES;            // seed for y, e1, e2
    
    // Unpack public key t into u16 polynomial representation
    if(!msg && !hash_pk) { ml_kem_unpack_pk_t_u16(ctx); }
    
    // Extract matrix seed rho from serialized public key
    memcpy(ctx->seed_rho, ctx->public_key_msg + ctx->public_key_msg_len - ML_KEM_SEED_BYTES, ML_KEM_SEED_BYTES);
    
    // Generate ephemeral secret vector y in NTT domain
    ml_kem_create_temp_secret_y(ctx, r);
    
    // Compute u = A * y + e1
    ml_kem_create_u(ctx, r);
    
    // Compute v = t * y + e2 + m
    ml_kem_create_v(ctx, r);
    
    // Compress and serialize ciphertext (u, v)
    ml_kem_compress_ciphertext(ctx);
    
    // Clear sensitive temporary buffer
    ml_kem_memzero(result_seeds, sizeof(result_seeds));
}
    
    
// Unpack public key coefficients from byte-packed (12-bit) format into u16 representation
void ml_kem_unpack_pk_t_u16(struct ml_kem_encaps_ctx *ctx)
{
	size_t i = 0; // Coefficient index
	size_t j = 0; // Byte index in serialized public key

	// Process packed data:
	// each 3 bytes (24 bits) contain 2 coefficients (each 12 bits)
	// Total number of coefficients is always even (512 / 768 / 1024), so no overflow risk
	while(i < ctx->k * ML_KEM_N && j < ctx->public_key_msg_len - ML_KEM_SEED_BYTES)
	{
		// Load lower 8 bits of the first coefficient
		// Upper bits are zero after cast to u16 → no mask required
		ctx->public_key[i] = (u16)(ctx->public_key_msg[j]);
		j++; // Move to next byte
		
		// Add upper 4 bits of the first coefficient:
		// mask lower 4 bits, shift left by 8, then combine
		ctx->public_key[i] |= (u16)(ctx->public_key_msg[j] & 0x0F) << 8;
		i++; // Move to next coefficient
		
		// Extract lower 4 bits of the second coefficient:
		// shift right by 4 → result is 0000 bbbb, cast to u16 preserves it
		ctx->public_key[i] = (u16)(ctx->public_key_msg[j] >> 4);
		j++; // Move to next byte
		
		// Add upper 8 bits of the second coefficient:
		// shift left by 4 and combine with previously extracted lower 4 bits
		ctx->public_key[i] |= (u16)(ctx->public_key_msg[j]) << 4;
		j++; // Advance to next byte
		i++; // Advance to next coefficient
	}
}

// Generate ephemeral secret vector y (in NTT domain) from seed
static void ml_kem_create_temp_secret_y(struct ml_kem_encaps_ctx *ctx, u8 *seed)
{
	// Prepare internal seed: (seed || counter)
	u8 inside_seed[ML_KEM_SEED_BYTES + 1];
	memcpy(inside_seed, seed, ML_KEM_SEED_BYTES);
	inside_seed[32] = 0;
	
	// Select CBD parameter eta and required XOF output size
	// depending on security level
	u8 eta;
	size_t number_bytes;

	if(ctx->k == ML_KEM_512) 
	{ 
		eta = ML_KEM_CBD_ETA_3; 
		number_bytes = ML_KEM_VECTOR_XOF_BYTES_L2;
	}
	else
	{ 
		eta = ML_KEM_CBD_ETA_2; 
		number_bytes = ML_KEM_VECTOR_XOF_BYTES_L34;
	}
	
	// Generate k polynomials of the vector y
	for(u8 i = 0; i < ctx->k; i++)
	{
		// Append counter to seed for domain separation
		inside_seed[32] = i;

		// Expand seed using SHAKE256 to obtain raw bytes
		ml_kem_shake256(ctx->raw_bytes, number_bytes, inside_seed, ML_KEM_SEED_BYTES + 1);

		// Convert raw bytes into polynomial using CBD
		ml_kem_gen_polynomial_for_cbd(ctx->y + i * ML_KEM_N, ctx->raw_bytes, eta);

		// Transform polynomial to NTT domain
		ml_kem_ntt_fips203(ctx->y + i * ML_KEM_N);
	}
}
		
// Compute vector u during encapsulation:
// u = A * y + e1
static int ml_kem_create_u(struct ml_kem_encaps_ctx *ctx, u8 *seed)
{
	// Prepare matrix seed (rho || i || j)
	u8 local_seed_matrix[ML_KEM_SEED_BYTES + 2];
	memcpy(local_seed_matrix, ctx->seed_rho, ML_KEM_SEED_BYTES);
	local_seed_matrix[32] = 0;
	local_seed_matrix[33] = 0;
    
    // Noise counter (starts after secret vector y indices)
	u8 counter_noise = ctx->k;

	// Prepare noise seed (r || counter)
	u8 local_seed_noise[ML_KEM_SEED_BYTES + 1];
	memcpy(local_seed_noise, seed, ML_KEM_SEED_BYTES);
	local_seed_noise[32] = 0;
    
    // Iterate over rows of matrix A
    // Matrix is generated on-the-fly from seed using rejection sampling (FIPS 203, Algorithm 7)
    // Polynomials are produced directly in NTT domain
    for(size_t i = 0; i < ctx->k; i++)
    {
		for(size_t j = 0; j < ctx->k; j++)
		{
			// Set domain separation bytes (i, j)
			local_seed_matrix[32] = (u8)i;
	        local_seed_matrix[33] = (u8)j;
	        
	        // Expand seed using SHAKE128 to obtain raw bytes for matrix polynomial
			ml_kem_shake128(ctx->raw_bytes, ML_KEM_MATRIX_XOF_BYTES, local_seed_matrix, ML_KEM_SEED_BYTES + 2);
			
			// Generate polynomial A[i][j] using rejection sampling
			// Return error if not enough valid coefficients were produced
			int ret = ml_kem_gen_polynomial_for_matrix(ctx->poly, ctx->raw_bytes, ML_KEM_MATRIX_XOF_BYTES);
			if(ret < 0) 
			{
				 ml_kem_memzero(ctx->poly, sizeof(u16) * ML_KEM_N);
	             ml_kem_memzero(local_seed_noise, sizeof(local_seed_noise));
	             ml_kem_memzero(local_seed_matrix, sizeof(local_seed_matrix));
				 return ret; 
			}
			
			// Multiply A[i][j] * y[j] (both in NTT domain)
			ml_kem_multiply(ctx->poly, ctx->poly, ctx->y + j * ML_KEM_N);
			
			// Accumulate into u[i]:
			// u[i] += A[i][j] * y[j]  (row-vector dot product)
			ml_kem_add(ctx->u + i * ML_KEM_N, ctx->u + i * ML_KEM_N, ctx->poly);
			
			// Clear temporary polynomial buffer
			ml_kem_memzero(ctx->poly, sizeof(u16) * ML_KEM_N);
		}
		
		// Convert accumulated result from NTT domain to coefficient domain
		ml_kem_intt_fips203(ctx->u + i * ML_KEM_N);
		
		// Generate noise polynomial e1[i] from seed
		local_seed_noise[32] = counter_noise;
		ml_kem_shake256(ctx->raw_bytes, ML_KEM_VECTOR_XOF_BYTES_L34, local_seed_noise, ML_KEM_SEED_BYTES + 1);
		
		// Sample noise polynomial using CBD (eta = 2 per standard)
		ml_kem_gen_polynomial_for_cbd(ctx->poly, ctx->raw_bytes, ML_KEM_CBD_ETA_2);
		
		// Add noise: u[i] = u[i] + e1[i]
		ml_kem_add(ctx->u + i * ML_KEM_N, ctx->u + i * ML_KEM_N, ctx->poly);
		
		// Clear temporary polynomial and increment noise counter
		ml_kem_memzero(ctx->poly, sizeof(u16) * ML_KEM_N);
		counter_noise++;
	}
	
	// Clear all sensitive temporary data and return success
	ml_kem_memzero(ctx->poly, sizeof(u16) * ML_KEM_N);
	ml_kem_memzero(local_seed_noise, sizeof(local_seed_noise));
	ml_kem_memzero(local_seed_matrix, sizeof(local_seed_matrix));
	return 0;
}

// Compute value v during encapsulation:
// v = t * y + e2 + m
static void ml_kem_create_v(struct ml_kem_encaps_ctx *ctx, u8 *seed)
{
	for(size_t i = 0; i < ctx->k; i++)
	{
		// Multiply corresponding public key polynomial t[i] with y[i] (NTT domain)
		ml_kem_multiply(ctx->poly, ctx->public_key + i * ML_KEM_N, ctx->y + i * ML_KEM_N);
		
		// Accumulate dot product:
		// v += t[i] * y[i]
		ml_kem_add(ctx->v, ctx->v, ctx->poly);
		
		// Clear temporary polynomial buffer after each iteration
		ml_kem_memzero(ctx->poly, sizeof(u16) * ML_KEM_N);
	}
	
	// Convert accumulated result from NTT domain to coefficient domain
	ml_kem_intt_fips203(ctx->v);
	
	// Prepare noise seed for e2: (r || counter)
	u8 local_seed_noise[ML_KEM_SEED_BYTES + 1];
	memcpy(local_seed_noise, seed, ML_KEM_SEED_BYTES);
	local_seed_noise[32] = ctx->k * 2;
	
	// Expand seed using SHAKE256 to obtain raw bytes for noise polynomial e2
	ml_kem_shake256(ctx->raw_bytes, ML_KEM_VECTOR_XOF_BYTES_L34, local_seed_noise, ML_KEM_SEED_BYTES + 1);
	
	// Sample noise polynomial e2 using CBD (eta = 2 per standard)
	ml_kem_gen_polynomial_for_cbd(ctx->poly, ctx->raw_bytes, ML_KEM_CBD_ETA_2);
	
	// Add noise: v = v + e2
	ml_kem_add(ctx->v, ctx->v, ctx->poly);
	
	// Clear temporary polynomial buffer
	ml_kem_memzero(ctx->poly, sizeof(u16) * ML_KEM_N);
	
	// Encode message m (32 bytes) into polynomial form
	u8 local_msg[32];
	memcpy(local_msg, ctx->seed_m, 32);

	int poly_counter = 0;       // coefficient index
	int msg_bytes_counter = 0;  // byte index (total 32 bytes)
	u16 temp = 0;               // temporary value

	// Convert each bit of m into polynomial coefficients
	// Each bit maps to a coefficient: 0 → 0, 1 → ML_KEM_MSG_COEFF (e.g., 1665)
	while(msg_bytes_counter < 32)
	{
		for(int i = 0; i < 8; i++)
		{
			// Extract least significant bit
			temp = (u16)(local_msg[msg_bytes_counter] & 0x1);

			// Map bit to coefficient value
			ctx->poly[poly_counter] = temp * (u16)ML_KEM_MSG_COEFF;

			// Shift to process next bit
			local_msg[msg_bytes_counter] >>= 1;

			poly_counter++;
		}
		msg_bytes_counter++;
	}
	
	// Add encoded message polynomial:
	// v = v + m
	ml_kem_add(ctx->v, ctx->v, ctx->poly);
	
	// Clear all temporary buffers containing sensitive data
	ml_kem_memzero(ctx->poly, sizeof(u16) * ML_KEM_N);
	ml_kem_memzero(local_msg, sizeof(local_msg));
	ml_kem_memzero(local_seed_noise, sizeof(local_seed_noise));
}

// Compress and serialize ciphertext components (u, v)
static void ml_kem_compress_ciphertext(struct ml_kem_encaps_ctx *ctx)
{
	u16 d_u, d_v;

	// Select compression parameters depending on security level
	if(ctx->k == ML_KEM_512 || ctx->k == ML_KEM_768)
	{
		d_u = 10;
		d_v = 4;
		
	}else{
		d_u = 11;
		d_v = 5;
	}
	
	size_t pos = 0;

	// Number of bytes per compressed polynomial of u
	size_t step_bytes = d_u * ML_KEM_N / 8;
	
	// Compress and pack each polynomial of vector u
	for(size_t i = 0; i < ctx->k; i++)
	{
		ml_kem_compress_and_pack(ctx->ciphertext + pos, ctx->u + i * ML_KEM_N, ML_KEM_N, d_u);
		pos += step_bytes;
	}
		
	// Compress and pack polynomial v
	ml_kem_compress_and_pack(ctx->ciphertext + pos, ctx->v, ML_KEM_N, d_v);
}
				


// ML-KEM coefficient compression function:
// maps x ∈ [0, q) to d-bit representation
static inline u16 ml_kem_compress(u16 x, u8 d)
{
   // Scale value to d-bit range with rounding
   u32 num = ((u32)x << d) + ML_KEM_Q_HALF;
   
   // Compute approximate division by q using reciprocal multiplication
   u32 q0 = (u32)(((u64)num * ML_KEM_Q_RECIP_48) >> 48);
   
   // Correct rounding if needed
   u32 qp1 = q0 + 1u;
   u32 needs_inc = (u32)((u64)qp1 * ML_KEM_Q <= num);
   u32 q = q0 + needs_inc;
   
   // Reduce to d bits
   return (u16)(q & ((1u << d) - 1u));
}

// Compress and pack polynomial coefficients into ciphertext byte stream.
// out      — output buffer (must be sufficiently large)
// coeffs   — polynomial coefficients (mod q)
// n        — number of coefficients (ML_KEM_N = 256)
// d        — number of bits per compressed coefficient (du or dv)
// Format:
//   - little-endian
//   - tightly packed bitstream (no padding)
//   - compliant with FIPS 203
static void ml_kem_compress_and_pack(u8 *out, const u16 *coeffs, size_t n, u8 d)
{
    u32 acc = 0;      // bit accumulator
    u32 acc_bits = 0; // number of bits currently stored in accumulator
    size_t i;

    for (i = 0; i < n; i++) 
    {
        // 1. Compress single coefficient 
        u16 c = ml_kem_compress(coeffs[i], d);

        // 2. Append d bits to accumulator
        acc |= ((u32)c << acc_bits);
        acc_bits += d;

        // 3. Flush full bytes to output
        while (acc_bits >= 8) 
        {
            *out++ = acc & 0xff;
            acc >>= 8;
            acc_bits -= 8;
        }
    }
     // Per ML-KEM specification:
     // n * d is always a multiple of 8,
     // therefore acc_bits == 0 at the end and no remaining bits need to be written.
}










