// SPDX-License-Identifier: GPL-2.0 OR MIT
// Copyright (c) 2026 K.S.Zavertailo

// File #2: ml_kem_create_keys.c
// Key generation module for ML-KEM (FIPS 203 compliant).
// Responsible for generating secret/public key pair and initializing persistent context

#include <sys/random.h>
#include <stdlib.h>
#include <string.h>
#include "ml_kem_core_header.h"

// External (cross-module) function declarations
int ml_kem_create_ctx_struct(struct ml_kem_temp *temp, struct ml_kem_ctx *ctx);
struct ml_kem_temp *ml_kem_temp_alloc(enum ml_kem_k level);
struct ml_kem_ctx *ml_kem_ctx_alloc(enum ml_kem_k level);
void ml_kem_destroy_temp_struct(struct ml_kem_temp *temp);
void ml_kem_destroy_ctx_struct(struct ml_kem_ctx *ctx);
void ml_kem_gen_polynomial_for_cbd(u16 *poly, const u8 *stream, const u8 eta);
int ml_kem_gen_polynomial_for_matrix(u16 *poly, const u8 *stream, int suma_bytes);

// Secure memory wipe (implementation-defined)
void ml_kem_memzero(void *ptr, size_t len);

// Internal (static) helpers
static int ml_kem_generation_entropy(struct ml_kem_temp *temp);
static void ml_kem_create_vector_poly(struct ml_kem_temp *temp);
static int ml_kem_create_public_key(struct ml_kem_temp *temp);
static void ml_kem_convert_to_bytes_format_and_copy(struct ml_kem_temp *temp, struct ml_kem_ctx *ctx);
static int ml_kem_finally_create_z_and_h_pk(struct ml_kem_ctx *ctx);


// Main key generation routine.
// This function initializes ML-KEM key material by:
// 1. Generating entropy and deriving seeds
// 2. Creating secret key (vector s)
// 3. Generating public key (vector t)
// 4. Serializing public key into byte format
// 5. Computing auxiliary values (z and H(pk))
// Arguments:
//   temp - temporary working structure (must be pre-allocated)
//   ctx  - persistent context (output, must be pre-allocated)
// Returns:
//   0 on success
//   negative error code (e.g. -EINVAL) on failure
int ml_kem_create_ctx_struct(struct ml_kem_temp *temp, struct ml_kem_ctx *ctx)
{
	// Validate temporary structure and its internal buffers
	if(!temp || !temp->poly || !temp->raw_bytes || !temp->secret || !temp->public_key)
	{ return -EINVAL; }
	
	// Validate persistent context and required buffers
	if(!ctx || !ctx->secret || !ctx->public_key_msg) { return -EINVAL; }
	
	// Validate ML-KEM parameters (defensive checks)
	if(temp->eta != ML_KEM_CBD_ETA_3 && temp->eta != ML_KEM_CBD_ETA_2) { return -EINVAL; }
	else if(temp->k != ML_KEM_512 && temp->k != ML_KEM_768 && temp->k != ML_KEM_1024) { return -EINVAL; }
	else if(temp->number_raw_bytes_vectors != ML_KEM_VECTOR_XOF_BYTES_L2 && temp->number_raw_bytes_vectors != ML_KEM_VECTOR_XOF_BYTES_L34) { return -EINVAL; }
	else if(ctx->k != temp->k) { return -EINVAL; }
	else if(ctx->public_key_msg_len != RES_PUBL_PART_LVL_512 && ctx->public_key_msg_len != RES_PUBL_PART_LVL_768 && ctx->public_key_msg_len != RES_PUBL_PART_LVL_1024)
	{ return -EINVAL; }
	
	// Step 1: Generate entropy and derive seed_rho / seed_sigma
	int ret = ml_kem_generation_entropy(temp);
	if(ret != 0) { return ret;}
	
	// Step 2: Generate secret key vector s (CBD sampling in NTT domain)
	ml_kem_create_vector_poly(temp);
	
	// Step 3: Generate public key vector t = A * s + e
	ret = ml_kem_create_public_key(temp);
	if(ret != 0) { return ret;}
	
	// Step 4: Serialize public key and copy required data into persistent context
	ml_kem_convert_to_bytes_format_and_copy(temp, ctx);
	
	// Step 5: Finalize context (generate z and H(pk))
	ret = ml_kem_finally_create_z_and_h_pk(ctx);
	if(ret != 0) { return ret;}
	
	return 0;
}

// Allocate and initialize temporary ML-KEM working structure.
// This structure is used only during key generation and is expected
// to be securely wiped and destroyed after use.
struct ml_kem_temp *ml_kem_temp_alloc(enum ml_kem_k level)
{
	// Allocate base structure
	struct ml_kem_temp *temp;
	temp = malloc(sizeof(struct ml_kem_temp));
	if(!temp) { return NULL; }
	ml_kem_memzero(temp, sizeof(struct ml_kem_temp));
	
	// Configure parameters based on security level
	if(level == ML_KEM_512)
	{
		temp->k = ML_KEM_512;
		temp->eta = ML_KEM_CBD_ETA_3;
		temp->number_raw_bytes_vectors = ML_KEM_VECTOR_XOF_BYTES_L2;
	}else if(level == ML_KEM_768)
	{
		temp->k = ML_KEM_768;
		temp->eta = ML_KEM_CBD_ETA_2;
		temp->number_raw_bytes_vectors = ML_KEM_VECTOR_XOF_BYTES_L34;
	}else if(level == ML_KEM_1024)
	{
		temp->k = ML_KEM_1024;
		temp->eta = ML_KEM_CBD_ETA_2;
		temp->number_raw_bytes_vectors = ML_KEM_VECTOR_XOF_BYTES_L34;
	}else { goto first_error_exit; }
	
	 // Allocate a single contiguous buffer for:
	 //   - temporary polynomial (poly)
	 //   - public key vector (t)
	 //   - secret key vector (s)
	 //
	 // Layout:
	 //   [ poly (1 * N) | public_key (k * N) | secret (k * N) ]
	 //
	 // This minimizes allocations and improves cache locality
	temp->poly = malloc(sizeof(u16) * ML_KEM_N * (2 * temp->k + 1));
	if(!temp->poly) { goto first_error_exit; }
	ml_kem_memzero(temp->poly, sizeof(u16) * ML_KEM_N * (2 * temp->k + 1));
	
	// Assign internal pointers into the shared buffer
	temp->public_key = temp->poly + ML_KEM_N;
	temp->secret = temp->public_key + temp->k * ML_KEM_N;
	
	// Allocate buffer for raw XOF output (used for matrix/vector generation)
	temp->raw_bytes = malloc(ML_KEM_MATRIX_XOF_BYTES);
	if(!temp->raw_bytes) { goto second_error_exit; }
	ml_kem_memzero(temp->raw_bytes, ML_KEM_MATRIX_XOF_BYTES);
	
	return temp;
	
	// Error handling
	second_error_exit:
		free(temp->poly);
	first_error_exit:
		free(temp);
	return NULL;
}
	
// Allocate and initialize persistent ML-KEM context.
// This structure stores long-lived key material and is used
// across encapsulation/decapsulation operations.
struct ml_kem_ctx *ml_kem_ctx_alloc(enum ml_kem_k level)
{
	// Allocate base structure
	struct ml_kem_ctx *ctx;
	ctx = malloc(sizeof(struct ml_kem_ctx));
	if(!ctx) { return NULL; }
	ml_kem_memzero(ctx, sizeof(struct ml_kem_ctx));
	
	// Configure parameters based on security level
	if(level == ML_KEM_512)
	{
		ctx->k = level;
		ctx->public_key_msg_len = RES_PUBL_PART_LVL_512;
	}else if(level == ML_KEM_768)
	{
		ctx->k = level;
		ctx->public_key_msg_len = RES_PUBL_PART_LVL_768;
	}else if(level == ML_KEM_1024)
	{
		ctx->k = level;
		ctx->public_key_msg_len = RES_PUBL_PART_LVL_1024;
	}else { goto first_error_exit; }
	
	// Allocate secret key vector (s)
	ctx->secret = malloc(sizeof(u16) * ctx->k * ML_KEM_N);
	if(!ctx->secret) { goto first_error_exit; }
	ml_kem_memzero(ctx->secret, sizeof(u16) * ctx->k * ML_KEM_N);
	
	 // Allocate buffer for serialized public key:
	 //   - compressed polynomial vector t
	 //   - appended seed_rho (matrix seed)
	 // Final format matches ML-KEM specification output.
	ctx->public_key_msg = malloc(ctx->public_key_msg_len);
	if(!ctx->public_key_msg) { goto second_error_exit; }
	ml_kem_memzero(ctx->public_key_msg, ctx->public_key_msg_len);
	
	return ctx;
	
	// Error handling
	second_error_exit:
		free(ctx->secret);
	first_error_exit:
		free(ctx);
	return NULL;
}

// Destroy and securely wipe temporary ML-KEM structure.
// This structure contains sensitive intermediate data and MUST be wiped before deallocation.
void ml_kem_destroy_temp_struct(struct ml_kem_temp *temp)
{
	// Validate pointer
	if(!temp) { return; }
	
	// Wipe and free raw XOF buffer (used for matrix/vector generation)
	if(temp->raw_bytes)
	{
		ml_kem_memzero(temp->raw_bytes, ML_KEM_MATRIX_XOF_BYTES);
		free(temp->raw_bytes);
		temp->raw_bytes = NULL;
	}
	
	 // Wipe and free contiguous buffer containing:
	 //   - temporary polynomial
	 //   - public key (intermediate form)
	 //   - secret key (s)
	 //
	 // Layout size: (2*k + 1) * N coefficients
	if(temp->poly)
	{
		ml_kem_memzero(temp->poly, sizeof(u16) * (temp->k * 2 + 1) * ML_KEM_N);
		free(temp->poly);
		temp->poly = NULL;
		temp->public_key = NULL;
		temp->secret = NULL;
	}
	
	// Wipe seed material (used for secret and noise generation)
	ml_kem_memzero(temp->seed_sigma, sizeof(temp->seed_sigma));
	ml_kem_memzero(temp->seed_rho, sizeof(temp->seed_rho));
	
	// Free structure itself (no further access expected)
	free(temp);
}	

// Destroy and securely wipe persistent ML-KEM context.
// This includes long-lived secret key material and auxiliary values.
void ml_kem_destroy_ctx_struct(struct ml_kem_ctx *ctx)
{
	// Validate pointer
	if(!ctx) { return; }
	
	// Wipe and free secret key (s)
	if(ctx->secret)
	{
		ml_kem_memzero(ctx->secret, sizeof(u16) * ctx->k * ML_KEM_N);
		free(ctx->secret);
		ctx->secret = NULL;
	}
	
	// Free serialized public key
	if(ctx->public_key_msg)
	{
		free(ctx->public_key_msg);
		ctx->public_key_msg = NULL;
	}
	
	 // Wipe auxiliary sensitive values:
	 //   - z    : fallback secret used in decapsulation
	 //   - h_pk : hash of public key (used in KDF)
	ml_kem_memzero(ctx->z, ML_KEM_SEED_BYTES);
    ml_kem_memzero(ctx->h_pk, ML_KEM_SEED_BYTES);
	 
	// Free structure itself
	free(ctx);
}
	
// Generate initial entropy and derive seed_rho / seed_sigma.
// FIPS 203-compatible approach: sample 32 random bytes, append parameter k,
// Then expand with SHA3-512 into two independent 32-byte seeds.
static int ml_kem_generation_entropy(struct ml_kem_temp *temp)
{
	u8 first_seed[ML_KEM_SEED_BYTES + 1];          // 32-byte random seed || 1-byte parameter k
    u8 seeds_rho_and_sigma[ML_KEM_SEED_BYTES * 2]; // 64-byte SHA3-512 output: rho || sigma
    
    /* In the test version get seed not use
    // Read 32 bytes of system entropy
    size_t offset = 0;
    ssize_t ret = 0;
    ssize_t len = ML_KEM_SEED_BYTES;
    while(offset < ML_KEM_SEED_BYTES)
    {
		ret = getrandom(first_seed + offset, len - offset, 0);
		if(ret < 0) 
		{ 
			if(errno == EINTR) { continue; }
			return -1; 
		}
		offset += ret;
	}
	*/
	
	// copy value for test
	memcpy(first_seed, mass_d, ML_KEM_SEED_BYTES);
	
	// Append ML-KEM parameter k (matrix/vector dimension)
	first_seed[32] = (u8)temp->k;
	
	// Expand input seed into:
	//   - seed_rho   : public matrix A seed
	//   - seed_sigma : secret/noise generation seed
	ml_kem_sha3_512(seeds_rho_and_sigma, first_seed, ML_KEM_SEED_BYTES + 1);
	ml_kem_memzero(first_seed, sizeof(first_seed));
	
	// Store derived seeds in temporary context
	memcpy(temp->seed_rho, seeds_rho_and_sigma, ML_KEM_SEED_BYTES);
	memcpy(temp->seed_sigma, seeds_rho_and_sigma + ML_KEM_SEED_BYTES, ML_KEM_SEED_BYTES);
	ml_kem_memzero(seeds_rho_and_sigma, sizeof(seeds_rho_and_sigma));
	
	return 0;
}

// Generate secret vector s and convert each polynomial into NTT form.
// For each polynomial in the vector:
//   1. build a 33-byte input: seed_sigma || counter
//   2. expand it with SHAKE256
//   3. sample coefficients via CBD
//   4. convert the polynomial to NTT domain
// The resulting vector is stored in temp->secret.
static void ml_kem_create_vector_poly(struct ml_kem_temp *temp)
{
	// Local seed buffer: seed_sigma || 1-byte counter
	u8 local_seed[ML_KEM_SEED_BYTES + 1];
	memcpy(local_seed, temp->seed_sigma, ML_KEM_SEED_BYTES);
	local_seed[32] = 0;
	
	// Generate each polynomial of the secret vector independently
	for(size_t i = 0; i < temp->k; i++)
	{
		// Encode polynomial index into the last byte
		local_seed[32] = (u8)i;
		
		// Expand per-polynomial input into raw pseudorandom bytes
		ml_kem_shake256(temp->raw_bytes, temp->number_raw_bytes_vectors, local_seed, ML_KEM_SEED_BYTES + 1);
		
		// Sample one polynomial from CBD stream
		ml_kem_gen_polynomial_for_cbd(temp->secret + i * ML_KEM_N, temp->raw_bytes, temp->eta);
		
		// Convert polynomial into NTT domain for subsequent ML-KEM operations
		ml_kem_ntt_fips203(temp->secret + i * ML_KEM_N);
		
		// Clear temporary XOF output before reusing the buffer
		ml_kem_memzero(temp->raw_bytes, temp->number_raw_bytes_vectors);
	}
}

// Generate public key vector t = A * s + e (in NTT domain)
static int ml_kem_create_public_key(struct ml_kem_temp *temp)
{
	// Local seed for matrix A generation: seed_rho || col || row
	u8 local_seed_matrix[ML_KEM_SEED_BYTES + 2];
	memcpy(local_seed_matrix, temp->seed_rho, ML_KEM_SEED_BYTES);
	local_seed_matrix[32] = 0;
	local_seed_matrix[33] = 0;
	
	// Noise counter starts after secret vector indices
	int counter_noise = temp->k;
	
	// Local seed for noise generation: seed_sigma || counter
	u8 local_seed_noise[ML_KEM_SEED_BYTES + 1];
	memcpy(local_seed_noise, temp->seed_sigma, ML_KEM_SEED_BYTES);
	local_seed_noise[32] = 0;
	
	// Iterate over rows of matrix A (each row produces one polynomial of t)
	for(size_t row = 0; row < temp->k; row++)
	{
		// Compute dot product: A[row] * s
		for(size_t col = 0; col < temp->k; col++)
		{
			// Encode matrix indices into seed (column, row)
			local_seed_matrix[32] = (u8)col;
			local_seed_matrix[33] = (u8)row;
			
			// Expand seed into raw bytes for matrix polynomial A[row][col]
			ml_kem_shake128(temp->raw_bytes, ML_KEM_MATRIX_XOF_BYTES, local_seed_matrix, ML_KEM_SEED_BYTES + 2);
			
			// Sample polynomial via rejection sampling
			int ret = ml_kem_gen_polynomial_for_matrix(temp->poly, temp->raw_bytes, ML_KEM_MATRIX_XOF_BYTES);
			if(ret < 0) 
			{ 
				ml_kem_memzero(temp->raw_bytes, ML_KEM_MATRIX_XOF_BYTES);
                ml_kem_memzero(local_seed_noise, sizeof(local_seed_noise));
                ml_kem_memzero(local_seed_matrix, sizeof(local_seed_matrix));
                ml_kem_memzero(temp->poly, sizeof(u16) * ML_KEM_N);
				return ret;
			}
			
			// Multiply A[row][col] with s[col] (both in NTT domain)
			ml_kem_multiply(temp->poly, temp->poly, temp->secret + col * ML_KEM_N);
			
			// Accumulate into t[row] (dot product)
			ml_kem_add(temp->public_key + row * ML_KEM_N, temp->public_key + row * ML_KEM_N, temp->poly);
			
			// Clear temporary polynomial buffer
			ml_kem_memzero(temp->poly, sizeof(u16) * ML_KEM_N);
		}
		
		// Generate noise polynomial e[row]
		local_seed_noise[32] = (u8)counter_noise;
		ml_kem_shake256(temp->raw_bytes, temp->number_raw_bytes_vectors, local_seed_noise, ML_KEM_SEED_BYTES + 1);
		
		// Sample noise via CBD and convert to NTT domain
		ml_kem_gen_polynomial_for_cbd(temp->poly, temp->raw_bytes, temp->eta);
		ml_kem_ntt_fips203(temp->poly);
		
		// Add noise to t[row]: t[row] = A[row]*s + e[row]
		ml_kem_add(temp->public_key + row * ML_KEM_N, temp->public_key + row * ML_KEM_N, temp->poly);
		
		// Clear temporary buffer and increment noise counter
		ml_kem_memzero(temp->poly, sizeof(u16) * ML_KEM_N);
		counter_noise++;
	}
	
	// Wipe temporary buffers and seeds
	ml_kem_memzero(temp->poly, sizeof(u16) * ML_KEM_N);
	ml_kem_memzero(local_seed_noise, sizeof(local_seed_noise));
	ml_kem_memzero(local_seed_matrix, sizeof(local_seed_matrix));
	
	return 0;
}

// Serialize public key vector t into byte representation and copy all required data into ctx.
// Each pair of 12-bit coefficients is packed into 3 bytes (little-endian bit layout).
static void ml_kem_convert_to_bytes_format_and_copy(struct ml_kem_temp *temp, struct ml_kem_ctx *ctx)
{
	// Byte array index and coefficient index
	size_t mass_counter = 0;
	size_t coeff_counter = 0;

	 // Packing format (per 2 coefficients, 12 bits each = 24 bits total):
	 //   coeff0: [c0_11 ... c0_0]
	 //   coeff1: [c1_11 ... c1_0]
	 // Stored as:
	 //   byte0 = lower 8 bits of coeff0
	 //   byte1 = upper 4 bits of coeff0 | lower 4 bits of coeff1
	 //   byte2 = upper 8 bits of coeff1
	 // Total: 2 coefficients -> 3 bytes
	 // Total number of coefficients is always even, so no boundary issues occur.
	while(coeff_counter < temp->k * ML_KEM_N)
	{
		// byte0: lower 8 bits of coeff0
		ctx->public_key_msg[mass_counter] = (u8)(temp->public_key[coeff_counter]);
		mass_counter++;

		// byte1: upper 4 bits of coeff0
		ctx->public_key_msg[mass_counter] = (u8)(temp->public_key[coeff_counter] >> 8);
		coeff_counter++;

		// byte1 (continued): lower 4 bits of coeff1
		ctx->public_key_msg[mass_counter] |= (u8)(temp->public_key[coeff_counter] << 4);
		mass_counter++;

		// byte2: upper 8 bits of coeff1
		ctx->public_key_msg[mass_counter] = (u8)(temp->public_key[coeff_counter] >> 4);
		coeff_counter++;

		mass_counter++;
	}

	// Append seed_rho (matrix seed) to the end of serialized public key
	memcpy(ctx->public_key_msg + ctx->public_key_msg_len - ML_KEM_SEED_BYTES, temp->seed_rho, ML_KEM_SEED_BYTES);

	// Copy secret key vector (already in NTT domain)
	memcpy(ctx->secret, temp->secret, sizeof(u16) * ctx->k * ML_KEM_N);

	// Store seed_rho in context (useful for re-derivation or testing scenarios)
	memcpy(ctx->seed_rho, temp->seed_rho, ML_KEM_SEED_BYTES);

	 // Note:
	 //   ctx->k and ctx->public_key_msg_len are initialized and validated
	 //   during context allocation and key generation setup.
}

// Generate auxiliary values for decapsulation:
//   - z    : random fallback secret
//   - h_pk : hash of serialized public key
static int ml_kem_finally_create_z_and_h_pk(struct ml_kem_ctx *ctx)
{
	// Fill z with 32 bytes of system entropy
    size_t offset = 0;
    ssize_t ret = 0;
    ssize_t len = ML_KEM_SEED_BYTES;
    while(offset < ML_KEM_SEED_BYTES)
    {
		ret = getrandom(ctx->z + offset, len - offset, 0);
		if(ret < 0) 
		{ 
			if(errno == EINTR) { continue; }
			return -1; 
		}
		offset += ret;
	}
	
	// Compute hash of public key (used in KDF during encaps/decaps)
	ml_kem_sha3_256(ctx->h_pk, ctx->public_key_msg, ctx->public_key_msg_len);

	return 0;
}
	
	
// Centered Binomial Distribution (CBD) sampler for ML-KEM.
// This function generates a polynomial where each coefficient is sampled as:
//   coeff = HW(x_bits) - HW(y_bits)
// where HW(.) is the Hamming weight of eta bits.
// Input stream is consumed sequentially, as required by the specification.
// Depending on eta:
//   eta = 2:
//     - 4 bits per coefficient (2 for x, 2 for y)
//     - 64-bit buffer → 16 coefficients per iteration
//   eta = 3:
//     - 6 bits per coefficient (3 for x, 3 for y)
//     - 48-bit buffer → 8 coefficients per iteration
// Bits are processed in order: first x bits, then y bits.
// Final coefficient is reduced modulo q (3329).
void ml_kem_gen_polynomial_for_cbd(u16 *poly, const u8 *stream, const u8 eta)
{
	// Number of bits in one byte (used for shifts)
	const int size_bytes = 8;

	// Bit buffer (up to 64 bits)
	u64 buffer = 0;
	
	// Determine package size depending on eta
	int one_package_bits;
	int one_package_bytes;
	int number_bytes = eta * 64; // 128 bytes (eta=2) or 192 bytes (eta=3)

	if(eta == 2)
	{
		// 64-bit package → 16 coefficients
		one_package_bits = 64;
		one_package_bytes = 8;
	}
	else
	{
		// 48-bit package → 8 coefficients
		one_package_bits = 48;
		one_package_bytes = 6;
	}

	// Accumulators for Hamming weights
	u8 x = 0;
	u8 y = 0;
	
	// Stream index
	int i = 0;

	// Output coefficient index
	int conter_coeff = 0;

	// Bit/byte tracking inside buffer
	int size_bytes_counter = 0;
	int counter_bits = 0;
	
	// Main loop over input stream
	while(i < number_bytes)
	{
		// Load next package (aligned to full bytes)
		for(int j = 0; j < one_package_bytes; j++)
		{
			buffer |= (u64)stream[i] << size_bytes_counter;
			size_bytes_counter += size_bytes;
			i++;
		}
		
		// Extract coefficients from buffer
		while(counter_bits < one_package_bits)
		{
			// Read eta bits for x (Hamming weight)
			for(int j = 0; j < eta; j++)
			{
				x += buffer & 1;
				buffer >>= 1;
				counter_bits++;
			}
			
			// Read eta bits for y (Hamming weight)
			for(int j = 0; j < eta; j++)
			{
				y += buffer & 1;
				buffer >>= 1;
				counter_bits++;
			}
			
			// Compute coefficient: x - y (mod q)
			poly[conter_coeff] = ml_kem_sub_mod(x, y);
			
			// Reset accumulators for next coefficient
			conter_coeff++;
			x = 0;
			y = 0;
		}
		
		// Reset buffer and counters for next package
		buffer = 0;
		size_bytes_counter = 0;
		counter_bits = 0;
	}		
}
		
		
// Sample polynomial coefficients for matrix A using rejection sampling (FIPS 203, Algorithm 7 - SampleNTT).
// Input stream is interpreted as a sequence of 12-bit values.
// Every 3 bytes produce two 12-bit candidates:
//   d1 = lower 12 bits  (byte0 + lower 4 bits of byte1)
//   d2 = upper 12 bits  (upper 4 bits of byte1 + byte2)
// Only values < q (3329) are accepted.
// Rejected values are skipped, and sampling continues.
// NOTE:
//   If input bytes are insufficient, function returns -ENOMEM.
//   Caller is expected to extend the stream (e.g., via SHAKE) and retry.
int ml_kem_gen_polynomial_for_matrix(u16 *poly, const u8 *stream, int suma_bytes)
{
	int j = 0;		// Output coefficient index
	size_t pos = 0; // Position in input stream

	// Temporary candidates (12-bit values)
	u16 d1 = 0;
	u16 d2 = 0;
        
	// Generate ML_KEM_N coefficients
	while (j < ML_KEM_N)
	{
		if(suma_bytes < 3) { return -ENOMEM; } 			 // Need at least 3 bytes to extract two candidates
		d1 = stream[pos] | ((stream[pos+1] & 0xF) << 8); // Extract first 12-bit value: byte0 + lower 4 bits of byte1
		d2 = (stream[pos+1] >> 4) | (stream[pos+2] << 4);// Extract second 12-bit value: upper 4 bits of byte1 + byte2

		// Accept values strictly less than q
		if (d1 < ML_KEM_Q) { poly[j++] = d1; }
        if (d2 < ML_KEM_Q && j < ML_KEM_N) { poly[j++] = d2; }

		// Advance stream position
        pos += 3;

		// Reset temporary variables
        d1 = d2 = 0;

		// Track remaining bytes
        suma_bytes -= 3;
	} 

	return suma_bytes;
}
	
// Secure memory wipe function.
//
// Uses a volatile pointer to prevent compiler optimizations
// that could remove the memory clearing operation.
//
// NOTE:
//   Effectiveness depends on compiler behavior.
//   For high-assurance environments, consider platform-specific primitives
//   (e.g., explicit_bzero, memset_s, or kernel equivalents).
void ml_kem_memzero(void *ptr, size_t len)
{
	if(!ptr) { return; }
	
	volatile unsigned char *inside_ptr = (volatile unsigned char *)ptr;

	for(size_t i = 0; i < len; i++)
	{
		inside_ptr[i] = 0;
	}
}
	
	
	
	
	
	
	
	
	
	

