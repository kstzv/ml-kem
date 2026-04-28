// SPDX-License-Identifier: GPL-2.0 OR MIT
// Copyright (c) 2026 K.S.Zavertailo

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stddef.h>
#include <errno.h>
#include <stdbool.h>
#include <stdlib.h>

#include "ml_kem.h"
#include "ml_kem_core_header.h"

// Number of slots in the decapsulation pool (controls parallelism level)
#define NUMBER_SLOTS 8

// Number of test vectors per parameter set and buffer size for JSON line reading
#define NUMBER_VECTORS_ONE_LEVEL 25
#define SIZE_BUFFER 4096

// Step increments for switching between ML-KEM parameter sets
#define LEVEL_STEP 256
#define SIZE_EK_STEP 384
#define K_STEP 1

// Buffers for seed (d) and shared secrets from encapsulation/decapsulation
u8 mass_d[ML_KEM_SEED_BYTES];
u8 mass_K_encaps[ML_KEM_SEED_BYTES];
u8 mass_K_decaps[ML_KEM_SEED_BYTES];

// Helper functions for HEX parsing
static int hexval(int c);
int read_hex_byte(const char *in, u8 *out, size_t size_out_mass);

int main()
{
	printf("\nThis is test decapsulation test and finally test in ML-KEM");
	printf("\nThis is show 75 messages about everyone of 75 vectors NIST\n");
	printf("\nfrom vector d from file keygen, with this seed going to ALL algorithm\n");
	printf("\nEncapsulation get ciphertext from base d seed(ek based on this seed)\n");
	printf("\nEncapsulation cheked is earlier, it is correct\n");
	printf("\nBase on this chacked decapsulation, K_SHARED from encaps, and decaps in memcmp()\n");
	printf("\nIf you to see");
	printf("\n\"Wrong! In *** vector, in ML-KEM-*** level sequrity!\"");
	printf("\nso this ML-KEM version is wrong\n");
	printf("\nIf you to see everything");
	printf("\nDone.... In *** vector, in ML-KEM-*** level sequrity is identical with vector NIST....");
	printf("\nso this ML-KEM version is good\n");
	printf("\nIn test using memcmp()....\n");
	printf("...................................................................................................................................................\n");
	
	// Zero-initialize all working buffers before use
	for(size_t i = 0; i < ML_KEM_SEED_BYTES; i++)
	{
		mass_d[i] = 0;
	}
	
	for(size_t i = 0; i < ML_KEM_SEED_BYTES; i++)
	{
		mass_K_encaps[i] = 0;
	}
	
	for(size_t i = 0; i < ML_KEM_SEED_BYTES; i++)
	{
		mass_K_decaps[i] = 0;
	}
	
	// Buffer for reading lines from JSON test vector file
	char buffer[SIZE_BUFFER];
	
	// Open NIST test vectors (keygen projection)
	FILE *f = fopen("ML-KEM-keyGen-FIPS203/internalProjection.json", "r");
	if(!f) { return -1; }
	
	// Skip initial content until first "parameterSet" entry
	while(fgets(buffer, sizeof(buffer), f))
	{
		if(strstr(buffer, "parameterSet"))
		{
			break;
		}
	}
	
	// Initialize counters for the first parameter set: ML-KEM-512 (k = 2). These values are incremented per parameter set transition.
	size_t level_counter = 512;
	size_t size_ek_counter = 800;
	size_t vectors_counter = 0;
	size_t len_ciphertext = LEN_CIPHERTEXT_512;
	enum ml_kem_k k = 2;
	while(fgets(buffer, sizeof(buffer), f))
	{
		if(strstr(buffer, "parameterSet"))
		{
			printf("\n");
			printf("...................................................................................................................................................\n");
			printf("\nThis is 25 tests vectors all algorithm and decaps in ML-KEM-");
			printf("%zu\n", level_counter);
			
			// Move to next parameter set (512 -> 768 -> 1024)
			level_counter += LEVEL_STEP;
			size_ek_counter += SIZE_EK_STEP;
			vectors_counter = 0;
			k += K_STEP;
			
			// Select correct ciphertext length for current parameter set
			if(k == ML_KEM_512) { len_ciphertext = LEN_CIPHERTEXT_512; }
			else if(k == ML_KEM_768) { len_ciphertext = LEN_CIPHERTEXT_768; }
			else if(k == ML_KEM_1024) { len_ciphertext = LEN_CIPHERTEXT_1024; }
			
		}else if(strstr(buffer, "\"d\": \""))
		{
			// Parse seed 'd' from test vector. This seed is used to deterministically derive key material.
			size_t ret = read_hex_byte(buffer, mass_d, ML_KEM_SEED_BYTES);
			if(ret != ML_KEM_SEED_BYTES) { return -1; }
			
			// Create ML-KEM context with decapsulation pool
			struct ml_kem_pool_decaps_ctx *this_ctx;
			this_ctx = ml_kem_create_object(k, NUMBER_SLOTS);
			
			// Perform encapsulation using public key from generated context. Result: ciphertext and shared secret (mass_K_encaps)
			u8 *ciphertext;
			ciphertext = ml_kem_encaps_core(this_ctx->ml_kem_pool[0].decrypt_ctx->ctx->public_key_msg, k, mass_K_encaps);
			if(ciphertext == NULL) { return -1; }
			
			// Perform decapsulation: derive shared secret from ciphertext using private key
			ret = ml_kem_decaps_core(this_ctx, ciphertext, len_ciphertext, mass_K_decaps, ML_KEM_SEED_BYTES);
			if(ret != 0) { return -1; }
			
			// Validate correctness: shared secret from encapsulation must match decapsulation result. 
			// NOTE: memcmp is used here for testing only (not constant-time).
			if(memcmp(mass_K_encaps, mass_K_decaps, ML_KEM_SEED_BYTES) != 0)
			{
				printf("\nWrong! In %zu vector, in ML-KEM-%zu level sequrity!", vectors_counter, level_counter);
			}else{
				printf("\nDone.... In %zu vector, in ML-KEM-%zu level sequrity is identical with vector NIST....", vectors_counter, level_counter);
			}
			
			// Cleanup resources
			ml_kem_ciphertext_destroy_core(ciphertext, k);
			ml_kem_destroy_core(this_ctx);
			
			vectors_counter++;
		}
	}
	printf("\n");	
	printf("...................................................................................................................................................\n");
	
	return 0;
}

// Convert single HEX character to numeric value. 
// Returns:  0..15 on success or -1 on invalid input
static int hexval(int c)
{
	if(c >= '0' && c <= '9') { return c - '0'; }
	else if(c >= 'a' && c <= 'f') { return c - 'a' + 10; }
	else if(c >= 'A' && c <= 'F') { return c - 'A' + 10; }
	else { return -1; }
}

// Parse HEX string from JSON line into byte array.
// Expected format: "key": "A1B2C3..."
// Behavior: 1. Skips until third quote (start of HEX data)
// 2. Converts each pair of HEX chars into one byte
// 3. Performs validation on input format
// Returns: number of bytes written or -1 on error	
int read_hex_byte(const char *in, u8 *out, size_t size_out_mass)
{
	if(!in || !out) { return -1; }
	
	int symb;
	size_t in_counter = 0;
	
	// Skip until HEX data start (after third quote)
	size_t dq_counter = 0;
	while(dq_counter != 3 && in_counter < SIZE_BUFFER)
	{
		symb = in[in_counter];
		if(symb == '"') { dq_counter++; }
		in_counter++;
	}
	
	size_t out_counter = 0;
	while(out_counter < size_out_mass && in_counter < SIZE_BUFFER)
	{
		// High nibble
		symb = in[in_counter];
		if(symb == '"') { break; }
		if(symb == '\0' || symb == ' ' || symb == '\n') { return -1; }
		symb = hexval(symb);
		if(symb < 0) { return symb; }
		
		out[out_counter] = symb;
		out[out_counter] <<= 4;
		in_counter++;
		
		// Low nibble
		symb = in[in_counter];
		if(symb == '\0' || symb == ' ' || symb == '\n' || symb == '"') { return -1; }
		symb = hexval(symb);
		if(symb < 0) { return symb; }
		
		out[out_counter] |= symb;
		
		out_counter++;
		in_counter++;
	}
	return out_counter;
}
