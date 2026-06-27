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

// Number of parallel decapsulation slots (pool size).
// This affects how many independent operations can be handled concurrently.

#define NUMBER_SLOTS 4

// Number of test vectors per security level and
// Buffer size for reading JSON lines.

#define NUMBER_VECTORS_ONE_LEVEL 25
#define SIZE_BUFFER 4096

// Step increments between ML-KEM parameter sets: 512 → 768 → 1024.
#define LEVEL_STEP 256
#define SIZE_EK_STEP 384
#define K_STEP 1

// Buffers for: 1.input seed (d) 2.expected public key (ek)
u8 mass_d[ML_KEM_SEED_BYTES];
u8 mass_ek[RES_PUBL_PART_LVL_1024];

// Helper functions for HEX parsing
static int hexval(int c);
int read_hex_byte(const char *in, u8 *out, size_t size_out_mass);

int main()
{
	// Test description output.
	// The test validates ML-KEM key generation against NIST vectors.
	printf("\nThis is test generation keys in ML-KEM");
	printf("\nThis is show 75 messages about everyone of 75 vectors NIST");
	printf("\nIf you to see");
	printf("\n\"Wrong! In *** vector, in ML-KEM-*** level sequrity!\"");
	printf("\nso this ML-KEM version is wrong\n");
	printf("\nIf you to see everything");
	printf("\nDone.... In *** vector, in ML-KEM-*** level sequrity is identical with vector NIST....");
	printf("\nso this ML-KEM version is good\n");
	printf("\nIn test using memcmp()....\n");
	printf("...................................................................................................................................................\n");
	
	// Explicit zeroing of buffers before use.
	// Important to avoid leftover data affecting test results.
	for(size_t i = 0; i < ML_KEM_SEED_BYTES; i++)
	{
		mass_d[i] = 0;
	}
	
	for(size_t i = 0; i < RES_PUBL_PART_LVL_1024; i++)
	{
		mass_ek[i] = 0;
	}
	
	// Buffer for reading lines from JSON file
	char buffer[SIZE_BUFFER];
	
	// Open NIST test vector file (KeyGen vectors).
	FILE *f = fopen("ML-KEM-keyGen-FIPS203/internalProjection.json", "r");
	if(!f) { return -1; }
	
	// Skip initial metadata until first "parameterSet" entry.
	while(fgets(buffer, sizeof(buffer), f))
	{
		if(strstr(buffer, "parameterSet"))
		{
			break;
		}
	}
	
	// Initialize counters for: 1.security level; 2.expected public key size; 3.vector index; 4.ML-KEM parameter k
	size_t level_counter = 512;
	size_t size_ek_counter = 800;
	size_t vectors_counter = 0;
	enum ml_kem_k k = 2;
	while(fgets(buffer, sizeof(buffer), f))
	{
		// New parameter set detected (switching security level).
		if(strstr(buffer, "parameterSet"))
		{
			printf("\n");
			printf("...................................................................................................................................................\n");
			printf("\nThis is 25 tests vectors generation keys in ML-KEM-");
			printf("%zu\n", level_counter);
			level_counter += LEVEL_STEP;
			size_ek_counter += SIZE_EK_STEP;
			vectors_counter = 0;
			k += K_STEP;
		}else if(strstr(buffer, "\"d\": \"")) // Read seed 'd' from JSON (input for KeyGen).
		{
			size_t ret = read_hex_byte(buffer, mass_d, ML_KEM_SEED_BYTES);
			if(ret != ML_KEM_SEED_BYTES) { return -1; }
		}else if(strstr(buffer, "\"ek\": \"")) // Read expected public key 'ek' from JSON.
		{
			size_t ret = read_hex_byte(buffer, mass_ek, RES_PUBL_PART_LVL_1024);
			if(ret != size_ek_counter) { return -1; }
			
			// Create ML-KEM context (includes key generation internally).
			struct ml_kem_pool_decaps_ctx *this_ctx;
			this_ctx = ml_kem_create_object(k, NUMBER_SLOTS, NULL);
			
			// Compare generated public key with NIST reference. Full byte-wise comparison ensures deterministic correctness.
			if(memcmp(mass_ek, this_ctx->ml_kem_pool[0].decrypt_ctx->ctx->public_key_msg, size_ek_counter) != 0)
			{
				printf("\nWrong! In %zu vector, in ML-KEM-%zu level sequrity!", vectors_counter, level_counter);
			}else{
				printf("\nDone.... In %zu vector, in ML-KEM-%zu level sequrity is identical with vector NIST....", vectors_counter, level_counter);
			}
			
			// Destroy context and securely wipe associated memory.
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
