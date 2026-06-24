// SPDX-License-Identifier: GPL-2.0 OR MIT
// Copyright (c) 2026 K.S.Zavertailo

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/crypto.h>
#include <linux/scatterlist.h>

#include <crypto/kpp.h>
#include <crypto/internal/kpp.h>

#include "ml_kem_core_header.h"
#include "ml_kem.h"

// Maximum buffer size used for temporary storage.
// Chosen as the largest possible ML-KEM ciphertext / public key size.

#define SIZE_BUFFER 1568

// Per-instance context for the KPP algorithm.
// Only one mode is active at a time:
// - encapsulation: encaps_ctx is used
// - decapsulation: decaps_ctx is used

struct ml_kem_kernel_handle {
    struct ml_kem_encaps_ctx *encaps_ctx;
    struct ml_kem_pool_decaps_ctx *decaps_ctx;
};

// Per-request context.
// Used as a temporary buffer for:
//	- public key input (encapsulation)
//	- ciphertext input (decapsulation)
//	- shared secret staging

struct ml_kem_req_ctx {
    u8 ml_kem_buffer[SIZE_BUFFER];
};

// Forward declarations of KPP callbacks
int ml_kem_kpp_set_secret(struct crypto_kpp *tfm, const void *buffer, unsigned int len);
int ml_kem_kpp_generate_public_key(struct kpp_request *req);
int ml_kem_kpp_compute_shared_secret(struct kpp_request *req);

// Return maximum size of output buffer. Required by KPP interface.
static unsigned int ml_kem_max_size(struct crypto_kpp *tfm)
{
    return SIZE_BUFFER;
}

// Initialize KPP context. No allocations are performed here.
// Context is initialized lazily via set_secret().
static int ml_kem_init(struct crypto_kpp *tfm)
{
    struct ml_kem_kernel_handle *ctx = kpp_tfm_ctx(tfm);

    ctx->decaps_ctx = NULL;
    ctx->encaps_ctx = NULL;

    return 0;
}

// Cleanup KPP context. Frees all allocated ML-KEM structures
// And securely wipes sensitive data.
static void ml_kem_exit(struct crypto_kpp *tfm)
{
   struct ml_kem_kernel_handle *ctx = kpp_tfm_ctx(tfm);
    
    if(!ctx) { return; }

	if(ctx->decaps_ctx)
	{
		ml_kem_destroy_core(ctx->decaps_ctx);
	}
	
	if(ctx->encaps_ctx)
	{
		ml_kem_wipe_encaps(ctx->encaps_ctx);
		ml_kem_destroy_encaps(ctx->encaps_ctx);
	}
}

// set_secret(): Initializes decapsulation context (private key side).
// Expected input format: 1. buffer[0] = security level (2, 3, 4) 2. buffer[1] = pool size
// NOTE: This function does NOT accept raw keys. It generates keypair internally and prepares decapsulation pool.
int ml_kem_kpp_set_secret(struct crypto_kpp *tfm, const void *buffer, unsigned int len)
{
	struct ml_kem_kernel_handle *ctx;
	ctx = kpp_tfm_ctx(tfm);
	
	if(ctx->decaps_ctx) { return -EINVAL; }
	
	 enum ml_kem_k level;
	if(len == 2) 
	{ 
		u8 ch = *(const u8 *)buffer;
		if(ch == 2)
		{
			level = ML_KEM_512;
		}else if(ch == 3)
		{
			level = ML_KEM_768;
		}else if(ch == 4)
		{
			level = ML_KEM_1024;
		}else { return -EINVAL; }
		
		u8 size_pool = ((const u8 *)buffer)[1];
		
		if(size_pool == 0 || size_pool > ML_KEM_MAX_POOL_SLOTS) { return -EINVAL; }
		
		ctx->decaps_ctx = ml_kem_create_object(level, size_pool);
		if(IS_ERR(ctx->decaps_ctx)) { return PTR_ERR(ctx->decaps_ctx); }
	}else if(len == 0)
	{
		return 0; // No-op allowed
	}else { return -EINVAL; }
	
	return 0;
}

// generate_public_key(): Dual-mode behavior: Decapsulation flow(mode): Returns public key generated during set_secret()
// Encapsulation flow(mode): Performs encapsulation: 1. input  = public key 2. output = ciphertext 3. shared secret stored internally
int ml_kem_kpp_generate_public_key(struct kpp_request *req)
{
	struct crypto_kpp *tfm;
	tfm = crypto_kpp_reqtfm(req);
	struct ml_kem_kernel_handle *ctx;
	ctx = kpp_tfm_ctx(tfm);
	
	// Decapsulation flow
	if(ctx->decaps_ctx && !ctx->encaps_ctx)
	{
		if(req->dst_len != ctx->decaps_ctx->ml_kem_pool->decrypt_ctx->ctx->public_key_msg_len)
		{ return -EINVAL; }
		
		sg_copy_from_buffer(req->dst, sg_nents(req->dst), ctx->decaps_ctx->ml_kem_pool->decrypt_ctx->ctx->public_key_msg, req->dst_len);
	}else if(!ctx->encaps_ctx && !ctx->decaps_ctx) // Encapsulation flow
	{
		enum ml_kem_k level;
		if(req->src_len == RES_PUBL_PART_LVL_512 && req->dst_len == LEN_CIPHERTEXT_512) { level = ML_KEM_512; }
		else if(req->src_len == RES_PUBL_PART_LVL_768 && req->dst_len == LEN_CIPHERTEXT_768) { level = ML_KEM_768; }
		else if(req->src_len == RES_PUBL_PART_LVL_1024 && req->dst_len == LEN_CIPHERTEXT_1024) { level = ML_KEM_1024; }
		else { return -EINVAL; }
		struct ml_kem_req_ctx *rctx = kpp_request_ctx(req);
		sg_copy_to_buffer(req->src, sg_nents(req->src), rctx->ml_kem_buffer, req->src_len);
		
		u8 *ciphertext;
		u8 ss[ML_KEM_SEED_BYTES];
		ciphertext = ml_kem_encaps_core(rctx->ml_kem_buffer, level, ss);
		if(IS_ERR(ciphertext)) 
		{ 
			memzero_explicit(ss, ML_KEM_SEED_BYTES);
			memzero_explicit(rctx->ml_kem_buffer, SIZE_BUFFER);
			return PTR_ERR(ciphertext); }
		
		sg_copy_from_buffer(req->dst, sg_nents(req->dst), ciphertext, req->dst_len);
		memzero_explicit(rctx->ml_kem_buffer, SIZE_BUFFER);
		memcpy(rctx->ml_kem_buffer, ss, ML_KEM_SEED_BYTES);
		memzero_explicit(ss, ML_KEM_SEED_BYTES);
		
		ml_kem_ciphertext_destroy_core(ciphertext, level);
	}else { return -EFAULT; }
	
	return 0;
}

// compute_shared_secret(): Dual-mode behavior: Decapsulation flow(mode): 1. input: ciphertext 2. output: shared secret
// Encapsulation flow(mode): returns previously generated shared secret
int ml_kem_kpp_compute_shared_secret(struct kpp_request *req)
{
	struct crypto_kpp *tfm;
	tfm = crypto_kpp_reqtfm(req);
	struct ml_kem_kernel_handle *ctx;
	ctx = kpp_tfm_ctx(tfm);
	
	if(req->dst_len != ML_KEM_SEED_BYTES) { return -EINVAL; }
	
	// Decapsulation flow
	if(ctx->decaps_ctx && !ctx->encaps_ctx)
	{
		if(!(req->src_len == LEN_CIPHERTEXT_512 || req->src_len == LEN_CIPHERTEXT_768 || req->src_len == LEN_CIPHERTEXT_1024))
		{ return -EINVAL; }
		
		struct ml_kem_req_ctx *rctx = kpp_request_ctx(req);
		sg_copy_to_buffer(req->src, sg_nents(req->src), rctx->ml_kem_buffer, req->src_len);
		
		u8 ss[ML_KEM_SEED_BYTES];
		int ret = ml_kem_decaps_core(ctx->decaps_ctx, rctx->ml_kem_buffer, req->src_len, ss, ML_KEM_SEED_BYTES);
		if(ret != 0) { return ret; }
		
		memzero_explicit(rctx->ml_kem_buffer, SIZE_BUFFER);
		memcpy(rctx->ml_kem_buffer, ss, ML_KEM_SEED_BYTES);
		
		sg_copy_from_buffer(req->dst, sg_nents(req->dst), ss, req->dst_len);
		memzero_explicit(ss, ML_KEM_SEED_BYTES);
	}else if(!ctx->encaps_ctx && !ctx->decaps_ctx) // Encapsulation flow
	{
		struct ml_kem_req_ctx *rctx = kpp_request_ctx(req);
		sg_copy_from_buffer(req->dst, sg_nents(req->dst), rctx->ml_kem_buffer, req->dst_len);
		memzero_explicit(rctx->ml_kem_buffer, SIZE_BUFFER);
	}else { return -EFAULT; }
	
	return 0;
}

// KPP algorithm registration structure
static struct kpp_alg ml_kem_pq_alg = {
     .set_secret = ml_kem_kpp_set_secret,                       
     .generate_public_key = ml_kem_kpp_generate_public_key,     
     .compute_shared_secret = ml_kem_kpp_compute_shared_secret, 
     .max_size = ml_kem_max_size,                               
     .init = ml_kem_init,
     .exit = ml_kem_exit,
     .base = {
        .cra_name        = "ml-kem",
        .cra_driver_name = "ml-kem-pq-alg",
        .cra_priority    = 100,
        .cra_flags       = CRYPTO_ALG_TYPE_KPP,
        .cra_blocksize   = 1,
        .cra_ctxsize     = sizeof(struct ml_kem_kernel_handle), 
        .cra_module      = THIS_MODULE,
    }
};

// Module initialization
static int __init hello_init(void)
{
    int ret = crypto_register_kpp(&ml_kem_pq_alg);
    if(ret != 0) 
    { 
		pr_err("Error loaded ml-lem module!\n");
		return ret;
	}
	
	pr_info("ml-kem: registered module.....\n");
    return 0;
}

// Module cleanup
static void __exit hello_exit(void)
{
    crypto_unregister_kpp(&ml_kem_pq_alg);
    pr_info("ml-lem module: unloaded.....\n");
}

module_init(hello_init);
module_exit(hello_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("K.S.Zavertaylo");
MODULE_DESCRIPTION("ML-KEM");
MODULE_VERSION("0.1");
