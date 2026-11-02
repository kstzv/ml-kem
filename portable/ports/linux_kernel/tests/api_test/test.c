// SPDX-License-Identifier: GPL-2.0 OR MIT
#include <linux/module.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/errno.h>
#include <linux/err.h>
#include <linux/slab.h>

#include <ml_kem.h>

static int ml_kem_api_test_level(enum ml_kem_k level, unsigned int bits, size_t slots, size_t pk_len, size_t ct_len, size_t sk_len)
{
    struct ml_kem_general_keys_decaps_ctx *ctx = NULL;			// For test create keys
    struct ml_kem_general_keys_decaps_ctx *ctx_import = NULL;   // For test import keys
    u8 *pk = NULL;
    u8 *ct = NULL;
    u8 *sk = NULL;
    u8 ss_enc[ML_KEM_SEED_BYTES] = { 0 };
    u8 ss_dec[ML_KEM_SEED_BYTES] = { 0 };
    int ret;

    // Kernel port reports construction errors via ERR_PTR()
    ctx = ml_kem_create_object(level, slots, NULL);
    if (IS_ERR(ctx)) 
    {
        ret = PTR_ERR(ctx);
        ctx = NULL;
        pr_err("ml_kem_api_test: ML-KEM-%u key generation failed: %d\n", bits, ret);
        goto out;
    }
    

    // Keep the large test buffers off the kernel stack
    pk = kmalloc(pk_len, GFP_KERNEL);
    ct = kmalloc(ct_len, GFP_KERNEL);
    sk = kmalloc(sk_len, GFP_KERNEL);
    if (!pk || !ct || !sk) 
    {
        ret = -ENOMEM;
        pr_err("ml_kem_api_test: ML-KEM-%u buffer allocation failed\n", bits);
        goto out;
    }
    
    ret = ml_kem_get_sk(ctx, sk, sk_len);
    if(ret != (int)sk_len) { pr_err("ml_kem_api_test: ML-KEM-%u ml_kem_get_sk() failed\n", bits); goto out; }
    
    ctx_import = ml_kem_create_object_from_imported_sk(sk, sk_len, 10);
    if(IS_ERR(ctx_import)) { ret = PTR_ERR(ctx_import); ctx_import = NULL; 
			pr_err("ml_kem_api_test: ML-KEM-%u ml_kem_create_object_from_imported_sk() failed: %d\n", bits, ret); goto out; }
	
	

    ret = ml_kem_get_public_key(ctx, pk, pk_len);
    if (ret) 
    {
        pr_err("ml_kem_api_test: ML-KEM-%u get public key failed: %d\n", bits, ret);
        goto out;
    }

    // New API: the caller supplies ciphertext and shared-secret buffers
    ret = ml_kem_encaps_core(NULL, pk, pk_len, ct, ct_len, ss_enc, sizeof(ss_enc), NULL);
    if (ret) 
    {
        pr_err("ml_kem_api_test: ML-KEM-%u encapsulation failed: %d\n", bits, ret);
        goto out;
    }

    ret = ml_kem_decaps_core(ctx, ct, ct_len, ss_dec, sizeof(ss_dec));
    if (ret) 
    {
        pr_err("ml_kem_api_test: ML-KEM-%u decapsulation failed: %d\n", bits, ret);
        goto out;
    }

    if (memcmp(ss_enc, ss_dec, sizeof(ss_enc)) != 0) {
        ret = -EINVAL;
        pr_err("ml_kem_api_test: ML-KEM-%u shared secrets differ\n", bits);
        goto out;
    }

    pr_info("ml_kem_api_test: ML-KEM-%u test passed\n", bits);
    ret = 0;

out:
    memzero_explicit(ss_enc, sizeof(ss_enc));
    memzero_explicit(ss_dec, sizeof(ss_dec));
    kfree(ct);
    kfree(pk);
    kfree_sensitive(sk);
    if(ctx) { ml_kem_destroy_core(ctx); }
    if(ctx_import) { ml_kem_destroy_core(ctx_import); }

    return ret;
}

static int __init ml_kem_api_test_init(void)
{
    int ret;

    pr_info("ml_kem_api_test: starting API tests\n");

    ret = ml_kem_api_test_level(ML_KEM_512, 512, 2, RES_PUBL_PART_LVL_512, LEN_CIPHERTEXT_512, LEN_SK_512);
    if (ret) { return ret; }

    ret = ml_kem_api_test_level(ML_KEM_768, 768, 4, RES_PUBL_PART_LVL_768, LEN_CIPHERTEXT_768, LEN_SK_768);
    if (ret) { return ret; }

    ret = ml_kem_api_test_level(ML_KEM_1024, 1024, 8, RES_PUBL_PART_LVL_1024, LEN_CIPHERTEXT_1024, LEN_SK_1024);
    if (ret) { return ret; }

    pr_info("ml_kem_api_test: all API tests passed\n");
    return 0;
}

static void __exit ml_kem_api_test_exit(void)
{
    pr_info("ml_kem_api_test: unloaded\n");
}

module_init(ml_kem_api_test_init);
module_exit(ml_kem_api_test_exit);

MODULE_LICENSE("Dual MIT/GPL");
MODULE_DESCRIPTION("ML-KEM Linux kernel API test");
MODULE_AUTHOR("K.S.Zavertailo");
