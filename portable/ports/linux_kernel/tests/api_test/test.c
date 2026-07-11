#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/errno.h>
#include <ml_kem.h>

static int __init ml_kem_api_test_init(void)
{
	// ptrs to pools
	struct ml_kem_pool_decaps_ctx *ctx_512 = NULL;
	struct ml_kem_pool_decaps_ctx *ctx_768 = NULL;
	struct ml_kem_pool_decaps_ctx *ctx_1024 = NULL;

	// ptrs to ciphertexts
	u8 *ct_512 = NULL;
	u8 *ct_768 = NULL;
	u8 *ct_1024 = NULL;

	// buffers for shared secrets and pk
	u8 ss_enc[ML_KEM_SEED_BYTES];
	u8 ss_dec[ML_KEM_SEED_BYTES];
	u8 pk[RES_PUBL_PART_LVL_1024];

	int ret = 0;

	pr_info("ml_kem_api_test: loaded\n");

	//----------------------Create-keys-------------------------------
	ctx_512 = ml_kem_create_object(ML_KEM_512, 2, NULL);
	if (!ctx_512) 
	{
		pr_info("ML-KEM-512 create failed\n");
		return -EINVAL;
	}

	ctx_768 = ml_kem_create_object(ML_KEM_768, 4, NULL);
	if (!ctx_768) 
	{
		pr_info("ML-KEM-768 create failed\n");
		ret = -EINVAL;
		goto out;
	}

	ctx_1024 = ml_kem_create_object(ML_KEM_1024, 8, NULL);
	if (!ctx_1024) 
	{
		pr_info("ML-KEM-1024 create failed\n");
		ret = -EINVAL;
		goto out;
	}

	//-------------------------Test-512-level------------------------------
	ret = ml_kem_get_public_key(ctx_512, pk, RES_PUBL_PART_LVL_512);
	if (ret != 0) { pr_info("Failed to get pk 512 level\n"); goto out; }

	ct_512 = ml_kem_encaps_core(pk, ML_KEM_512, ss_enc, NULL);
	if (!ct_512) 
	{
		ret = -EINVAL;
		pr_info("Failed in encaps 512 level\n");
		goto out;
	}

	ret = ml_kem_decaps_core(ctx_512, ct_512, LEN_CIPHERTEXT_512, ss_dec, ML_KEM_SEED_BYTES);
	if (ret || memcmp(ss_enc, ss_dec, ML_KEM_SEED_BYTES)) 
	{
		pr_info("ML-KEM-512 test decaps failed\n");
		ret = -EINVAL;
		goto out;
	}

	pr_info("ML-KEM-512 test passed\n");

	//-------------------------Test-768-level------------------------------
	ret = ml_kem_get_public_key(ctx_768, pk, RES_PUBL_PART_LVL_768);
	if (ret != 0) { pr_info("Failed to get pk 768 level\n"); goto out; }

	ct_768 = ml_kem_encaps_core(pk, ML_KEM_768, ss_enc, NULL);
	if (!ct_768) 
	{
		pr_info("Failed in encaps 768 level\n");
		ret = -EINVAL;
		goto out;
	}

	ret = ml_kem_decaps_core(ctx_768, ct_768, LEN_CIPHERTEXT_768, ss_dec, ML_KEM_SEED_BYTES);
	if (ret || memcmp(ss_enc, ss_dec, ML_KEM_SEED_BYTES)) 
	{
		pr_info("ML-KEM-768 test failed\n");
		ret = -EINVAL;
		goto out;
	}

	pr_info("ML-KEM-768 test passed\n");

	//-------------------------Test-1024-level------------------------------
	ret = ml_kem_get_public_key(ctx_1024, pk, RES_PUBL_PART_LVL_1024);
	if (ret != 0) { pr_info("Failed to get pk 1024 level\n"); goto out; }

	ct_1024 = ml_kem_encaps_core(pk, ML_KEM_1024, ss_enc, NULL);
	if (!ct_1024) 
	{
		pr_info("Failed in encaps 1024 level\n");
		ret = -EINVAL;
		goto out;
	}

	ret = ml_kem_decaps_core(ctx_1024, ct_1024, LEN_CIPHERTEXT_1024, ss_dec, ML_KEM_SEED_BYTES);
	if (ret || memcmp(ss_enc, ss_dec, ML_KEM_SEED_BYTES)) 
	{
		pr_info("ML-KEM-1024 test failed\n");
		ret = -EINVAL;
		goto out;
	}

	pr_info("ML-KEM-1024 test passed\n");

	// Exit
	out:
		ml_kem_ciphertext_destroy_core(ct_1024, ML_KEM_1024);
		ml_kem_ciphertext_destroy_core(ct_768, ML_KEM_768);
		ml_kem_ciphertext_destroy_core(ct_512, ML_KEM_512);
		ml_kem_destroy_core(ctx_1024);
		ml_kem_destroy_core(ctx_768);
		ml_kem_destroy_core(ctx_512);

	return ret;
}

// Exit from test
static void __exit ml_kem_api_test_exit(void)
{
	pr_info("ml_kem_api_test: unloaded\n");
}

module_init(ml_kem_api_test_init);
module_exit(ml_kem_api_test_exit);

MODULE_LICENSE("Dual MIT/GPL");
MODULE_DESCRIPTION("ML-KEM Linux kernel API test");
MODULE_AUTHOR("K.S.Zavertailo");
