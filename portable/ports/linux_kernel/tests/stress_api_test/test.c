// SPDX-License-Identifier: GPL-2.0 OR MIT
// Copyright (c) 2026 K.S.Zavertailo

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/err.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/sched.h>
#include <linux/moduleparam.h>

#include <ml_kem.h>

 // Number of encapsulation/decapsulation cycles per ML-KEM level.
 // Can be changed while loading the module:
 // sudo insmod stress_api_test.ko iterations=100000
static unsigned int iterations = 10000;
module_param(iterations, uint, 0444);
MODULE_PARM_DESC(iterations, "Number of encapsulation/decapsulation iterations per ML-KEM level");

 // Number of slots in the reusable decapsulation pool.
 // This test is single-threaded, so one slot would technically be enough.
 // Four slots are used to test ordinary pool initialization as well.
static unsigned int pool_slots = 4;
module_param(pool_slots, uint, 0444);
MODULE_PARM_DESC(pool_slots, "Number of slots in the ML-KEM decapsulation pool");

 // Return the serialized public-key length for a parameter set.
static size_t ml_kem_test_pk_len(enum ml_kem_k level)
{
	if(level == ML_KEM_512) { return RES_PUBL_PART_LVL_512; }
	else if(level == ML_KEM_768) { return RES_PUBL_PART_LVL_768; }
	else if(level == ML_KEM_1024) { return RES_PUBL_PART_LVL_1024; }
	else { return 0; }
}

 // Return the ciphertext length for a parameter set.
static size_t ml_kem_test_ct_len(enum ml_kem_k level)
{
	if(level == ML_KEM_512) { return LEN_CIPHERTEXT_512; }
	else if(level == ML_KEM_768) { return LEN_CIPHERTEXT_768; }
	else if(level == ML_KEM_1024) { return LEN_CIPHERTEXT_1024; }
	else { return 0; }
}

 // Human-readable parameter-set name for kernel messages.
static const char *ml_kem_test_level_name(enum ml_kem_k level)
{
	if(level == ML_KEM_512) { return "ML-KEM-512"; }
	else if(level == ML_KEM_768) { return "ML-KEM-768"; }
	else if(level == ML_KEM_1024) { return "ML-KEM-1024"; }
	else { return "ML-KEM-UNKNOWN"; }
}


 // Run the stress test for one ML-KEM parameter set.
 // Test sequence:
 //   create pool
 //       |
 //   export public key
 //       |
 //  repeat N times:
 //        encapsulate
 //        decapsulate
 //        compare shared secrets
 //        destroy ciphertext
 //        |
 //   destroy pool
static int ml_kem_run_stress_test(enum ml_kem_k level)
{
	struct ml_kem_pool_decaps_ctx *pool = NULL;
	u8 *public_key = NULL;
	u8 *ciphertext = NULL;

	u8 ss_enc[ML_KEM_SEED_BYTES];
	u8 ss_dec[ML_KEM_SEED_BYTES];

	const char *level_name;
	size_t public_key_len;
	size_t ciphertext_len;

	unsigned int i;
	int ret = 0;

	level_name = ml_kem_test_level_name(level);
	public_key_len = ml_kem_test_pk_len(level);
	ciphertext_len = ml_kem_test_ct_len(level);

	if (public_key_len == 0 || ciphertext_len == 0) { return -EINVAL; }

	pr_info("ml_kem_stress: starting %s, iterations=%u, pool_slots=%u\n", level_name, iterations, pool_slots);

	 // Allocate the test-owned public-key buffer outside the kernel stack.
	 // The largest public key is 1568 bytes, so avoiding a large local
	 // stack buffer is preferable inside kernel code.
	public_key = kzalloc(public_key_len, GFP_KERNEL);
	if (!public_key) 
	{
		pr_err("ml_kem_stress: %s public-key allocation failed\n", level_name);
		return -ENOMEM;
	}

	 // The kernel port returns either a valid pointer or ERR_PTR(error).
	pool = ml_kem_create_object(level, pool_slots, NULL);
	if (IS_ERR(pool)) 
	{
		ret = PTR_ERR(pool);
		pool = NULL;
		pr_err("ml_kem_stress: %s pool creation failed: %d\n", level_name, ret);
		goto out;
	}

	if (!pool) 
	{
		ret = -EFAULT;
		pr_err("ml_kem_stress: %s pool creation returned NULL\n", level_name);
		goto out;
	}

	ret = ml_kem_get_public_key(pool, public_key, public_key_len);
	if (ret != 0) 
	{
		pr_err("ml_kem_stress: %s get-public-key failed: %d\n", level_name, ret);
		goto out;
	}

	for (i = 0; i < iterations; i++) 
	{
		memzero_explicit(ss_enc, sizeof(ss_enc));
		memzero_explicit(ss_dec, sizeof(ss_dec));

		ciphertext = ml_kem_encaps_core(public_key, level, ss_enc, NULL);

		if (IS_ERR(ciphertext)) 
		{
			ret = PTR_ERR(ciphertext);
			ciphertext = NULL;
			pr_err("ml_kem_stress: %s encapsulation failed at iteration %u: %d\n", level_name, i, ret);
			goto out;
		}

		if (!ciphertext) 
		{
			ret = -EFAULT;
			pr_err("ml_kem_stress: %s encapsulation returned NULL at iteration %u\n", level_name, i);
			goto out;
		}

		ret = ml_kem_decaps_core(pool, ciphertext, ciphertext_len, ss_dec, ML_KEM_SEED_BYTES);
		if (ret != 0) 
		{
			pr_err("ml_kem_stress: %s decapsulation failed at iteration %u: %d\n", level_name, i, ret);
			goto out;
		}

		if (memcmp(ss_enc, ss_dec, ML_KEM_SEED_BYTES) != 0) 
		{
			ret = -EBADMSG;
			pr_err("ml_kem_stress: %s shared-secret mismatch at iteration %u\n", level_name, i);
			goto out;
		}

		ml_kem_ciphertext_destroy_core(ciphertext, level);
		ciphertext = NULL;

		 // Allow the scheduler to run other tasks during a long test.
		 // This does not affect the cryptographic implementation.
		if ((i & 0x3fU) == 0) { cond_resched(); }
	}

	pr_info("ml_kem_stress: %s passed all %u iterations\n", level_name, iterations);

out:
	 // ciphertext must only be passed to its destructor when it is a
	 // genuine allocated pointer. Passing ERR_PTR() would be invalid.
	if (ciphertext && !IS_ERR(ciphertext)) { ml_kem_ciphertext_destroy_core(ciphertext, level); }

	if (pool && !IS_ERR(pool)) { ml_kem_destroy_core(pool); }

	if (public_key) 
	{
		memzero_explicit(public_key, public_key_len);
		kfree(public_key);
	}

	memzero_explicit(ss_enc, sizeof(ss_enc));
	memzero_explicit(ss_dec, sizeof(ss_dec));

	return ret;
}

static int __init ml_kem_stress_test_init(void)
{
	int ret;

	pr_info("ml_kem_stress: module loaded\n");

	if (iterations == 0) 
	{
		pr_err("ml_kem_stress: iterations must be greater than zero\n");
		return -EINVAL;
	}

	if (pool_slots == 0 || pool_slots > ML_KEM_MAX_POOL_SLOTS) 
	{
		pr_err("ml_kem_stress: invalid pool_slots=%u; valid range is 1..%u\n", pool_slots, ML_KEM_MAX_POOL_SLOTS);
		return -EINVAL;
	}

	ret = ml_kem_run_stress_test(ML_KEM_512);
	if (ret != 0) { return ret; }

	ret = ml_kem_run_stress_test(ML_KEM_768);
	if (ret != 0) { return ret; }

	ret = ml_kem_run_stress_test(ML_KEM_1024);
	if (ret != 0) { return ret; }

	pr_info("ml_kem_stress: all parameter sets passed\n");

	return 0;
}

static void __exit ml_kem_stress_test_exit(void)
{
	pr_info("ml_kem_stress: module unloaded\n");
}

module_init(ml_kem_stress_test_init);
module_exit(ml_kem_stress_test_exit);

MODULE_LICENSE("Dual MIT/GPL");
MODULE_DESCRIPTION("ML-KEM Linux kernel API stress test");
MODULE_AUTHOR("K.S.Zavertailo");
