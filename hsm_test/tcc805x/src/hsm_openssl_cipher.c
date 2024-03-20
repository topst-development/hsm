/*******************************************************************************

*   Copyright (c) Telechips Inc.


*   TCC Version 1.0

This source code contains confidential information of Telechips.

Any unauthorized use without a written permission of Telechips including not
limited to re-distribution in source or binary form is strictly prohibited.

This source code is provided "AS IS" and nothing contained in this source code
shall constitute any express or implied warranty of any kind, including without
limitation, any warranty of merchantability, fitness for a particular purpose
or non-infringement of any patent, copyright or other third party intellectual
property right.
No warranty is made, express or implied, regarding the information's accuracy,
completeness, or performance.

In no event shall Telechips be liable for any claim, damages or other
liability arising from, out of or in connection with this source code or
the use in the source code.

This source code is provided subject to the terms of a Mutual Non-Disclosure
Agreement between Telechips and Company.
*
*******************************************************************************/
//#define NDEBUG
#define TLOG_LEVEL TLOG_DEBUG
#include "hsm_log.h"

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <sys/ioctl.h>

#include "hsm_cipher.h"
#include "hsm_cipher_text.h"

/* openssl */
#include "openssl/aes.h"
#include "openssl/hmac.h"
#include "openssl/rsa.h"
#include "openssl/sha.h"

#include "openssl/ec.h"
#include "openssl/bn.h"
#include "openssl/err.h"
#include "openssl/ossl_typ.h"

#include "crypto/sm3.h"
#include "crypto/sm4.h"

#define HSM_OPENSSL_OK (1u)

typedef unsigned long ulong;

uint32_t hsm_openssl_run_aes(tcc_hsm_ioctl_aes_param *param)
{
    uint32_t i = 0;
	uint32_t ret = TCCHSM_ERR;
	uint32_t op_mode = 0;
	int32_t rv = 0;
	AES_KEY enc_key;
	SM4_KEY key;
    uint8_t iv[TCC_HSM_AES_IV_SIZE];
	EVP_CIPHER_CTX *ctx;

	op_mode = (param->obj_id & 0x00FFFFFFu);

	/* type of key size is bit  */
	if (AES_set_encrypt_key(param->key, param->key_size * 8, &enc_key) < 0) {
		return TCCHSM_ERR;
	}

    switch (param->obj_id) {
    case OID_AES_ECB_128:
    case OID_AES_ECB_192:
    case OID_AES_ECB_256:
        for (i = 0; i < (param->src_size / TCC_AES_ECB_OFFSET); i++) {
            AES_encrypt(
                (uint8_t *)((ulong)param->src + i * TCC_AES_ECB_OFFSET),
                (uint8_t *)((ulong)param->dst + i * TCC_AES_ECB_OFFSET), &enc_key);
        }
		ret = TCCHSM_SUCCESS;
		break;

    case OID_AES_CBC_128:
    case OID_AES_CBC_192:
    case OID_AES_CBC_256:
        /* IV is changed by AES_cbc_encrypt */
        memcpy(iv, param->iv, param->iv_size);
        AES_cbc_encrypt(
            (uint8_t *)(ulong)param->src, (uint8_t *)(ulong)param->dst, param->src_size, &enc_key, iv,
            AES_ENCRYPT);
		ret = TCCHSM_SUCCESS;
		break;

	case (OID_AES_CCM_128 | OID_AES_ENCRYPT):
	case (OID_AES_CCM_192 | OID_AES_ENCRYPT):
	case (OID_AES_CCM_256 | OID_AES_ENCRYPT):
		ctx = EVP_CIPHER_CTX_new();

		/* Set cipher type and mode */
		if (op_mode == OID_AES_CCM_128) {
			EVP_EncryptInit_ex(ctx, EVP_aes_128_ccm(), NULL, NULL, NULL);
		} else if (op_mode == OID_AES_CCM_192) {
			EVP_EncryptInit_ex(ctx, EVP_aes_192_ccm(), NULL, NULL, NULL);
		} else if (op_mode == OID_AES_CCM_256) {
			EVP_EncryptInit_ex(ctx, EVP_aes_256_ccm(), NULL, NULL, NULL);
		} else {
			ELOG("Invalid operation mode(0x%x)\n", op_mode);
			EVP_CIPHER_CTX_free(ctx);
			break;
		}
		/* Set nonce length if default 96 bits is not appropriate */
		EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, param->iv_size, NULL);
		/* Set tag length */
		EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, param->tag_size, NULL);
		/* Initialise key and IV */
		EVP_EncryptInit_ex(ctx, NULL, NULL, param->key, param->iv);
		/* Set plaintext length: only needed if AAD is used */
		EVP_EncryptUpdate(ctx, NULL, &param->src_size, NULL, param->src_size);
		/* Zero or one call to specify any AAD */
		EVP_EncryptUpdate(ctx, NULL, &param->aad_size, param->aad, param->aad_size);
		/* Encrypt plaintext: can only be called once */
		EVP_EncryptUpdate(
			ctx, (uint8_t *)param->dst, &param->dst_size, (uint8_t *)param->src, param->src_size);
		/* Finalise: note get no output for CCM */
		EVP_EncryptFinal_ex(ctx, (uint8_t *)param->dst, &param->dst_size);
		/* Get tag */
		EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, 16, param->tag);
		EVP_CIPHER_CTX_free(ctx);

		ret = TCCHSM_SUCCESS;
		break;

	case (OID_AES_CCM_128 | OID_AES_DECRYPT):
	case (OID_AES_CCM_192 | OID_AES_DECRYPT):
	case (OID_AES_CCM_256 | OID_AES_DECRYPT):
		ctx = EVP_CIPHER_CTX_new();

		/* Set cipher type and mode */
		if (op_mode == OID_AES_CCM_128) {
			EVP_DecryptInit_ex(ctx, EVP_aes_128_ccm(), NULL, NULL, NULL);
		} else if (op_mode == OID_AES_CCM_192) {
			EVP_DecryptInit_ex(ctx, EVP_aes_192_ccm(), NULL, NULL, NULL);
		} else if (op_mode == OID_AES_CCM_256) {
			EVP_DecryptInit_ex(ctx, EVP_aes_256_ccm(), NULL, NULL, NULL);
		} else {
			ELOG("Invalid operation mode(0x%x)\n", op_mode);
			EVP_CIPHER_CTX_free(ctx);
			break;
		}

		/* Set nonce length, omit for 96 bits */
		EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, param->iv_size, NULL);
		/* Set expected tag value */
		EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, param->tag_size, param->tag);
		/* Specify key and IV */
		EVP_DecryptInit_ex(ctx, NULL, NULL, param->key, param->iv);
		/* Set ciphertext length: only needed if we have AAD */
		EVP_DecryptUpdate(ctx, NULL, &param->src_size, NULL, param->src_size);
		/* Zero or one call to specify any AAD */
		EVP_DecryptUpdate(ctx, NULL, &param->aad_size, param->aad, param->aad_size);
		/* Decrypt plaintext, verify tag: can only be called once */
		rv = EVP_DecryptUpdate(
			ctx, (uint8_t *)param->dst, &param->dst_size, (uint8_t *)param->src, param->src_size);

		if (rv <= 0) {
			ELOG("EVP_DecryptFinal_ex fail");
			ret = TCCHSM_ERR;
		} else {
			ret = TCCHSM_SUCCESS;
		}

		EVP_CIPHER_CTX_free(ctx);

		break;

	case (OID_AES_GCM_128 | OID_AES_ENCRYPT):
	case (OID_AES_GCM_192 | OID_AES_ENCRYPT):
	case (OID_AES_GCM_256 | OID_AES_ENCRYPT):
		ctx = EVP_CIPHER_CTX_new();

		/* Set cipher type and mode */
		if (op_mode == OID_AES_GCM_128) {
			EVP_EncryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, NULL, NULL);
		} else if (op_mode == OID_AES_GCM_192) {
			EVP_EncryptInit_ex(ctx, EVP_aes_192_gcm(), NULL, NULL, NULL);
		} else if (op_mode == OID_AES_GCM_256) {
			EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL);
		} else {
			ELOG("Invalid operation mode(0x%x)\n", op_mode);
			EVP_CIPHER_CTX_free(ctx);
			break;
		}

		/* Set IV length if default 96 bits is not appropriate */
		EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, param->iv_size, NULL);
		/* Initialise key and IV */
		EVP_EncryptInit_ex(ctx, NULL, NULL, param->key, param->iv);
		/* Zero or more calls to specify any AAD */
		EVP_EncryptUpdate(ctx, NULL, &param->aad_size, param->aad, param->aad_size);
		/* Encrypt plaintext */
		EVP_EncryptUpdate(
			ctx, (uint8_t *)param->dst, &param->dst_size, (uint8_t *)param->src, param->src_size);
		/* Finalise: note get no output for GCM */
		EVP_EncryptFinal_ex(ctx, (uint8_t *)param->dst, &param->dst_size);
		/* Get tag */
		EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, 16, param->tag);
		EVP_CIPHER_CTX_free(ctx);

		ret = TCCHSM_SUCCESS;
		break;

	case (OID_AES_GCM_128 | OID_AES_DECRYPT):
	case (OID_AES_GCM_192 | OID_AES_DECRYPT):
	case (OID_AES_GCM_256 | OID_AES_DECRYPT):
		ctx = EVP_CIPHER_CTX_new();

		/* Set cipher type and mode */
		if (op_mode == OID_AES_GCM_128) {
			EVP_DecryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, NULL, NULL);
		} else if (op_mode == OID_AES_GCM_192) {
			EVP_DecryptInit_ex(ctx, EVP_aes_192_gcm(), NULL, NULL, NULL);
		} else if (op_mode == OID_AES_GCM_256) {
			EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL);
		} else {
			ELOG("Invalid operation mode(0x%x)\n", op_mode);
			EVP_CIPHER_CTX_free(ctx);
			break;
		}

		/* Set IV length if default 96 bits is not appropriate */
		EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, param->iv_size, NULL);
		/* Initialise key and IV */
		EVP_DecryptInit_ex(ctx, NULL, NULL, param->key, param->iv);
		/* Zero or more calls to specify any AAD */
		EVP_DecryptUpdate(ctx, NULL, &param->aad_size, param->aad, param->aad_size);
		/* Encrypt plaintext */
		EVP_DecryptUpdate(
			ctx, (uint8_t *)param->dst, &param->dst_size, (uint8_t *)param->src, param->src_size);
		/* Set expected tag value. */
		EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, param->tag_size, (void *)param->tag);
		/* Finalise: note get no output for GCM */
		rv = EVP_DecryptFinal_ex(ctx, (uint8_t *)param->dst, &param->dst_size);
		if (rv <= 0) {
			ELOG("EVP_DecryptFinal_ex fail");
			ret = TCCHSM_ERR;
		} else {
			ret = TCCHSM_SUCCESS;
		}

		EVP_CIPHER_CTX_free(ctx);
		break;

	case OID_SM4_ECB_128_OPENSSL:
        if (SM4_set_key(param->key, &key) < 0) {
			return TCCHSM_ERR;
		}
        for (i = 0; i < (param->src_size / TCC_AES_ECB_OFFSET); i++) {
            SM4_encrypt(
                (uint8_t *)((ulong)param->src + i * TCC_AES_ECB_OFFSET),
                (uint8_t *)((ulong)param->dst + i * TCC_AES_ECB_OFFSET), &key);
        }
		ret = TCCHSM_SUCCESS;
		break;
    default:
        ELOG("Invalid object type\n");
		ret = TCCHSM_ERR_INVALID_PARAM;
		break;
    }

    return ret;
}

uint32_t hsm_openssl_gen_hash(tcc_hsm_ioctl_hash_param *param)
{
    switch (param->obj_id) {
    case OID_SHA1_160: {
        SHA_CTX ctx;

        SHA1_Init(&ctx);
        SHA1_Update(&ctx, (const void *)(ulong)param->src, param->src_size);
        SHA1_Final(param->digest, &ctx);
        break;
    }

    case OID_SM3_256: {
        SM3_CTX ctx;

        sm3_init(&ctx);
        sm3_update(&ctx, (const void *)(ulong)param->src, param->src_size);
        sm3_final(param->digest, &ctx);
        break;
    }
    default:
        ELOG("Invalid object type\n");
		return TCCHSM_ERR_INVALID_PARAM;
	}

	return TCCHSM_SUCCESS;
}

uint32_t hsm_openssl_gen_mac(uint32_t cmd, tcc_hsm_ioctl_mac_param *param)
{
	uint32_t ret = TCCHSM_ERR;
	uint32_t len = EVP_MAX_MD_SIZE;
    HMAC_CTX *ctx;

    switch (cmd) {
    case HSM_GEN_CMAC_VERIFY_CMD:
        ELOG("Not yet supported \n");
        break;

    case HSM_GEN_GMAC_CMD:
        ELOG("Not yet supported \n");
        break;

    case HSM_GEN_SM3_HMAC_CMD:
    case HSM_GEN_SM3_HMAC_BY_KT_CMD:
        ctx = HMAC_CTX_new();
        HMAC_Init_ex(ctx, param->key, (int32_t)param->key_size, EVP_sm3(), NULL);
        HMAC_Update(ctx, (const uint8_t *)(ulong)param->src, param->src_size);
        HMAC_Final(ctx, param->mac, &len);
        HMAC_CTX_free(ctx);
		ret = TCCHSM_SUCCESS;
		break;

    case HSM_GEN_HMAC_CMD:
    case HSM_GEN_HMAC_BY_KT_CMD:
        ctx = HMAC_CTX_new();
        HMAC_Init_ex(ctx, param->key, (int32_t)param->key_size, EVP_sha1(), NULL);
        HMAC_Update(ctx, (const uint8_t *)(ulong)param->src, param->src_size);
        HMAC_Final(ctx, param->mac, &len);
        HMAC_CTX_free(ctx);
		ret = TCCHSM_SUCCESS;
		break;

    default:
        ELOG("Invalid cmd(0x%x)\n", cmd);
        return ret;
    }

    return ret;
}

static uint32_t hsm_openssl_encode_ecdsa_sig(
    uint8_t *signature, uint32_t signatureLen, uint8_t *derSign, uint32_t *derSignLen)
{
	uint32_t ret = TCCHSM_ERR_INVALID_STATE;
	ECDSA_SIG *ecdsaSign = NULL;

    ecdsaSign = ECDSA_SIG_new();
    if (ecdsaSign == NULL) {
        ELOG("ECDSA_SIG_new error, error code\n");
		ret = TCCHSM_ERR_INVALID_STATE;
		goto exit;
    }

    ECDSA_SIG_set0(
        ecdsaSign, BN_bin2bn((uint8_t *)signature, signatureLen / 2, NULL),
        BN_bin2bn((uint8_t *)signature + (signatureLen / 2), signatureLen / 2, NULL));
    *derSignLen = i2d_ECDSA_SIG(ecdsaSign, NULL);

    if (derSign == NULL) {
		ret = TCCHSM_ERR_INVALID_MEMORY;
		goto exit;
    }

    i2d_ECDSA_SIG(ecdsaSign, &derSign);

	ret = TCCHSM_SUCCESS;

exit:
    if (ecdsaSign != NULL) {
        ECDSA_SIG_free(ecdsaSign);
    }

    return ret;
}

static uint32_t hsm_openssl_decode_ecdsa_sig(uint8_t *signature, size_t *signatureLen)
{
    uint32_t ret = 1;
    ECDSA_SIG *ecdsaSign = NULL;
    uint8_t *derBuf;
    BIGNUM *r;
    BIGNUM *s;
    uint8_t *bufR = NULL;
    uint8_t *bufS = NULL;
    uint32_t bufRSize;
    uint32_t bufSSize;

    ecdsaSign = ECDSA_SIG_new();
    if (ecdsaSign == NULL) {
        ELOG("ECDSA_SIG_new error, error code : %s", ERR_error_string(ERR_get_error(), NULL));
		ret = TCCHSM_ERR_INVALID_STATE;
		goto exit;
    }

    derBuf = signature;
    d2i_ECDSA_SIG(&ecdsaSign, (const uint8_t **)&derBuf, *signatureLen);
    ECDSA_SIG_get0(ecdsaSign, (const BIGNUM **)&r, (const BIGNUM **)&s);

    bufR = OPENSSL_malloc(*signatureLen);
    if (bufR == NULL) {
		ret = TCCHSM_ERR_INVALID_MEMORY;
		goto exit;
    }

    bufS = OPENSSL_malloc(*signatureLen);
    if (bufS == NULL) {
		ret = TCCHSM_ERR_INVALID_MEMORY;
		goto exit;
    }

    bufRSize = BN_bn2binpad(r, bufR, 64 / 2);
    bufSSize = BN_bn2binpad(s, bufS, 64 / 2);

    /* Update real signature length */
    *signatureLen = bufRSize + bufSSize;

    /* Update decoded signature data */
    memcpy(signature, bufR, bufRSize);
    memcpy(signature + bufSSize, bufS, bufSSize);

	ret = TCCHSM_SUCCESS;
exit:
    if (bufR != NULL) {
        OPENSSL_free(bufR);
    }

    if (bufS != NULL) {
        OPENSSL_free(bufS);
    }

    if (ecdsaSign != NULL) {
        ECDSA_SIG_free(ecdsaSign);
    }

    return ret;
}

static uint32_t hsm_openssl_get_padding(uint32_t cmd)
{
    switch (cmd) {
    case HSM_RUN_RSASSA_PKCS_SIGN_CMD:
    case HSM_RUN_RSASSA_PKCS_VERIFY_CMD:
        return RSA_PKCS1_PADDING;
    case HSM_RUN_RSASSA_PSS_SIGN_CMD:
    case HSM_RUN_RSASSA_PSS_VERIFY_CMD:
        return RSA_PKCS1_PSS_PADDING;
    default:
        ELOG("Not yet supported obj_id(0x%x)\n", cmd);
		return TCCHSM_ERR_INVALID_PARAM;
	}
}

static uint32_t hsm_openssl_get_curve_name(uint32_t obj_id)
{
    switch (obj_id) {
    case OID_ECC_P256:
        return NID_X9_62_prime256v1;
    case OID_ECC_P384:
        return NID_secp384r1;
    case OID_ECC_P521:
        return NID_secp521r1;
    case OID_ECC_BP256:
        return NID_brainpoolP256r1;
    case OID_ECC_BP384:
        return NID_brainpoolP384r1;
    case OID_ECC_BP512:
        return NID_brainpoolP512r1;
    case OID_SM2_256_SM3_256:
    default:
        ELOG("Not yet supported obj_id(0x%x)\n", obj_id);
		return TCCHSM_ERR_INVALID_PARAM;
	}
}

static uint32_t hsm_openssl_alloc_keyHandle(
    uint32_t cmd, RSA *rsa_key, EC_KEY *ec_key, EVP_PKEY **pkey, EVP_PKEY_CTX **pkey_ctx)
{
	uint32_t ret = TCCHSM_ERR;

	/* Create pKey */
    *pkey = EVP_PKEY_new();
    if (*pkey == NULL) {
        ELOG("EVP_PKEY_new error, error code\n");
		ret = TCCHSM_ERR_INVALID_MEMORY;
		goto err;
    }

    switch (cmd) {
    case HSM_RUN_RSASSA_PKCS_SIGN_CMD:
    case HSM_RUN_RSASSA_PKCS_VERIFY_CMD:
    case HSM_RUN_RSASSA_PSS_SIGN_CMD:
    case HSM_RUN_RSASSA_PSS_VERIFY_CMD:
        /* Set pKey */
        ret = EVP_PKEY_assign_RSA(*pkey, rsa_key);
        if (ret != HSM_OPENSSL_OK) {
            ELOG("EVP_PKEY_set1_RSA fail(0x%x)\n", ret);
			ret = TCCHSM_ERR_INVALID_STATE;
			goto err;
        }
        /* Create pKey_ctx */
        *pkey_ctx = EVP_PKEY_CTX_new(*pkey, NULL);
        if (*pkey_ctx == NULL) {
            ELOG("Create pkey fail\n");
			ret = TCCHSM_ERR_INVALID_STATE;
			goto err;
        }

        /* Initialize pkey_ctx */
        ret = EVP_PKEY_sign_init(*pkey_ctx);
        if (ret != HSM_OPENSSL_OK) {
            ELOG("pkey init fail(0x%x)\n", ret);
			ret = TCCHSM_ERR_INVALID_STATE;
			goto err;
        }

        /* Set pkey_ctx padding */
        ret = EVP_PKEY_CTX_set_rsa_padding(*pkey_ctx, hsm_openssl_get_padding(cmd));
        if (ret != HSM_OPENSSL_OK) {
            ELOG("pkey set fail(0x%x)\n", ret);
			ret = TCCHSM_ERR_INVALID_STATE;
			goto err;
        }

        /* Set signature_md, Fix hash type to sha256 */
        ret = EVP_PKEY_CTX_set_signature_md(*pkey_ctx, EVP_sha256());
        if (ret != HSM_OPENSSL_OK) {
            ELOG("set signature_md fail(0x%x)\n", ret);
			ret = TCCHSM_ERR_INVALID_STATE;
			goto err;
        }

        /* Set salt length in casa of PSS*/
        if ((cmd == HSM_RUN_RSASSA_PSS_SIGN_CMD) || (cmd == HSM_RUN_RSASSA_PSS_VERIFY_CMD)) {
            ret = EVP_PKEY_CTX_set_rsa_pss_saltlen(*pkey_ctx, 32);
            if (ret != HSM_OPENSSL_OK) {
                ELOG("set signature_md fail(0x%x)\n", ret);
				ret = TCCHSM_ERR_INVALID_STATE;
				goto err;
            }
        }
        break;

    case HSM_RUN_ECDSA_SIGN_CMD:
    case HSM_RUN_ECDSA_VERIFY_CMD:
        ret = EVP_PKEY_assign_EC_KEY(*pkey, ec_key);
        if (ret != HSM_OPENSSL_OK) {
            ELOG("EVP_PKEY_assign_EC_KEY error(0x%x)\n", ret);
			ret = TCCHSM_ERR_INVALID_STATE;
			goto err;
        }
        /* Create pKey_ctx */
        *pkey_ctx = EVP_PKEY_CTX_new(*pkey, NULL);
        if (*pkey_ctx == NULL) {
            ELOG("Create pkey fail\n");
			ret = TCCHSM_ERR_INVALID_STATE;
			goto err;
        }

        if (cmd == HSM_RUN_ECDSA_SIGN_CMD) {
            /* Initialize pkey_ctx */
            ret = EVP_PKEY_sign_init(*pkey_ctx);

        } else if (cmd == HSM_RUN_ECDSA_VERIFY_CMD) {
            ret = EVP_PKEY_verify_init(*pkey_ctx);
        }
        if (ret != HSM_OPENSSL_OK) {
            ELOG("pkey init fail(0x%x)\n", ret);
			ret = TCCHSM_ERR_INVALID_STATE;
			goto err;
        }

        /* Set signature_md, Fix hash type to sha1 */
        ret = EVP_PKEY_CTX_set_signature_md(*pkey_ctx, EVP_sha1());
        if (ret != HSM_OPENSSL_OK) {
            ELOG("set signature_md fail(0x%x)\n", ret);
			ret = TCCHSM_ERR_INVALID_STATE;
			goto err;
        }
        break;

    default:
        ELOG("Invalid cmd(0x%x)\n", cmd);
		return TCCHSM_ERR_INVALID_PARAM;
	}

	return TCCHSM_SUCCESS;

err:
    if (*pkey_ctx != NULL) {
        EVP_PKEY_CTX_free(*pkey_ctx);
    }

    return ret;
}

uint32_t hsm_openssl_run_ecdsa(uint32_t cmd, tcc_hsm_ioctl_ecdsa_param *param)
{
    EVP_PKEY *pkey = NULL;
    EC_KEY *ec_key = NULL;
    EVP_PKEY_CTX *pkey_ctx = NULL;
    uint32_t curve = 0;
    BIGNUM *pri_key = NULL;
    BIGNUM *pub_key_x = NULL;
    BIGNUM *pub_key_y = NULL;
    uint8_t *out = NULL;
    uint32_t out_len = 0;
	uint32_t ret = TCCHSM_ERR;
	uint32_t ecdsaDerSignSize = 0;
    uint8_t *ecdsaDerSign = NULL;

    ec_key = EC_KEY_new_by_curve_name(hsm_openssl_get_curve_name(param->obj_id));
    if (ec_key == NULL) {
        ELOG("EC_KEY_new_by_curve_name error, error code\n");
		ret = TCCHSM_ERR_INVALID_MEMORY;
		goto exit;
    }

    ret = hsm_openssl_alloc_keyHandle(cmd, NULL, ec_key, &pkey, &pkey_ctx);
	if (ret != TCCHSM_SUCCESS) {
		ELOG("Alloc keyHandle fail(0x%x)\n", ret);
		return TCCHSM_ERR_INVALID_STATE;
	}

    switch (cmd) {
    case HSM_RUN_ECDSA_SIGN_CMD:
        /* Set private key */
        pri_key = BN_bin2bn(param->key, param->key_size, NULL);
        ret = EC_KEY_set_private_key(ec_key, pri_key);
        BN_free(pri_key);
        if (ret != HSM_OPENSSL_OK) {
            ELOG("EC_KEY_set_private_key error(0x%x)\n", ret);
			ret = TCCHSM_ERR_INVALID_STATE;
			goto exit;
        }

        /* Get signature length */
        ret = EVP_PKEY_sign(pkey_ctx, NULL, (size_t *)&out_len, param->digest, param->digest_size);
        if (ret != HSM_OPENSSL_OK) {
            ELOG("rsa Signing(pss) fail(0x%x)\n", ret);
			ret = TCCHSM_ERR_INVALID_STATE;
			goto exit;
        }

        out = OPENSSL_malloc(out_len);
        if (out == NULL) {
			ret = TCCHSM_ERR_INVALID_STATE;
			goto exit;
        }
        memset(out, 0, out_len);


        ret = EVP_PKEY_sign(pkey_ctx, out, (size_t *)&out_len, param->digest, param->digest_size);
        if (ret != HSM_OPENSSL_OK) {
            ELOG("rsa Signing(pss) fail(0x%x)\n", ret);
			ret = TCCHSM_ERR_INVALID_STATE;
			goto exit;
        }

        /* output of EVP_PKEY_sign is der format,
         * So convert der format ro normal format */
        ret = hsm_openssl_decode_ecdsa_sig(out, (size_t *)&out_len);
		if (ret != TCCHSM_SUCCESS) {
			ELOG("Error Encode ECDSA signature");
			ret = TCCHSM_ERR_INVALID_STATE;
			goto exit;
        }
        memcpy(param->sig, out, param->sig_size);
		ret = TCCHSM_SUCCESS;

		break;

    case HSM_RUN_ECDSA_VERIFY_CMD:
        /* Set public key */
        pub_key_x = BN_bin2bn(&param->key[0], (param->key_size / 2), NULL);
        pub_key_y = BN_bin2bn(&param->key[(param->key_size / 2)], (param->key_size / 2), NULL);
        ret = EC_KEY_set_public_key_affine_coordinates(ec_key, pub_key_x, pub_key_y);
        BN_free(pub_key_x);
        BN_free(pub_key_y);
        if (ret != HSM_OPENSSL_OK) {
            ELOG("EC_KEY_set_public_key_affine_coordinates error(0x%x)\n", ret);
			ret = TCCHSM_ERR_INVALID_MEMORY;
			goto exit;
        }

        /* Get sig_size of der format */
        ret = hsm_openssl_encode_ecdsa_sig(param->sig, param->sig_size, NULL, &ecdsaDerSignSize);
		if (ret != TCCHSM_ERR_INVALID_MEMORY) {
			ret = TCCHSM_ERR_INVALID_STATE;
			goto exit;
        }

        ecdsaDerSign = OPENSSL_malloc(ecdsaDerSignSize);
        if (ecdsaDerSign == NULL) {
            TRACE;
			ret = TCCHSM_ERR_INVALID_STATE;
			goto exit;
        }

        /* Input of EVP_PKEY_verify is der format,
         * So convert normal format ro der format */
        ret = hsm_openssl_encode_ecdsa_sig(
            param->sig, param->sig_size, ecdsaDerSign, &ecdsaDerSignSize);
		if (ret != TCCHSM_SUCCESS) {
			TRACE;
			ret = TCCHSM_ERR_INVALID_STATE;
			goto exit;
        }

        ret = EVP_PKEY_verify(
            pkey_ctx, ecdsaDerSign, ecdsaDerSignSize, param->digest, param->digest_size);
        if (ret != HSM_OPENSSL_OK) {
            ELOG("rsa EVP_PKEY_verify(pss) fail(0x%x)\n", ret);
			ret = TCCHSM_ERR_INVALID_STATE;
			goto exit;
        }
		ret = TCCHSM_SUCCESS;
		break;

    default:
        ELOG("Invalid cmd(0x%x)\n", cmd);
        break;
    }

exit:
#ifndef __ANDROID__ // To avoid segmentation fault in Android build
    if (pkey_ctx != NULL) {
        EVP_PKEY_CTX_free(pkey_ctx);
    }
#endif
    if (ec_key != NULL) {
        EC_KEY_free(ec_key);
    }
    if (ecdsaDerSign != NULL) {
        OPENSSL_free(ecdsaDerSign);
    }
    if (out != NULL) {
        OPENSSL_free(out);
    }

    return ret;
}

uint32_t hsm_openssl_run_rsa(uint32_t cmd, tcc_hsm_ioctl_rsassa_param *param)
{
    RSA *rsa_key = NULL;
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *pkey_ctx = NULL;
	uint32_t ret = TCCHSM_ERR;

	/* Create RSA Key */
    rsa_key = RSA_new();
    if (rsa_key == NULL) {
        ELOG("RSA_new error, error code\n");
		return TCCHSM_ERR_INVALID_MEMORY;
	}

    /* Set RSA Key */
    ret = RSA_set0_key(
        rsa_key, BN_bin2bn((uint8_t *)param->modN, param->modN_size, NULL),
        BN_bin2bn(rsa_pubkey, sizeof(rsa_pubkey), NULL),
        BN_bin2bn((uint8_t *)(ulong)param->key, param->key_size, NULL));
    if (ret != HSM_OPENSSL_OK) {
        ELOG("RSA_set0_key fail(0x%x)\n", ret);
		return TCCHSM_ERR_INVALID_STATE;
	}

    ret = hsm_openssl_alloc_keyHandle(cmd, rsa_key, NULL, &pkey, &pkey_ctx);
	if (ret != TCCHSM_SUCCESS) {
		ELOG("Alloc keyHandle fail(0x%x)\n", ret);
		return TCCHSM_ERR_INVALID_STATE;
	}

    switch (cmd) {
    case HSM_RUN_RSASSA_PKCS_SIGN_CMD:
    case HSM_RUN_RSASSA_PSS_SIGN_CMD:
        ret = EVP_PKEY_sign(
            pkey_ctx, param->sig, (size_t *)&param->sig_size, param->digest, param->digest_size);
        if (ret != HSM_OPENSSL_OK) {
            ELOG("rsa Signing(pss) fail(0x%x)\n", ret);
			ret = TCCHSM_ERR_INVALID_STATE;
			goto exit;
        }
		ret = TCCHSM_SUCCESS;
		break;

    case HSM_RUN_RSASSA_PKCS_VERIFY_CMD:
    case HSM_RUN_RSASSA_PSS_VERIFY_CMD:
        ret = EVP_PKEY_verify_init(pkey_ctx);
        if (ret != HSM_OPENSSL_OK) {
            ELOG("EVP_PKEY_verify_init error(0x%x)\n", ret);
			ret = TCCHSM_ERR_INVALID_STATE;
			goto exit;
        }
        ret = EVP_PKEY_verify(
            pkey_ctx, param->sig, param->sig_size, param->digest, param->digest_size);
        if (ret != HSM_OPENSSL_OK) {
            ELOG("rsa EVP_PKEY_verify(pss) fail(0x%x)\n", ret);
			ret = TCCHSM_ERR_INVALID_STATE;
			goto exit;
        }
		ret = TCCHSM_SUCCESS;
		break;

    default:
        ELOG("Invalid cmd type(0x%x)\n", cmd);
		ret = TCCHSM_ERR_INVALID_PARAM;
		break;
    }

exit:
    if (rsa_key != NULL) {
        RSA_free(rsa_key);
    }
    if (pkey_ctx != NULL) {
        EVP_PKEY_CTX_free(pkey_ctx);
    }
    return ret;
}

uint32_t hsm_openssl_get_rand(tcc_hsm_ioctl_rng_param *param)
{
    ELOG("Not yet supported\n");

	return TCCHSM_SUCCESS;
}
