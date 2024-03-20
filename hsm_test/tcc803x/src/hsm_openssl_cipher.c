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

#include "hsm_common.h"
#include "hsm_cipher.h"
#include "hsm_cipher_text.h"
#include "hsm_openssl_cipher.h"

/* openssl */
#include "openssl/aes.h"
#include "openssl/des.h"
#include "openssl/cmac.h"
#include "openssl/rsa.h"
#include "openssl/sha.h"

#include "openssl/ec.h"
#include "openssl/bn.h"
#include "openssl/err.h"
#include "openssl/ossl_typ.h"

#include "crypto/sm3.h"
#include "crypto/sm4.h"
static void HexDump(const void *data, uint32_t size)
{
    int8_t ascii[17];
    size_t i, j;
    ascii[16] = '\0';
    for (i = 0; i < size; ++i) {
        BLOG("%02X ", ((uint8_t *)data)[i]);
        if (((uint8_t *)data)[i] >= ' ' && ((uint8_t *)data)[i] <= '~') {
            ascii[i % 16] = ((uint8_t *)data)[i];
        } else {
            ascii[i % 16] = '.';
        }
        if ((i + 1) % 8 == 0 || i + 1 == size) {
            BLOG(" ");
            if ((i + 1) % 16 == 0) {
                BLOG("|  %s \n", ascii);
            } else if (i + 1 == size) {
                ascii[(i + 1) % 16] = '\0';
                if ((i + 1) % 16 <= 8) {
                    BLOG(" ");
                }
                for (j = (i + 1) % 16; j < 16; ++j) {
                    BLOG("   ");
                }
                BLOG("|  %s \n", ascii);
            }
        }
    }
}

uint32_t hsm_openssl_run_aes(
    uint32_t algorithm, uint8_t *key, uint32_t key_size, uint8_t *iv, uint8_t iv_size,
    tcc_hsm_ioctl_run_cipher_param *param)
{
    AES_KEY aes_key;
    SM4_KEY sm4_key;
    uint32_t i = 0;
    uint32_t ret = HSM_GENERIC_ERR;

    switch (param->enc) {
    case SOTB_CIPHER_ENCRYPTION:
        /* Set key, type of key size is bit  */
        if (AES_set_encrypt_key(key, key_size * 8, &aes_key) < 0) {
            ELOG("AES_set_encrypt_key Fail\n");
            return HSM_GENERIC_ERR;
        }
        if (algorithm == ECB) {
            for (i = 0; i < (param->srcSize / TCC_AES_ECB_OFFSET); i++) {
                AES_encrypt(
                    (uint8_t *)(param->srcAddr + i * TCC_AES_ECB_OFFSET),
                    (uint8_t *)(param->dstAddr + i * TCC_AES_ECB_OFFSET), &aes_key);
            }
        } else if (algorithm == CBC) {
            AES_cbc_encrypt(
                (uint8_t *)param->srcAddr, (uint8_t *)param->dstAddr, param->srcSize, &aes_key, iv,
                AES_ENCRYPT);
        }
        ret = HSM_OK;
        break;

    case SOTB_CIPHER_DECRYPTION:
        /* Set key, type of key size is bit  */
        if (AES_set_decrypt_key(key, key_size * 8, &aes_key) < 0) {
            ELOG("AES_set_encrypt_key Fail\n");
            return HSM_GENERIC_ERR;
        }
        if (algorithm == ECB) {
            for (i = 0; i < (param->srcSize / TCC_AES_ECB_OFFSET); i++) {
                AES_decrypt(
                    (uint8_t *)(param->srcAddr + i * TCC_AES_ECB_OFFSET),
                    (uint8_t *)(param->dstAddr + i * TCC_AES_ECB_OFFSET), &aes_key);
            }
        } else if (algorithm == CBC) {
            AES_cbc_encrypt(
                (uint8_t *)param->srcAddr, (uint8_t *)param->dstAddr, param->srcSize, &aes_key, iv,
                AES_DECRYPT);
        }

        ret = HSM_OK;
        break;

    default:
        ELOG("Invalid object type\n");
        ret = HSM_ERR_INVALID_PARAM;
        break;
    }
    return ret;
}

uint32_t hsm_openssl_run_des(
    uint32_t algorithm, uint8_t *key, uint32_t key_size, uint8_t *iv, uint8_t iv_size,
    tcc_hsm_ioctl_run_cipher_param *param)
{
    AES_KEY aes_key;
    SM4_KEY sm4_key;
    uint32_t i = 0;
    DES_key_schedule schedule;
    uint32_t ret = HSM_GENERIC_ERR;

    if (DES_set_key((const_DES_cblock *)key, &schedule) < 0) {
        ELOG("DES_set_key Fail\n");
        return HSM_GENERIC_ERR;
    }
    if (algorithm == ECB) {
        for (i = 0; i < (param->srcSize / TCC_DES_ECB_OFFSET); i++) {
            DES_ecb_encrypt(
                (DES_cblock *)(param->srcAddr + i * TCC_DES_ECB_OFFSET),
                (DES_cblock *)(param->dstAddr + i * TCC_DES_ECB_OFFSET), &schedule, param->enc);
        }
    } else if (algorithm == CBC) {
        DES_cbc_encrypt(
            (uint8_t *)param->srcAddr, (uint8_t *)param->dstAddr, param->srcSize, &schedule,
            (DES_cblock *)iv, param->enc);
    }

    return HSM_OK;
}

uint32_t hsm_openssl_run_tdes(
    uint32_t algorithm, uint8_t *key, uint32_t key_size, uint8_t *iv, uint8_t iv_size,
    tcc_hsm_ioctl_run_cipher_param *param)
{
    AES_KEY aes_key;
    SM4_KEY sm4_key;
    uint32_t i = 0;
    DES_key_schedule schedule1, schedule2;
    uint32_t ret = HSM_GENERIC_ERR;

    if (DES_set_key((const_DES_cblock *)&key[0], &schedule1) < 0) {
        ELOG("DES_set_key Fail\n");
        return HSM_GENERIC_ERR;
    }
    if (DES_set_key((const_DES_cblock *)&key[8], &schedule2) < 0) {
        ELOG("DES_set_key Fail\n");
        return HSM_GENERIC_ERR;
    }

    if (algorithm == ECB) {
        for (i = 0; i < (param->srcSize / TCC_DES_ECB_OFFSET); i++) {
            DES_ecb2_encrypt(
                (DES_cblock *)(param->srcAddr + i * TCC_DES_ECB_OFFSET),
                (DES_cblock *)(param->dstAddr + i * TCC_DES_ECB_OFFSET), &schedule1, &schedule2,
                param->enc);
        }
    } else if (algorithm == CBC) {
        DES_ede2_cbc_encrypt(
            (uint8_t *)param->srcAddr, (uint8_t *)param->dstAddr, param->srcSize, &schedule1,
            &schedule2, (DES_cblock *)iv, param->enc);
    }

    return HSM_OK;
}
#if 1
uint32_t hsm_openssl_gen_mac(uint8_t *key, uint32_t key_size, tcc_hsm_ioctl_run_cmac_param *param)
{
    uint32_t ret = HSM_GENERIC_ERR;
    uint32_t len = EVP_MAX_MD_SIZE;
    CMAC_CTX *ctx;

    ctx = CMAC_CTX_new();
    CMAC_Init(ctx, key, key_size, EVP_aes_128_cbc(), NULL);
    CMAC_Update(ctx, (const uint8_t *)param->srcAddr, param->srcSize);
    CMAC_Final(ctx, param->macAddr, (size_t *)&param->mac_size);
    CMAC_CTX_free(ctx);

    return HSM_OK;
}

#endif
