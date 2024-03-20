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
#include <unistd.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <sys/poll.h>
#include <linux/types.h>
#include <fcntl.h>

#include "hsm_cipher.h"
#include "hsm_cipher_text.h"
#include "hsm_openssl_cipher.h"

#define TESTAPP_MAJOR_VER (5)
#define TESTAPP_MINOR_VER (2)

#define HSM_REQUIRED_DRIVER_VER_X (0u)
#define HSM_REQUIRED_DRIVER_VER_Y (1u)
#define HSM_REQUIRED_DRIVER_VER_Z (0u)

typedef unsigned long ulong;

#define hsm_DEVICE "/dev/tcc_hsm"
static uint8_t HwPACKET_MEMORY[1024 * 2];
static char *hsm_cmd[37] = {"0 set key from otp",
							"1 set key from snor",
							"2 run aes",
							"3 run aes by kt",
							"4 run sm4",
							"5 run sm4 by kt",
							"6 verify cmac",
							"7 verify cmac by kt",
							"8 gen gmac",
							"9 gen gmac by kt",
							"10 gen hmac",
							"11 gen hmac by kt",
							"12 gen sm3 hmac",
							"13 gen sm3 hmac by kt",
							"14 gen sha",
							"15 gen sm3",
							"16 run ecdsa sign",
							"17 run ecdsa sign by kt",
							"18 run ecdsa verify",
							"19 run ecdsa verify by kt",
							"20 run rsassa pkcs sign",
							"21 run rsassa pkcs sign by kt",
							"22 run rsassa pkcs verify",
							"23 run rsassa pkcs verify by kt",
							"24 run rsassa pss sign",
							"25 run rsassa pss sign by kt",
							"26 run rsassa pss verify",
							"27 run rsassa pss verify by kt",
							"28 gen random number",
							"29 write otp",
							"30 write snor",
							"31 get fw version",
							"32 get driver version",
							"33 full test",
							"34 full test without KT",
							"35 aging(10,000)",
							NULL};

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

static void hsm_print_cmd(void)
{
    int32_t i = 0;

    BLOG("\ncommand for hsm\n\n");

    for (i = 0; hsm_cmd[i] != NULL; i++) {
        BLOG("  %s\n", hsm_cmd[i]);
    }

    BLOG("\n");

    return;
}

static uint32_t hsm_set_key_test(int32_t fd, uint32_t core_type, uint32_t cmd)
{
    uint8_t *src_addr = HwPACKET_MEMORY;
    uint8_t *dst_addr = (HwPACKET_MEMORY + 1024);
    tcc_hsm_ioctl_set_key_param param = {0};
	uint32_t ret = TCCHSM_ERR;

	/* Set AES key */
    if (core_type == CORE_TYPE_A72) {
        param.key_index = A72_AES_KEY_INDEX;
        param.addr = A72_AESKEY_ADDR;
    } else if (core_type == CORE_TYPE_A53) {
        param.key_index = A53_AES_KEY_INDEX;
        param.addr = A53_AESKEY_ADDR;
    } else {
        ELOG("Invalid core type!\n");
        return ret;
    }
    param.data_size = sizeof(key);
    ret = ioctl(fd, cmd, &param);
	if (ret != TCCHSM_SUCCESS) {
		ELOG("hsm_set_key test fail(%d) aeskey_addr=0x%x\n", ret, param.addr);
        return ret;
    }

    DLOG("set_key_test(AES key addr=0x%x) Success\n", param.addr);

    /* Set MAC key*/
    if (core_type == CORE_TYPE_A72) {
        param.key_index = A72_MAC_KEY_INDEX;
        param.addr = A72_MACKEY_ADDR;
    } else if (core_type == CORE_TYPE_A53) {
        param.key_index = A53_MAC_KEY_INDEX;
        param.addr = A53_MACKEY_ADDR;
    } else {
        ELOG("Invalid core type!\n");
        return ret;
    }
    param.data_size = sizeof(mac_key);
    ret = ioctl(fd, cmd, &param);
	if (ret != TCCHSM_SUCCESS) {
		ELOG("hsm_set_key test fail(%d) mackey_addr=0x%x\n", ret, param.addr);
        return ret;
    }

    DLOG("set_key_test(MAC key addr=0x%x) Success\n", param.addr);

    if ((cmd == HSM_SET_KEY_FROM_SNOR_CMD) && (core_type == CORE_TYPE_A72)) {
		/* Set ECDSA P256 key*/
        param.key_index = A72_ECDSA_P256_PRIKEY_INDEX;
        param.addr = A72_ECDSA_P256_PRIKEY_ADDR;
		param.data_size = sizeof(secp256r1_private);
		ret = ioctl(fd, cmd, &param);
		if (ret != TCCHSM_SUCCESS) {
			ELOG("hsm_set_key test fail(%d) ecdsa prikey_addr=0x%x\n", ret, param.addr);
			return ret;
	    }

        param.key_index = A72_ECDSA_P256_PUBKEY_INDEX;
        param.addr = A72_ECDSA_P256_PUBKEY_ADDR;
		param.data_size = sizeof(secp256r1_public);
		ret = ioctl(fd, cmd, &param);
		if (ret != TCCHSM_SUCCESS) {
			ELOG("hsm_set_key test fail(%d) ecdsa pubkey_addr=0x%x\n", ret, param.addr);
			return ret;
	    }

	    DLOG("set_key_test(ECDSA P256 key addr=0x%x) Success\n", param.addr);

		/* Set RSA PKCS 1024 key*/
        param.key_index = A72_RSASSA_PRIKEY_INDEX;
        param.addr = A72_RSASSA_PRIKEY_ADDR;
		param.data_size = sizeof(rsa_prikey);
		ret = ioctl(fd, cmd, &param);
		if (ret != TCCHSM_SUCCESS) {
			ELOG("hsm_set_key test fail(%d) rsa prikey_addr=0x%x\n", ret, param.addr);
			return ret;
	    }

        param.key_index = A72_RSASSA_PRIKEY_INDEX;
		param.addr = A72_RSASSA_MOD_ADDR;
		param.data_size = sizeof(modN);
	    ret = ioctl(fd, HSM_SET_MODN_FROM_SNOR_CMD, &param);
		if (ret != TCCHSM_SUCCESS) {
			ELOG("hsm_set_key test fail(%d) rsa modn_addr=0x%x\n", ret, param.addr);
			return ret;
		}

        param.key_index = A72_RSASSA_PUBKEY_INDEX;
        param.addr = A72_RSASSA_PUBKEY_ADDR;
		param.data_size = sizeof(rsa_pubkey);
		ret = ioctl(fd, cmd, &param);
		if (ret != TCCHSM_SUCCESS) {
			ELOG("hsm_set_key test fail(%d) rsa pubkey_addr=0x%x\n", ret, param.addr);
			return ret;
		}

        param.key_index = A72_RSASSA_PUBKEY_INDEX;
		param.addr = A72_RSASSA_MOD_ADDR;
		param.data_size = sizeof(modN);
	    ret = ioctl(fd, HSM_SET_MODN_FROM_SNOR_CMD, &param);
		if (ret != TCCHSM_SUCCESS) {
			ELOG("hsm_set_key test fail(%d) rsa modn_addr=0x%x\n", ret, param.addr);
			return ret;
		}
	    DLOG("set_key_test(RSA PKCS 1024 key addr=0x%x) Success\n", param.addr);
	}

    return ret;
}

static uint32_t hsm_run_aes_test(int32_t fd, uint32_t cmd)
{
	uint8_t *ssl_src_addr = (HwPACKET_MEMORY);
	uint8_t *ssl_dst_addr = (HwPACKET_MEMORY + 512);
	uint8_t *hsm_src_addr = (HwPACKET_MEMORY + 1024);
	uint8_t *hsm_dst_addr = (HwPACKET_MEMORY + 1536);
	tcc_hsm_ioctl_aes_param param = {0};
	tcc_hsm_ioctl_rng_param rng = {0};
	uint8_t ssl_tag[16] = {0};
	uint32_t ret = TCCHSM_ERR;

	/* Get random number used as input data */
    rng.rng = (unsigned long)rng_data;
    rng.rng_size = sizeof(rng_data);
    ret = ioctl(fd, HSM_GET_RNG_CMD, &rng);
	if (ret != TCCHSM_SUCCESS) {
		ELOG("hsm_get_rand test fail(%d)\n", ret);
        return ret;
    }

    switch (cmd) {
    case HSM_RUN_AES_CMD:
        /* AES ECB */
        param.obj_id = (OID_AES_ECB_128 | OID_AES_ENCRYPT);
        param.src_size = sizeof(rng_data);
        param.src = (ulong)rng_data;
        param.key_size = sizeof(key);
        memcpy(param.key, key, param.key_size);
        param.iv_size = 0;
        param.counter_size = 0;
        param.dst_size = sizeof(ECB_cipher);
        param.dma = HSM_NONE_DMA;

        param.dst = (ulong)ssl_dst_addr;
        ret = hsm_openssl_run_aes(&param);
		if (ret != TCCHSM_SUCCESS) {
			ELOG("hsm_run_aes test fail(%d)\n", ret);
            return ret;
        }

        param.dst = (ulong)hsm_dst_addr;
        ret = ioctl(fd, cmd, &param);
		if (ret != TCCHSM_SUCCESS) {
			ELOG("hsm_run_aes test fail(%d)\n", ret);
            return ret;
        }
        if (memcmp(hsm_dst_addr, ssl_dst_addr, param.dst_size) != 0) {
            HexDump(hsm_dst_addr, param.dst_size);
            HexDump(ssl_dst_addr, param.dst_size);
            ELOG("Wrong cipher data\n");
			return TCCHSM_ERR;
		}

        /* AES CBC */
        param.obj_id = (OID_AES_CBC_128 | OID_AES_ENCRYPT);
        param.src_size = sizeof(rng_data);
        param.src = (ulong)rng_data;
        param.dst_size = sizeof(CBC_cipher);
        param.key_size = sizeof(key);
        memcpy(param.key, key, param.key_size);
        param.iv_size = sizeof(aes_iv);
        param.counter_size = 0;
        memcpy(param.iv, aes_iv, param.iv_size);
        param.dma = HSM_NONE_DMA;

        param.dst = (ulong)ssl_dst_addr;
        ret = hsm_openssl_run_aes(&param);
		if (ret != TCCHSM_SUCCESS) {
			ELOG("hsm_run_aes test fail(%d)\n", ret);
            return ret;
        }

        param.dst = (ulong)hsm_dst_addr;
        ret = ioctl(fd, cmd, &param);
		if (ret != TCCHSM_SUCCESS) {
			ELOG("hsm_run_aes test fail(%d)\n", ret);
            return ret;
        }

        if (memcmp(hsm_dst_addr, ssl_dst_addr, param.dst_size) != 0) {
            HexDump(hsm_dst_addr, param.dst_size);
            HexDump(ssl_dst_addr, param.dst_size);
            ELOG("Wrong cipher data\n");
			return TCCHSM_ERR;
		}
#if 0
		/* CCM and GCM are not yet supported in dma mode */
		/* AES CCM Encrytpion */
		param.obj_id = (OID_AES_CCM_128 | OID_AES_ENCRYPT);
		param.dst_size = sizeof(CCM_cipher);
		param.src_size = sizeof(rng_data);
		param.src = (unsigned long)rng_data;
        param.key_size = sizeof(key);
        memcpy(param.key, key, param.key_size);
        param.iv_size = sizeof(iv);
        param.counter_size = sizeof(iv);
        memcpy(param.iv, iv, param.iv_size);
        param.tag_size = sizeof(AES_ccm_tag);
        param.aad_size = sizeof(AES_aad);
        memcpy(param.aad, AES_aad, param.aad_size);
        param.dma = HSM_NONE_DMA;

        param.dst = (unsigned long)ssl_dst_addr;
        ret = hsm_openssl_run_aes(&param);
		memcpy(ssl_tag, param.tag, param.tag_size);
		if (ret != TCCHSM_SUCCESS) {
			ELOG("hsm_run_aes test fail(%d)\n", ret);
            return ret;
        }

        param.dst = (unsigned long)hsm_dst_addr;
		param.dst_size = sizeof(CCM_cipher);
		ret = ioctl(fd, cmd, &param);
		if (ret != TCCHSM_SUCCESS) {
			ELOG("hsm_run_aes test fail(%d)\n", ret);
			return ret;
		}

		if (memcmp(ssl_dst_addr, hsm_dst_addr, param.dst_size) != 0) {
			HexDump(ssl_dst_addr, param.dst_size);
			HexDump(hsm_dst_addr, param.dst_size);
			ELOG("Wrong cipher data\n");
			return TCCHSM_ERR;
        }

		/* AES CCM Decrytpion */
		param.obj_id = (OID_AES_CCM_128 | OID_AES_DECRYPT);
		param.src_size = sizeof(rng_data);
		param.src = (unsigned long)ssl_dst_addr;
		param.dst_size = sizeof(rng_data);
		param.key_size = sizeof(key);
		memcpy(param.key, key, param.key_size);
		param.iv_size = sizeof(iv);
		param.counter_size = sizeof(iv);
		memcpy(param.iv, iv, param.iv_size);
		param.tag_size = sizeof(AES_ccm_tag);
		param.aad_size = sizeof(AES_aad);
		memcpy(param.aad, AES_aad, param.aad_size);
		param.dma = HSM_NONE_DMA;

		param.dst = (unsigned long)ssl_src_addr;
		ret = hsm_openssl_run_aes(&param);
		if (ret != TCCHSM_SUCCESS) {
			ELOG("hsm_run_aes test fail(%d)\n", ret);
			return ret;
		}

		param.dst = (unsigned long)hsm_src_addr;
		param.dst_size = sizeof(rng_data);
		ret = ioctl(fd, cmd, &param);
		if (ret != TCCHSM_SUCCESS) {
			ELOG("hsm_run_aes test fail(%d)\n", ret);
			return ret;
		}

		if (memcmp(hsm_src_addr, ssl_src_addr, param.src_size) != 0) {
			HexDump(hsm_src_addr, param.src_size);
			HexDump(ssl_src_addr, param.src_size);
			ELOG("Wrong cipher data\n");
			return TCCHSM_ERR;
		}

		/* AES GCM Encryption */
		param.obj_id = (OID_AES_GCM_128 | OID_AES_ENCRYPT);
		param.dst_size = sizeof(GCM_cipher);
		param.src_size = sizeof(rng_data);
		param.src = (unsigned long)rng_data;
		param.key_size = sizeof(key);
		memcpy(param.key, key, param.key_size);
		param.iv_size = sizeof(iv);
		param.counter_size = 0;
		memcpy(param.iv, iv, param.iv_size);
		param.tag_size = sizeof(AES_gcm_tag);
		memcpy(param.aad, AES_aad, param.aad_size);
		param.aad_size = sizeof(AES_aad);
		param.dma = HSM_NONE_DMA;

        param.dst = (unsigned long)ssl_dst_addr;
        ret = hsm_openssl_run_aes(&param);
        if (ret != TCCHSM_SUCCESS) {
            ELOG("hsm_run_aes test fail(%d)\n", ret);
            return ret;
        }

		param.dst = (unsigned long)hsm_dst_addr;
		param.dst_size = sizeof(GCM_cipher);
		ret = ioctl(fd, cmd, &param);
		if (ret != TCCHSM_SUCCESS) {
			ELOG("hsm_run_aes test fail(%d)\n", ret);
			return ret;
		}

        if (memcmp(hsm_dst_addr, ssl_dst_addr, param.dst_size) != 0) {
            HexDump(hsm_dst_addr, param.dst_size);
            HexDump(ssl_dst_addr, param.dst_size);
            ELOG("Wrong cipher data\n");
            return TCCHSM_ERR;
        }

		/* AES GCM Decryption */
		param.obj_id = (OID_AES_GCM_128 | OID_AES_DECRYPT);
		param.dst_size = sizeof(rng_data);
		param.src = (unsigned long)ssl_dst_addr;
		param.src_size = sizeof(rng_data);
		param.key_size = sizeof(key);
		memcpy(param.key, key, param.key_size);
		param.iv_size = sizeof(iv);
		param.counter_size = 0;
		memcpy(param.iv, iv, param.iv_size);
		param.tag_size = sizeof(AES_gcm_tag);
		memcpy(param.aad, AES_aad, param.aad_size);
		param.aad_size = sizeof(AES_aad);
		param.dma = HSM_NONE_DMA;

		param.dst = (unsigned long)ssl_src_addr;
		ret = hsm_openssl_run_aes(&param);
		if (ret != TCCHSM_SUCCESS) {
			ELOG("hsm_run_aes test fail(%d)\n", ret);
			return ret;
		}

		param.dst = (unsigned long)hsm_src_addr;
		param.dst_size = sizeof(rng_data);
		ret = ioctl(fd, cmd, &param);
		if (ret != TCCHSM_SUCCESS) {
			ELOG("hsm_run_aes test fail(%d)\n", ret);
			return ret;
		}

		if (memcmp(hsm_src_addr, ssl_src_addr, param.src_size) != 0) {
			HexDump(hsm_src_addr, param.src_size);
			HexDump(ssl_src_addr, param.src_size);
			ELOG("Wrong cipher data\n");
			return TCCHSM_ERR;
		}
#endif
		DLOG("RUN_AES Success\n");
		break;

    case HSM_RUN_SM4_CMD:
        /* SM4 ECB */
        param.obj_id = (OID_SM4_ECB_128_OPENSSL | OID_SM4_ENCRYPT);
        param.dst_size = sizeof(sm4_ECB_cipher);
        param.src_size = sizeof(rng_data);
        param.src = (unsigned long)rng_data;
        param.key_size = sizeof(key);
        memcpy(param.key, key, param.key_size);
        param.dma = HSM_NONE_DMA;

        param.dst = (unsigned long)ssl_dst_addr;
        ret = hsm_openssl_run_aes(&param);
		if (ret != TCCHSM_SUCCESS) {
			ELOG("hsm_run_aes test fail(%d)\n", ret);
            return ret;
        }

        param.obj_id = (OID_SM4_ECB_128 | OID_SM4_ENCRYPT);
        param.dst = (unsigned long)hsm_dst_addr;
        ret = ioctl(fd, cmd, &param);
		if (ret != TCCHSM_SUCCESS) {
			ELOG("hsm_run_aes test fail(%d)\n", ret);
            return ret;
        }

        if (memcmp(hsm_dst_addr, ssl_dst_addr, param.dst_size) != 0) {
            HexDump(hsm_dst_addr, param.dst_size);
            HexDump(ssl_dst_addr, param.dst_size);
            ELOG("Wrong cipher data\n");
			return TCCHSM_ERR;
		}

        DLOG("RUN_SM4 Success\n");
        break;

    default:
        ELOG("Wrong cmd type\n");
        break;
    }

    return ret;
}

static uint32_t hsm_run_aes_by_kt_test(int32_t fd, uint32_t core_type, uint32_t cmd)
{
	uint8_t *ssl_src_addr = (HwPACKET_MEMORY);
	uint8_t *ssl_dst_addr = (HwPACKET_MEMORY + 512);
	uint8_t *hsm_src_addr = (HwPACKET_MEMORY + 1024);
	uint8_t *hsm_dst_addr = (HwPACKET_MEMORY + 1536);
	tcc_hsm_ioctl_aes_by_kt_param hsm_param = {0};
	tcc_hsm_ioctl_aes_param ssl_param = {0};
    tcc_hsm_ioctl_rng_param rng = {0};
	uint32_t ret = TCCHSM_ERR;

	if (core_type == CORE_TYPE_A72) {
        hsm_param.key_index = A72_AES_KEY_INDEX;
    } else if (core_type == CORE_TYPE_A53) {
        hsm_param.key_index = A53_AES_KEY_INDEX;
    } else {
        ELOG("Invalid core type! \n");
        return ret;
    }

    /* Get random number used as input data */
    rng.rng = (unsigned long)rng_data;
    rng.rng_size = sizeof(rng_data);
    ret = ioctl(fd, HSM_GET_RNG_CMD, &rng);
	if (ret != TCCHSM_SUCCESS) {
		ELOG("hsm_get_rand test fail(%d)\n", ret);
        return ret;
    }

    switch (cmd) {
    case HSM_RUN_AES_BY_KT_CMD:
        /* AES ECB */
        ssl_param.obj_id = (OID_AES_ECB_128 | OID_AES_ENCRYPT);
        ssl_param.src_size = sizeof(rng_data);
        ssl_param.src = (unsigned long)rng_data;
        ssl_param.dst_size = sizeof(ECB_cipher);
        ssl_param.key_size = sizeof(key);
        memcpy(ssl_param.key, key, ssl_param.key_size);
        ssl_param.iv_size = sizeof(aes_iv);
		ssl_param.counter_size = 0;
        ssl_param.dma = HSM_NONE_DMA;
        ssl_param.dst = (ulong)ssl_dst_addr;
        ret = hsm_openssl_run_aes(&ssl_param);
		if (ret != TCCHSM_SUCCESS) {
			ELOG("hsm_run_aes test fail(%d)\n", ret);
            return ret;
        }

        hsm_param.obj_id = (OID_AES_ECB_128 | OID_AES_ENCRYPT);
        hsm_param.dst_size = sizeof(ECB_cipher);
        hsm_param.src_size = sizeof(rng_data);
        hsm_param.src = (unsigned long)rng_data;
        hsm_param.iv_size = sizeof(aes_iv);
		hsm_param.counter_size = 0;
        hsm_param.dma = HSM_NONE_DMA;
        hsm_param.dst = (ulong)hsm_dst_addr;
        ret = ioctl(fd, cmd, &hsm_param);
		if (ret != TCCHSM_SUCCESS) {
			ELOG("hsm_run_aes_by_kt test fail(%d)\n", ret);
            return ret;
        }
        if (memcmp(hsm_dst_addr, ssl_dst_addr, ssl_param.dst_size) != 0) {
            HexDump(hsm_dst_addr, hsm_param.dst_size);
            HexDump(ssl_dst_addr, ssl_param.dst_size);
            ELOG("Wrong cipher data\n");
			return TCCHSM_ERR;
		}

        /* AES CBC */
        ssl_param.obj_id = (OID_AES_CBC_128 | OID_AES_ENCRYPT);
        ssl_param.src_size = sizeof(rng_data);
        ssl_param.src = (unsigned long)rng_data;
        ssl_param.dst_size = sizeof(CBC_cipher);
        ssl_param.key_size = sizeof(key);
        memcpy(ssl_param.key, key, ssl_param.key_size);
        ssl_param.iv_size = sizeof(aes_iv);
		ssl_param.counter_size = 0;
        ssl_param.dma = HSM_NONE_DMA;
        ssl_param.dst = (ulong)ssl_dst_addr;
        ret = hsm_openssl_run_aes(&ssl_param);
		if (ret != TCCHSM_SUCCESS) {
			ELOG("hsm_run_aes test fail(%d)\n", ret);
            return ret;
        }

        hsm_param.obj_id = (OID_AES_CBC_128 | OID_AES_ENCRYPT);
        hsm_param.src_size = sizeof(rng_data);
        hsm_param.src = (unsigned long)rng_data;
        hsm_param.dst_size = sizeof(CBC_cipher);
        hsm_param.iv_size = sizeof(aes_iv);
		hsm_param.counter_size = 0;
        hsm_param.dma = HSM_NONE_DMA;
        hsm_param.dst = (ulong)hsm_dst_addr;
        ret = ioctl(fd, cmd, &hsm_param);
		if (ret != TCCHSM_SUCCESS) {
			ELOG("hsm_run_aes_by_kt test fail(%d)\n", ret);
            return ret;
        }
        if (memcmp(hsm_dst_addr, ssl_dst_addr, ssl_param.dst_size) != 0) {
            HexDump(hsm_dst_addr, hsm_param.dst_size);
            HexDump(ssl_dst_addr, ssl_param.dst_size);
            ELOG("Wrong cipher data\n");
			return TCCHSM_ERR;
		}
#if 0
		/* CCM and GCM are not yet supported in dma mode */
		/* AES CCM Encrytpion */
		hsm_param.obj_id = (OID_AES_CCM_128 | OID_AES_ENCRYPT);
		hsm_param.dst_size = sizeof(CCM_cipher);
		hsm_param.src_size = sizeof(rng_data);
		hsm_param.src = (unsigned long)rng_data;
		hsm_param.dst_size = sizeof(CCM_cipher);
		hsm_param.iv_size = sizeof(iv);
		hsm_param.counter_size = sizeof(iv);
		memcpy(hsm_param.iv, iv, hsm_param.iv_size);
		hsm_param.tag_size = sizeof(AES_ccm_tag);
		hsm_param.aad_size = sizeof(AES_aad);
		memcpy(hsm_param.aad, AES_aad, hsm_param.aad_size);
		hsm_param.dma = HSM_NONE_DMA;
		hsm_param.dst = (unsigned long)hsm_dst_addr;
		ret = ioctl(fd, cmd, &hsm_param);
		if (ret != TCCHSM_SUCCESS) {
			ELOG("hsm_run_aes test fail(%d)\n", ret);
			return ret;
		}

		ssl_param.obj_id = (OID_AES_CCM_128 | OID_AES_ENCRYPT);
		ssl_param.dst_size = sizeof(CCM_cipher);
		ssl_param.src_size = sizeof(rng_data);
		ssl_param.src = (unsigned long)rng_data;
		ssl_param.dst_size = sizeof(CCM_cipher);
		ssl_param.iv_size = sizeof(iv);
		ssl_param.counter_size = sizeof(iv);
		memcpy(ssl_param.iv, iv, ssl_param.iv_size);
		ssl_param.key_size = sizeof(key);
		memcpy(ssl_param.key, key, ssl_param.key_size);
		ssl_param.tag_size = sizeof(AES_ccm_tag);
		ssl_param.aad_size = sizeof(AES_aad);
		memcpy(ssl_param.aad, AES_aad, ssl_param.aad_size);
		ssl_param.dma = HSM_NONE_DMA;
		ssl_param.dst = (unsigned long)ssl_dst_addr;
		ret = hsm_openssl_run_aes(&ssl_param);
		if (ret != TCCHSM_SUCCESS) {
			ELOG("hsm_run_aes test fail(%d)\n", ret);
			return ret;
		}

		if (memcmp(ssl_dst_addr, hsm_dst_addr, hsm_param.dst_size) != 0) {
			HexDump(ssl_dst_addr, hsm_param.dst_size);
			HexDump(hsm_dst_addr, hsm_param.dst_size);
			ELOG("Wrong cipher data\n");
			return TCCHSM_ERR;
		}

		/* AES CCM Decrytpion */
		hsm_param.obj_id = (OID_AES_CCM_128 | OID_AES_DECRYPT);
		hsm_param.src_size = sizeof(rng_data);
		hsm_param.src = (unsigned long)ssl_dst_addr;
		hsm_param.dst_size = sizeof(rng_data);
		hsm_param.iv_size = sizeof(iv);
		hsm_param.counter_size = sizeof(iv);
		memcpy(hsm_param.iv, iv, hsm_param.iv_size);
		hsm_param.tag_size = sizeof(AES_ccm_tag);
		hsm_param.aad_size = sizeof(AES_aad);
		memcpy(hsm_param.aad, AES_aad, hsm_param.aad_size);
		hsm_param.dma = HSM_NONE_DMA;
		hsm_param.dst = (unsigned long)hsm_src_addr;
		ret = ioctl(fd, cmd, &hsm_param);
		if (ret != TCCHSM_SUCCESS) {
			ELOG("hsm_run_aes test fail(%d)\n", ret);
			return ret;
		}

		ssl_param.obj_id = (OID_AES_CCM_128 | OID_AES_DECRYPT);
		ssl_param.src_size = sizeof(rng_data);
		ssl_param.src = (unsigned long)ssl_dst_addr;
		ssl_param.dst_size = sizeof(rng_data);
		ssl_param.iv_size = sizeof(iv);
		ssl_param.counter_size = sizeof(iv);
		memcpy(ssl_param.iv, iv, hsm_param.iv_size);
		ssl_param.key_size = sizeof(key);
		memcpy(ssl_param.key, key, ssl_param.key_size);
		ssl_param.tag_size = sizeof(AES_ccm_tag);
		ssl_param.aad_size = sizeof(AES_aad);
		memcpy(ssl_param.aad, AES_aad, ssl_param.aad_size);
		ssl_param.dma = HSM_NONE_DMA;
		ssl_param.dst = (unsigned long)ssl_src_addr;
		ret = hsm_openssl_run_aes(&ssl_param);
		if (ret != TCCHSM_SUCCESS) {
			ELOG("hsm_run_aes test fail(%d)\n", ret);
			return ret;
		}

		if (memcmp(hsm_src_addr, ssl_src_addr, hsm_param.src_size) != 0) {
			HexDump(hsm_src_addr, hsm_param.src_size);
			HexDump(ssl_src_addr, hsm_param.src_size);
			ELOG("Wrong cipher data\n");
			return TCCHSM_ERR;
		}

		/* AES GCM Encrytpion */
		hsm_param.obj_id = (OID_AES_GCM_128 | OID_AES_ENCRYPT);
		hsm_param.dst_size = sizeof(GCM_cipher);
		hsm_param.src_size = sizeof(rng_data);
		hsm_param.src = (unsigned long)rng_data;
		hsm_param.dst_size = sizeof(GCM_cipher);
		hsm_param.iv_size = sizeof(iv);
		hsm_param.counter_size = 0;
		memcpy(hsm_param.iv, iv, hsm_param.iv_size);
		hsm_param.tag_size = sizeof(AES_gcm_tag);
		hsm_param.aad_size = sizeof(AES_aad);
		memcpy(hsm_param.aad, AES_aad, hsm_param.aad_size);
		hsm_param.dma = HSM_NONE_DMA;
		hsm_param.dst = (unsigned long)hsm_dst_addr;
		ret = ioctl(fd, cmd, &hsm_param);
		if (ret != TCCHSM_SUCCESS) {
			ELOG("hsm_run_aes test fail(%d)\n", ret);
			return ret;
		}

		ssl_param.obj_id = (OID_AES_GCM_128 | OID_AES_ENCRYPT);
		ssl_param.dst_size = sizeof(GCM_cipher);
		ssl_param.src_size = sizeof(rng_data);
		ssl_param.src = (unsigned long)rng_data;
		ssl_param.dst_size = sizeof(GCM_cipher);
		ssl_param.iv_size = sizeof(iv);
		ssl_param.counter_size = 0;
		memcpy(ssl_param.iv, iv, ssl_param.iv_size);
		ssl_param.key_size = sizeof(key);
		memcpy(ssl_param.key, key, ssl_param.key_size);
		ssl_param.tag_size = sizeof(AES_gcm_tag);
		ssl_param.aad_size = sizeof(AES_aad);
		memcpy(ssl_param.aad, AES_aad, ssl_param.aad_size);
		ssl_param.dma = HSM_NONE_DMA;
		ssl_param.dst = (unsigned long)ssl_dst_addr;
		ret = hsm_openssl_run_aes(&ssl_param);
		if (ret != TCCHSM_SUCCESS) {
			ELOG("hsm_run_aes test fail(%d)\n", ret);
			return ret;
		}

		if (memcmp(ssl_dst_addr, hsm_dst_addr, hsm_param.dst_size) != 0) {
			HexDump(ssl_dst_addr, hsm_param.dst_size);
			HexDump(hsm_dst_addr, hsm_param.dst_size);
			ELOG("Wrong cipher data\n");
			return TCCHSM_ERR;
		}

		/* AES CCM Decrytpion */
		hsm_param.obj_id = (OID_AES_GCM_128 | OID_AES_DECRYPT);
		hsm_param.src_size = sizeof(rng_data);
		hsm_param.src = (unsigned long)ssl_dst_addr;
		hsm_param.dst_size = sizeof(rng_data);
		hsm_param.iv_size = sizeof(iv);
		hsm_param.counter_size = 0;
		memcpy(hsm_param.iv, iv, hsm_param.iv_size);
		hsm_param.tag_size = sizeof(AES_gcm_tag);
		hsm_param.aad_size = sizeof(AES_aad);
		memcpy(hsm_param.aad, AES_aad, hsm_param.aad_size);
		hsm_param.dma = HSM_NONE_DMA;
		hsm_param.dst = (unsigned long)hsm_src_addr;
		ret = ioctl(fd, cmd, &hsm_param);
		if (ret != TCCHSM_SUCCESS) {
			ELOG("hsm_run_aes test fail(%d)\n", ret);
			return ret;
		}

		ssl_param.obj_id = (OID_AES_GCM_128 | OID_AES_DECRYPT);
		ssl_param.src_size = sizeof(rng_data);
		ssl_param.src = (unsigned long)ssl_dst_addr;
		ssl_param.dst_size = sizeof(rng_data);
		ssl_param.iv_size = sizeof(iv);
		ssl_param.counter_size = 0;
		memcpy(ssl_param.iv, iv, hsm_param.iv_size);
		ssl_param.key_size = sizeof(key);
		memcpy(ssl_param.key, key, ssl_param.key_size);
		ssl_param.tag_size = sizeof(AES_gcm_tag);
		ssl_param.aad_size = sizeof(AES_aad);
		memcpy(ssl_param.aad, AES_aad, ssl_param.aad_size);
		ssl_param.dma = HSM_NONE_DMA;
		ssl_param.dst = (unsigned long)ssl_src_addr;
		ret = hsm_openssl_run_aes(&ssl_param);
		if (ret != TCCHSM_SUCCESS) {
			ELOG("hsm_run_aes test fail(%d)\n", ret);
			return ret;
		}

		if (memcmp(hsm_src_addr, ssl_src_addr, hsm_param.src_size) != 0) {
			HexDump(hsm_src_addr, hsm_param.src_size);
			HexDump(ssl_src_addr, hsm_param.src_size);
			ELOG("Wrong cipher data\n");
			return TCCHSM_ERR;
		}
#endif
		DLOG("RUN_AES_BY_KT Success\n");
		break;

    case HSM_RUN_SM4_BY_KT_CMD:
        /* SM4 ECB */
        ssl_param.obj_id = (OID_SM4_ECB_128_OPENSSL | OID_AES_ENCRYPT);
        ssl_param.src_size = sizeof(rng_data);
        ssl_param.src = (unsigned long)rng_data;
        ssl_param.dst_size = sizeof(sm4_ECB_cipher);
        ssl_param.key_size = sizeof(key);
        memcpy(ssl_param.key, key, ssl_param.key_size);
        ssl_param.iv_size = sizeof(aes_iv);
        ssl_param.counter_size = sizeof(aes_iv);
        ssl_param.dma = HSM_NONE_DMA;
        ssl_param.dst = (ulong)ssl_dst_addr;
        ret = hsm_openssl_run_aes(&ssl_param);
		if (ret != TCCHSM_SUCCESS) {
			ELOG("hsm_run_aes test fail(%d)\n", ret);
            return ret;
        }

        hsm_param.obj_id = (OID_SM4_ECB_128 | OID_AES_ENCRYPT);
        hsm_param.src_size = sizeof(rng_data);
        hsm_param.src = (unsigned long)rng_data;
        hsm_param.dst_size = sizeof(sm4_ECB_cipher);
        hsm_param.iv_size = sizeof(aes_iv);
        hsm_param.dma = HSM_NONE_DMA;
        hsm_param.dst = (ulong)hsm_dst_addr;
        ret = ioctl(fd, cmd, &hsm_param);
		if (ret != TCCHSM_SUCCESS) {
			ELOG("hsm_run_aes_by_kt test fail(%d)\n", ret);
            return ret;
        }
        if (memcmp(hsm_dst_addr, ssl_dst_addr, ssl_param.dst_size) != 0) {
            HexDump(hsm_dst_addr, hsm_param.dst_size);
            HexDump(ssl_dst_addr, ssl_param.dst_size);
            ELOG("Wrong cipher data\n");
			return TCCHSM_ERR;
		}
        DLOG("RUN_SM4_BY_KT Success\n");
        break;

    default:
        ELOG("Wrong cmd type\n");
        break;
    }

    return ret;
}

static uint32_t hsm_gen_hash_test(int32_t fd, uint32_t cmd)
{
    tcc_hsm_ioctl_hash_param param = {0};
    uint8_t *ssl_dig_addr = (HwPACKET_MEMORY);
    uint8_t *hsm_dig_addr = (HwPACKET_MEMORY + 1024);
    tcc_hsm_ioctl_rng_param rng = {0};
	uint32_t ret = TCCHSM_ERR;

	if (cmd == HSM_GEN_SHA_CMD) {
        param.obj_id = OID_SHA1_160;
        param.digest_size = TCC_HSM_SHA1_DIG_SIZE;
    } else if (cmd == HSM_GEN_SM3_CMD) {
        param.obj_id = OID_SM3_256;
        param.digest_size = TCC_HSM_SM3_DIG_SIZE;
    }

    /* Get random number used as input data */
    rng.rng = (unsigned long)rng_data;
    rng.rng_size = sizeof(rng_data);
    ret = ioctl(fd, HSM_GET_RNG_CMD, &rng);
	if (ret != TCCHSM_SUCCESS) {
		ELOG("hsm_get_rand test fail(%d)\n", ret);
        return ret;
    }

    param.src_size = sizeof(rng_data);
    param.src = (unsigned long)rng_data;
    param.dma = HSM_NONE_DMA;

    ret = hsm_openssl_gen_hash(&param);
	if (ret != TCCHSM_SUCCESS) {
		ELOG("hsm_run_aes test fail(%d)\n", ret);
        return ret;
    }
    memcpy(ssl_dig_addr, param.digest, param.digest_size);

    ret = ioctl(fd, cmd, &param);
	if (ret != TCCHSM_SUCCESS) {
		ELOG("hsm_gen_hash test fail(%d)\n", ret);
        return ret;
    }
    memcpy(hsm_dig_addr, param.digest, param.digest_size);

    if (memcmp(ssl_dig_addr, hsm_dig_addr, param.digest_size) != 0) {
        HexDump(ssl_dig_addr, param.digest_size);
        HexDump(hsm_dig_addr, param.digest_size);
        ELOG("Wrong cipher data\n");
		return TCCHSM_ERR;
	}

    DLOG("Hash success\n");

    return ret;
}

static uint32_t hsm_gen_mac_test(int32_t fd, uint32_t cmd)
{
    uint8_t *ssl_mac_addr = (HwPACKET_MEMORY);
    uint8_t *hsm_mac_addr = (HwPACKET_MEMORY + 1024);
    tcc_hsm_ioctl_mac_param param = {0};
    tcc_hsm_ioctl_rng_param rng = {0};
	uint32_t ret = TCCHSM_ERR;

	/* Get random number used as input data */
    rng.rng = (unsigned long)rng_data;
    rng.rng_size = sizeof(rng_data);
    ret = ioctl(fd, HSM_GET_RNG_CMD, &rng);
	if (ret != TCCHSM_SUCCESS) {
		ELOG("hsm_get_rand test fail(%d)\n", ret);
        return ret;
    }

    switch (cmd) {
    case HSM_GEN_CMAC_VERIFY_CMD:
        param.obj_id = 0u;
        param.dma = HSM_NONE_DMA;
        param.src_size = sizeof(plain_data);
        param.src = (unsigned long)plain_data;
        param.key_size = sizeof(key);
        memcpy(param.key, key, param.key_size);
        param.mac_size = sizeof(cmac_out);
        memcpy(param.mac, cmac_out, param.mac_size);

        ret = ioctl(fd, cmd, &param);
		if (ret != TCCHSM_SUCCESS) {
			ELOG("hsm_gen_mac cmac test fail(%d)\n", ret);
            return ret;
        }
        DLOG("Verify cmac Success\n");
        break;

    case HSM_GEN_GMAC_CMD:
        ELOG("Not yet supported \n");
        break;

    case HSM_GEN_HMAC_CMD:
        param.obj_id = OID_HMAC_SHA1_160;
        param.dma = HSM_NONE_DMA;
        param.src_size = sizeof(rng_data);
        param.src = (unsigned long)rng_data;
        param.key_size = sizeof(mac_key);
        memcpy(param.key, mac_key, param.key_size);
        param.mac_size = TCC_HSM_HMAC_MAC_SIZE;

        ret = hsm_openssl_gen_mac(cmd, &param);
		if (ret != TCCHSM_SUCCESS) {
			ELOG("hsm_run_aes test fail(%d)\n", ret);
            return ret;
        }
        memcpy(ssl_mac_addr, param.mac, param.mac_size);

        ret = ioctl(fd, cmd, &param);
		if (ret != TCCHSM_SUCCESS) {
			ELOG("hsm_gen_mac cmac test fail(%d)\n", ret);
            return ret;
        }
        memcpy(hsm_mac_addr, param.mac, param.mac_size);

        if (memcmp(ssl_mac_addr, hsm_mac_addr, param.mac_size) != 0) {
            HexDump(ssl_mac_addr, param.mac_size);
            HexDump(hsm_mac_addr, param.mac_size);
            ELOG("hmac Fail, Wrong cipher data(%d)\n", param.mac_size);
			return TCCHSM_ERR;
		}
        DLOG("Gen hmac Success\n");
        break;

    case HSM_GEN_SM3_HMAC_CMD:
        param.obj_id = 0;
        param.dma = HSM_NONE_DMA;
        param.src_size = sizeof(rng_data);
        param.src = (unsigned long)rng_data;
        param.key_size = sizeof(mac_key);
        memcpy(param.key, mac_key, param.key_size);
        param.mac_size = TCC_HSM_SM3_HMAC_MAC_SIZE;

        ret = hsm_openssl_gen_mac(cmd, &param);
		if (ret != TCCHSM_SUCCESS) {
			ELOG("hsm_run_aes test fail(%d)\n", ret);
            return ret;
        }
        memcpy(ssl_mac_addr, param.mac, param.mac_size);

        ret = ioctl(fd, cmd, &param);
		if (ret != TCCHSM_SUCCESS) {
			ELOG("hsm_gen_mac cmac test fail(%d)\n", ret);
            return ret;
        }
        memcpy(hsm_mac_addr, param.mac, param.mac_size);

        if (memcmp(ssl_mac_addr, hsm_mac_addr, param.mac_size) != 0) {
            HexDump(ssl_mac_addr, param.mac_size);
            HexDump(hsm_mac_addr, param.mac_size);
            ELOG("sm3 hmac Fail, Wrong cipher data(%d)\n", param.mac_size);
			return TCCHSM_ERR;
		}
        DLOG("Gen sm3 hmac Success\n");
        break;

    default:
        ELOG("Invalid cmd(%d)\n", cmd);
        return ret;
    }
    return ret;
}

static uint32_t hsm_gen_mac_by_kt_test(int32_t fd, uint32_t core_type, uint32_t cmd)
{
    tcc_hsm_ioctl_mac_by_kt_param hsm_param = {0};
    tcc_hsm_ioctl_mac_param ssl_param = {0};
    tcc_hsm_ioctl_rng_param rng = {0};
	uint32_t ret = TCCHSM_ERR;

	if (core_type == CORE_TYPE_A72) {
        if (cmd == HSM_GEN_CMAC_VERIFY_BY_KT_CMD) {
            hsm_param.key_index = A72_AES_KEY_INDEX;
        } else {
            hsm_param.key_index = A72_MAC_KEY_INDEX;
        }
    } else if (core_type == CORE_TYPE_A53) {
        if (cmd == HSM_GEN_CMAC_VERIFY_BY_KT_CMD) {
            hsm_param.key_index = A53_AES_KEY_INDEX;
        } else {
            hsm_param.key_index = A53_MAC_KEY_INDEX;
        }
    }

    /* Get random number used as input data */
    rng.rng = (unsigned long)rng_data;
    rng.rng_size = sizeof(rng_data);
    ret = ioctl(fd, HSM_GET_RNG_CMD, &rng);
	if (ret != TCCHSM_SUCCESS) {
		ELOG("hsm_get_rand test fail(%d)\n", ret);
        return ret;
    }

    switch (cmd) {
    case HSM_GEN_CMAC_VERIFY_BY_KT_CMD:
        hsm_param.obj_id = 0u;
        hsm_param.dma = HSM_NONE_DMA;
        hsm_param.src_size = sizeof(plain_data);
        hsm_param.src = (unsigned long)plain_data;
        hsm_param.mac_size = sizeof(cmac_out);
        memcpy(hsm_param.mac, cmac_out, hsm_param.mac_size);

        ret = ioctl(fd, cmd, &hsm_param);
		if (ret != TCCHSM_SUCCESS) {
			ELOG("hsm_gen_mac cmac test fail(%d)\n", ret);
            return ret;
        }
        DLOG("Verify cmac by kt Success\n");
        break;

    case HSM_GEN_GMAC_BY_KT_CMD:
        ELOG("Not supported yet\n");
        break;

    case HSM_GEN_HMAC_BY_KT_CMD:
        ssl_param.obj_id = OID_HMAC_SHA1_160;
        ssl_param.dma = HSM_NONE_DMA;
        ssl_param.src_size = sizeof(rng_data);
        ssl_param.src = (unsigned long)rng_data;
        ssl_param.key_size = sizeof(mac_key);
        memcpy(ssl_param.key, mac_key, ssl_param.key_size);
        ssl_param.mac_size = TCC_HSM_HMAC_MAC_SIZE;

        ret = hsm_openssl_gen_mac(cmd, &ssl_param);
		if (ret != TCCHSM_SUCCESS) {
			ELOG("hsm_run_aes test fail(%d)\n", ret);
            return ret;
        }

        hsm_param.obj_id = OID_HMAC_SHA1_160;
        hsm_param.dma = HSM_NONE_DMA;
        hsm_param.src_size = sizeof(rng_data);
        hsm_param.src = (unsigned long)rng_data;
        hsm_param.mac_size = TCC_HSM_HMAC_MAC_SIZE;
        ret = ioctl(fd, cmd, &hsm_param);
		if (ret != TCCHSM_SUCCESS) {
			ELOG("hsm_gen_mac hmac test fail(%d)\n", ret);
            return ret;
        }
        if (memcmp(ssl_param.mac, hsm_param.mac, ssl_param.mac_size) != 0) {
            HexDump(ssl_param.mac, ssl_param.mac_size);
            HexDump(hsm_param.mac, hsm_param.mac_size);
            ELOG("hmac Fail, Wrong cipher data(%d)\n", ssl_param.mac_size);
			return TCCHSM_ERR;
		}
        DLOG("Gen hmac by kt Success\n");
        break;

    case HSM_GEN_SM3_HMAC_BY_KT_CMD:
        ssl_param.obj_id = 0u;
        ssl_param.dma = HSM_NONE_DMA;
        ssl_param.src_size = sizeof(rng_data);
        ssl_param.src = (unsigned long)rng_data;
        ssl_param.key_size = sizeof(mac_key);
        memcpy(ssl_param.key, mac_key, ssl_param.key_size);
        ssl_param.mac_size = TCC_HSM_SM3_HMAC_MAC_SIZE;

        ret = hsm_openssl_gen_mac(cmd, &ssl_param);
		if (ret != TCCHSM_SUCCESS) {
			ELOG("hsm_run_aes test fail(%d)\n", ret);
            return ret;
        }

        hsm_param.obj_id = OID_HMAC_SHA1_160;
        hsm_param.dma = HSM_NONE_DMA;
        hsm_param.src_size = sizeof(rng_data);
        hsm_param.src = (unsigned long)rng_data;
        hsm_param.mac_size = TCC_HSM_SM3_HMAC_MAC_SIZE;
        ret = ioctl(fd, cmd, &hsm_param);
		if (ret != TCCHSM_SUCCESS) {
			ELOG("hsm_gen_mac hmac test fail(%d)\n", ret);
            return ret;
        }
        if (memcmp(ssl_param.mac, hsm_param.mac, ssl_param.mac_size) != 0) {
            HexDump(ssl_param.mac, ssl_param.mac_size);
            HexDump(hsm_param.mac, hsm_param.mac_size);
            ELOG("hmac Fail, Wrong cipher data(%d)\n", ssl_param.mac_size);
			return TCCHSM_ERR;
		}
        DLOG("Gen sm3 hmac by kt Success\n");
        break;

    default:
        ELOG("Invalid cmd(%d)\n", cmd);
    }

    return ret;
}

static uint32_t hsm_run_ecdsa_test(int32_t fd, uint32_t cmd)
{
    tcc_hsm_ioctl_ecdsa_param param = {0};
    tcc_hsm_ioctl_rng_param rng = {0};
	tcc_hsm_ioctl_ecdh_key_param ecdsa_key = {0};
	uint32_t ret = TCCHSM_ERR;

	/* Get random number used as input data */
    rng.rng = (unsigned long)rng_data;
    rng.rng_size = sizeof(rng_data);
    ret = ioctl(fd, HSM_GET_RNG_CMD, &rng);
	if (ret != TCCHSM_SUCCESS) {
		ELOG("hsm_get_rand test fail(%d)\n", ret);
        return ret;
    }

	/* Generate ecdsa key pair */
	ecdsa_key.key_type = 0;
	ecdsa_key.obj_id = OID_ECC_P256;
	ecdsa_key.prikey_size = 32;
	ecdsa_key.pubkey_size = 64;
	ret = ioctl(fd, HSM_RUN_ECDH_PHASE_I_CMD, &ecdsa_key);
	if (ret != TCCHSM_SUCCESS) {
		ELOG("hsm_get_rand test fail(%d)\n", ret);
		return ret;
	}

	/* sign to openssl and verify to hsm */
    cmd = HSM_RUN_ECDSA_SIGN_CMD;
    param.obj_id = OID_ECC_P256;
	param.key_size = ecdsa_key.prikey_size;
	memcpy(param.key, ecdsa_key.prikey, param.key_size);
	param.digest_size = sizeof(rng_data);
    memcpy(param.digest, rng_data, param.digest_size);
    param.sig_size = sizeof(secp256r1_sig);
    ret = hsm_openssl_run_ecdsa(cmd, &param);
	if (ret != TCCHSM_SUCCESS) {
		ELOG("ecdsa openssl signing test fail(%d)\n", ret);
        return ret;
    }

    cmd = HSM_RUN_ECDSA_VERIFY_CMD;
    param.obj_id = OID_ECC_P256;
	param.key_size = ecdsa_key.pubkey_size;
	memcpy(param.key, ecdsa_key.pubkey, param.key_size);
	param.digest_size = sizeof(rng_data);
    memcpy(param.digest, rng_data, param.digest_size);
    param.sig_size = sizeof(secp256r1_sig);
    ret = ioctl(fd, cmd, &param);
	if (ret != TCCHSM_SUCCESS) {
		ELOG("ecdsa hsm verify test fail(%d)\n", ret);
        return ret;
    }

    /* sign to hsm and verify to openssl */
    cmd = HSM_RUN_ECDSA_SIGN_CMD;
    param.obj_id = OID_ECC_P256;
	param.key_size = ecdsa_key.prikey_size;
	memcpy(param.key, ecdsa_key.prikey, param.key_size);
	param.digest_size = sizeof(rng_data);
    memcpy(param.digest, rng_data, param.digest_size);
    param.sig_size = sizeof(secp256r1_sig);
    ret = ioctl(fd, cmd, &param);
	if (ret != TCCHSM_SUCCESS) {
		ELOG("hsm_run_ecdsa verify test fail(%d)\n", ret);
        return ret;
    }
    cmd = HSM_RUN_ECDSA_VERIFY_CMD;
    param.obj_id = OID_ECC_P256;
	param.key_size = ecdsa_key.pubkey_size;
	memcpy(param.key, ecdsa_key.pubkey, param.key_size);
	param.digest_size = sizeof(rng_data);
    memcpy(param.digest, rng_data, param.digest_size);
    param.sig_size = sizeof(secp256r1_sig);
    ret = hsm_openssl_run_ecdsa(cmd, &param);
	if (ret != TCCHSM_SUCCESS) {
		ELOG("hsm_run_ecdsa verify test fail(%d)\n", ret);
        return ret;
    }
    DLOG("ecdsa signing and verify success\n");
    return ret;
}

static uint32_t hsm_run_ecdsa_by_kt_test(int32_t fd, uint32_t cmd)
{
    tcc_hsm_ioctl_ecdsa_by_kt_param hsm_param = {0};
    tcc_hsm_ioctl_ecdsa_param openssl_param = {0};
	uint32_t ret = TCCHSM_ERR;

    cmd = HSM_RUN_ECDSA_SIGN_BY_KT_CMD;
    hsm_param.obj_id = OID_ECC_P256;
	hsm_param.key_index = A72_ECDSA_P256_PRIKEY_INDEX;
	hsm_param.digest_size = sizeof(secp256r1_dig);
    memcpy(hsm_param.digest, secp256r1_dig, hsm_param.digest_size);
    hsm_param.sig_size = sizeof(secp256r1_sig);
	memset(hsm_param.sig, 0, hsm_param.sig_size);
    ret = ioctl(fd, cmd, &hsm_param);
	if (ret != TCCHSM_SUCCESS) {
		ELOG("ecdsa by kt hsm sign test fail(%d)\n", ret);
        return ret;
    }

    cmd = HSM_RUN_ECDSA_VERIFY_CMD;
    openssl_param.obj_id = OID_ECC_P256;
	openssl_param.key_size = sizeof(secp256r1_public);
	memcpy(openssl_param.key, secp256r1_public, openssl_param.key_size);
	openssl_param.digest_size = sizeof(secp256r1_dig);
    memcpy(openssl_param.digest, secp256r1_dig, openssl_param.digest_size);
	openssl_param.sig_size = hsm_param.sig_size;
	memcpy(openssl_param.sig, hsm_param.sig, openssl_param.sig_size);
    ret = hsm_openssl_run_ecdsa(cmd, &openssl_param);
	if (ret != TCCHSM_SUCCESS) {
		ELOG("hsm_run_ecdsa verify test fail(%d)\n", ret);
        return ret;
    }

	/* sign to openssl and verify to hsm */
    cmd = HSM_RUN_ECDSA_SIGN_CMD;
    openssl_param.obj_id = OID_ECC_P256;
	openssl_param.key_size = sizeof(secp256r1_private);
	memcpy(openssl_param.key, secp256r1_private, openssl_param.key_size);
    openssl_param.sig_size = sizeof(secp256r1_sig);
	memset(openssl_param.sig, 0, openssl_param.sig_size);
    ret = hsm_openssl_run_ecdsa(cmd, &openssl_param);
	if (ret != TCCHSM_SUCCESS) {
		ELOG("ecdsa openssl signing test fail(%d)\n", ret);
        return ret;
    }

    cmd = HSM_RUN_ECDSA_VERIFY_BY_KT_CMD;
    hsm_param.obj_id = OID_ECC_P256;
	hsm_param.key_index = A72_ECDSA_P256_PUBKEY_INDEX;
	hsm_param.sig_size = openssl_param.sig_size;
	memcpy(hsm_param.sig, openssl_param.sig, hsm_param.sig_size);
    ret = ioctl(fd, cmd, &hsm_param);
	if (ret != TCCHSM_SUCCESS) {
		ELOG("ecdsa by kt hsm verify test fail(%d)\n", ret);
        return ret;
    }

    DLOG("ecdsa by kt signing and verify success\n");

    return ret;
}

static uint32_t hsm_run_rsa_test(int32_t fd, uint32_t cmd)
{
    tcc_hsm_ioctl_rsassa_param param = {0};
    uint8_t *ssl_dst_addr = (HwPACKET_MEMORY);
    uint8_t *hsm_dst_addr = (HwPACKET_MEMORY + 1024);
    tcc_hsm_ioctl_rng_param rng = {0};
	uint32_t ret = TCCHSM_ERR;

	/* Get random number used as input data */
    rng.rng = (unsigned long)rng_data;
    rng.rng_size = sizeof(rng_data);
    ret = ioctl(fd, HSM_GET_RNG_CMD, &rng);
	if (ret != TCCHSM_SUCCESS) {
		ELOG("hsm_get_rand test fail(%d)\n", ret);
        return ret;
    }

    switch (cmd) {
    case HSM_RUN_RSASSA_PKCS_SIGN_CMD:
    case HSM_RUN_RSASSA_PKCS_VERIFY_CMD:
        /* Signing */
        cmd = HSM_RUN_RSASSA_PKCS_SIGN_CMD;
        param.obj_id = 0u;
        param.modN_size = sizeof(modN);
        memcpy(param.modN, modN, param.modN_size);
        param.key_size = sizeof(rsa_prikey);
        memcpy(param.key, rsa_prikey, param.key_size);
        param.digest_size = sizeof(rng_data);
        memcpy(param.digest, rng_data, param.digest_size);
        param.sig_size = param.modN_size;

        ret = hsm_openssl_run_rsa(cmd, &param);
		if (ret != TCCHSM_SUCCESS) {
			ELOG("hsm_openssl_run_rsa test fail(%d)\n", ret);
            return ret;
        }
        memcpy(ssl_dst_addr, param.sig, param.sig_size);

        ret = ioctl(fd, cmd, &param);
		if (ret != TCCHSM_SUCCESS) {
			ELOG("hsm_run_rsa signing test fail(%d)\n", ret);
            return ret;
        }
        memcpy(hsm_dst_addr, param.sig, param.sig_size);

        if (memcmp(hsm_dst_addr, ssl_dst_addr, param.sig_size) != 0) {
            HexDump(ssl_dst_addr, param.sig_size);
            HexDump(hsm_dst_addr, param.sig_size);
            ELOG("rsa sign Fail, Wrong cipher data(%d)\n", param.sig_size);
			return TCCHSM_ERR;
		}
        /* Verify */
        cmd = HSM_RUN_RSASSA_PKCS_VERIFY_CMD;
        param.obj_id = OID_ECC_BP256;
        param.key_size = sizeof(rsa_pubkey);
        memcpy(param.key, rsa_pubkey, param.key_size);
        param.digest_size = sizeof(rng_data);
        memcpy(param.digest, rng_data, param.digest_size);
        param.sig_size = param.modN_size;

        ret = hsm_openssl_run_rsa(cmd, &param);
		if (ret != TCCHSM_SUCCESS) {
			ELOG("hsm_openssl_run_rsa test fail(%d)\n", ret);
            return ret;
        }

        ret = ioctl(fd, cmd, &param);
		if (ret != TCCHSM_SUCCESS) {
			ELOG("hsm_run_rsa verify test fail(%d)\n", ret);
            return ret;
        }

        DLOG("rsassa pkcs signing and verifing success\n");
        break;

    case HSM_RUN_RSASSA_PSS_SIGN_CMD:
    case HSM_RUN_RSASSA_PSS_VERIFY_CMD:
        /* Set data */
        cmd = HSM_RUN_RSASSA_PSS_SIGN_CMD;
        param.obj_id = RSASSA_PSS_OID_HASH;
        param.modN_size = sizeof(modN);
        memcpy(param.modN, modN, param.modN_size);
        param.key_size = sizeof(rsa_prikey);
        memcpy(param.key, rsa_prikey, param.key_size);
        param.digest_size = sizeof(rng_data);
        memcpy(param.digest, rng_data, param.digest_size);
        param.sig_size = param.modN_size;

        /* sign to openssl and verify to hsm */
        ret = hsm_openssl_run_rsa(cmd, &param);
		if (ret != TCCHSM_SUCCESS) {
			ELOG("hsm_openssl_run_rsa test fail(%d)\n", ret);
            return ret;
        }
        memcpy(ssl_dst_addr, param.sig, param.sig_size);

        cmd = HSM_RUN_RSASSA_PSS_VERIFY_CMD;
        param.key_size = sizeof(rsa_pubkey);
        memcpy(param.key, rsa_pubkey, param.key_size);
        param.digest_size = sizeof(rng_data);
        memcpy(param.digest, rng_data, param.digest_size);
        param.sig_size = param.modN_size;
        ret = ioctl(fd, cmd, &param);
		if (ret != TCCHSM_SUCCESS) {
			ELOG("hsm_run_rsa verify test fail(%d)\n", ret);
            return ret;
        }

        /* sign to hsm and verify to openssl */
        cmd = HSM_RUN_RSASSA_PSS_SIGN_CMD;
        param.modN_size = sizeof(modN);
        memcpy(param.modN, modN, param.modN_size);
        param.key_size = sizeof(rsa_prikey);
        memcpy(param.key, rsa_prikey, param.key_size);
        param.digest_size = sizeof(rng_data);
        memcpy(param.digest, rng_data, param.digest_size);
        param.sig_size = param.modN_size;

        ret = ioctl(fd, cmd, &param);
		if (ret != TCCHSM_SUCCESS) {
			ELOG("hsm_run_rsa signing test fail(%d)\n", ret);
            return ret;
        }

        cmd = HSM_RUN_RSASSA_PSS_VERIFY_CMD;
        param.key_size = sizeof(rsa_pubkey);
        memcpy(param.key, rsa_pubkey, param.key_size);
        param.digest_size = sizeof(rng_data);
        memcpy(param.digest, rng_data, param.digest_size);
        param.sig_size = param.modN_size;

        ret = hsm_openssl_run_rsa(cmd, &param);
		if (ret != TCCHSM_SUCCESS) {
			ELOG("hsm_openssl_run_rsa test fail(%d)\n", ret);
            return ret;
        }
        DLOG("rsassa pss signing and verifing success\n");
        break;

    default:
        ELOG("Invalid cmd(0x%x)\n", cmd);
        break;
    }

    return ret;
}

static uint32_t hsm_run_rsa_by_kt_test(int32_t fd, uint32_t cmd)
{
    tcc_hsm_ioctl_rsassa_by_kt_param hsm_param = {0};
    tcc_hsm_ioctl_rsassa_param openssl_param = {0};
    tcc_hsm_ioctl_rng_param rng = {0};
	uint32_t ret = TCCHSM_ERR;

	/* Get random number used as input data */
    rng.rng = (unsigned long)rng_data;
    rng.rng_size = sizeof(rng_data);
    ret = ioctl(fd, HSM_GET_RNG_CMD, &rng);
	if (ret != TCCHSM_SUCCESS) {
		ELOG("hsm_get_rand test fail(%d)\n", ret);
        return ret;
    }

    switch (cmd) {
    case HSM_RUN_RSASSA_PKCS_SIGN_BY_KT_CMD:
    case HSM_RUN_RSASSA_PKCS_VERIFY_BY_KT_CMD:
        /* sign to openssl and verify to hsm */
        cmd = HSM_RUN_RSASSA_PKCS_SIGN_CMD;
        openssl_param.obj_id = 0u;
        openssl_param.modN_size = sizeof(modN);
        memcpy(openssl_param.modN, modN, openssl_param.modN_size);
        openssl_param.key_size = sizeof(rsa_prikey);
        memcpy(openssl_param.key, rsa_prikey, openssl_param.key_size);
        openssl_param.digest_size = sizeof(rng_data);
        memcpy(openssl_param.digest, rng_data, openssl_param.digest_size);
        openssl_param.sig_size = openssl_param.modN_size;
		memset(openssl_param.sig, 0, openssl_param.sig_size);
        ret = hsm_openssl_run_rsa(cmd, &openssl_param);
		if (ret != TCCHSM_SUCCESS) {
			ELOG("hsm_openssl_run_rsa test fail(%d)\n", ret);
            return ret;
        }

        cmd = HSM_RUN_RSASSA_PKCS_VERIFY_BY_KT_CMD;
        hsm_param.obj_id = 0U;
		hsm_param.key_index = A72_RSASSA_PUBKEY_INDEX;
        hsm_param.digest_size = sizeof(rng_data);
        memcpy(hsm_param.digest, rng_data, hsm_param.digest_size);
        hsm_param.sig_size = openssl_param.sig_size;
		memcpy(hsm_param.sig, openssl_param.sig, hsm_param.sig_size);
        ret = ioctl(fd, cmd, &hsm_param);
		if (ret != TCCHSM_SUCCESS) {
			ELOG("hsm_run_rsa verify test fail(%d)\n", ret);
            return ret;
        }

        /* sign to hsm and verify to openssl */
		cmd = HSM_RUN_RSASSA_PKCS_SIGN_BY_KT_CMD;
		hsm_param.obj_id = 0u;
		hsm_param.key_index = A72_RSASSA_PRIKEY_INDEX;
		hsm_param.sig_size = openssl_param.modN_size;
		memset(hsm_param.sig, 0, hsm_param.sig_size);
	    ret = ioctl(fd, cmd, &hsm_param);
		if (ret != TCCHSM_SUCCESS) {
			ELOG("hsm_run_rsa_by_kt signing test fail(%d)\n", ret);
	        return ret;
		}

		cmd = HSM_RUN_RSASSA_PKCS_VERIFY_CMD;
		openssl_param.obj_id = 0U;
        openssl_param.key_size = sizeof(rsa_pubkey);
        memcpy(openssl_param.key, rsa_pubkey, openssl_param.key_size);
        openssl_param.sig_size = hsm_param.sig_size;
		memcpy(openssl_param.sig, hsm_param.sig, openssl_param.sig_size);
        ret = hsm_openssl_run_rsa(cmd, &openssl_param);
		if (ret != TCCHSM_SUCCESS) {
			ELOG("hsm_openssl_run_rsa test fail(%d)\n", ret);
            return ret;
        }

		DLOG("rsassa pcks by kt signing and verifing success\n");
		break;

    case HSM_RUN_RSASSA_PSS_SIGN_BY_KT_CMD:
    case HSM_RUN_RSASSA_PSS_VERIFY_BY_KT_CMD:
        /* sign to openssl and verify to hsm */
        cmd = HSM_RUN_RSASSA_PSS_SIGN_CMD;
        openssl_param.obj_id = 0U;
        openssl_param.modN_size = sizeof(modN);
        memcpy(openssl_param.modN, modN, openssl_param.modN_size);
        openssl_param.key_size = sizeof(rsa_prikey);
        memcpy(openssl_param.key, rsa_prikey, openssl_param.key_size);
        openssl_param.digest_size = sizeof(rng_data);
        memcpy(openssl_param.digest, rng_data, openssl_param.digest_size);
        openssl_param.sig_size = openssl_param.modN_size;
        ret = hsm_openssl_run_rsa(cmd, &openssl_param);
		if (ret != TCCHSM_SUCCESS) {
			ELOG("hsm_openssl_run_rsa test fail(%d)\n", ret);
            return ret;
        }

        cmd = HSM_RUN_RSASSA_PSS_VERIFY_BY_KT_CMD;
        hsm_param.obj_id = 0U;
		hsm_param.key_index = A72_RSASSA_PUBKEY_INDEX;
        hsm_param.digest_size = sizeof(rng_data);
        memcpy(hsm_param.digest, rng_data, hsm_param.digest_size);
        hsm_param.sig_size = openssl_param.sig_size;
		memcpy(hsm_param.sig, openssl_param.sig, hsm_param.sig_size);
        ret = ioctl(fd, cmd, &hsm_param);
		if (ret != TCCHSM_SUCCESS) {
			ELOG("hsm_run_rsa verify test fail(%d)\n", ret);
            return ret;
        }

        /* sign to hsm and verify to openssl */
        cmd = HSM_RUN_RSASSA_PSS_SIGN_BY_KT_CMD;
		hsm_param.key_index = A72_RSASSA_PRIKEY_INDEX;
        hsm_param.sig_size = openssl_param.modN_size;
		memset(hsm_param.sig, 0, hsm_param.sig_size);
        ret = ioctl(fd, cmd, &hsm_param);
		if (ret != TCCHSM_SUCCESS) {
			ELOG("hsm_run_rsa signing test fail(%d)\n", ret);
            return ret;
        }

        cmd = HSM_RUN_RSASSA_PSS_VERIFY_CMD;
        openssl_param.key_size = sizeof(rsa_pubkey);
        memcpy(openssl_param.key, rsa_pubkey, openssl_param.key_size);
        openssl_param.sig_size = hsm_param.sig_size;
		memcpy(openssl_param.sig, hsm_param.sig, openssl_param.sig_size);
        ret = hsm_openssl_run_rsa(cmd, &openssl_param);
		if (ret != TCCHSM_SUCCESS) {
			ELOG("hsm_openssl_run_rsa test fail(%d)\n", ret);
            return ret;
        }
        DLOG("rsassa pss by kt signing and verifing success\n");
		break;

    default:
        ELOG("Invalid cmd(0x%x)\n", cmd);
        break;
	}

	return ret;
}

static uint32_t hsm_write_test(int32_t fd, uint32_t core_type, uint32_t cmd)
{
    tcc_hsm_ioctl_write_param param = {0};
	uint8_t temp[16] = {0};
	uint32_t ret = TCCHSM_ERR;

	// write aes test key
    if (core_type == CORE_TYPE_A72) {
        param.addr = A72_AESKEY_ADDR;
    } else if (core_type == CORE_TYPE_A53) {
        param.addr = A53_AESKEY_ADDR;
    } else {
        ELOG("Invalid core type! \n");
        return ret;
    }

    param.data_size = sizeof(key);
    param.data = (unsigned long)key;

    ret = ioctl(fd, cmd, &param);
	if (ret != TCCHSM_SUCCESS) {
		ELOG("hsm_write_test fail(%d) addr=0x%x\n", ret, param.addr);
        return ret;
    }

    DLOG("hsm_write_test(aeskey_addr=0x%x) Success\n", param.addr);

    // write mac test key
    if (core_type == CORE_TYPE_A72) {
        param.addr = A72_MACKEY_ADDR;
    } else if (core_type == CORE_TYPE_A53) {
        param.addr = A53_MACKEY_ADDR;
    } else {
        ELOG("Invalid core type! \n");
        return ret;
    }
    param.data_size = sizeof(mac_key);
    param.data = (unsigned long)mac_key;

    ret = ioctl(fd, cmd, &param);
	if (ret != TCCHSM_SUCCESS) {
		ELOG("hsm_write_test fail(%d) addr=0x%x\n", ret, param.addr);
        return ret;
    }

    DLOG("hsm_write_test(mackey_addr=0x%x) Success\n", param.addr);

    if ((cmd == HSM_WRITE_SNOR_CMD) && (core_type == CORE_TYPE_A72)) {
	    // write ecdsa p256 test key
		param.addr = A72_ECDSA_P256_PRIKEY_ADDR;
		param.data_size = sizeof(secp256r1_private);
		param.data = (unsigned long)secp256r1_private;
	    ret = ioctl(fd, cmd, &param);
		if (ret != TCCHSM_SUCCESS) {
			ELOG("hsm_write_test fail(%d) addr=0x%x\n", ret, param.addr);
			return ret;
		}

		param.addr = A72_ECDSA_P256_PUBKEY_ADDR;
		param.data_size = sizeof(secp256r1_public);
		param.data = (unsigned long)secp256r1_public;
	    ret = ioctl(fd, cmd, &param);
		if (ret != TCCHSM_SUCCESS) {
			ELOG("hsm_write_test fail(%d) addr=0x%x\n", ret, param.addr);
			return ret;
		}

	    DLOG("hsm_write_test(ecdsakey_addr=0x%x) Success\n", param.addr);

	    // write rsassa pkcs 1024 test key
		param.addr = A72_RSASSA_PRIKEY_ADDR;
		param.data_size = sizeof(rsa_prikey);
		param.data = (unsigned long)rsa_prikey;
	    ret = ioctl(fd, cmd, &param);
		if (ret != TCCHSM_SUCCESS) {
			ELOG("hsm_write_test fail(%d) addr=0x%x\n", ret, param.addr);
			return ret;
		}

		param.addr = A72_RSASSA_PUBKEY_ADDR;
        memcpy(temp, rsa_pubkey, sizeof(rsa_pubkey));
		param.data_size = sizeof(temp);
		param.data = (unsigned long)temp;
	    ret = ioctl(fd, cmd, &param);
		if (ret != TCCHSM_SUCCESS) {
			ELOG("hsm_write_test fail(%d) addr=0x%x\n", ret, param.addr);
			return ret;
		}

		param.addr = A72_RSASSA_MOD_ADDR;
		param.data_size = sizeof(modN);
		param.data = (unsigned long)modN;
	    ret = ioctl(fd, cmd, &param);
		if (ret != TCCHSM_SUCCESS) {
			ELOG("hsm_write_test fail(%d) addr=0x%x\n", ret, param.addr);
			return ret;
		}

	    DLOG("hsm_write_test(rsakey_addr=0x%x) Success\n", param.addr);
	}

    return ret;
}

static uint32_t hsm_get_rng_test(int32_t fd, uint32_t cmd)
{
    tcc_hsm_ioctl_rng_param param = {0};
    uint32_t rng[8] = {0};
	uint32_t ret = TCCHSM_ERR;

	param.rng = (unsigned long)rng;
    param.rng_size = sizeof(rng);
    ret = ioctl(fd, cmd, &param);
	if (ret != TCCHSM_SUCCESS) {
		ELOG("hsm_get_rand test fail(%d)\n", ret);
        return ret;
    }
    DLOG("Random number(0x%x)\n", param.rng_size);
    DLOG("%08X %08X %08X %08X %08X %08X %08X %08X\n",
    		rng[0], rng[1], rng[2], rng[3], rng[4], rng[5], rng[6], rng[7]);

    return ret;
}

static uint32_t hsm_get_fw_version_test(int32_t fd, uint32_t cmd)
{
    tcc_hsm_ioctl_version_param param = {0};
	uint32_t ret = TCCHSM_ERR;

	ret = ioctl(fd, cmd, &param);
	if (ret != TCCHSM_SUCCESS) {
		ELOG("hsm_get_version test fail(%d)\n", ret);
        return ret;
    }

	DLOG("HSM FW verson:%d.%d.%d\n", param.x, param.y, param.z);

	return ret;
}

static uint32_t hsm_get_driver_version_test(int32_t fd, uint32_t cmd)
{
	tcc_hsm_ioctl_version_param param = {0};
	uint32_t ret = TCCHSM_ERR;

	ret = ioctl(fd, cmd, &param);
	if (ret != TCCHSM_SUCCESS) {
		ELOG("hsm_get_version test fail(%d)\n", ret);
		return ret;
	}

	DLOG("HSM Driver verson:%d.%d.%d\n", param.x, param.y, param.z);

	return ret;
}

static void hsm_full_test(int32_t fd, uint32_t core_type, int32_t cnt)
{
    int32_t i = 0;
	uint32_t ret = TCCHSM_SUCCESS;

	for (i = 0; i < cnt; i++) {
        ret = hsm_run_aes_test(fd, HSM_RUN_AES_CMD);
		if (ret != TCCHSM_SUCCESS) {
			ELOG(" Fail test(%d, %d)\n", i, cnt);
            return;
        }
        ret = hsm_run_aes_test(fd, HSM_RUN_SM4_CMD);
		if (ret != TCCHSM_SUCCESS) {
			ELOG(" Fail test(%d, %d)\n", i, cnt);
            return;
        }
        ret = hsm_run_aes_by_kt_test(fd, core_type, HSM_RUN_AES_BY_KT_CMD);
		if (ret != TCCHSM_SUCCESS) {
			ELOG(" Fail test(%d, %d)\n", i, cnt);
            return;
        }
        ret = hsm_run_aes_by_kt_test(fd, core_type, HSM_RUN_SM4_BY_KT_CMD);
		if (ret != TCCHSM_SUCCESS) {
			ELOG(" Fail test(%d, %d)\n", i, cnt);
            return;
        }
        ret = hsm_gen_mac_test(fd, HSM_GEN_CMAC_VERIFY_CMD);
		if (ret != TCCHSM_SUCCESS) {
			ELOG(" Fail test(%d, %d)\n", i, cnt);
            return;
        }
        ret = hsm_gen_mac_test(fd, HSM_GEN_HMAC_CMD);
		if (ret != TCCHSM_SUCCESS) {
			ELOG(" Fail test(%d, %d)\n", i, cnt);
            return;
        }
        ret = hsm_gen_mac_test(fd, HSM_GEN_SM3_HMAC_CMD);
		if (ret != TCCHSM_SUCCESS) {
			ELOG(" Fail test(%d, %d)\n", i, cnt);
            return;
        }
        ret = hsm_gen_mac_by_kt_test(fd, core_type, HSM_GEN_CMAC_VERIFY_BY_KT_CMD);
		if (ret != TCCHSM_SUCCESS) {
			ELOG(" Fail test(%d, %d)\n", i, cnt);
            return;
        }
        ret = hsm_gen_mac_by_kt_test(fd, core_type, HSM_GEN_HMAC_BY_KT_CMD);
		if (ret != TCCHSM_SUCCESS) {
			ELOG(" Fail test(%d, %d)\n", i, cnt);
            return;
        }
        ret = hsm_gen_mac_by_kt_test(fd, core_type, HSM_GEN_SM3_HMAC_BY_KT_CMD);
		if (ret != TCCHSM_SUCCESS) {
			ELOG(" Fail test(%d, %d)\n", i, cnt);
            return;
        }
        ret = hsm_gen_hash_test(fd, HSM_GEN_SHA_CMD);
		if (ret != TCCHSM_SUCCESS) {
			ELOG(" Fail test(%d, %d)\n", i, cnt);
            return;
        }
        ret = hsm_gen_hash_test(fd, HSM_GEN_SM3_CMD);
		if (ret != TCCHSM_SUCCESS) {
			ELOG(" Fail test(%d, %d)\n", i, cnt);
            return;
        }
        ret = hsm_run_ecdsa_test(fd, HSM_RUN_ECDSA_SIGN_CMD);
		if (ret != TCCHSM_SUCCESS) {
			ELOG(" Fail test(%d, %d)\n", i, cnt);
            return;
        }
        ret = hsm_run_ecdsa_test(fd, HSM_RUN_ECDSA_VERIFY_CMD);
		if (ret != TCCHSM_SUCCESS) {
			ELOG(" Fail test(%d, %d)\n", i, cnt);
            return;
        }
        ret = hsm_run_rsa_test(fd, HSM_RUN_RSASSA_PKCS_SIGN_CMD);
		if (ret != TCCHSM_SUCCESS) {
			ELOG(" Fail test(%d, %d)\n", i, cnt);
            return;
        }
        ret = hsm_run_rsa_test(fd, HSM_RUN_RSASSA_PKCS_VERIFY_CMD);
		if (ret != TCCHSM_SUCCESS) {
			ELOG(" Fail test(%d, %d)\n", i, cnt);
            return;
        }
        ret = hsm_run_rsa_test(fd, HSM_RUN_RSASSA_PSS_SIGN_CMD);
		if (ret != TCCHSM_SUCCESS) {
			ELOG(" Fail test(%d, %d)\n", i, cnt);
            return;
        }
        ret = hsm_run_rsa_test(fd, HSM_RUN_RSASSA_PSS_VERIFY_CMD);
		if (ret != TCCHSM_SUCCESS) {
			ELOG(" Fail test(%d, %d)\n", i, cnt);
            return;
        }
		if(core_type == CORE_TYPE_A72) {
	        ret = hsm_run_ecdsa_by_kt_test(fd, HSM_RUN_ECDSA_SIGN_BY_KT_CMD);
			if (ret != TCCHSM_SUCCESS) {
				ELOG(" Fail test(%d, %d)\n", i, cnt);
	            return;
	        }
	        ret = hsm_run_ecdsa_by_kt_test(fd, HSM_RUN_ECDSA_VERIFY_BY_KT_CMD);
			if (ret != TCCHSM_SUCCESS) {
				ELOG(" Fail test(%d, %d)\n", i, cnt);
	            return;
	        }
	        ret = hsm_run_rsa_by_kt_test(fd, HSM_RUN_RSASSA_PKCS_SIGN_BY_KT_CMD);
			if (ret != TCCHSM_SUCCESS) {
				ELOG(" Fail test(%d, %d)\n", i, cnt);
	            return;
	        }
	        ret = hsm_run_rsa_by_kt_test(fd, HSM_RUN_RSASSA_PKCS_VERIFY_BY_KT_CMD);
			if (ret != TCCHSM_SUCCESS) {
				ELOG(" Fail test(%d, %d)\n", i, cnt);
	            return;
	        }
	        ret = hsm_run_rsa_by_kt_test(fd, HSM_RUN_RSASSA_PSS_SIGN_BY_KT_CMD);
			if (ret != TCCHSM_SUCCESS) {
				ELOG(" Fail test(%d, %d)\n", i, cnt);
	            return;
	        }
	        ret = hsm_run_rsa_by_kt_test(fd, HSM_RUN_RSASSA_PSS_VERIFY_BY_KT_CMD);
			if (ret != TCCHSM_SUCCESS) {
				ELOG(" Fail test(%d, %d)\n", i, cnt);
	            return;
	        }
		}
        ret = hsm_get_rng_test(fd, HSM_GET_RNG_CMD);
		if (ret != TCCHSM_SUCCESS) {
			ELOG(" Fail test(%d, %d)\n", i, cnt);
            return;
        }
		ret = hsm_get_fw_version_test(fd, HSM_GET_FW_VER_CMD);
		if (ret != TCCHSM_SUCCESS) {
			ELOG(" Fail test(%d, %d)\n", i, cnt);
			return;
		}
		ret = hsm_get_driver_version_test(fd, HSM_GET_DRIVER_VER_CMD);
		if (ret != TCCHSM_SUCCESS) {
			ELOG(" Fail test(%d, %d)\n", i, cnt);
            return;
        }
    }

    DLOG("Success test(%d, %d)\n", i, cnt);

    return;
}

static void hsm_full_without_kt_test(int32_t fd, uint32_t core_type, int32_t cnt)
{
    int32_t i = 0;
	uint32_t ret = TCCHSM_SUCCESS;

	for (i = 0; i < cnt; i++) {
        ret = hsm_run_aes_test(fd, HSM_RUN_AES_CMD);
		if (ret != TCCHSM_SUCCESS) {
			ELOG(" Fail test(%d, %d)\n", i, cnt);
            return;
        }
        ret = hsm_run_aes_test(fd, HSM_RUN_SM4_CMD);
		if (ret != TCCHSM_SUCCESS) {
			ELOG(" Fail test(%d, %d)\n", i, cnt);
            return;
        }
        ret = hsm_gen_mac_test(fd, HSM_GEN_CMAC_VERIFY_CMD);
		if (ret != TCCHSM_SUCCESS) {
			ELOG(" Fail test(%d, %d)\n", i, cnt);
            return;
        }
        ret = hsm_gen_mac_test(fd, HSM_GEN_HMAC_CMD);
		if (ret != TCCHSM_SUCCESS) {
			ELOG(" Fail test(%d, %d)\n", i, cnt);
            return;
        }
        ret = hsm_gen_mac_test(fd, HSM_GEN_SM3_HMAC_CMD);
		if (ret != TCCHSM_SUCCESS) {
			ELOG(" Fail test(%d, %d)\n", i, cnt);
            return;
        }
        ret = hsm_gen_hash_test(fd, HSM_GEN_SHA_CMD);
		if (ret != TCCHSM_SUCCESS) {
			ELOG(" Fail test(%d, %d)\n", i, cnt);
            return;
        }
        ret = hsm_gen_hash_test(fd, HSM_GEN_SM3_CMD);
		if (ret != TCCHSM_SUCCESS) {
			ELOG(" Fail test(%d, %d)\n", i, cnt);
            return;
        }
        ret = hsm_run_ecdsa_test(fd, HSM_RUN_ECDSA_SIGN_CMD);
		if (ret != TCCHSM_SUCCESS) {
			ELOG(" Fail test(%d, %d)\n", i, cnt);
            return;
        }
        ret = hsm_run_ecdsa_test(fd, HSM_RUN_ECDSA_VERIFY_CMD);
		if (ret != TCCHSM_SUCCESS) {
			ELOG(" Fail test(%d, %d)\n", i, cnt);
            return;
        }
        ret = hsm_run_rsa_test(fd, HSM_RUN_RSASSA_PKCS_SIGN_CMD);
		if (ret != TCCHSM_SUCCESS) {
			ELOG(" Fail test(%d, %d)\n", i, cnt);
            return;
        }
        ret = hsm_run_rsa_test(fd, HSM_RUN_RSASSA_PKCS_VERIFY_CMD);
		if (ret != TCCHSM_SUCCESS) {
			ELOG(" Fail test(%d, %d)\n", i, cnt);
            return;
        }
        ret = hsm_run_rsa_test(fd, HSM_RUN_RSASSA_PSS_SIGN_CMD);
		if (ret != TCCHSM_SUCCESS) {
			ELOG(" Fail test(%d, %d)\n", i, cnt);
            return;
        }
        ret = hsm_run_rsa_test(fd, HSM_RUN_RSASSA_PSS_VERIFY_CMD);
		if (ret != TCCHSM_SUCCESS) {
			ELOG(" Fail test(%d, %d)\n", i, cnt);
            return;
        }
        ret = hsm_get_rng_test(fd, HSM_GET_RNG_CMD);
		if (ret != TCCHSM_SUCCESS) {
			ELOG(" Fail test(%d, %d)\n", i, cnt);
            return;
        }
		ret = hsm_get_fw_version_test(fd, HSM_GET_FW_VER_CMD);
		if (ret != TCCHSM_SUCCESS) {
			ELOG(" Fail test(%d, %d)\n", i, cnt);
			return;
		}
		ret = hsm_get_driver_version_test(fd, HSM_GET_DRIVER_VER_CMD);
		if (ret != TCCHSM_SUCCESS) {
			ELOG(" Fail test(%d, %d)\n", i, cnt);
            return;
        }
    }

    DLOG("Success test(%d, %d)\n", i, cnt);

    return;
}

static uint32_t hsm_convert_cmd(uint32_t cmd)
{
    switch (cmd) {
    case TCCHSM_IOCTL_SET_KEY_FROM_OTP:
        return HSM_SET_KEY_FROM_OTP_CMD;

    case TCCHSM_IOCTL_SET_KEY_FROM_SNOR:
        return HSM_SET_KEY_FROM_SNOR_CMD;

    case TCCHSM_IOCTL_RUN_AES:
        return HSM_RUN_AES_CMD;

    case TCCHSM_IOCTL_RUN_AES_BY_KT:
        return HSM_RUN_AES_BY_KT_CMD;

    case TCCHSM_IOCTL_RUN_SM4:
        return HSM_RUN_SM4_CMD;

    case TCCHSM_IOCTL_RUN_SM4_BY_KT:
        return HSM_RUN_SM4_BY_KT_CMD;

    case TCCHSM_IOCTL_VERIFY_CMAC:
        return HSM_GEN_CMAC_VERIFY_CMD;

    case TCCHSM_IOCTL_GEN_GMAC:
        return HSM_GEN_GMAC_CMD;

    case TCCHSM_IOCTL_GEN_HMAC:
        return HSM_GEN_HMAC_CMD;

    case TCCHSM_IOCTL_GEN_SM3_HMAC:
        return HSM_GEN_SM3_HMAC_CMD;

    case TCCHSM_IOCTL_VERIFY_CMAC_BY_KT:
        return HSM_GEN_CMAC_VERIFY_BY_KT_CMD;

    case TCCHSM_IOCTL_GEN_GMAC_BY_KT:
        return HSM_GEN_GMAC_BY_KT_CMD;

    case TCCHSM_IOCTL_GEN_HMAC_BY_KT:
        return HSM_GEN_HMAC_BY_KT_CMD;

    case TCCHSM_IOCTL_GEN_SM3_HMAC_BY_KT:
        return HSM_GEN_SM3_HMAC_BY_KT_CMD;

    case TCCHSM_IOCTL_GEN_SHA:
        return HSM_GEN_SHA_CMD;

    case TCCHSM_IOCTL_GEN_SM3:
        return HSM_GEN_SM3_CMD;

    case TCCHSM_IOCTL_RUN_ECDSA_SIGN:
        return HSM_RUN_ECDSA_SIGN_CMD;

    case TCCHSM_IOCTL_RUN_ECDSA_SIGN_BY_KT:
        return HSM_RUN_ECDSA_SIGN_BY_KT_CMD;

    case TCCHSM_IOCTL_RUN_ECDSA_VERIFY:
        return HSM_RUN_ECDSA_VERIFY_CMD;

    case TCCHSM_IOCTL_RUN_ECDSA_VERIFY_BY_KT:
        return HSM_RUN_ECDSA_VERIFY_BY_KT_CMD;

    case TCCHSM_IOCTL_RUN_RSASSA_PKCS_SIGN:
        return HSM_RUN_RSASSA_PKCS_SIGN_CMD;

    case TCCHSM_IOCTL_RUN_RSASSA_PKCS_SIGN_BY_KT:
        return HSM_RUN_RSASSA_PKCS_SIGN_BY_KT_CMD;

    case TCCHSM_IOCTL_RUN_RSASSA_PKCS_VERIFY:
        return HSM_RUN_RSASSA_PKCS_VERIFY_CMD;

    case TCCHSM_IOCTL_RUN_RSASSA_PKCS_VERIFY_BY_KT:
        return HSM_RUN_RSASSA_PKCS_VERIFY_BY_KT_CMD;

    case TCCHSM_IOCTL_RUN_RSASSA_PSS_SIGN:
        return HSM_RUN_RSASSA_PSS_SIGN_CMD;

    case TCCHSM_IOCTL_RUN_RSASSA_PSS_SIGN_BY_KT:
        return HSM_RUN_RSASSA_PSS_SIGN_BY_KT_CMD;

    case TCCHSM_IOCTL_RUN_RSASSA_PSS_VERIFY:
        return HSM_RUN_RSASSA_PSS_VERIFY_CMD;

    case TCCHSM_IOCTL_RUN_RSASSA_PSS_VERIFY_BY_KT:
        return HSM_RUN_RSASSA_PSS_VERIFY_BY_KT_CMD;

    case TCCHSM_IOCTL_WRITE_OTP:
        return HSM_WRITE_OTP_CMD;

    case TCCHSM_IOCTL_WRITE_SNOR:
        return HSM_WRITE_SNOR_CMD;

    case TCCHSM_IOCTL_GET_RNG:
        return HSM_GET_RNG_CMD;

	case TCCHSM_IOCTL_GET_FW_VER:
		return HSM_GET_FW_VER_CMD;

	case TCCHSM_IOCTL_GET_DRIVER_VER:
		return HSM_GET_DRIVER_VER_CMD;

	case TCCHSM_IOCTL_FULL:
        return TCCHSM_IOCTL_FULL;

	case TCCHSM_IOCTL_FULL_WITHOUT_KT:
        return TCCHSM_IOCTL_FULL_WITHOUT_KT;

    case TCCHSM_IOCTL_AGING:
        return TCCHSM_IOCTL_AGING;

    default:
        ELOG("unknown command(%d)\n", cmd);
		return TCCHSM_ERR_INVALID_PARAM;
	}
}

uint32_t main(void)
{
	tcc_hsm_ioctl_version_param param = {0};
	uint32_t conv_cmd = 0, core_type = 0, cmd = 0;
    int32_t fd = -1;
    uint32_t ret = 0;

	DLOG("Test App Version:%d.%d\n", TESTAPP_MAJOR_VER, TESTAPP_MINOR_VER);

	fd = open(hsm_DEVICE, O_RDWR);
	if (fd < 0) {
        ELOG("Err Can't open tcc_hsm\n");
        return 0;
    }

	/* Check HSM Driver version */
	ret = ioctl(fd, HSM_GET_DRIVER_VER_CMD, &param);
	if (ret != TCCHSM_SUCCESS) {
		ELOG("hsm_get_driver_version fail(%d)\n", ret);
		return ret;
	}
	if ((param.x != HSM_REQUIRED_DRIVER_VER_X) || (param.y != HSM_REQUIRED_DRIVER_VER_Y)
		|| (param.z < HSM_REQUIRED_DRIVER_VER_Z)) {
		ELOG(
			"HSM Driver verison(%d.%d.%d) must be higher than equal to %d.%d.%d\n", param.x,
			param.y, param.z, HSM_REQUIRED_DRIVER_VER_X, HSM_REQUIRED_DRIVER_VER_Y,
			HSM_REQUIRED_DRIVER_VER_Z);
		return TCCHSM_ERR_VERSION_MISMATCH;
	}

	/* Select core type */
    BLOG("Input Core Type(A72 = 1 or A53 = 2):");
    scanf("%d", &core_type);
    if (core_type != CORE_TYPE_A72 && core_type != CORE_TYPE_A53) {
        ELOG("Invalid core type\n");
        return 0;
    }

    while (1) {
        hsm_print_cmd();
        BLOG("Input test number:");
        scanf("%d", &cmd);
        conv_cmd = hsm_convert_cmd(cmd);

        switch (cmd) {
        case TCCHSM_IOCTL_SET_KEY_FROM_OTP:
            ret = hsm_set_key_test(fd, core_type, conv_cmd);
            break;

        case TCCHSM_IOCTL_SET_KEY_FROM_SNOR:
            ret = hsm_set_key_test(fd, core_type, conv_cmd);
            break;

        case TCCHSM_IOCTL_RUN_AES:
        case TCCHSM_IOCTL_RUN_SM4:
            ret = hsm_run_aes_test(fd, conv_cmd);
            break;

        case TCCHSM_IOCTL_RUN_AES_BY_KT:
        case TCCHSM_IOCTL_RUN_SM4_BY_KT:
            ret = hsm_run_aes_by_kt_test(fd, core_type, conv_cmd);
            break;

        case TCCHSM_IOCTL_VERIFY_CMAC:
        case TCCHSM_IOCTL_GEN_GMAC:
        case TCCHSM_IOCTL_GEN_HMAC:
        case TCCHSM_IOCTL_GEN_SM3_HMAC:
            ret = hsm_gen_mac_test(fd, conv_cmd);
            break;

        case TCCHSM_IOCTL_VERIFY_CMAC_BY_KT:
        case TCCHSM_IOCTL_GEN_GMAC_BY_KT:
        case TCCHSM_IOCTL_GEN_HMAC_BY_KT:
        case TCCHSM_IOCTL_GEN_SM3_HMAC_BY_KT:
            ret = hsm_gen_mac_by_kt_test(fd, core_type, conv_cmd);
            break;

        case TCCHSM_IOCTL_GEN_SHA:
        case TCCHSM_IOCTL_GEN_SM3:
            ret = hsm_gen_hash_test(fd, conv_cmd);
            break;

        case TCCHSM_IOCTL_RUN_ECDSA_SIGN:
        case TCCHSM_IOCTL_RUN_ECDSA_VERIFY:
            ret = hsm_run_ecdsa_test(fd, conv_cmd);
            break;

        case TCCHSM_IOCTL_RUN_ECDSA_SIGN_BY_KT:
        case TCCHSM_IOCTL_RUN_ECDSA_VERIFY_BY_KT:
            ret = hsm_run_ecdsa_by_kt_test(fd, conv_cmd);
            break;

        case TCCHSM_IOCTL_RUN_RSASSA_PKCS_SIGN:
        case TCCHSM_IOCTL_RUN_RSASSA_PKCS_VERIFY:
        case TCCHSM_IOCTL_RUN_RSASSA_PSS_SIGN:
        case TCCHSM_IOCTL_RUN_RSASSA_PSS_VERIFY:
            ret = hsm_run_rsa_test(fd, conv_cmd);
            break;

        case TCCHSM_IOCTL_RUN_RSASSA_PKCS_SIGN_BY_KT:
        case TCCHSM_IOCTL_RUN_RSASSA_PKCS_VERIFY_BY_KT:
        case TCCHSM_IOCTL_RUN_RSASSA_PSS_SIGN_BY_KT:
        case TCCHSM_IOCTL_RUN_RSASSA_PSS_VERIFY_BY_KT:
            ret = hsm_run_rsa_by_kt_test(fd, conv_cmd);
            break;

        case TCCHSM_IOCTL_WRITE_OTP:
            ret = hsm_write_test(fd, core_type, conv_cmd);
            break;

        case TCCHSM_IOCTL_WRITE_SNOR:
            ret = hsm_write_test(fd, core_type, conv_cmd);
            break;

        case TCCHSM_IOCTL_GET_RNG:
            ret = hsm_get_rng_test(fd, conv_cmd);
            break;

		case TCCHSM_IOCTL_GET_FW_VER:
			ret = hsm_get_fw_version_test(fd, conv_cmd);
			break;

		case TCCHSM_IOCTL_GET_DRIVER_VER:
			ret = hsm_get_driver_version_test(fd, conv_cmd);
			break;

		case TCCHSM_IOCTL_FULL:
            hsm_full_test(fd, core_type, 1);
            break;

		case TCCHSM_IOCTL_FULL_WITHOUT_KT:
			hsm_full_without_kt_test(fd, core_type, 1);
            break;

		case TCCHSM_IOCTL_AGING:
            hsm_full_test(fd, core_type, 10000);
            break;

        default:
            ELOG("unknown command(%d)\n", cmd);
            break;
        }

        BLOG("\n");
    }

    if (fd > 0) {
        close(fd);
        fd = -1;
    }

    return 0;
}
