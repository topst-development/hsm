
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

static unsigned char HwPACKET_MEMORY[28 * 1024];
extern uint32_t key_idx;

static void HexDump(const void* data, uint32_t size)
{
    int8_t ascii[17];
    size_t i, j;
    ascii[16] = '\0';
    for (i = 0; i < size; ++i) {
        BLOG("%02X ", ((uint8_t*)data)[i]);
        if (((uint8_t*)data)[i] >= ' ' && ((uint8_t*)data)[i] <= '~') {
            ascii[i % 16] = ((uint8_t*)data)[i];
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

static uint32_t cryptoSetMode(
    int32_t fd, uint32_t keyIndex, uint32_t alog, uint32_t opmode, uint32_t residual, uint32_t smsg)
{
    struct tcc_hsm_ioctl_set_mode_param param;

    param.keyIndex = keyIndex;
    param.algorithm = alog;
    param.opMode = opmode;
    param.residual = residual;
    param.sMsg = smsg;

    if (ioctl(fd, TCCHSM_IOCTL_SET_MODE, &param) != 0) {
        ELOG("Error set mode\n");
        return HSM_GENERIC_ERR;
    }

    return HSM_OK;
}

static uint32_t cryptoSetKDFData(int fd, uint32_t keyIndex, uintptr_t* kdfData)
{
#if 0
    struct tcc_hsm_ioctl_set_kdfdata_param param;

    param.keyIndex = keyIndex;
    param.kdfData = (struct tcc_hsm_kdfdata *)kdfData;

    if(ioctl(fd, TCCHSM_IOCTL_SET_KDFDATA, &param) != 0) {
        ELOG("Error set kdfData\n");
        return HSM_GENERIC_ERR;
    }

    return HSM_OK;
#else
    return HSM_GENERIC_ERR;
#endif
}

static uint32_t cryptoSetKLData(int fd, uint32_t keyIndex, uintptr_t* klData)
{
    struct tcc_hsm_ioctl_set_kldata_param param;

    param.keyIndex = keyIndex;
    param.klData = (struct tcc_hsm_kldata*)klData;

    if (ioctl(fd, TCCHSM_IOCTL_SET_KLDATA, &param) != 0) {
        ELOG("Error set klData\n");
        return HSM_GENERIC_ERR;
    }

    return HSM_OK;
}

static uint32_t cryptoSet(
    int fd, uint32_t alog, uint32_t opmode, uint32_t residual, uint32_t smsg, uint32_t keyIndex,
    uint8_t* key, uint8_t* syskey, uint8_t* iv1, uint8_t* iv2)
{
    struct tcc_hsm_ioctl_set_mode_param mode_param;
    struct tcc_hsm_ioctl_set_iv_param iv_param;
    struct tcc_hsm_ioctl_set_key_param key_param;
    uint32_t keysize = 0;
    uint32_t ivsize = 0;

    if (alog == AES_128 || alog == TDES_128 || alog == DVB_CSA3) {
        keysize = ivsize = SOTB_CIPHER_KEYSIZE_FOR_128;
    } else {
        keysize = ivsize = SOTB_CIPHER_KEYSIZE_FOR_64;
    }

    mode_param.keyIndex = keyIndex;
    mode_param.algorithm = alog;
    mode_param.opMode = opmode;
    mode_param.residual = residual;
    mode_param.sMsg = smsg;

    if (ioctl(fd, TCCHSM_IOCTL_SET_MODE, &mode_param) != 0) {
        ELOG("Error set mode\n");
        return HSM_GENERIC_ERR;
    }

    if (iv1 != NULL) {
        iv_param.keyIndex = keyIndex;
        iv_param.ivSize = ivsize;
        iv_param.iv = iv1;

        if (ioctl(fd, TCCHSM_IOCTL_SET_IV, &iv_param) != 0) {
            ELOG("Error set IV\n");
            return HSM_GENERIC_ERR;
        }
    }

    if (key != NULL) {
        key_param.keyIndex = keyIndex;
        key_param.keyType = CORE_Key;
        key_param.keyMode = 0;
        key_param.keySize = keysize;
        key_param.key = key;

        if (ioctl(fd, TCCHSM_IOCTL_SET_KEY, &key_param) != 0) {
            ELOG("Error set key\n");
            return HSM_GENERIC_ERR;
        }
    }

    return HSM_OK;
}

static uint32_t cryptoRun(
    int fd, unsigned char* srcAddr, unsigned char* dstAddr, uint32_t srcSize, uint32_t keyIndex,
    uint32_t enc, uint32_t swSel, uint32_t klIndex, uint32_t keyMode)
{
    tcc_hsm_ioctl_run_cipher_param param;

    param.keyIndex = keyIndex;
    param.srcAddr = (uint8_t*)srcAddr;
    param.dstAddr = (uint8_t*)dstAddr;
    param.srcSize = srcSize;
    param.enc = enc;
    param.cwSel = swSel;
    param.klIndex = klIndex;
    param.keyMode = keyMode;

    if (ioctl(fd, TCCHSM_IOCTL_RUN_CIPHER, &param) != 0) {
        ELOG("Error run cipher\n");
        return HSM_GENERIC_ERR;
    }

    return param.srcSize;
}

uint32_t sotbCipherAESDecTest(int fd)
{
    unsigned char* ssl_dst_addr = HwPACKET_MEMORY;
    unsigned char* hsm_dst_addr = (HwPACKET_MEMORY + 1024);
    tcc_hsm_ioctl_run_cipher_param param;
    tcc_hsm_ioctl_rng_param rng;
    uint8_t rng_data[32] = {0};
    uint32_t Ret = 0;

    /* Get random number used as input data
     * Max size is 16bytes, so run twice */
    rng.rng = (uint8_t*)&rng_data[0];
    rng.size = TCCHSM_RNG_MAX;
    Ret = ioctl(fd, TCCHSM_IOCTL_GET_RNG, &rng);
    rng.rng = (uint8_t*)&rng_data[16];
    Ret = ioctl(fd, TCCHSM_IOCTL_GET_RNG, &rng);
    if (Ret != HSM_OK) {
        ELOG("hsm_get_rand test fail(%d)\n", Ret);
        return Ret;
    }

    /* Test 1: AES128, ECB, 16Byte */
	param.keyIndex = key_idx;
	param.srcAddr = (uint8_t*)rng_data;
	param.srcSize = 16;
    param.enc = SOTB_CIPHER_DECRYPTION;
    param.cwSel = CPU_Key;
    param.klIndex = 0;
    param.keyMode = 0;

    param.dstAddr = (uint8_t*)hsm_dst_addr;
	Ret = cryptoSet(fd, AES_128, ECB, 0, 1, key_idx, key_aes128, syskey, iv1, iv2);
	Ret = ioctl(fd, TCCHSM_IOCTL_RUN_CIPHER, &param);
	if (Ret != 0) {
        ELOG("Error run cipher\n");
        return HSM_GENERIC_ERR;
    }

    param.dstAddr = (uint8_t*)ssl_dst_addr;
    Ret = hsm_openssl_run_aes(ECB, key_aes128, sizeof(key_aes128), iv1, sizeof(iv1), &param);
    if (Ret != HSM_OK) {
        ELOG("Error run cipher\n");
        return HSM_GENERIC_ERR;
    }
    if (memcmp(hsm_dst_addr, ssl_dst_addr, param.srcSize) != 0) {
        HexDump(hsm_dst_addr, param.srcSize);
        HexDump(ssl_dst_addr, param.srcSize);
        ELOG("Wrong cipher data\n");
        return HSM_GENERIC_ERR;
    }

    /* Test 2: AES128, CBC, 16Byte */
	param.keyIndex = key_idx;
	param.srcAddr = (uint8_t*)rng_data;
	param.srcSize = 16;
    param.enc = SOTB_CIPHER_DECRYPTION;
    param.cwSel = CPU_Key;
    param.klIndex = 0;
    param.keyMode = 0;

    param.dstAddr = (uint8_t*)hsm_dst_addr;
	Ret = cryptoSet(fd, AES_128, CBC, 0, 0, key_idx, key_aes128, syskey, iv1, iv2);
	Ret = ioctl(fd, TCCHSM_IOCTL_RUN_CIPHER, &param);
	if (Ret != 0) {
        ELOG("Error run cipher\n");
        return HSM_GENERIC_ERR;
    }

    param.dstAddr = (uint8_t*)ssl_dst_addr;
    Ret = hsm_openssl_run_aes(CBC, key_aes128, sizeof(key_aes128), iv1, sizeof(iv1), &param);
    if (Ret != HSM_OK) {
        ELOG("Error run cipher\n");
        return HSM_GENERIC_ERR;
    }
    if (memcmp(hsm_dst_addr, ssl_dst_addr, param.srcSize) != 0) {
        HexDump(hsm_dst_addr, param.srcSize);
        HexDump(ssl_dst_addr, param.srcSize);
        ELOG("Wrong cipher data\n");
        return HSM_GENERIC_ERR;
    }

    /* Test 3: AES128, ECB, 32Byte */
	param.keyIndex = key_idx;
	param.srcAddr = (uint8_t*)rng_data;
	param.srcSize = 32;
    param.enc = SOTB_CIPHER_DECRYPTION;
    param.cwSel = CPU_Key;
    param.klIndex = 0;
    param.keyMode = 0;

    param.dstAddr = (uint8_t*)hsm_dst_addr;
	Ret = cryptoSet(fd, AES_128, ECB, 0, 0, key_idx, key_aes128, syskey, iv1, iv2);
	Ret = ioctl(fd, TCCHSM_IOCTL_RUN_CIPHER, &param);
	if (Ret != 0) {
        ELOG("Error run cipher\n");
        return HSM_GENERIC_ERR;
    }

    param.dstAddr = (uint8_t*)ssl_dst_addr;
    Ret = hsm_openssl_run_aes(ECB, key_aes128, sizeof(key_aes128), NULL, 0, &param);
    if (Ret != HSM_OK) {
        ELOG("Error run cipher\n");
        return HSM_GENERIC_ERR;
    }
    if (memcmp(hsm_dst_addr, ssl_dst_addr, param.srcSize) != 0) {
        HexDump(hsm_dst_addr, param.srcSize);
        HexDump(ssl_dst_addr, param.srcSize);
        ELOG("Wrong cipher data\n");
        return HSM_GENERIC_ERR;
    }

    /* Test 4: AES128, CBC, 32Byte */
	param.keyIndex = key_idx;
	param.srcAddr = (uint8_t*)rng_data;
	param.srcSize = 32;
    param.enc = SOTB_CIPHER_DECRYPTION;
    param.cwSel = CPU_Key;
    param.klIndex = 0;
    param.keyMode = 0;

    param.dstAddr = (uint8_t*)hsm_dst_addr;
	Ret = cryptoSet(fd, AES_128, CBC, 0, 0, key_idx, key_aes128, syskey, iv1, iv2);
	Ret = ioctl(fd, TCCHSM_IOCTL_RUN_CIPHER, &param);
	if (Ret != 0) {
        ELOG("Error run cipher\n");
        return HSM_GENERIC_ERR;
    }

    param.dstAddr = (uint8_t*)ssl_dst_addr;
    Ret = hsm_openssl_run_aes(CBC, key_aes128, sizeof(key_aes128), iv1, sizeof(iv1), &param);
    if (Ret != HSM_OK) {
        ELOG("Error run cipher\n");
        return HSM_GENERIC_ERR;
    }
    if (memcmp(hsm_dst_addr, ssl_dst_addr, param.srcSize) != 0) {
        HexDump(hsm_dst_addr, param.srcSize);
        HexDump(ssl_dst_addr, param.srcSize);
        ELOG("Wrong cipher data\n");
        return HSM_GENERIC_ERR;
    }

    return SOTB_CIPHER_ERROR_NONE;
}

uint32_t sotbCipherAESEncTest(int fd)
{
    uint32_t uiErr = 0;
    unsigned char* ssl_dst_addr = HwPACKET_MEMORY;
    unsigned char* hsm_dst_addr = (HwPACKET_MEMORY + 1024);
    tcc_hsm_ioctl_run_cipher_param param;
    tcc_hsm_ioctl_rng_param rng;
    uint8_t rng_data[32] = {0};
    uint32_t Ret = 0;

    /* Get random number used as input data
     * Max size is 16bytes, so run twice */
    rng.rng = (uint8_t*)&rng_data[0];
    rng.size = TCCHSM_RNG_MAX;
    Ret = ioctl(fd, TCCHSM_IOCTL_GET_RNG, &rng);
    rng.rng = (uint8_t*)&rng_data[16];
    Ret = ioctl(fd, TCCHSM_IOCTL_GET_RNG, &rng);
    if (Ret != HSM_OK) {
        ELOG("hsm_get_rand test fail(%d)\n", Ret);
        return Ret;
    }

    /* Test 1: AES128, ECB, 16Byte */
	param.keyIndex = key_idx;
	param.srcAddr = (uint8_t*)rng_data;
	param.srcSize = 16;
    param.enc = SOTB_CIPHER_ENCRYPTION;
    param.cwSel = CPU_Key;
    param.klIndex = 0;
    param.keyMode = 0;

    param.dstAddr = (uint8_t*)hsm_dst_addr;
	Ret = cryptoSet(fd, AES_128, ECB, 0, 1, key_idx, key_aes128, syskey, iv1, iv2);
	Ret = ioctl(fd, TCCHSM_IOCTL_RUN_CIPHER, &param);
	if (Ret != HSM_OK) {
        ELOG("Error run cipher\n");
        return HSM_GENERIC_ERR;
    }

    param.dstAddr = (uint8_t*)ssl_dst_addr;
    Ret = hsm_openssl_run_aes(ECB, key_aes128, sizeof(key_aes128), NULL, 0, &param);
    if (Ret != HSM_OK) {
        ELOG("Error run cipher\n");
        return HSM_GENERIC_ERR;
    }
    if (memcmp(hsm_dst_addr, ssl_dst_addr, param.srcSize) != 0) {
        HexDump(hsm_dst_addr, param.srcSize);
        HexDump(ssl_dst_addr, param.srcSize);
        ELOG("Wrong cipher data\n");
        return HSM_GENERIC_ERR;
    }

    /* Test 2: AES128, CBC, 16Byte */
	param.keyIndex = key_idx;
	param.srcAddr = (uint8_t*)rng_data;
	param.srcSize = 16;
    param.enc = SOTB_CIPHER_ENCRYPTION;
    param.cwSel = CPU_Key;
    param.klIndex = 0;
    param.keyMode = 0;

    param.dstAddr = (uint8_t*)hsm_dst_addr;
	Ret = cryptoSet(fd, AES_128, CBC, 0, 1, key_idx, key_aes128, syskey, iv1, iv2);
	Ret = ioctl(fd, TCCHSM_IOCTL_RUN_CIPHER, &param);
	if (Ret != HSM_OK) {
        ELOG("Error run cipher\n");
        return HSM_GENERIC_ERR;
    }

    param.dstAddr = (uint8_t*)ssl_dst_addr;
    Ret = hsm_openssl_run_aes(CBC, key_aes128, sizeof(key_aes128), iv1, sizeof(iv1), &param);
    if (Ret != HSM_OK) {
        ELOG("Error run cipher\n");
        return HSM_GENERIC_ERR;
    }
    if (memcmp(hsm_dst_addr, ssl_dst_addr, param.srcSize) != 0) {
        HexDump(hsm_dst_addr, param.srcSize);
        HexDump(ssl_dst_addr, param.srcSize);
        ELOG("Wrong cipher data\n");
        return HSM_GENERIC_ERR;
    }

    /* Test 3: AES128, ECB, 32Byte */
	param.keyIndex = key_idx;
	param.srcAddr = (uint8_t*)rng_data;
	param.srcSize = 32;
    param.enc = SOTB_CIPHER_ENCRYPTION;
    param.cwSel = CPU_Key;
    param.klIndex = 0;
    param.keyMode = 0;

    param.dstAddr = (uint8_t*)hsm_dst_addr;
	Ret = cryptoSet(fd, AES_128, ECB, 0, 1, key_idx, key_aes128, syskey, iv1, iv2);
	Ret = ioctl(fd, TCCHSM_IOCTL_RUN_CIPHER, &param);
	if (Ret != HSM_OK) {
        ELOG("Error run cipher\n");
        return HSM_GENERIC_ERR;
    }

    param.dstAddr = (uint8_t*)ssl_dst_addr;
    Ret = hsm_openssl_run_aes(ECB, key_aes128, sizeof(key_aes128), NULL, 0, &param);
    if (Ret != HSM_OK) {
        ELOG("Error run cipher\n");
        return HSM_GENERIC_ERR;
    }
    if (memcmp(hsm_dst_addr, ssl_dst_addr, param.srcSize) != 0) {
        HexDump(hsm_dst_addr, param.srcSize);
        HexDump(ssl_dst_addr, param.srcSize);
        ELOG("Wrong cipher data\n");
        return HSM_GENERIC_ERR;
    }

    /* Test 4: AES128, CBC, 32Byte */
	param.keyIndex = key_idx;
	param.srcAddr = (uint8_t*)rng_data;
	param.srcSize = 32;
    param.enc = SOTB_CIPHER_ENCRYPTION;
    param.cwSel = CPU_Key;
    param.klIndex = 0;
    param.keyMode = 0;

    param.dstAddr = (uint8_t*)hsm_dst_addr;
	Ret = cryptoSet(fd, AES_128, CBC, 0, 1, key_idx, key_aes128, syskey, iv1, iv2);
	Ret = ioctl(fd, TCCHSM_IOCTL_RUN_CIPHER, &param);
	if (Ret != HSM_OK) {
        ELOG("Error run cipher\n");
        return HSM_GENERIC_ERR;
    }

    param.dstAddr = (uint8_t*)ssl_dst_addr;
    Ret = hsm_openssl_run_aes(CBC, key_aes128, sizeof(key_aes128), iv1, sizeof(iv1), &param);
    if (Ret != HSM_OK) {
        ELOG("Error run cipher\n");
        return HSM_GENERIC_ERR;
    }
    if (memcmp(hsm_dst_addr, ssl_dst_addr, param.srcSize) != 0) {
        HexDump(hsm_dst_addr, param.srcSize);
        HexDump(ssl_dst_addr, param.srcSize);
        ELOG("Wrong cipher data\n");
        return HSM_GENERIC_ERR;
    }

    return SOTB_CIPHER_ERROR_NONE;
}

uint32_t sotbCipherDESDecTest(int fd)
{
    unsigned char* ssl_dst_addr = HwPACKET_MEMORY;
    unsigned char* hsm_dst_addr = (HwPACKET_MEMORY + 1024);
    tcc_hsm_ioctl_run_cipher_param param;
    tcc_hsm_ioctl_rng_param rng;
    uint8_t rng_data[32] = {0};
    uint32_t Ret = 0;

    /* Get random number used as input data
     * Max size is 16bytes, so run twice */
    rng.rng = (uint8_t*)&rng_data[0];
    rng.size = TCCHSM_RNG_MAX;
    Ret = ioctl(fd, TCCHSM_IOCTL_GET_RNG, &rng);
    rng.rng = (uint8_t*)&rng_data[16];
    Ret = ioctl(fd, TCCHSM_IOCTL_GET_RNG, &rng);
    if (Ret != HSM_OK) {
        ELOG("hsm_get_rand test fail(%d)\n", Ret);
        return Ret;
    }

    /* Test 1: DES128, ECB, 16Byte */
	param.keyIndex = key_idx;
	param.srcAddr = (uint8_t*)rng_data;
	param.srcSize = 16;
    param.enc = SOTB_CIPHER_DECRYPTION;
    param.cwSel = CPU_Key;
    param.klIndex = 0;
    param.keyMode = 0;

    param.dstAddr = (uint8_t*)hsm_dst_addr;
	Ret = cryptoSet(fd, DES, ECB, 0, 0, key_idx, key_des, syskey, iv1, iv2);
	Ret = ioctl(fd, TCCHSM_IOCTL_RUN_CIPHER, &param);
	if (Ret != 0) {
        ELOG("Error run cipher\n");
        return HSM_GENERIC_ERR;
    }

    param.dstAddr = (uint8_t*)ssl_dst_addr;
    Ret = hsm_openssl_run_des(ECB, key_des, sizeof(key_des), NULL, 0, &param);
    if (Ret != HSM_OK) {
        ELOG("Error run cipher\n");
        return HSM_GENERIC_ERR;
    }

    if (memcmp(hsm_dst_addr, ssl_dst_addr, param.srcSize) != 0) {
        HexDump(hsm_dst_addr, param.srcSize);
        HexDump(ssl_dst_addr, param.srcSize);
        ELOG("Wrong cipher data\n");
        return HSM_GENERIC_ERR;
    }

    /* Test 2: DES128, CBC, 16Byte */
	param.keyIndex = key_idx;
	param.srcAddr = (uint8_t*)rng_data;
	param.srcSize = 16;
    param.enc = SOTB_CIPHER_DECRYPTION;
    param.cwSel = CPU_Key;
    param.klIndex = 0;
    param.keyMode = 0;

    param.dstAddr = (uint8_t*)hsm_dst_addr;
	Ret = cryptoSet(fd, DES, CBC, 0, 0, key_idx, key_des, syskey, iv1, iv2);
	Ret = ioctl(fd, TCCHSM_IOCTL_RUN_CIPHER, &param);
	if (Ret != 0) {
        ELOG("Error run cipher\n");
        return HSM_GENERIC_ERR;
    }

    param.dstAddr = (uint8_t*)ssl_dst_addr;
    Ret = hsm_openssl_run_des(CBC, key_des, sizeof(key_des), iv1, sizeof(iv1), &param);
    if (Ret != HSM_OK) {
        ELOG("Error run cipher\n");
        return HSM_GENERIC_ERR;
    }

    if (memcmp(hsm_dst_addr, ssl_dst_addr, param.srcSize) != 0) {
        HexDump(hsm_dst_addr, param.srcSize);
        HexDump(ssl_dst_addr, param.srcSize);
        ELOG("Wrong cipher data\n");
        return HSM_GENERIC_ERR;
    }

    /* Test 3: DES128, ECB, 32Byte */
	param.keyIndex = key_idx;
	param.srcAddr = (uint8_t*)rng_data;
	param.srcSize = 32;
    param.enc = SOTB_CIPHER_DECRYPTION;
    param.cwSel = CPU_Key;
    param.klIndex = 0;
    param.keyMode = 0;

    param.dstAddr = (uint8_t*)hsm_dst_addr;
	Ret = cryptoSet(fd, DES, ECB, 0, 0, key_idx, key_des, syskey, iv1, iv2);
	Ret = ioctl(fd, TCCHSM_IOCTL_RUN_CIPHER, &param);
	if (Ret != 0) {
        ELOG("Error run cipher\n");
        return HSM_GENERIC_ERR;
    }

    param.dstAddr = (uint8_t*)ssl_dst_addr;
    Ret = hsm_openssl_run_des(ECB, key_des, sizeof(key_des), NULL, 0, &param);
    if (Ret != HSM_OK) {
        ELOG("Error run cipher\n");
        return HSM_GENERIC_ERR;
    }

    if (memcmp(hsm_dst_addr, ssl_dst_addr, param.srcSize) != 0) {
        HexDump(hsm_dst_addr, param.srcSize);
        HexDump(ssl_dst_addr, param.srcSize);
        ELOG("Wrong cipher data\n");
        return HSM_GENERIC_ERR;
    }

    /* Test 4: DES128, CBC, 32Byte */
	param.keyIndex = key_idx;
	param.srcAddr = (uint8_t*)rng_data;
	param.srcSize = 32;
    param.enc = SOTB_CIPHER_DECRYPTION;
    param.cwSel = CPU_Key;
    param.klIndex = 0;
    param.keyMode = 0;

    param.dstAddr = (uint8_t*)hsm_dst_addr;
	Ret = cryptoSet(fd, DES, CBC, 0, 0, key_idx, key_des, syskey, iv1, iv2);
	Ret = ioctl(fd, TCCHSM_IOCTL_RUN_CIPHER, &param);
	if (Ret != 0) {
        ELOG("Error run cipher\n");
        return HSM_GENERIC_ERR;
    }

    param.dstAddr = (uint8_t*)ssl_dst_addr;
    Ret = hsm_openssl_run_des(CBC, key_des, sizeof(key_des), iv1, sizeof(iv1), &param);
    if (Ret != HSM_OK) {
        ELOG("Error run cipher\n");
        return HSM_GENERIC_ERR;
    }

    if (memcmp(hsm_dst_addr, ssl_dst_addr, param.srcSize) != 0) {
        HexDump(hsm_dst_addr, param.srcSize);
        HexDump(ssl_dst_addr, param.srcSize);
        ELOG("Wrong cipher data\n");
        return HSM_GENERIC_ERR;
    }

    return SOTB_CIPHER_ERROR_NONE;
}

uint32_t sotbCipherDESEncTest(int fd)
{
    unsigned char* ssl_dst_addr = HwPACKET_MEMORY;
    unsigned char* hsm_dst_addr = (HwPACKET_MEMORY + 1024);
    tcc_hsm_ioctl_run_cipher_param param;
    tcc_hsm_ioctl_rng_param rng;
    uint8_t rng_data[32] = {0};
    uint32_t Ret = 0;

    /* Get random number used as input data
     * Max size is 16bytes, so run twice */
    rng.rng = (uint8_t*)&rng_data[0];
    rng.size = TCCHSM_RNG_MAX;
    Ret = ioctl(fd, TCCHSM_IOCTL_GET_RNG, &rng);
    rng.rng = (uint8_t*)&rng_data[16];
    Ret = ioctl(fd, TCCHSM_IOCTL_GET_RNG, &rng);
    if (Ret != HSM_OK) {
        ELOG("hsm_get_rand test fail(%d)\n", Ret);
        return Ret;
    }

    /* Test 1: DES128, ECB, 16Byte */
	param.keyIndex = key_idx;
	param.srcAddr = (uint8_t*)rng_data;
	param.srcSize = 16;
    param.enc = SOTB_CIPHER_ENCRYPTION;
    param.cwSel = CPU_Key;
    param.klIndex = 0;
    param.keyMode = 0;

    param.dstAddr = (uint8_t*)hsm_dst_addr;
	Ret = cryptoSet(fd, DES, ECB, 0, 0, key_idx, key_des, syskey, iv1, iv2);
	Ret = ioctl(fd, TCCHSM_IOCTL_RUN_CIPHER, &param);
	if (Ret != 0) {
        ELOG("Error run cipher\n");
        return HSM_GENERIC_ERR;
    }

    param.dstAddr = (uint8_t*)ssl_dst_addr;
    Ret = hsm_openssl_run_des(ECB, key_des, sizeof(key_des), NULL, 0, &param);
    if (Ret != HSM_OK) {
        ELOG("Error run cipher\n");
        return HSM_GENERIC_ERR;
    }

    if (memcmp(hsm_dst_addr, ssl_dst_addr, param.srcSize) != 0) {
        HexDump(hsm_dst_addr, param.srcSize);
        HexDump(ssl_dst_addr, param.srcSize);
        ELOG("Wrong cipher data\n");
        return HSM_GENERIC_ERR;
    }

    /* Test 2: DES128, CBC, 16Byte */
	param.keyIndex = key_idx;
	param.srcAddr = (uint8_t*)rng_data;
	param.srcSize = 16;
    param.enc = SOTB_CIPHER_ENCRYPTION;
    param.cwSel = CPU_Key;
    param.klIndex = 0;
    param.keyMode = 0;

    param.dstAddr = (uint8_t*)hsm_dst_addr;
	Ret = cryptoSet(fd, DES, CBC, 0, 0, key_idx, key_des, syskey, iv1, iv2);
	Ret = ioctl(fd, TCCHSM_IOCTL_RUN_CIPHER, &param);
	if (Ret != 0) {
        ELOG("Error run cipher\n");
        return HSM_GENERIC_ERR;
    }

    param.dstAddr = (uint8_t*)ssl_dst_addr;
    Ret = hsm_openssl_run_des(CBC, key_des, sizeof(key_des), iv1, sizeof(iv1), &param);
    if (Ret != HSM_OK) {
        ELOG("Error run cipher\n");
        return HSM_GENERIC_ERR;
    }

    if (memcmp(hsm_dst_addr, ssl_dst_addr, param.srcSize) != 0) {
        HexDump(hsm_dst_addr, param.srcSize);
        HexDump(ssl_dst_addr, param.srcSize);
        ELOG("Wrong cipher data\n");
        return HSM_GENERIC_ERR;
    }

    /* Test 3: DES128, ECB, 32Byte */
	param.keyIndex = key_idx;
	param.srcAddr = (uint8_t*)rng_data;
	param.srcSize = 32;
    param.enc = SOTB_CIPHER_ENCRYPTION;
    param.cwSel = CPU_Key;
    param.klIndex = 0;
    param.keyMode = 0;

    param.dstAddr = (uint8_t*)hsm_dst_addr;
	Ret = cryptoSet(fd, DES, ECB, 0, 0, key_idx, key_des, syskey, iv1, iv2);
	Ret = ioctl(fd, TCCHSM_IOCTL_RUN_CIPHER, &param);
	if (Ret != 0) {
        ELOG("Error run cipher\n");
        return HSM_GENERIC_ERR;
    }

    param.dstAddr = (uint8_t*)ssl_dst_addr;
    Ret = hsm_openssl_run_des(ECB, key_des, sizeof(key_des), NULL, 0, &param);
    if (Ret != HSM_OK) {
        ELOG("Error run cipher\n");
        return HSM_GENERIC_ERR;
    }

    if (memcmp(hsm_dst_addr, ssl_dst_addr, param.srcSize) != 0) {
        HexDump(hsm_dst_addr, param.srcSize);
        HexDump(ssl_dst_addr, param.srcSize);
        ELOG("Wrong cipher data\n");
        return HSM_GENERIC_ERR;
    }

    /* Test 4: DES128, CBC, 32Byte */
	param.keyIndex = key_idx;
	param.srcAddr = (uint8_t*)rng_data;
	param.srcSize = 32;
    param.enc = SOTB_CIPHER_ENCRYPTION;
    param.cwSel = CPU_Key;
    param.klIndex = 0;
    param.keyMode = 0;

    param.dstAddr = (uint8_t*)hsm_dst_addr;
	Ret = cryptoSet(fd, DES, CBC, 0, 0, key_idx, key_des, syskey, iv1, iv2);
	Ret = ioctl(fd, TCCHSM_IOCTL_RUN_CIPHER, &param);
	if (Ret != 0) {
        ELOG("Error run cipher\n");
        return HSM_GENERIC_ERR;
    }

    param.dstAddr = (uint8_t*)ssl_dst_addr;
    Ret = hsm_openssl_run_des(CBC, key_des, sizeof(key_des), iv1, sizeof(iv1), &param);
    if (Ret != HSM_OK) {
        ELOG("Error run cipher\n");
        return HSM_GENERIC_ERR;
    }

    if (memcmp(hsm_dst_addr, ssl_dst_addr, param.srcSize) != 0) {
        HexDump(hsm_dst_addr, param.srcSize);
        HexDump(ssl_dst_addr, param.srcSize);
        ELOG("Wrong cipher data\n");
        return HSM_GENERIC_ERR;
    }

    return SOTB_CIPHER_ERROR_NONE;
}

uint32_t sotbCipherTDESDecTest(int fd)
{
    unsigned char* ssl_dst_addr = HwPACKET_MEMORY;
    unsigned char* hsm_dst_addr = (HwPACKET_MEMORY + 1024);
    tcc_hsm_ioctl_run_cipher_param param;
    tcc_hsm_ioctl_rng_param rng;
    uint8_t rng_data[32] = {0};
    uint32_t Ret = 0;

    /* Get random number used as input data
     * Max size is 16bytes, so run twice */
    rng.rng = (uint8_t*)&rng_data[0];
    rng.size = TCCHSM_RNG_MAX;
    Ret = ioctl(fd, TCCHSM_IOCTL_GET_RNG, &rng);
    rng.rng = (uint8_t*)&rng_data[16];
    Ret = ioctl(fd, TCCHSM_IOCTL_GET_RNG, &rng);
    if (Ret != HSM_OK) {
        ELOG("hsm_get_rand test fail(%d)\n", Ret);
        return Ret;
    }

    /* Test 1: DES128, ECB, 16Byte */
	param.keyIndex = key_idx;
	param.srcAddr = (uint8_t*)rng_data;
	param.srcSize = 16;
    param.enc = SOTB_CIPHER_DECRYPTION;
    param.cwSel = CPU_Key;
    param.klIndex = 0;
    param.keyMode = 0;

    param.dstAddr = (uint8_t*)hsm_dst_addr;
	Ret = cryptoSet(fd, TDES_128, ECB, 0, 0, key_idx, key_tdes128, syskey, iv1, iv2);
	Ret = ioctl(fd, TCCHSM_IOCTL_RUN_CIPHER, &param);
	if (Ret != 0) {
        ELOG("Error run cipher\n");
        return HSM_GENERIC_ERR;
    }

    param.dstAddr = (uint8_t*)ssl_dst_addr;
    Ret = hsm_openssl_run_tdes(ECB, key_tdes128, sizeof(key_tdes128), NULL, 0, &param);
    if (Ret != HSM_OK) {
        ELOG("Error run cipher\n");
        return HSM_GENERIC_ERR;
    }

    if (memcmp(hsm_dst_addr, ssl_dst_addr, param.srcSize) != 0) {
        HexDump(rng_data, param.srcSize);
        HexDump(hsm_dst_addr, param.srcSize);
        HexDump(ssl_dst_addr, param.srcSize);
        ELOG("Wrong cipher data\n");
        return HSM_GENERIC_ERR;
    }

    /* Test 2: DES128, CBC, 16Byte */
	param.keyIndex = key_idx;
	param.srcAddr = (uint8_t*)rng_data;
	param.srcSize = 16;
    param.enc = SOTB_CIPHER_DECRYPTION;
    param.cwSel = CPU_Key;
    param.klIndex = 0;
    param.keyMode = 0;

    param.dstAddr = (uint8_t*)hsm_dst_addr;
	Ret = cryptoSet(fd, TDES_128, CBC, 0, 0, key_idx, key_tdes128, syskey, iv1, iv2);
	Ret = ioctl(fd, TCCHSM_IOCTL_RUN_CIPHER, &param);
	if (Ret != 0) {
        ELOG("Error run cipher\n");
        return HSM_GENERIC_ERR;
    }

    param.dstAddr = (uint8_t*)ssl_dst_addr;
    Ret = hsm_openssl_run_tdes(CBC, key_tdes128, sizeof(key_tdes128), iv1, sizeof(iv1), &param);
    if (Ret != HSM_OK) {
        ELOG("Error run cipher\n");
        return HSM_GENERIC_ERR;
    }

    if (memcmp(hsm_dst_addr, ssl_dst_addr, param.srcSize) != 0) {
        HexDump(hsm_dst_addr, param.srcSize);
        HexDump(ssl_dst_addr, param.srcSize);
        ELOG("Wrong cipher data\n");
        return HSM_GENERIC_ERR;
    }

    /* Test 3: DES128, ECB, 32Byte */
	param.keyIndex = key_idx;
	param.srcAddr = (uint8_t*)rng_data;
	param.srcSize = 32;
    param.enc = SOTB_CIPHER_DECRYPTION;
    param.cwSel = CPU_Key;
    param.klIndex = 0;
    param.keyMode = 0;

    param.dstAddr = (uint8_t*)hsm_dst_addr;
	Ret = cryptoSet(fd, TDES_128, ECB, 0, 0, key_idx, key_tdes128, syskey, iv1, iv2);
	Ret = ioctl(fd, TCCHSM_IOCTL_RUN_CIPHER, &param);
	if (Ret != 0) {
        ELOG("Error run cipher\n");
        return HSM_GENERIC_ERR;
    }

    param.dstAddr = (uint8_t*)ssl_dst_addr;
    Ret = hsm_openssl_run_tdes(ECB, key_tdes128, sizeof(key_tdes128), NULL, 0, &param);
    if (Ret != HSM_OK) {
        ELOG("Error run cipher\n");
        return HSM_GENERIC_ERR;
    }

    if (memcmp(hsm_dst_addr, ssl_dst_addr, param.srcSize) != 0) {
        HexDump(hsm_dst_addr, param.srcSize);
        HexDump(ssl_dst_addr, param.srcSize);
        ELOG("Wrong cipher data\n");
        return HSM_GENERIC_ERR;
    }

    /* Test 4: DES128, CBC, 32Byte */
	param.keyIndex = key_idx;
	param.srcAddr = (uint8_t*)rng_data;
	param.srcSize = 32;
    param.enc = SOTB_CIPHER_DECRYPTION;
    param.cwSel = CPU_Key;
    param.klIndex = 0;
    param.keyMode = 0;

    param.dstAddr = (uint8_t*)hsm_dst_addr;
	Ret = cryptoSet(fd, TDES_128, CBC, 0, 0, key_idx, key_tdes128, syskey, iv1, iv2);
	Ret = ioctl(fd, TCCHSM_IOCTL_RUN_CIPHER, &param);
	if (Ret != 0) {
        ELOG("Error run cipher\n");
        return HSM_GENERIC_ERR;
    }

    param.dstAddr = (uint8_t*)ssl_dst_addr;
    Ret = hsm_openssl_run_tdes(CBC, key_tdes128, sizeof(key_tdes128), iv1, sizeof(iv1), &param);
    if (Ret != HSM_OK) {
        ELOG("Error run cipher\n");
        return HSM_GENERIC_ERR;
    }

    if (memcmp(hsm_dst_addr, ssl_dst_addr, param.srcSize) != 0) {
        HexDump(hsm_dst_addr, param.srcSize);
        HexDump(ssl_dst_addr, param.srcSize);
        ELOG("Wrong cipher data\n");
        return HSM_GENERIC_ERR;
    }

    return SOTB_CIPHER_ERROR_NONE;
}

uint32_t sotbCipherTDESEncTest(int fd)
{
    unsigned char* ssl_dst_addr = HwPACKET_MEMORY;
    unsigned char* hsm_dst_addr = (HwPACKET_MEMORY + 1024);
    tcc_hsm_ioctl_run_cipher_param param;
    tcc_hsm_ioctl_rng_param rng;
    uint8_t rng_data[32] = {0};
    uint32_t Ret = 0;

    /* Get random number used as input data
     * Max size is 16bytes, so run twice */
    rng.rng = (uint8_t*)&rng_data[0];
    rng.size = TCCHSM_RNG_MAX;
    Ret = ioctl(fd, TCCHSM_IOCTL_GET_RNG, &rng);
    rng.rng = (uint8_t*)&rng_data[16];
    Ret = ioctl(fd, TCCHSM_IOCTL_GET_RNG, &rng);
    if (Ret != HSM_OK) {
        ELOG("hsm_get_rand test fail(%d)\n", Ret);
        return Ret;
    }

    /* Test 1: DES128, ECB, 16Byte */
	param.keyIndex = key_idx;
	param.srcAddr = (uint8_t*)rng_data;
	param.srcSize = 16;
    param.enc = SOTB_CIPHER_ENCRYPTION;
    param.cwSel = CPU_Key;
    param.klIndex = 0;
    param.keyMode = 0;

    param.dstAddr = (uint8_t*)hsm_dst_addr;
	Ret = cryptoSet(fd, TDES_128, ECB, 0, 0, key_idx, key_tdes128, syskey, iv1, iv2);
	Ret = ioctl(fd, TCCHSM_IOCTL_RUN_CIPHER, &param);
	if (Ret != 0) {
        ELOG("Error run cipher\n");
        return HSM_GENERIC_ERR;
    }

    param.dstAddr = (uint8_t*)ssl_dst_addr;
    Ret = hsm_openssl_run_tdes(ECB, key_tdes128, sizeof(key_tdes128), NULL, 0, &param);
    if (Ret != HSM_OK) {
        ELOG("Error run cipher\n");
        return HSM_GENERIC_ERR;
    }

    if (memcmp(hsm_dst_addr, ssl_dst_addr, param.srcSize) != 0) {
        HexDump(rng_data, param.srcSize);
        HexDump(hsm_dst_addr, param.srcSize);
        HexDump(ssl_dst_addr, param.srcSize);
        ELOG("Wrong cipher data\n");
        return HSM_GENERIC_ERR;
    }

    /* Test 2: DES128, CBC, 16Byte */
	param.keyIndex = key_idx;
	param.srcAddr = (uint8_t*)rng_data;
	param.srcSize = 16;
    param.enc = SOTB_CIPHER_ENCRYPTION;
    param.cwSel = CPU_Key;
    param.klIndex = 0;
    param.keyMode = 0;

    param.dstAddr = (uint8_t*)hsm_dst_addr;
	Ret = cryptoSet(fd, TDES_128, CBC, 0, 0, key_idx, key_tdes128, syskey, iv1, iv2);
	Ret = ioctl(fd, TCCHSM_IOCTL_RUN_CIPHER, &param);
	if (Ret != 0) {
        ELOG("Error run cipher\n");
        return HSM_GENERIC_ERR;
    }

    param.dstAddr = (uint8_t*)ssl_dst_addr;
    Ret = hsm_openssl_run_tdes(CBC, key_tdes128, sizeof(key_tdes128), iv1, sizeof(iv1), &param);
    if (Ret != HSM_OK) {
        ELOG("Error run cipher\n");
        return HSM_GENERIC_ERR;
    }

    if (memcmp(hsm_dst_addr, ssl_dst_addr, param.srcSize) != 0) {
        HexDump(hsm_dst_addr, param.srcSize);
        HexDump(ssl_dst_addr, param.srcSize);
        ELOG("Wrong cipher data\n");
        return HSM_GENERIC_ERR;
    }

    /* Test 3: DES128, ECB, 32Byte */
	param.keyIndex = key_idx;
	param.srcAddr = (uint8_t*)rng_data;
	param.srcSize = 32;
    param.enc = SOTB_CIPHER_ENCRYPTION;
    param.cwSel = CPU_Key;
    param.klIndex = 0;
    param.keyMode = 0;

    param.dstAddr = (uint8_t*)hsm_dst_addr;
	Ret = cryptoSet(fd, TDES_128, ECB, 0, 0, key_idx, key_tdes128, syskey, iv1, iv2);
	Ret = ioctl(fd, TCCHSM_IOCTL_RUN_CIPHER, &param);
	if (Ret != 0) {
        ELOG("Error run cipher\n");
        return HSM_GENERIC_ERR;
    }

    param.dstAddr = (uint8_t*)ssl_dst_addr;
    Ret = hsm_openssl_run_tdes(ECB, key_tdes128, sizeof(key_tdes128), NULL, 0, &param);
    if (Ret != HSM_OK) {
        ELOG("Error run cipher\n");
        return HSM_GENERIC_ERR;
    }

    if (memcmp(hsm_dst_addr, ssl_dst_addr, param.srcSize) != 0) {
        HexDump(hsm_dst_addr, param.srcSize);
        HexDump(ssl_dst_addr, param.srcSize);
        ELOG("Wrong cipher data\n");
        return HSM_GENERIC_ERR;
    }

    /* Test 4: DES128, CBC, 32Byte */
	param.keyIndex = key_idx;
	param.srcAddr = (uint8_t*)rng_data;
	param.srcSize = 32;
    param.enc = SOTB_CIPHER_ENCRYPTION;
    param.cwSel = CPU_Key;
    param.klIndex = 0;
    param.keyMode = 0;

    param.dstAddr = (uint8_t*)hsm_dst_addr;
	Ret = cryptoSet(fd, TDES_128, CBC, 0, 0, key_idx, key_tdes128, syskey, iv1, iv2);
	Ret = ioctl(fd, TCCHSM_IOCTL_RUN_CIPHER, &param);
	if (Ret != 0) {
        ELOG("Error run cipher\n");
        return HSM_GENERIC_ERR;
    }

    param.dstAddr = (uint8_t*)ssl_dst_addr;
    Ret = hsm_openssl_run_tdes(CBC, key_tdes128, sizeof(key_tdes128), iv1, sizeof(iv1), &param);
    if (Ret != HSM_OK) {
        ELOG("Error run cipher\n");
        return HSM_GENERIC_ERR;
    }

    if (memcmp(hsm_dst_addr, ssl_dst_addr, param.srcSize) != 0) {
        HexDump(hsm_dst_addr, param.srcSize);
        HexDump(ssl_dst_addr, param.srcSize);
        ELOG("Wrong cipher data\n");
        return HSM_GENERIC_ERR;
    }

    return SOTB_CIPHER_ERROR_NONE;
}

uint32_t sotbCipherCSA2DecTest(int fd)
{
    unsigned char* SrcAddr = HwPACKET_MEMORY;
    unsigned char* DstAddr = (HwPACKET_MEMORY + 1024);
    uint32_t SrcSize = 0;
    uint32_t Ret = 0;

    SrcSize = 184;
	Ret = cryptoSet(fd, DVB_CSA2, ECB, 0, 0, key_idx, CSA2_KEY, 0, 0, 0);
	Ret = cryptoRun(
		fd, CSA2_CIPHERTEXT, DstAddr, SrcSize, key_idx, SOTB_CIPHER_DECRYPTION, CPU_Key, 0, 0);
	if (Ret != SrcSize || memcmp(CSA2_PLAINTEXT, (const void*)DstAddr, SrcSize) != 0) {
		ELOG("CSA2 Fail\n");
        return SOTB_CIPHER_RUN_FAIL;
    }

    return SOTB_CIPHER_ERROR_NONE;
}

uint32_t sotbCipherCSA3DecTest(int fd)
{
    unsigned char* SrcAddr = HwPACKET_MEMORY;
    unsigned char* DstAddr = (HwPACKET_MEMORY + 1024);
    uint32_t SrcSize = 0;
    uint32_t Ret = 0;

    SrcSize = 184;
	Ret = cryptoSet(fd, DVB_CSA3, ECB, 0, 0, key_idx, CSA3_KEY, 0, 0, 0);
	Ret = cryptoRun(
		fd, CSA3_CIPHERTEXT, DstAddr, SrcSize, key_idx, SOTB_CIPHER_DECRYPTION, CPU_Key, 0, 0);
	if (Ret != SrcSize || memcmp(CSA3_PLAINTEXT, (const void*)DstAddr, SrcSize) != 0) {
		ELOG("CSA3 Fail\n");
        return SOTB_CIPHER_RUN_FAIL;
    }

    return SOTB_CIPHER_ERROR_NONE;
}

uint32_t sotbCipherCMACTest(int fd)
{
    unsigned char* ssl_dst_addr = HwPACKET_MEMORY;
    unsigned char* hsm_dst_addr = (HwPACKET_MEMORY + 1024);
    tcc_hsm_ioctl_run_cmac_param param = {0};
    struct tcc_hsm_ioctl_set_key_param key_param;
    tcc_hsm_ioctl_rng_param rng;
    uint8_t rng_data[64] = {0};
    uint32_t SrcSize = 0;
    uint32_t Ret = 0;

    /* Get random number used as input data
     * Max size is 16bytes, so run four times */
    rng.size = TCCHSM_RNG_MAX;
    rng.rng = (uint8_t*)&rng_data[0];
    Ret = ioctl(fd, TCCHSM_IOCTL_GET_RNG, &rng);
    rng.rng = (uint8_t*)&rng_data[16];
    Ret = ioctl(fd, TCCHSM_IOCTL_GET_RNG, &rng);
    rng.rng = (uint8_t*)&rng_data[32];
    Ret = ioctl(fd, TCCHSM_IOCTL_GET_RNG, &rng);
    rng.rng = (uint8_t*)&rng_data[48];
    Ret = ioctl(fd, TCCHSM_IOCTL_GET_RNG, &rng);
    if (Ret != HSM_OK) {
        ELOG("hsm_get_rand test fail(%d)\n", Ret);
        return Ret;
    }

	key_param.keyIndex = key_idx;
	key_param.keyType = CMAC_Key;
	key_param.keyMode = 0;
    key_param.keySize = sizeof(key_cmac);
    key_param.key = key_cmac;

    if (ioctl(fd, TCCHSM_IOCTL_SET_KEY, &key_param) != 0) {
        ELOG("Error set key\n");
        return HSM_GENERIC_ERR;
    }
	param.keyIndex = key_idx;
	param.srcAddr = (uint8_t*)rng_data;
	param.srcSize = sizeof(rng_data);
    param.flag = (CMAC_FLAG_FIRST | CMAC_FLAG_LAST);

    param.macAddr = (uint8_t*)hsm_dst_addr;
    Ret = ioctl(fd, TCCHSM_IOCTL_RUN_MAC, &param);
    if (Ret != 0) {
        ELOG("Error run cipher\n");
        return HSM_GENERIC_ERR;
    }

	param.keyIndex = key_idx;
	param.srcAddr = (uint8_t*)rng_data;
	param.srcSize = sizeof(rng_data);
    param.flag = (CMAC_FLAG_FIRST | CMAC_FLAG_LAST);
    param.macAddr = (uint8_t*)ssl_dst_addr;
    Ret = hsm_openssl_gen_mac(key_cmac, sizeof(key_cmac), &param);
    if (Ret != HSM_OK) {
        ELOG("Error run cipher\n");
        return HSM_GENERIC_ERR;
    }

    if (memcmp(hsm_dst_addr, ssl_dst_addr, param.mac_size) != 0) {
        HexDump(hsm_dst_addr, param.mac_size);
        HexDump(ssl_dst_addr, param.mac_size);
        ELOG("Wrong cipher data\n");
        return HSM_GENERIC_ERR;
    }

    return SOTB_CIPHER_ERROR_NONE;
}

uint32_t sotbCipherKLWithKDFTest(int fd)
{
    unsigned char* SrcAddr = HwPACKET_MEMORY;
    unsigned char* DstAddr = (HwPACKET_MEMORY + 1024);
    uint32_t SrcSize = 0;
    uint32_t KLIndex = 0;
    uint32_t Ret = 0;

    stSotbKdfInData KdfData;
    stSotbKLInData KLInData;

    // KDF0 + KL0
    // KDF0 = Stag1~Stag3 (Tdes decryption)
    // KDF : TDES Decryption, KL : AES Decryption (CR : AES Decryption)
	Ret = cryptoSetMode(fd, key_idx, AES_128, ECB, 0, 0);
	if (Ret) {
		ELOG("KDFKL0 AES ECB 128 Set Mode Fail\n");
        return SOTB_CIPHER_RUN_FAIL;
    }

    memcpy(&KdfData.ucModuleID[0], TDES_MID, sizeof(TDES_MID));
    memcpy(&KdfData.ucVendorID[0], TDES_VID, sizeof(TDES_VID));

	Ret = cryptoSetKDFData(fd, key_idx, (uintptr_t*)&KdfData);
	if (Ret) {
		ELOG("KDFKL0 AES ECB 128 Set KDF Data Fail\n");
        return SOTB_CIPHER_RUN_FAIL;
    }

    memset(&KLInData, 0, sizeof(stSotbKLInData));
    memcpy(&KLInData.ucDin1[0], KL_DIN1, sizeof(KL_DIN1));
    memcpy(&KLInData.ucDin2[0], KL_DIN2, sizeof(KL_DIN2));
    memcpy(&KLInData.ucDin3[0], KL0_DIN3, sizeof(KL0_DIN3));

    memcpy(&KLInData.ucNonce[0], KL_NONCE_INPUT, sizeof(KL_NONCE_INPUT));

    KLInData.uiNonceUsed = 1;
    KLInData.uiKLIndex = KLIndex = 0;

	Ret = cryptoSetKLData(fd, key_idx, (uintptr_t*)&KLInData);
	if (Ret) {
		ELOG("KDFKL0 AES ECB 128 Set KL Data Fail\n");
        return SOTB_CIPHER_RUN_FAIL;
    }

    SrcSize = 16;
	Ret = cryptoRun(
		fd, &KL_WithKDF_CIPHERTEXT[KLIndex][0], DstAddr, SrcSize, key_idx, SOTB_CIPHER_DECRYPTION,
		TCKL, KLIndex, 0);
	if (Ret != SrcSize || memcmp(&KL_WithKDF_PLAINTEXT[KLIndex][0], DstAddr, SrcSize) != 0) {
		ELOG("KDFKL0 AES ECB 128 Decryption Fail\n");
        return SOTB_CIPHER_RUN_FAIL;
    }

    // KDF1 + KL1
    // KDF1 = Stag1~Stag4 (Tdes Decryption)
    // KDF : TDES Decryption, KL : AES Decryption (CR : AES Decryption)
	Ret = cryptoSetMode(fd, key_idx, AES_128, ECB, 0, 0);
	if (Ret) {
		ELOG("KDFKL1 AES ECB 128 Set Mode Fail\n");
        return SOTB_CIPHER_RUN_FAIL;
    }

    memcpy(&KdfData.ucModuleID[0], TDES_MID, sizeof(TDES_MID));
    memcpy(&KdfData.ucVendorID[0], TDES_VID, sizeof(TDES_VID));

	Ret = cryptoSetKDFData(fd, key_idx, (uintptr_t*)&KdfData);
	if (Ret) {
		ELOG("KDFKL1 AES ECB 128 Set KDF Data Fail\n");
        return SOTB_CIPHER_RUN_FAIL;
    }

    memset(&KLInData, 0, sizeof(stSotbKLInData));
    memcpy(&KLInData.ucDin1[0], KL_DIN1, sizeof(KL_DIN1));
    memcpy(&KLInData.ucDin2[0], KL_DIN2, sizeof(KL_DIN2));
    memcpy(&KLInData.ucDin3[0], KL1_DIN3, sizeof(KL1_DIN3));

    memcpy(&KLInData.ucNonce[0], KL_NONCE_INPUT, sizeof(KL_NONCE_INPUT));

    KLInData.uiNonceUsed = 1;
    KLInData.uiKLIndex = KLIndex = 1;

	Ret = cryptoSetKLData(fd, key_idx, (uintptr_t*)&KLInData);
	if (Ret) {
		ELOG("KDFKL1 AES ECB 128 Set KL Data Fail\n");
        return SOTB_CIPHER_RUN_FAIL;
    }

    SrcSize = 16;
	Ret = cryptoRun(
		fd, &KL_WithKDF_CIPHERTEXT[KLIndex][0], DstAddr, SrcSize, key_idx, SOTB_CIPHER_DECRYPTION,
		TCKL, KLIndex, 0);
	if (Ret != SrcSize || memcmp(&KL_WithKDF_PLAINTEXT[KLIndex][0], DstAddr, SrcSize) != 0) {
		ELOG("KDFKL1 AES ECB 128 Decryption Fail\n");
        return SOTB_CIPHER_RUN_FAIL;
    }

    // KDF2 + KL2
    // KDF2 = Stag1~Stag3 (AES Encryption)
    // KDF : AES Encryption, KL : AES Decryption (CR : AES Decryption)
	Ret = cryptoSetMode(fd, key_idx, AES_128, ECB, 0, 0);
	if (Ret) {
		ELOG("KDFKL2 AES ECB 128 Set Mode Fail\n");
        return SOTB_CIPHER_RUN_FAIL;
    }

    memcpy(&KdfData.ucModuleID[0], AES_MID, sizeof(AES_MID));
    memcpy(&KdfData.ucVendorID[0], AES_VID, sizeof(AES_VID));

	Ret = cryptoSetKDFData(fd, key_idx, (uintptr_t*)&KdfData);
	if (Ret) {
		ELOG("KDFKL2 AES ECB 128 Set KDF Data Fail\n");
        return SOTB_CIPHER_RUN_FAIL;
    }

    memset(&KLInData, 0, sizeof(stSotbKLInData));
    memcpy(&KLInData.ucDin1[0], KL_DIN1, sizeof(KL_DIN1));
    memcpy(&KLInData.ucDin2[0], KL_DIN2, sizeof(KL_DIN2));
    memcpy(&KLInData.ucDin3[0], KL2_DIN3, sizeof(KL2_DIN3));

    memcpy(&KLInData.ucNonce[0], KL_NONCE_INPUT, sizeof(KL_NONCE_INPUT));

    KLInData.uiNonceUsed = 1;
    KLInData.uiKLIndex = KLIndex = 2;

	Ret = cryptoSetKLData(fd, key_idx, (uintptr_t*)&KLInData);
	if (Ret) {
		ELOG("KDFKL2 AES ECB 128 Set KL Data Fail\n");
        return SOTB_CIPHER_RUN_FAIL;
    }

    SrcSize = 16;
	Ret = cryptoRun(
		fd, &KL_WithKDF_CIPHERTEXT[KLIndex][0], DstAddr, SrcSize, key_idx, SOTB_CIPHER_DECRYPTION,
		TCKL, KLIndex, 0);
	if (Ret != SrcSize || memcmp(&KL_WithKDF_PLAINTEXT[KLIndex][0], DstAddr, SrcSize) != 0) {
		ELOG("KDFKL2 AES ECB 128 Decryption Fail\n");
        return SOTB_CIPHER_RUN_FAIL;
    }

    // KDF3 + KL3
    // KDF3 = Stag1~Stag4 (AES Encryption)
    // KDF : AES Encryption, KL : AES Decryption (CR : AES Decryption)
	Ret = cryptoSetMode(fd, key_idx, AES_128, ECB, 0, 0);
	if (Ret) {
		ELOG("KDFKL3 AES ECB 128 Set Mode Fail\n");
        return SOTB_CIPHER_RUN_FAIL;
    }

    memcpy(&KdfData.ucModuleID[0], AES_MID, sizeof(AES_MID));
    memcpy(&KdfData.ucVendorID[0], AES_VID, sizeof(AES_VID));

	Ret = cryptoSetKDFData(fd, key_idx, (uintptr_t*)&KdfData);
	if (Ret) {
		ELOG("KDFKL3 AES ECB 128 Set KDF Data Fail\n");
        return SOTB_CIPHER_RUN_FAIL;
    }

    memset(&KLInData, 0, sizeof(stSotbKLInData));
    memcpy(&KLInData.ucDin1[0], KL_DIN1, sizeof(KL_DIN1));
    memcpy(&KLInData.ucDin2[0], KL_DIN2, sizeof(KL_DIN2));
    memcpy(&KLInData.ucDin3[0], KL3_DIN3, sizeof(KL3_DIN3));

    memcpy(&KLInData.ucNonce[0], KL_NONCE_INPUT, sizeof(KL_NONCE_INPUT));

    KLInData.uiNonceUsed = 1;
    KLInData.uiKLIndex = KLIndex = 3;

	Ret = cryptoSetKLData(fd, key_idx, (uintptr_t*)&KLInData);
	if (Ret) {
		ELOG("KDFKL3 AES ECB 128 Set KL Data Fail\n");
        return SOTB_CIPHER_RUN_FAIL;
    }

    SrcSize = 16;
	Ret = cryptoRun(
		fd, &KL_WithKDF_CIPHERTEXT[KLIndex][0], DstAddr, SrcSize, key_idx, SOTB_CIPHER_DECRYPTION,
		TCKL, KLIndex, 0);
	if (Ret != SrcSize || memcmp(&KL_WithKDF_PLAINTEXT[KLIndex][0], DstAddr, SrcSize) != 0) {
		ELOG("KDFKL3 AES ECB 128 Decryption Fail\n");
        return SOTB_CIPHER_RUN_FAIL;
    }

    // KDF4 + KL4
    // KDF4 = Stag1~Stag4 (AES Decryption)
    // KDF : AES Decryption, KL : TDES Decryption (CR : TDES Decryption)
	Ret = cryptoSetMode(fd, key_idx, TDES_128, ECB, 0, 0);
	if (Ret) {
		ELOG("KDFKL4 TDES ECB 128 Set Mode Fail\n");
        return SOTB_CIPHER_RUN_FAIL;
    }

    memcpy(&KdfData.ucModuleID[0], AES_MID, sizeof(AES_MID));
    memcpy(&KdfData.ucVendorID[0], AES_VID, sizeof(AES_VID));

	Ret = cryptoSetKDFData(fd, key_idx, (uintptr_t*)&KdfData);
	if (Ret) {
		ELOG("KDFKL4 TDES ECB 128 Set KDF Data Fail\n");
        return SOTB_CIPHER_RUN_FAIL;
    }

    memset(&KLInData, 0, sizeof(stSotbKLInData));
    memcpy(&KLInData.ucDin1[0], KL_DIN1, sizeof(KL_DIN1));
    memcpy(&KLInData.ucDin2[0], KL_DIN2, sizeof(KL_DIN2));
    memcpy(&KLInData.ucDin3[0], KL4_DIN3, sizeof(KL4_DIN3));

    memcpy(&KLInData.ucNonce[0], KL_NONCE_INPUT, sizeof(KL_NONCE_INPUT));

    KLInData.uiNonceUsed = 1;
    KLInData.uiKLIndex = KLIndex = 4;

	Ret = cryptoSetKLData(fd, key_idx, (uintptr_t*)&KLInData);
	if (Ret) {
		ELOG("KDFKL4 TDES ECB 128 Set KL Data Fail\n");
        return SOTB_CIPHER_RUN_FAIL;
    }

    SrcSize = 16;
	Ret = cryptoRun(
		fd, &KL_WithKDF_CIPHERTEXT[KLIndex][0], DstAddr, SrcSize, key_idx, SOTB_CIPHER_DECRYPTION,
		TCKL, KLIndex, 0);
	if (Ret != SrcSize || memcmp(&KL_WithKDF_PLAINTEXT[KLIndex][0], DstAddr, SrcSize) != 0) {
		ELOG("KDFKL4 TDES ECB 128 Decryption Fail\n");
        return SOTB_CIPHER_RUN_FAIL;
    }

    // KDF5 + KL5
    // KDF5 = Stag1~Stag3 (TDES Decryption)
    // KDF : TDES Decryption, KL : TDES Decryption (CR : TDES Decryption)
	Ret = cryptoSetMode(fd, key_idx, TDES_128, ECB, 0, 0);
	if (Ret) {
		ELOG("KDFKL5 TDES ECB 128 Set Mode Fail\n");
        return SOTB_CIPHER_RUN_FAIL;
    }

    memcpy(&KdfData.ucModuleID[0], TDES_MID, sizeof(TDES_MID));
    memcpy(&KdfData.ucVendorID[0], TDES_VID, sizeof(TDES_VID));

	Ret = cryptoSetKDFData(fd, key_idx, (uintptr_t*)&KdfData);
	if (Ret) {
		ELOG("KDFKL5 TDES ECB 128 Set KDF Data Fail\n");
        return SOTB_CIPHER_RUN_FAIL;
    }

    memset(&KLInData, 0, sizeof(stSotbKLInData));
    memcpy(&KLInData.ucDin1[0], KL_DIN1, sizeof(KL_DIN1));
    memcpy(&KLInData.ucDin2[0], KL_DIN2, sizeof(KL_DIN2));
    memcpy(&KLInData.ucDin3[0], KL5_DIN3, sizeof(KL5_DIN3));

    memcpy(&KLInData.ucNonce[0], KL_NONCE_INPUT, sizeof(KL_NONCE_INPUT));

    KLInData.uiNonceUsed = 1;
    KLInData.uiKLIndex = KLIndex = 5;

	Ret = cryptoSetKLData(fd, key_idx, (uintptr_t*)&KLInData);
	if (Ret) {
		ELOG("KDFKL5 TDES ECB 128 Set KL Data Fail\n");
        return SOTB_CIPHER_RUN_FAIL;
    }

    SrcSize = 16;
	Ret = cryptoRun(
		fd, &KL_WithKDF_CIPHERTEXT[KLIndex][0], DstAddr, SrcSize, key_idx, SOTB_CIPHER_DECRYPTION,
		TCKL, KLIndex, 0);
	if (Ret != SrcSize || memcmp(&KL_WithKDF_PLAINTEXT[KLIndex][0], DstAddr, SrcSize) != 0) {
		ELOG("KDFKL5 TDES ECB 128 Decryption Fail\n");
        return SOTB_CIPHER_RUN_FAIL;
    }

    // KDF6 + KL6
    // KDF6 = Stag1~Stag3 (TDES Decryption)
    // KDF : TDES Decryption, KL : TDES Decryption (CR : TDES Decryption)
	Ret = cryptoSetMode(fd, key_idx, TDES_128, ECB, 0, 0);
	if (Ret) {
		ELOG("KDFKL6 TDES ECB 128 Set Mode Fail\n");
        return SOTB_CIPHER_RUN_FAIL;
    }

    memcpy(&KdfData.ucModuleID[0], TDES_MID, sizeof(TDES_MID));
    memcpy(&KdfData.ucVendorID[0], TDES_VID, sizeof(TDES_VID));

	Ret = cryptoSetKDFData(fd, key_idx, (uintptr_t*)&KdfData);
	if (Ret) {
		ELOG("KDFKL6 TDES ECB 128 Set KDF Data Fail\n");
        return SOTB_CIPHER_RUN_FAIL;
    }

    memset(&KLInData, 0, sizeof(stSotbKLInData));
    memcpy(&KLInData.ucDin1[0], KL_DIN1, sizeof(KL_DIN1));
    memcpy(&KLInData.ucDin2[0], KL_DIN2, sizeof(KL_DIN2));
    memcpy(&KLInData.ucDin3[0], KL6_DIN3, sizeof(KL6_DIN3));

    memcpy(&KLInData.ucNonce[0], KL_NONCE_INPUT, sizeof(KL_NONCE_INPUT));

    KLInData.uiNonceUsed = 1;
    KLInData.uiKLIndex = KLIndex = 6;

	Ret = cryptoSetKLData(fd, key_idx, (uintptr_t*)&KLInData);
	if (Ret) {
		ELOG("KDFKL6 TDES ECB 128 Set KL Data Fail\n");
        return SOTB_CIPHER_RUN_FAIL;
    }

    SrcSize = 16;
	Ret = cryptoRun(
		fd, &KL_WithKDF_CIPHERTEXT[KLIndex][0], DstAddr, SrcSize, key_idx, SOTB_CIPHER_DECRYPTION,
		TCKL, KLIndex, 0);
	if (Ret != SrcSize || memcmp(&KL_WithKDF_PLAINTEXT[KLIndex][0], DstAddr, SrcSize) != 0) {
		ELOG("KDFKL6 TDES ECB 128 Decryption Fail\n");
        return SOTB_CIPHER_RUN_FAIL;
    }

    // KDF7 + KL7
    // KDF7 = Stag1~Stag3 (TDES Encryption)
    // KDF : TDES Encryption, KL : TDES Decryption (CR : TDES Decryption)
	Ret = cryptoSetMode(fd, key_idx, TDES_128, ECB, 0, 0);
	if (Ret) {
		ELOG("KDFKL7 TDES ECB 128 Set Mode Fail\n");
        return SOTB_CIPHER_RUN_FAIL;
    }

    memcpy(&KdfData.ucModuleID[0], TDES_MID, sizeof(TDES_MID));
    memcpy(&KdfData.ucVendorID[0], TDES_VID, sizeof(TDES_VID));

	Ret = cryptoSetKDFData(fd, key_idx, (uintptr_t*)&KdfData);
	if (Ret) {
		ELOG("KDFKL7 TDES ECB 128 Set KDF Data Fail\n");
        return SOTB_CIPHER_RUN_FAIL;
    }

    memset(&KLInData, 0, sizeof(stSotbKLInData));

    memcpy(&KLInData.ucDin1[0], &KL7_DIN[0][0], SOTB_CIPHER_BLOCKSIZE_FOR_128);
    memcpy(&KLInData.ucDin2[0], &KL7_DIN[1][0], SOTB_CIPHER_BLOCKSIZE_FOR_128);
    memcpy(&KLInData.ucDin3[0], &KL7_DIN[2][0], SOTB_CIPHER_BLOCKSIZE_FOR_128);
    memcpy(&KLInData.ucDin4[0], &KL7_DIN[3][0], SOTB_CIPHER_BLOCKSIZE_FOR_128);
    memcpy(&KLInData.ucDin5[0], &KL7_DIN[4][0], SOTB_CIPHER_BLOCKSIZE_FOR_128);
    memcpy(&KLInData.ucDin6[0], &KL7_DIN[5][0], SOTB_CIPHER_BLOCKSIZE_FOR_128);
    memcpy(&KLInData.ucDin7[0], &KL7_DIN[6][0], SOTB_CIPHER_BLOCKSIZE_FOR_128);
    memcpy(&KLInData.ucDin8[0], &KL7_DIN[7][0], SOTB_CIPHER_BLOCKSIZE_FOR_128);

    memcpy(&KLInData.ucNonce[0], KL_NONCE_INPUT, sizeof(KL_NONCE_INPUT));

    KLInData.uiNonceUsed = 1;
    KLInData.uiKLIndex = KLIndex = 7;

	Ret = cryptoSetKLData(fd, key_idx, (uintptr_t*)&KLInData);
	if (Ret) {
		ELOG("KDFKL7 TDES ECB 128 Set KL Data Fail\n");
        return SOTB_CIPHER_RUN_FAIL;
    }

    SrcSize = 16;
	Ret = cryptoRun(
		fd, &KL_WithKDF_CIPHERTEXT[KLIndex][0], DstAddr, SrcSize, key_idx, SOTB_CIPHER_DECRYPTION,
		TCKL, KLIndex, 0);
	if (Ret != SrcSize || memcmp(&KL_WithKDF_PLAINTEXT[KLIndex][0], DstAddr, SrcSize) != 0) {
		ELOG("KDFKL7 TDES ECB 128 Decryption Fail\n");
        return SOTB_CIPHER_RUN_FAIL;
    }

    return SOTB_CIPHER_ERROR_NONE;
}

/*
 * Before sotbCipherKLWithRKTTest, Tester must write key ladder config data to OTP ROM.
 * Please refer to 4. How to Write Key Ladder Data To OTP chapter
 * in TCC803x Security-User Guide for HSM.pdf.
 */
uint32_t sotbCipherKLWithRKTest(int fd)
{
    unsigned char* SrcAddr = HwPACKET_MEMORY;
    unsigned char* DstAddr = (HwPACKET_MEMORY + 1024);
    uint32_t SrcSize = 0;
    uint32_t KLIndex = 0;
    uint32_t Ret = 0;

    stSotbKLInData KLInData;

    // KL7 : AES Decryption
	Ret = cryptoSetMode(fd, key_idx, AES_128, ECB, 0, 0);
	if (Ret) {
		ELOG("TCKL AES ECB 128 Set Mode Fail\n");
        return SOTB_CIPHER_RUN_FAIL;
    }

    memset(&KLInData, 0, sizeof(stSotbKLInData));
    memcpy(&KLInData.ucDin1[0], DIN0, sizeof(DIN0));
    memcpy(&KLInData.ucDin2[0], DIN1, sizeof(DIN1));
    memcpy(&KLInData.ucDin3[0], DIN2, sizeof(DIN2));

    KLInData.uiNonceUsed = 0;
    KLInData.uiKLIndex = KLIndex = 0;

	Ret = cryptoSetKLData(fd, key_idx, (uintptr_t*)&KLInData);
	if (Ret) {
		ELOG("TCKL AES ECB 128 Set KL Data Failed\n");
        return SOTB_CIPHER_RUN_FAIL;
    }

    // AES Encryption Pass Test
    SrcSize = 16;
    Ret = cryptoRun(
        fd, FOR_KL_PLAINTEXT, DstAddr, SrcSize, key_idx, SOTB_CIPHER_ENCRYPTION, TCKL,
        KLIndex, 0);
    if (Ret != SrcSize || memcmp(AES_ECB_FOR_KL_CIPHERTEXT, DstAddr, SrcSize) != 0) {
        ELOG("TCKL AES ECB 128 key Encryption Pass Test Failed(%d)\n", Ret);
        return SOTB_CIPHER_RUN_FAIL;
    }

    // AES Decryption Fail Test
    SrcSize = 16;
	Ret = cryptoRun(
		fd, AES_ECB_FOR_KL_CIPHERTEXT, DstAddr, SrcSize, key_idx, SOTB_CIPHER_DECRYPTION, TCKL,
		KLIndex, 0);
	if (Ret != SrcSize || memcmp(FOR_KL_PLAINTEXT, DstAddr, SrcSize) == 0) {
        ELOG("TCKL AES ECB 128 key Decryption Fail Test Failed(%d)\n", Ret);
        return SOTB_CIPHER_RUN_FAIL;
    }

    return SOTB_CIPHER_ERROR_NONE;
}
