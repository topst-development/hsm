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
#include <string.h>
#include <stdint.h>

#ifndef HSM_CIPHER_H
#define HSM_CIPHER_H

#define SOTB_CIPHER_ERROR_NONE 0
#define SOTB_CIPHER_UNKNOWN_OPMODE 1
#define SOTB_CIPHER_UNKNOWN_KEYSIZE 2
#define SOTB_CIPHER_UNKNOWN_ALGORITHM 3
#define SOTB_CIPHER_UNKNOWN_IVMODE 4
#define SOTB_CIPHER_UNKNOWN_IVSIZE 5
#define SOTB_CIPHER_UNKNOWN_ADDR 6
#define SOTB_CIPHER_UNKNOWN_BLOCKSIZE 7
#define SOTB_CIPHER_UNKNOWN_KEYTABLE_SLOTINDEX 8
#define SOTB_CIPHER_UNKNOWN_CMD 9
#define SOTB_CIPHER_NOTSUPPORT_NONCE 10
#define SOTB_CIPHER_UNKNOWN_CCADDR 11
#define SOTB_CIPHER_NOTSUPPOTR_CCADDR_SIZE 12
#define SOTB_CIPHER_NOTSUPPORT_KEYMODE 13
#define SOTB_CIPHER_SWUSAGE_ALGO_MISMATCH 14
#define SOTB_CIPHER_SWUSAGE_KEYSZIE_MISMATCH 15
#define SOTB_CIPHER_SWUSAGE_ENC_NOTALLOW 16
#define SOTB_CIPHER_SWUSAGE_DEC_NOTALLOW 17
#define SOTB_CIPHER_SWUSAGE_REQUEST_ERROR 18
#define SOTB_CIPHER_SWUSAGE_UNDEFINE_ALGO 19
#define SOTB_CIPHER_RUN_FAIL 0xffffffff

#define SOTB_CIPHER_KEYSIZE_FOR_64 8
#define SOTB_CIPHER_KEYSIZE_FOR_128 16
#define SOTB_CIPHER_KEYSIZE_FOR_192 24
#define SOTB_CIPHER_KEYSIZE_FOR_256 32

#define SOC_TEST_VECTOR
//#define SOC_TEST_VECTOR_DECRYPT

//#define STAGE6_TEST
#define KDF_TEST

#define HwCA2_CONFIG ((volatile CA2_CONFIG *)(HwCORTEXM4_SECURE_PERI_CFG_BASE))
#define HwSOTB_KEYTABLE ((volatile SOTB_KEYTABLE *)(HwCORTEXM4_KEY_TABLE_CTRL_BASE))
#define HwSOTB_CIPHER ((volatile SOTB_CIPHER *)(HwCORTEXM4_SOTB_CIPHER_BASE))
#define HwSOTB_TCKL ((volatile SOTB_TCKL *)(HwCORTEXM4_TC_KEY_LADDER_BASE))

#define SOTB_CIPHER_IV1 1
#define SOTB_CIPHER_IV2 2

#define SOTB_CIPHER_IVSIZE_FOR_64 8
#define SOTB_CIPHER_IVSIZE_FOR_128 16

#define SOTB_CIPHER_BLOCKSIZE_FOR_64 8
#define SOTB_CIPHER_BLOCKSIZE_FOR_128 16

#define SOTB_CIPHER_KEYSIZE_FOR_64 8
#define SOTB_CIPHER_KEYSIZE_FOR_128 16
#define SOTB_CIPHER_KEYSIZE_FOR_192 24
#define SOTB_CIPHER_KEYSIZE_FOR_256 32

#define SOTB_CIPHER_SYS_KEYSIZE 32

#define SOTB_CIPHER_MAX_KEYSLOT 8

#define SOTB_CIPHER_DECRYPTION 0
#define SOTB_CIPHER_ENCRYPTION 1

#define SOTB_CIPHER_READKEY 0
#define SOTB_CIPHER_WRITEKEY 1

#define SOTB_CIPHER_MAX_LENGTH 8176 // (MAX)8191

#define SOTB_CIPHER_KEYTABLE_MAX_KEYSLOT 31

#define SOTB_CIPHER_ERROR_NONE 0
#define SOTB_CIPHER_UNKNOWN_OPMODE 1
#define SOTB_CIPHER_UNKNOWN_KEYSIZE 2
#define SOTB_CIPHER_UNKNOWN_ALGORITHM 3
#define SOTB_CIPHER_UNKNOWN_IVMODE 4
#define SOTB_CIPHER_UNKNOWN_IVSIZE 5
#define SOTB_CIPHER_UNKNOWN_ADDR 6
#define SOTB_CIPHER_UNKNOWN_BLOCKSIZE 7
#define SOTB_CIPHER_UNKNOWN_KEYTABLE_SLOTINDEX 8
#define SOTB_CIPHER_UNKNOWN_CMD 9
#define SOTB_CIPHER_NOTSUPPORT_NONCE 10
#define SOTB_CIPHER_UNKNOWN_CCADDR 11
#define SOTB_CIPHER_NOTSUPPOTR_CCADDR_SIZE 12
#define SOTB_CIPHER_NOTSUPPORT_KEYMODE 13
#define SOTB_CIPHER_SWUSAGE_ALGO_MISMATCH 14
#define SOTB_CIPHER_SWUSAGE_KEYSZIE_MISMATCH 15
#define SOTB_CIPHER_SWUSAGE_ENC_NOTALLOW 16
#define SOTB_CIPHER_SWUSAGE_DEC_NOTALLOW 17
#define SOTB_CIPHER_SWUSAGE_REQUEST_ERROR 18
#define SOTB_CIPHER_SWUSAGE_UNDEFINE_ALGO 19
#define SOTB_CIPHER_RUN_FAIL 0xffffffff

#define SOTB_KL_ERROR_NONE 0
#define SOTB_KL_UNKNOWN_OPMODE 1
#define SOTB_KL_UNKNOWN_ALGORITHM 2
#define SOTB_KL_UNKNOWN_INDEX 3

#define SOTB_KL_NONCE_SIZE 16

#define SOTB_CIPHER_EVEN_MASK 0x01
#define SOTB_CIPHER_ODD_MASK 0x02

#define SOTB_CIPHER_SETMODE 0x1000
#define SOTB_CIPHER_SETKEY 0x1001
#define SOTB_CIPHER_SETIV 0x1002
#define SOTB_CIPHER_SETDATA 0x1003
#define SOTB_CIPHER_RUN 0x1004
#define SOTB_CIPHER_SETKDFDATA 0x1005
#define SOTB_CIPHER_SETKLDATA 0x1006
#define SOTB_CIPHER_GETKLNRESP 0x1007

#define TCCHSM_RNG_MAX 16

#define TCC_AES_ECB_OFFSET (16u)
#define TCC_DES_ECB_OFFSET (8u)

enum core_type
{
	CORE_TYPE_A53 = 1,
	CORE_TYPE_A7 = 2,
	CORE_TYPE_R5 = 3,
	CORE_TYPE_HSM = 4,
};

enum tcc_hsm_ioctl_cmd
{
    TCCHSM_IOCTL_GET_VERSION,
    TCCHSM_IOCTL_START,
    TCCHSM_IOCTL_STOP,
    TCCHSM_IOCTL_SET_MODE,
    TCCHSM_IOCTL_SET_KEY,
    TCCHSM_IOCTL_SET_IV,
    TCCHSM_IOCTL_SET_KLDATA,
    TCCHSM_IOCTL_RUN_CIPHER,
    TCCHSM_IOCTL_RUN_CIPHER_BY_DMA,
    TCCHSM_IOCTL_RUN_MAC,
    TCCHSM_IOCTL_WRITE_OTP,
    TCCHSM_IOCTL_GET_RNG,
    TCCHSM_IOCTL_MAX
};

enum tcc_hsm_ioctl_cipher_algo
{
    NONE = 0,
    DVB_CSA2 = 1,
    DVB_CSA3 = 2,
    AES_128 = 3,
    DES = 4,
    TDES_128 = 5,
    Multi2 = 6,
};

enum tcc_hsm_ioctl_cipher_op_mode
{
    ECB = 0,
    CBC = 1,
    CTR_128 = 4,
    CTR_64 = 5,
};

enum tcc_hsm_ioctl_cipher_key_type
{
    CORE_Key = 0,
    Multi2_System_Key = 1,
    CMAC_Key = 2,
};

typedef enum {
    TS_NOT_SCRAMBLED = 0,
    TS_RESERVED,
    TS_SCRAMBLED_WITH_EVENKEY,
    TS_SCRAMBLED_WITH_ODDKEY
} MpegTsScramblingCtrl;

enum tcc_hsm_ioctl_cipher_enc
{
    DECRYPTION = 0,
    ENCRYPTION = 1,
};

enum tcc_hsm_ioctl_cipher_cw_sel
{
    TCKL = 0,
    CPU_Key = 1,
};

typedef enum _CMAC_FLAG {
    CMAC_FLAG_NONE = 0,
    CMAC_FLAG_FIRST = 1,
    CMAC_FLAG_LAST = 2,
} CMAC_FLAG;

typedef struct tcc_hsm_ioctl_set_mode_param
{
    uint32_t keyIndex;
    uint32_t algorithm;
    uint32_t opMode;
    uint32_t residual;
    uint32_t sMsg;
} tcc_hsm_ioctl_set_mode_param;

typedef struct tcc_hsm_ioctl_version_param
{
    uint32_t major;
    uint32_t minor;
} tcc_hsm_ioctl_version_param;

typedef struct _SOTB_KDfInData
{
    uint8_t ucVendorID[16];
    uint8_t ucModuleID[16];
} stSotbKdfInData;

typedef struct _SOTB_KLInData
{
    uint32_t uiKLIndex;
    uint32_t uiNonceUsed;
    uint8_t ucDin1[16];
    uint8_t ucDin2[16];
    uint8_t ucDin3[16];
    uint8_t ucDin4[16];
    uint8_t ucDin5[16];
    uint8_t ucDin6[16];
    uint8_t ucDin7[16];
    uint8_t ucDin8[16];
    uint8_t ucNonce[16];
    uint8_t ucNResp[16];
} stSotbKLInData;

typedef struct _SOTB_Crypto_Data
{
    uint32_t KeySlotIdx;
    uint32_t CWSel;    // refer to SOTB_CIPHER_CTRL_SEL_KT
    uint32_t Algo;     // refer to SOTB_CIPHER_CTRL_ALGO
    uint32_t Opmode;   // refer to SOTB_CIPHER_OP_MODE
    uint32_t Residual; //
    uint32_t Smsg;     //
    uint32_t SrcAddr;
    uint32_t DestAddr;
    uint32_t SrcLen;
    uint32_t CipherAddr;     // must have set to Packet memory address
    uint32_t CipherAddrSize; // CipherAddr size
    uint32_t KeySize;
    uint32_t IVSize;
    uint32_t userData; // Set private user data
    uint8_t KeydataEven[16];
    uint8_t KeydataOdd[16];
    uint8_t SysKeydata[32];
    uint8_t IVdata1[16];
    uint8_t IVdata2[16];
} stSotbCryptoData;

typedef struct tcc_hsm_ioctl_set_key_param
{
    uint32_t keyIndex;
    uint32_t keyType;
    uint32_t keyMode;
    uint32_t keySize;
    uint8_t *key;
} tcc_hsm_ioctl_set_key_param;

typedef struct tcc_hsm_ioctl_set_iv_param
{
    uint32_t keyIndex;
    uint32_t ivSize;
    uint8_t *iv;
} tcc_hsm_ioctl_set_iv_param;

typedef struct tcc_hsm_kldata
{
    uint32_t klIndex;
    uint32_t nonceUsed;
    uint8_t Din1[16];
    uint8_t Din2[16];
    uint8_t Din3[16];
    uint8_t Din4[16];
    uint8_t Din5[16];
    uint8_t Din6[16];
    uint8_t Din7[16];
    uint8_t Din8[16];
    uint8_t nonce[16];
    uint8_t nonceResp[16];
} tcc_hsm_kldata;

typedef struct tcc_hsm_ioctl_set_kldata_param
{
    uint32_t keyIndex;
    struct tcc_hsm_kldata *klData;
} tcc_hsm_ioctl_set_kldata_param;

typedef struct tcc_hsm_ioctl_run_cipher_param
{
    uint32_t keyIndex;
    uint8_t *srcAddr;
    uint8_t *dstAddr;
    uint32_t srcSize;
    uint32_t enc;
    uint32_t cwSel;
    uint32_t klIndex;
    uint32_t keyMode;
} tcc_hsm_ioctl_run_cipher_param;

typedef struct tcc_hsm_ioctl_run_cmac_param
{
    uint32_t keyIndex;
    uint32_t flag;
    uint8_t *srcAddr;
    uint32_t srcSize;
    uint8_t *macAddr;
    uint32_t mac_size;
} tcc_hsm_ioctl_run_cmac_param;

typedef struct tcc_hsm_ioctl_otp_param
{
    uint32_t addr;
    uint8_t *buf;
    uint32_t size;
} tcc_hsm_ioctl_otp_param;

typedef struct tcc_hsm_ioctl_rng_param
{
    uint8_t *rng;
    uint32_t size;
} tcc_hsm_ioctl_rng_param;

uint32_t sotbCipherAESDecTest(int fd);
uint32_t sotbCipherAESEncTest(int fd);
uint32_t sotbCipherDESDecTest(int fd);
uint32_t sotbCipherDESEncTest(int fd);
uint32_t sotbCipherTDESDecTest(int fd);
uint32_t sotbCipherTDESEncTest(int fd);
uint32_t sotbCipherCSA2DecTest(int fd);
uint32_t sotbCipherCSA3DecTest(int fd);
uint32_t sotbCipherCMACTest(int fd);
uint32_t sotbCipherKLWithKDFTest(int fd);
uint32_t sotbCipherKLWithRKTest(int fd);

#endif // HSM_CIPHER_H
