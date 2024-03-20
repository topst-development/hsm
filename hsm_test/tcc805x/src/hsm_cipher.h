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
#ifndef HSM_CIPHER_H
#define HSM_CIPHER_H

#include <string.h>
#include <stdint.h>

// clang-format off
/* Error Code 0x000000XX */
#define TCCHSM_SUCCESS 					(0x00000000u)
#define TCCHSM_ERR 						(0x00000001u)
#define TCCHSM_ERR_INVALID_PARAM 		(0x00000002u)
#define TCCHSM_ERR_INVALID_STATE 		(0x00000003u)
#define TCCHSM_ERR_INVALID_MEMORY		(0x00000004u)
#define TCCHSM_ERR_UNSUPPORTED_FUNC 	(0x00000005u)
#define TCCHSM_ERR_OTP 					(0x00000006u)
#define TCCHSM_ERR_CRYPTO 				(0x00000007u)
#define TCCHSM_ERR_OCCUPIED_RESOURCE 	(0x00000008u)
#define TCCHSM_ERR_IMG_INTEGRITY 		(0x00000009u)
#define TCCHSM_ERR_RBID_MISMATCH 		(0x0000000Au)
#define TCCHSM_ERR_IMGID_MISMATCH 		(0x0000000Bu)
#define TCCHSM_ERR_ATTR_MISMATCH 		(0x0000000Cu)
#define TCCHSM_ERR_VERSION_MISMATCH		(0x0000000Du)
/* Error Code 0x0000XX00 */
#define ERROR_AES						(0x00001000u)
#define ERROR_AES_ECB					(0x00001100u)
#define ERROR_AES_CBC					(0x00001200u)
#define ERROR_CMAC_AES					(0x00001800u)
#define ERROR_SHA						(0x00002000u)
#define ERROR_SHA1						(0x00002100u)
#define ERROR_SHA2						(0x00002200u)
#define ERROR_SHA3						(0x00002300u)
#define ERROR_SHA256					(0x00002800u)
#define ERROR_RNG						(0x00004000u)
#define ERROR_RNG_TRNG					(0x00004100u)
#define ERROR_RNG_PRNG					(0x00004200u)
#define ERROR_RNG_PRNG_Instantiate		(0x00004300u)
#define ERROR_RNG_PRNG_Reseed			(0x00004400u)
#define ERROR_RNG_PRNG_Generate			(0x00004500u)
#define ERROR_RSA						(0x00005000u)
#define ERROR_RSA_PSS_VRFY				(0x00005240u)
#define ERROR_RSA_PSS_VRFY_DIGEST		(0x00005260u)
#define ERROR_RSA_GEN_KEY				(0x00005300u)
#define ERROR_ECC						(0x00006000u)
#define ERROR_ECDSA						(0x00007000u)
#define ERROR_ECDSA_NIST_VRFY			(0x00007110u)
#define ERROR_ECDSA_BP_VRFY				(0x00007210u)
#define ERROR_PKA						(0x0000E000u)
#define ERROR_FAIL						(0x0000F100u)
/* Error Code 0x00XX0000 */
#define INVALID_LEN						(0x00010000u)
#define INVALID_SEL						(0x00FE0000u)
#define INVALID_VAL						(0x00FF0000u)
#define INVALID_STS						(0x00FD0000u)
#define INVALID_SZ						(0x00FC0000u)
#define INVALID_FORM					(0x00FB0000u)
#define INVALID_STATUS					(0x00190000u)
/* Error Code 0xXX000000 */
#define ERR_IV							(0x02000000u)
#define ERR_TAG							(0x03000000u)
#define RR_KEY							(0x04000000u)
#define ERR_BLOCK						(0x05000000u)
#define ERR_MSG							(0x06000000u)
#define ERR_MODE						(0x07000000u)
#define ERR_OID_ALG						(0x08000000u)
#define ERR_OID_SIZE					(0x09000000u)
#define ERR_SIGNATURE					(0x0A000000u)
#define ERR_PUBLICKEY					(0x0B000000u)
#define ERR_BUSY						(0x10000000u)
#define ERR_KAT							(0x14000000u)
#define ERR_HT							(0x15000000u)
#define ERR_RANDOM						(0x16000000u)
#define ERR_SALT						(0x17000000u)
#define ERR_STATE_E						(0x22000000u)	// Name: ERR_STATE, to avoid build error
#define ERR_ENTROPY						(0x23000000u)
#define ERR_RESEED_COUNTER				(0x26000000u)
#define ERR_INPUT_STRING				(0x27000000u)
#define ERR_REQ_RNG						(0x28000000u)
#define ERR_SEED						(0x29000000u)
#define ERR_LABEL						(0x30000000u)
#define ERR_HW							(0xFF000000u)
#define ERR_DECRYPTION					(0xDD000000u)

#define HSM_IOCTL_MAGIC 'H'
#define	HSM_SET_KEY_FROM_OTP_CMD		_IOWR(HSM_IOCTL_MAGIC, 0, unsigned int)
#define	HSM_SET_KEY_FROM_SNOR_CMD		_IOWR(HSM_IOCTL_MAGIC, 1, unsigned int)
#define	HSM_RUN_AES_CMD					_IOWR(HSM_IOCTL_MAGIC, 2, unsigned int)
#define	HSM_RUN_AES_BY_KT_CMD			_IOWR(HSM_IOCTL_MAGIC, 3, unsigned int)
#define	HSM_RUN_SM4_CMD					_IOWR(HSM_IOCTL_MAGIC, 4, unsigned int)
#define	HSM_RUN_SM4_BY_KT_CMD			_IOWR(HSM_IOCTL_MAGIC, 5, unsigned int)
#define	HSM_GEN_CMAC_VERIFY_CMD			_IOWR(HSM_IOCTL_MAGIC, 6, unsigned int)
#define	HSM_GEN_CMAC_VERIFY_BY_KT_CMD	_IOWR(HSM_IOCTL_MAGIC, 7, unsigned int)
#define	HSM_GEN_GMAC_CMD				_IOWR(HSM_IOCTL_MAGIC, 8, unsigned int)
#define	HSM_GEN_GMAC_BY_KT_CMD			_IOWR(HSM_IOCTL_MAGIC, 9, unsigned int)
#define	HSM_GEN_HMAC_CMD				_IOWR(HSM_IOCTL_MAGIC, 10, unsigned int)
#define	HSM_GEN_HMAC_BY_KT_CMD			_IOWR(HSM_IOCTL_MAGIC, 11, unsigned int)
#define	HSM_GEN_SM3_HMAC_CMD			_IOWR(HSM_IOCTL_MAGIC, 12, unsigned int)
#define	HSM_GEN_SM3_HMAC_BY_KT_CMD		_IOWR(HSM_IOCTL_MAGIC, 13, unsigned int)
#define	HSM_GEN_SHA_CMD					_IOWR(HSM_IOCTL_MAGIC, 14, unsigned int)
#define	HSM_GEN_SM3_CMD					_IOWR(HSM_IOCTL_MAGIC, 15, unsigned int)
#define	HSM_RUN_ECDSA_SIGN_CMD			_IOWR(HSM_IOCTL_MAGIC, 16, unsigned int)
#define	HSM_RUN_ECDSA_VERIFY_CMD		_IOWR(HSM_IOCTL_MAGIC, 17, unsigned int)
#define	HSM_RUN_RSASSA_PKCS_SIGN_CMD	_IOWR(HSM_IOCTL_MAGIC, 18, unsigned int)
#define	HSM_RUN_RSASSA_PKCS_VERIFY_CMD	_IOWR(HSM_IOCTL_MAGIC, 19, unsigned int)
#define	HSM_RUN_RSASSA_PSS_SIGN_CMD		_IOWR(HSM_IOCTL_MAGIC, 20, unsigned int)
#define	HSM_RUN_RSASSA_PSS_VERIFY_CMD	_IOWR(HSM_IOCTL_MAGIC, 21, unsigned int)
#define	HSM_GET_RNG_CMD					_IOWR(HSM_IOCTL_MAGIC, 22, unsigned int)
#define	HSM_WRITE_OTP_CMD				_IOWR(HSM_IOCTL_MAGIC, 23, unsigned int)
#define	HSM_WRITE_SNOR_CMD				_IOWR(HSM_IOCTL_MAGIC, 24, unsigned int)
#define	HSM_GET_FW_VER_CMD				_IOWR(HSM_IOCTL_MAGIC, 25, unsigned int)
#define	HSM_RUN_ECDH_PUBKEY_COMPUTE_CMD	_IOWR(HSM_IOCTL_MAGIC, 26, unsigned int)
#define	HSM_RUN_ECDH_PHASE_I_CMD		_IOWR(HSM_IOCTL_MAGIC, 27, unsigned int)
#define	HSM_RUN_ECDH_PHASE_II_CMD		_IOWR(HSM_IOCTL_MAGIC, 28, unsigned int)
#define	HSM_GET_DRIVER_VER_CMD			_IOWR(HSM_IOCTL_MAGIC, 29, unsigned int)
#define HSM_RUN_ECDSA_SIGN_BY_KT_CMD            (_IOWR(HSM_IOCTL_MAGIC, 30U, uint32_t))
#define HSM_RUN_ECDSA_VERIFY_BY_KT_CMD          (_IOWR(HSM_IOCTL_MAGIC, 31U, uint32_t))
#define HSM_RUN_RSASSA_PKCS_SIGN_BY_KT_CMD      (_IOWR(HSM_IOCTL_MAGIC, 32U, uint32_t))
#define HSM_RUN_RSASSA_PKCS_VERIFY_BY_KT_CMD    (_IOWR(HSM_IOCTL_MAGIC, 33U, uint32_t))
#define HSM_RUN_RSASSA_PSS_SIGN_BY_KT_CMD       (_IOWR(HSM_IOCTL_MAGIC, 34U, uint32_t))
#define HSM_RUN_RSASSA_PSS_VERIFY_BY_KT_CMD     (_IOWR(HSM_IOCTL_MAGIC, 35U, uint32_t))
#define HSM_SET_MODN_FROM_OTP_CMD               (_IOWR(HSM_IOCTL_MAGIC, 36U, uint32_t))
#define HSM_SET_MODN_FROM_SNOR_CMD              (_IOWR(HSM_IOCTL_MAGIC, 37U, uint32_t))

// clang-format on

#define TCC_AES_ECB_OFFSET (16u)

#define RSASSA_PSS_SALT_LEN (32u)
#define RSASSA_PSS_OID_HASH (OID_SHA2_256)

#define TCC_HSM_AES_KEY_SIZE (32u)
#define TCC_HSM_AES_IV_SIZE (32u)
#define TCC_HSM_AES_TAG_SIZE (32u)
#define TCC_HSM_AES_AAD_SIZE (32u)

#define TCC_HSM_SHA1_DIG_SIZE (20u)
#define TCC_HSM_SM3_DIG_SIZE (32u)

#define TCC_HSM_MAC_KEY_SIZE (32u)
#define TCC_HSM_MAC_MSG_SIZE (32u)
#define TCC_HSM_HMAC_MAC_SIZE (20u)
#define TCC_HSM_SM3_HMAC_MAC_SIZE (32u)

#define TCC_HSM_HASH_DIGEST_SIZE (64u)
#define TCC_HSM_ECDSA_KEY_SIZE (64u)
#define TCC_HSM_ECDSA_P521_KEY_SIZE (68u)
#define TCC_HSM_ECDSA_DIGEST_SIZE (64u)
#define TCC_HSM_ECDSA_SIGN_SIZE (64u)

#define TCC_HSM_RSA_MODN_SIZE (512u)
#define TCC_HSM_RSA_DIG_SIZE (64u)
#define TCC_HSM_RSA_SIG_SIZE (512u)

enum tcc_hsm_ioctl_cmd
{
	TCCHSM_IOCTL_SET_KEY_FROM_OTP,
	TCCHSM_IOCTL_SET_KEY_FROM_SNOR,
	TCCHSM_IOCTL_RUN_AES,
	TCCHSM_IOCTL_RUN_AES_BY_KT,
	TCCHSM_IOCTL_RUN_SM4,
	TCCHSM_IOCTL_RUN_SM4_BY_KT,
	TCCHSM_IOCTL_VERIFY_CMAC,
	TCCHSM_IOCTL_VERIFY_CMAC_BY_KT,
	TCCHSM_IOCTL_GEN_GMAC,
	TCCHSM_IOCTL_GEN_GMAC_BY_KT,
	TCCHSM_IOCTL_GEN_HMAC,
	TCCHSM_IOCTL_GEN_HMAC_BY_KT,
	TCCHSM_IOCTL_GEN_SM3_HMAC,
	TCCHSM_IOCTL_GEN_SM3_HMAC_BY_KT,
	TCCHSM_IOCTL_GEN_SHA,
	TCCHSM_IOCTL_GEN_SM3,
	TCCHSM_IOCTL_RUN_ECDSA_SIGN,
	TCCHSM_IOCTL_RUN_ECDSA_SIGN_BY_KT,
	TCCHSM_IOCTL_RUN_ECDSA_VERIFY,
	TCCHSM_IOCTL_RUN_ECDSA_VERIFY_BY_KT,
	TCCHSM_IOCTL_RUN_RSASSA_PKCS_SIGN,
	TCCHSM_IOCTL_RUN_RSASSA_PKCS_SIGN_BY_KT,
	TCCHSM_IOCTL_RUN_RSASSA_PKCS_VERIFY,
	TCCHSM_IOCTL_RUN_RSASSA_PKCS_VERIFY_BY_KT,
	TCCHSM_IOCTL_RUN_RSASSA_PSS_SIGN,
	TCCHSM_IOCTL_RUN_RSASSA_PSS_SIGN_BY_KT,
	TCCHSM_IOCTL_RUN_RSASSA_PSS_VERIFY,
	TCCHSM_IOCTL_RUN_RSASSA_PSS_VERIFY_BY_KT,
	TCCHSM_IOCTL_GET_RNG,
	TCCHSM_IOCTL_WRITE_OTP,
	TCCHSM_IOCTL_WRITE_SNOR,
	TCCHSM_IOCTL_GET_FW_VER,
	TCCHSM_IOCTL_GET_DRIVER_VER,
	TCCHSM_IOCTL_FULL,
	TCCHSM_IOCTL_FULL_WITHOUT_KT,
	TCCHSM_IOCTL_AGING,
	TCCHSM_IOCTL_MAX
};

enum key_index
{
    A72_AES_KEY_INDEX = 0x0000,
    A72_MAC_KEY_INDEX = 0x0001,
    A53_AES_KEY_INDEX = 0x0002,
    A53_MAC_KEY_INDEX = 0x0003,
    R5_AES_KEY_INDEX = 0x0004,
    R5_MAC_KEY_INDEX = 0x0005,
    A72_ECDSA_P256_PRIKEY_INDEX = 0x0006,
    A72_ECDSA_P256_PUBKEY_INDEX = 0x0007,
    A72_RSASSA_PRIKEY_INDEX = 0x0008,
    A72_RSASSA_PUBKEY_INDEX = 0x0009,
    A72_RSASSA_MODN_INDEX = 0x000A,
    R5_ECDSA_P256_PRIKEY_INDEX = 0x000B,
    R5_ECDSA_P256_PUBKEY_INDEX = 0x000C,
    R5_RSASSA_PRIKEY_INDEX = 0x000D,
    R5_RSASSA_PUBKEY_INDEX = 0x000E,
    R5_RSASSA_MODN_INDEX = 0x000F
};

enum key_address
{
    A72_AESKEY_ADDR = 0x100,
    A72_MACKEY_ADDR = 0x110,
    A53_AESKEY_ADDR = 0x130,
    A53_MACKEY_ADDR = 0x140,
    R5_AESKEY_ADDR = 0x160,
    R5_MACKEY_ADDR = 0x170,
    A72_ECDSA_P256_PRIKEY_ADDR = 0x200,
    A72_ECDSA_P256_PUBKEY_ADDR = 0x240,
    A72_RSASSA_PRIKEY_ADDR = 0x300,
    A72_RSASSA_PUBKEY_ADDR = 0x400,
    A72_RSASSA_MOD_ADDR = 0x500,
    R5_ECDSA_P256_PRIKEY_ADDR = 0x600,
    R5_ECDSA_P256_PUBKEY_ADDR = 0x640,
    R5_RSASSA_PRIKEY_ADDR = 0x700,
    R5_RSASSA_PUBKEY_ADDR = 0x800,
    R5_RSASSA_MOD_ADDR = 0x900
};

enum core_type
{
    CORE_TYPE_A72 = 1,
    CORE_TYPE_A53 = 2,
    CORE_TYPE_R5 = 3,
    CORE_TYPE_HSM = 4,
};
typedef enum _dma_type { HSM_NONE_DMA = 0, HSM_DMA } dma_type;

enum tcc_hsm_ioctl_obj_id_aes
{
    OID_AES_ENCRYPT = 0x00000000,
    OID_AES_DECRYPT = 0x01000000,
    OID_AES_ECB_128 = 0x00100008,
    OID_AES_ECB_192 = 0x00180008,
    OID_AES_ECB_256 = 0x00200008,
    OID_AES_CBC_128 = 0x00100108,
    OID_AES_CBC_192 = 0x00180108,
    OID_AES_CBC_256 = 0x00200108,
    OID_AES_CTR_128 = 0x00100208,
    OID_AES_CTR_192 = 0x00180208,
    OID_AES_CTR_256 = 0x00200208,
    OID_AES_XTS_128 = 0x00100308,
    OID_AES_XTS_256 = 0x00200308,
    OID_AES_CCM_128 = 0x00101008,
    OID_AES_CCM_192 = 0x00181008,
    OID_AES_CCM_256 = 0x00201008,
    OID_AES_GCM_128 = 0x00101108,
    OID_AES_GCM_192 = 0x00181108,
    OID_AES_GCM_256 = 0x00201108,
};

enum tcc_hsm_ioctl_obj_id_sm4
{
    OID_SM4_ENCRYPT = 0x00000000,
    OID_SM4_DECRYPT = 0x01000000,
    OID_SM4_ECB_128 = 0x00100008,
    OID_SM4_CBC_128 = 0x00100108,
    OID_SM4_ECB_128_OPENSSL = 0x00100009,
    OID_SM4_CBC_128_OPENSSL = 0x00100109,
};

enum tcc_hsm_ioctl_obj_id_hmac
{
    OID_HMAC_SHA1_160 = 0x00011100,
    OID_HMAC_SHA2_224 = 0x00012200,
    OID_HMAC_SHA2_256 = 0x00012300,
    OID_HMAC_SHA2_384 = 0x00012400,
    OID_HMAC_SHA2_512 = 0x00012500,
    OID_HMAC_SHA3_224 = 0x00013200,
    OID_HMAC_SHA3_256 = 0x00013300,
    OID_HMAC_SHA3_384 = 0x00013400,
    OID_HMAC_SHA3_512 = 0x00013500,
};

enum tcc_hsm_ioctl_obj_id_hash
{
    OID_SHA1_160 = 0x00001100,
    OID_SHA2_224 = 0x00002200,
    OID_SHA2_256 = 0x00002300,
    OID_SHA2_384 = 0x00002400,
    OID_SHA2_512 = 0x00002500,
    OID_SHA3_224 = 0x00003200,
    OID_SHA3_256 = 0x00003300,
    OID_SHA3_384 = 0x00003400,
    OID_SHA3_512 = 0x00003500,
    OID_SM3_256 = 0x01002300,
};

enum tcc_hsm_ioctl_obj_id_ecc
{
    OID_ECC_P256 = 0x00000013, // secp256r1
    OID_ECC_P384 = 0x00000014,
    OID_ECC_P521 = 0x00000015,
    OID_ECC_BP256 = 0x00000053, // brainpoolp256r1
    OID_ECC_BP384 = 0x00000054,
    OID_ECC_BP512 = 0x00000055,
    OID_SM2_256_SM3_256 = 0x010023A3,
};

typedef struct tcc_hsm_ioctl_set_key_param
{
    uint32_t addr;
    uint32_t data_size;
    uint32_t key_index;
} tcc_hsm_ioctl_set_key_param;

typedef struct tcc_hsm_ioctl_aes_param
{
    uint32_t obj_id;
    uint8_t key[TCC_HSM_AES_KEY_SIZE];
    uint32_t key_size;
    uint8_t iv[TCC_HSM_AES_IV_SIZE];
    uint32_t iv_size;
    uint32_t counter_size;
    uint8_t tag[TCC_HSM_AES_TAG_SIZE];
    uint32_t tag_size;
    uint8_t aad[TCC_HSM_AES_AAD_SIZE];
    uint32_t aad_size;
    unsigned long src;
    uint32_t src_size;
    unsigned long dst;
    uint32_t dst_size;
    uint32_t dma;
} tcc_hsm_ioctl_aes_param;

typedef struct tcc_hsm_ioctl_aes_by_kt_param
{
    uint32_t obj_id;
    uint32_t key_index;
    uint8_t iv[TCC_HSM_AES_IV_SIZE];
    uint32_t iv_size;
    uint32_t counter_size;
    uint8_t tag[TCC_HSM_AES_TAG_SIZE];
    uint32_t tag_size;
    uint8_t aad[TCC_HSM_AES_AAD_SIZE];
    uint32_t aad_size;
    unsigned long src;
    uint32_t src_size;
    unsigned long dst;
    uint32_t dst_size;
    uint32_t dma;
} tcc_hsm_ioctl_aes_by_kt_param;

typedef struct tcc_hsm_ioctl_mac_param
{
    uint32_t obj_id;
    uint8_t key[TCC_HSM_MAC_KEY_SIZE];
    uint32_t key_size;
    unsigned long src;
    uint32_t src_size;
    uint8_t mac[TCC_HSM_MAC_MSG_SIZE];
    uint32_t mac_size;
    uint32_t dma;
} tcc_hsm_ioctl_mac_param;

typedef struct tcc_hsm_ioctl_mac_by_kt_param
{
    uint32_t obj_id;
    uint32_t key_index;
    unsigned long src;
    uint32_t src_size;
    uint8_t mac[TCC_HSM_MAC_MSG_SIZE];
    uint32_t mac_size;
    uint32_t dma;
} tcc_hsm_ioctl_mac_by_kt_param;

typedef struct tcc_hsm_ioctl_hash_param
{
    uint32_t obj_id;
    unsigned long src;
    uint32_t src_size;
    uint8_t digest[TCC_HSM_HASH_DIGEST_SIZE];
    uint32_t digest_size;
    uint32_t dma;
} tcc_hsm_ioctl_hash_param;

typedef struct tcc_hsm_ioctl_ecdsa_param
{
    uint32_t obj_id;
    uint8_t key[TCC_HSM_ECDSA_KEY_SIZE];
    uint32_t key_size;
    uint8_t digest[TCC_HSM_ECDSA_DIGEST_SIZE];
    uint32_t digest_size;
    uint8_t sig[TCC_HSM_ECDSA_SIGN_SIZE];
    uint32_t sig_size;
} tcc_hsm_ioctl_ecdsa_param;

typedef struct tcc_hsm_ioctl_ecdsa_by_kt_param
{
    uint32_t obj_id;
    uint32_t key_index;
    uint8_t digest[TCC_HSM_ECDSA_DIGEST_SIZE];
    uint32_t digest_size;
    uint8_t sig[TCC_HSM_ECDSA_SIGN_SIZE];
    uint32_t sig_size;
} tcc_hsm_ioctl_ecdsa_by_kt_param;

typedef struct tcc_hsm_ioctl_rsassa_param
{
    uint32_t obj_id;
    uint8_t modN[TCC_HSM_RSA_MODN_SIZE];
    uint32_t modN_size;
    uint8_t key[TCC_HSM_RSA_MODN_SIZE];
    uint32_t key_size;
    uint8_t digest[TCC_HSM_RSA_DIG_SIZE];
    uint32_t digest_size;
    uint8_t sig[TCC_HSM_RSA_SIG_SIZE];
    uint32_t sig_size;
} tcc_hsm_ioctl_rsassa_param;

typedef struct tcc_hsm_ioctl_rsassa_by_kt_param
{
    uint32_t obj_id;
    uint32_t key_index;
    uint8_t digest[TCC_HSM_RSA_DIG_SIZE];
    uint32_t digest_size;
    uint8_t sig[TCC_HSM_RSA_SIG_SIZE];
    uint32_t sig_size;
} tcc_hsm_ioctl_rsassa_by_kt_param;

typedef struct tcc_hsm_ioctl_write_param
{
    uint32_t addr;
    unsigned long data;
    uint32_t data_size;
} tcc_hsm_ioctl_write_param;

typedef struct tcc_hsm_ioctl_rng_param
{
    unsigned long rng;
    uint32_t rng_size;
} tcc_hsm_ioctl_rng_param;

typedef struct tcc_hsm_ioctl_version_param
{
    uint32_t x;
    uint32_t y;
    uint32_t z;
} tcc_hsm_ioctl_version_param;

typedef struct tcc_hsm_ioctl_ecdh_key_param
{
	uint32_t key_type;
	uint32_t obj_id;
	uint8_t prikey[TCC_HSM_ECDSA_P521_KEY_SIZE];
	uint32_t prikey_size;
	uint8_t pubkey[TCC_HSM_ECDSA_P521_KEY_SIZE * 2];
	uint32_t pubkey_size;
} tcc_hsm_ioctl_ecdh_key_param;

#endif // HSM_CIPHER_H
