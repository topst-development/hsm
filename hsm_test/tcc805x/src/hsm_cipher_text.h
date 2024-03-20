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
// clang-format off

#ifndef HSM_CIPHER_TEXT_H
#define HSM_CIPHER_TEXT_H

#include <stdint.h>

/* Common */
extern unsigned char dst_buffer[1024 * 2];
extern unsigned char plain_data[32];
extern unsigned char key[16];
extern unsigned char iv[12];
extern unsigned char aes_iv[16];

/* AES Test */
extern unsigned char ECB_cipher[32];
extern unsigned char CBC_cipher[32];
extern unsigned char CCM_cipher[32];
extern unsigned char GCM_cipher[32];
extern unsigned char AES_ccm_tag[16];
extern unsigned char AES_gcm_tag[16];
extern unsigned char AES_aad[16];
extern unsigned char sm4_ECB_cipher[32];

/* MAC Test */
extern unsigned char mac_key[32];
extern unsigned char cmac_out[16];
extern unsigned char hmac_out[20];
extern unsigned char sm3_hmac_out[32];

/* RSASSA Test */
extern unsigned char modN[128];
extern unsigned char rsa_prikey[128];
extern unsigned char rsa_pubkey[4];
extern unsigned char pkcs_sig[128];
extern unsigned char pss_sig[128];
extern unsigned char digest[32];

/* ECDSA Test */
extern unsigned char secp256r1_dig[32];
extern unsigned char secp256r1_private[32];
extern unsigned char secp256r1_public[64];
extern unsigned char secp256r1_sig[64];

/* HASH Test */
extern unsigned char Digest_SHA1_160[20];
extern unsigned char Digest_SM3_256[32];
extern unsigned char Digest_SHA256_256[32];
extern unsigned char Hash_Message[32];

/* Random Number Test */
extern unsigned char rng_data[32];

// clang-format on
#endif // HSM_CIPHER_TEXT_H
