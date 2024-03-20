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
#ifndef HSM_OPENSSL_CIPHER_H
#define HSM_OPENSSL_CIPHER_H

#include <stdint.h>
#include "hsm_cipher.h"

uint32_t hsm_openssl_run_aes(tcc_hsm_ioctl_aes_param *param);
uint32_t hsm_openssl_gen_hash(tcc_hsm_ioctl_hash_param *param);
uint32_t hsm_openssl_gen_mac(uint32_t cmd, tcc_hsm_ioctl_mac_param *param);
uint32_t hsm_openssl_run_ecdsa(uint32_t cmd, tcc_hsm_ioctl_ecdsa_param *param);
uint32_t hsm_openssl_run_rsa(uint32_t cmd, tcc_hsm_ioctl_rsassa_param *param);
uint32_t hsm_openssl_get_rand(tcc_hsm_ioctl_rng_param *param);

#endif // HSM_OPENSSL_CIPHER_H
