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
#include <stdint.h>

#ifndef HSM_CIPHER_TEXT_H
#define HSM_CIPHER_TEXT_H

uint8_t AES128_1_1001[1];
uint8_t AES128_1_1002[1];
uint8_t AES128_16_0000[16];
uint8_t AES128_16_1100[16];
uint8_t AES128_16_1110[16];
uint8_t AES128_16_1122[16];
uint8_t AES128_16_1433[16];
uint8_t AES128_16_1533[16];
uint8_t AES128_17_0000[17];
uint8_t AES128_17_1100[17];
uint8_t AES128_17_1110[17];
uint8_t AES128_17_1122[17];
uint8_t AES128_17_1433[17];
uint8_t AES128_17_1533[17];
uint8_t AES128_32_0000[32];
uint8_t AES128_32_1033[32];
uint8_t AES128_32_1100[32];
uint8_t AES128_32_1110[32];
uint8_t AES128_32_1122[32];
uint8_t AES128_32_1433[32];
uint8_t AES128_32_1533[32];
uint8_t AES128_7_1001[7];
uint8_t AES128_7_1002[7];
uint8_t DES_1_1001[1];
uint8_t DES_1_1002[1];
uint8_t DES_16_0000[16];
uint8_t DES_16_0010[16];
uint8_t DES_16_0020[16];
uint8_t DES_16_1100[16];
uint8_t DES_16_1130[16];
uint8_t DES_16_1142[16];
uint8_t DES_17_0000[17];
uint8_t DES_17_0010[17];
uint8_t DES_17_0020[17];
uint8_t DES_17_1100[17];
uint8_t DES_17_1130[17];
uint8_t DES_17_1142[17];
uint8_t DES_7_1001[7];
uint8_t DES_7_1002[7];
uint8_t DES_8_0000[8];
uint8_t DES_8_0010[8];
uint8_t DES_8_0020[8];
uint8_t DES_8_1100[8];
uint8_t DES_8_1130[8];
uint8_t DES_8_1142[8];
uint8_t Multi2_1_1001[1];
uint8_t Multi2_1_1002[1];
uint8_t Multi2_16_0000[16];
uint8_t Multi2_16_0010[16];
uint8_t Multi2_16_0020[16];
uint8_t Multi2_16_1100[16];
uint8_t Multi2_16_1130[16];
uint8_t Multi2_16_1142[16];
uint8_t Multi2_17_0000[17];
uint8_t Multi2_17_0010[17];
uint8_t Multi2_17_0020[17];
uint8_t Multi2_17_1100[17];
uint8_t Multi2_17_1130[17];
uint8_t Multi2_17_1142[17];
uint8_t Multi2_7_1001[7];
uint8_t Multi2_7_1002[7];
uint8_t Multi2_8_0000[8];
uint8_t Multi2_8_0010[8];
uint8_t Multi2_8_0020[8];
uint8_t Multi2_8_1100[8];
uint8_t Multi2_8_1130[8];
uint8_t Multi2_8_1142[8];
uint8_t TDES128_1_1001[1];
uint8_t TDES128_1_1002[1];
uint8_t TDES128_16_0000[16];
uint8_t TDES128_16_0010[16];
uint8_t TDES128_16_0020[16];
uint8_t TDES128_16_1100[16];
uint8_t TDES128_16_1130[16];
uint8_t TDES128_16_1142[16];
uint8_t TDES128_17_0000[17];
uint8_t TDES128_17_0010[17];
uint8_t TDES128_17_0020[17];
uint8_t TDES128_17_1100[17];
uint8_t TDES128_17_1130[17];
uint8_t TDES128_17_1142[17];
uint8_t TDES128_32_0000[32];
uint8_t TDES128_32_0010[32];
uint8_t TDES128_32_0020[32];
uint8_t TDES128_32_1100[32];
uint8_t TDES128_32_1130[32];
uint8_t TDES128_32_1142[32];
uint8_t TDES128_7_1001[7];
uint8_t TDES128_7_1002[7];
uint8_t key_cmac[16];
uint8_t Plain_Text_0000_1[1];
uint8_t Plain_Text_0000_15[15];
uint8_t Plain_Text_0000_16[16];
uint8_t Plain_Text_0000_17[17];
uint8_t Plain_Text_0000_32[32];
uint8_t Plain_Text_0000_7[7];
uint8_t Plain_Text_0000_8[8];
uint8_t DIN0[16];
uint8_t DIN1[16];
uint8_t DIN2[16];
uint8_t DIN3[16];
uint8_t DIN4[16];
uint8_t DIN5[16];
uint8_t Nonce[16];
uint8_t FOR_KL_PLAINTEXT[16];
uint8_t TDES_CBC_IV_FOR_KL[8];
uint8_t TDES_ECB_FOR_KL_CIPHERTEXT[16];
uint8_t TDES_CBC_FOR_KL_CIPHERTEXT[16];
uint8_t AES_CBC_IV_FOR_KL[16];
uint8_t AES_ECB_FOR_KL_CIPHERTEXT[16];
uint8_t AES_CBC_FOR_KL_CIPHERTEXT[16];
uint8_t TDES_VID[16];
uint8_t AES_VID[16];
uint8_t TDES_MID[16];
uint8_t AES_MID[16];
uint8_t KL_DIN1[16];
uint8_t KL_DIN2[16];
uint8_t KL0_DIN3[16];
uint8_t KL1_DIN3[16];
uint8_t KL2_DIN3[16];
uint8_t KL3_DIN3[16];
uint8_t KL4_DIN3[16];
uint8_t KL5_DIN3[16];
uint8_t KL6_DIN3[16];
uint8_t KL_NONCE_INPUT[16];
uint8_t KL_WithKDF_CIPHERTEXT[8][16];
uint8_t KL_WithKDF_PLAINTEXT[8][16];
uint8_t KL7_DIN[8][16];
uint8_t CSA2_KEY[8];
uint8_t CSA2_CIPHERTEXT[184];
uint8_t CSA2_PLAINTEXT[184];
uint8_t CSA3_KEY[16];
uint8_t CSA3_CIPHERTEXT[184];
uint8_t CSA3_PLAINTEXT[184];
uint8_t key_aes128[16];
uint8_t key_tdes128[16];
uint8_t key_des[8];
uint8_t iv1[16];
uint8_t iv2[16];
uint8_t syskey[32];

#endif // HSM_CIPHER_TEXT_H
