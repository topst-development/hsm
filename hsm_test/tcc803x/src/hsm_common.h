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

#ifndef HSM_COMMON_H
#define HSM_COMMON_H

// clang-format off
#define HSM_OK 						0x0000u
#define HSM_GENERIC_ERR 			0x0001u
#define HSM_ERR_INVALID_PARAM		0x0002u
#define HSM_ERR_INVALID_STATE 		0x0003u
#define HSM_ERR_INVALID_MEMORY		0x0004u
#define HSM_ERR_UNSUPPORT_FUNC		0x0005u
#define HSM_ERR_SOTB_CIPHER			0x0006u
#define HSM_ERR_OCCUPIED_RESOURCE	0x0007u
// clang-format on

#endif // HSM_COMMON_H
