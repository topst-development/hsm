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
#include <sys/ioctl.h>
#include <fcntl.h>

#include "hsm_cipher.h"
#include "hsm_common.h"

#define HSM_MAJOR 1
#define HSM_MINOR 2

#define HSM_DEVICE "/dev/tcc_hsm"

// clang-format off
#define TCCHSM_GET_VER_TEST				(0u)
#define TCCHSM_AES_TEST 				(1u)
#define TCCHSM_DES_TEST 				(2u)
#define TCCHSM_TDES_TEST 				(3u)
#define TCCHSM_CSA2_TEST 				(4u)
#define TCCHSM_CSA3_TEST 				(5u)
#define TCCHSM_CMAC_TEST 				(6u)
#define TCCHSM_KLWITHKDF_TEST 			(7u)
#define TCCHSM_KLWITHRK_TEST 			(8u)
#define TCCHSM_OTP_TEST 				(9u)
#define TCCHSM_RNG_TEST 				(10u)
#define TCCHSM_OTP_WRITE_FOR_KDF_TEST	(11u)
#define TCCHSM_OTP_WRITE_FOR_RK_TEST	(12u)
#define TCCHSM_FULL_TEST 				(13u)
#define TCCHSM_AGING_TEST 				(14u)
#define TCCHSM_EXIT 					(15u)

static int8_t *hsm_cmd[] = {
	"0 get version",
	"1 aes",
	"2 des",
	"3 tdes",
	"4 csa2",
	"5 csa3",
	"6 cmac",
	"7 klwithkdf",
	"8 klwithrk",
	"9 otp",
	"10 rng",
	"11 otp_write_for_KLWithKDF",
	"12 otp_write_for_KLWithRK",
	"13 full",
	"14 aging",
	"15 exit",
	NULL
};
uint32_t key_idx;
// clang-format on

static void tccHSMPrintCmd(void)
{
    int32_t i = 0u;

    BLOG("\ncommand for hsm\n\n");

    for (i = 0u; hsm_cmd[i] != NULL; i++) {
        BLOG("  %s\n", hsm_cmd[i]);
    }

    BLOG("\n");

    return;
}

static uint32_t tccHSMGetVerTest(int fd)
{
	tcc_hsm_ioctl_version_param param = {0};
	uint32_t ret = HSM_GENERIC_ERR;

    ret = ioctl(fd, TCCHSM_IOCTL_GET_VERSION, &param);
    if (ret != HSM_OK) {
        ELOG(" Error tccHSMGetVerTest(%d)\n", ret);
    }

    DLOG("HSM F/W Ver: %d.%d \n", param.major, param.minor);

    return ret;
}

static uint32_t tccHSMAESTest(int fd)
{
    uint32_t ret = HSM_GENERIC_ERR;

    DLOG("Start tccHSMAESTest\n");

    ret = sotbCipherAESDecTest(fd);
    if (ret != HSM_OK) {
        ELOG("Error sotbCipherAESDecTest\n");
        return ret;
    }

    ret = sotbCipherAESEncTest(fd);
    if (ret != HSM_OK) {
        ELOG("Error sotbCipherAESEncTest\n");
        return ret;
    }

    DLOG("Success tccHSMAESTest\n");

    return ret;
}

static uint32_t tccHSMDESTest(int fd)
{
    uint32_t ret = HSM_GENERIC_ERR;

    DLOG("Start tccHSMDESTest\n");

    ret = sotbCipherDESDecTest(fd);
    if (ret != HSM_OK) {
        ELOG("Error sotbCipherDESDecTest\n");
        return ret;
    }

    ret = sotbCipherDESEncTest(fd);
    if (ret != HSM_OK) {
        ELOG("Error sotbCipherDESEncTest\n");
        return ret;
    }

    DLOG("Success tccHSMDESTest\n");

    return ret;
}

static uint32_t tccHSMTDESTest(int fd)
{
    uint32_t ret = HSM_GENERIC_ERR;

    DLOG("Start tccHSMTDESTest\n");

    ret = sotbCipherTDESDecTest(fd);
    if (ret != HSM_OK) {
        ELOG("Error sotbCipherTDESDecTest\n");
        return ret;
    }

    ret = sotbCipherTDESEncTest(fd);
    if (ret != HSM_OK) {
        ELOG("Error sotbCipherTDESEncTest\n");
        return ret;
    }

    DLOG("Success tccHSMTDESTest\n");

    return ret;
}

static uint32_t tccHSMCSA2Test(int fd)
{
    uint32_t ret = HSM_GENERIC_ERR;

    DLOG("Start tccHSMCSA2Test\n");

    ret = sotbCipherCSA2DecTest(fd);
    if (ret != HSM_OK) {
        ELOG("Error sotbCipherCSA2DecTest\n");
        return ret;
    }

    DLOG("Success tccHSMCSA2Test\n");

    return ret;
}

static uint32_t tccHSMCSA3Test(int fd)
{
    uint32_t ret = HSM_GENERIC_ERR;

    DLOG("Start tccHSMCSA3Test\n");

    ret = sotbCipherCSA3DecTest(fd);
    if (ret != HSM_OK) {
        ELOG("Error sotbCipherCSA3DecTest\n");
        return ret;
    }

    DLOG("Success tccHSMCSA3Test\n");

    return ret;
}

static uint32_t tccHSMCMACTest(int fd)
{
    uint32_t ret = HSM_GENERIC_ERR;

    DLOG("Start tccHSMCMACTest\n");

    ret = sotbCipherCMACTest(fd);
    if (ret != HSM_OK) {
        ELOG("Error tccHSMCMACTest\n");
        return ret;
    }

    DLOG("Success tccHSMCMACTest\n");

    return ret;
}

static uint32_t tccHSMKLWithKDFTest(int fd)
{
    uint32_t ret = HSM_GENERIC_ERR;

    DLOG("Start tccHSMKLWithKDFTest\n");

    ret = sotbCipherKLWithKDFTest(fd);
    if (ret != HSM_OK) {
        ELOG("Error sotbCipherKLWithKDFTest\n");
        return ret;
    }

    DLOG("Success tccHSMKLWithKDFTest\n");

    return ret;
}

static uint32_t tccHSMKLWithRKTest(int fd)
{
    uint32_t ret = HSM_GENERIC_ERR;

    DLOG("Start tccHSMKLWithRKTest\n");

    ret = sotbCipherKLWithRKTest(fd);
    if (ret != HSM_OK) {
        ELOG("Error sotbCipherKLWithRKTest\n");
        return ret;
    }

    DLOG("Success tccHSMKLWithRKTest\n");

    return ret;
}

static uint32_t tccHSMOTPTest(int fd)
{
    struct tcc_hsm_ioctl_otp_param param;
    uint32_t ret = HSM_GENERIC_ERR;

    uint8_t key_aes128[16] = {0x61, 0x6c, 0x67, 0x6f, 0x20, 0x41, 0x45, 0x53,
                              0x61, 0x6c, 0x67, 0x6f, 0x20, 0x61, 0x65, 0x73};

    param.addr = 0x00000060;
    param.buf = key_aes128;
    param.size = 16;

    ret = ioctl(fd, TCCHSM_IOCTL_WRITE_OTP, &param);
    if (ret != HSM_OK) {
        ELOG(" Error tccHSMOTPTest write\n");
        return ret;
    }

    return ret;
}

static uint32_t tccHSMRNGTest(int fd)
{
    struct tcc_hsm_ioctl_rng_param param;
    uint32_t ret = HSM_GENERIC_ERR;

    uint32_t rng[4] = {
        0,
    };
    int i;

    param.rng = (uint8_t *)rng;
    param.size = 16;

    ret = ioctl(fd, TCCHSM_IOCTL_GET_RNG, &param);
    if (ret != HSM_OK) {
        ELOG(" Error tccHSMRNGTest\n");
    }

    DLOG("%08X %08X %08X %08X\n", rng[0], rng[1], rng[2], rng[3]);

    return ret;
}

static uint32_t tccHSMOTPWriteForKLWithKDF(int fd)
{
#if 0
    struct tcc_hsm_ioctl_otp_param param;
    uint32_t ret = HSM_GENERIC_ERR;

    uint32_t kdfAddr = 0x8C0;
    uint32_t kdfInfo[8] = {0x00033300, 0x00333330, 0x00000000, 0x00000030,
                           0x00111130, 0x00033300, 0x00033300, 0x00222230};
    uint32_t crAddr = 0x8E0;
    uint32_t crInfo[16] = {0x1100d021, 0x00000111, 0x1100d021, 0x00000111, 0x1100d021, 0x00000111,
                           0x1100d021, 0x00000111, 0x3300d121, 0x00000333, 0x3300d121, 0x00000333,
                           0x3300d121, 0x00000333, 0x3360d171, 0x33333333};
    uint32_t kdfKeyAddr = 0x1610;
    uint32_t kdfKeyInfo[8] = {0x61727479, 0x6F6D7970, 0x6F6D6574, 0x77656C63,
                              0xFCFDFEFF, 0xF8F9FAFB, 0xF4F5F6F7, 0xF0F1F2F3};
    unsigned long buf[16] = {
        0,
    };
    int i = 0;

    param.addr = kdfAddr;
    param.buf = (uint8_t *)kdfInfo;
    param.size = sizeof(kdfInfo);
    ret = ioctl(fd, TCCHSM_IOCTL_WRITE_OTP, &param);
    if (ret != HSM_OK) {
        ELOG(" Error tccHSMOTPWrite write\n");
        return ret;
    }

    param.addr = crAddr;
    param.buf = (uint8_t *)crInfo;
    param.size = sizeof(crInfo);
    ret = ioctl(fd, TCCHSM_IOCTL_WRITE_OTP, &param);
    if (ret != HSM_OK) {
        ELOG(" Error tccHSMOTPWrite write\n");
        return ret;
    }

    for (i = 0; i <= 0xE0; i += 0x20) {
        param.addr = kdfKeyAddr + i;
        param.buf = (uint8_t *)kdfKeyInfo;
        param.size = sizeof(kdfKeyInfo);
        ret = ioctl(fd, TCCHSM_IOCTL_WRITE_OTP, &param);
        if (ret != HSM_OK) {
            ELOG(" Error tccHSMOTPWrite write\n");
            return ret;
        }
    }

    return ret;
#else
	return HSM_ERR_UNSUPPORT_FUNC;
#endif
}

static uint32_t tccHSMOTPWriteForKLWithRK(int fd)
{
#if 0
    struct tcc_hsm_ioctl_otp_param param;
    uint32_t ret = HSM_GENERIC_ERR;

    uint32_t kdfAddr = 0x8C0;
    uint32_t kdfInfo = 0x00000001;

    uint32_t crAddr = 0x8E0;
    uint32_t crInfo[2] = {0x00025021, 0x00000111};

    uint32_t rootKeyAddr = 0x1710;
    uint32_t rootKeyInfo[4] = {0x89ABCDEF, 0x01234567, 0x89ABCDEF, 0x01234567};

    unsigned long buf[16] = {
        0,
    };

    param.addr = kdfAddr;
    param.buf = (uint8_t *)&kdfInfo;
    param.size = sizeof(kdfInfo);
    ret = ioctl(fd, TCCHSM_IOCTL_WRITE_OTP, &param);
    if (ret != 0) {
        ELOG(" Error tccHSMOTPWrite write\n");
        return ret;
    }

    param.addr = crAddr;
    param.buf = (uint8_t *)crInfo;
    param.size = sizeof(crInfo);
    ret = ioctl(fd, TCCHSM_IOCTL_WRITE_OTP, &param);
    if (ret != HSM_OK) {
        ELOG(" Error tccHSMOTPWrite write\n");
        return ret;
    }

    param.addr = rootKeyAddr;
    param.buf = (uint8_t *)rootKeyInfo;
    param.size = sizeof(rootKeyInfo);
    ret = ioctl(fd, TCCHSM_IOCTL_WRITE_OTP, &param);
    if (ret != HSM_OK) {
        ELOG(" Error tccHSMOTPWrite write\n");
        return ret;
    }

    return ret;
#else
	return HSM_ERR_UNSUPPORT_FUNC;
#endif
}

static uint32_t tccHSMFullTest(int fd, int cnt)
{
    uint32_t ret = HSM_GENERIC_ERR;
    int i;

    if (cnt > 1) {
        DLOG("Start tccHSMAgingTest\n");
    } else {
        DLOG("Start tccHSMFullTest\n");
    }

    for (i = 0; i < cnt; i++) {
        ret = sotbCipherAESDecTest(fd);
        if (ret != HSM_OK) {
            ELOG("Error sotbCipherAESDecTest(%d, %d)\n", i, cnt);
            return ret;
        }

        ret = sotbCipherAESEncTest(fd);
        if (ret != HSM_OK) {
            ELOG("Error sotbCipherAESEncTest(%d, %d)\n", i, cnt);
            return ret;
        }

        ret = sotbCipherDESDecTest(fd);
        if (ret != HSM_OK) {
            ELOG("Error sotbCipherDESDecTest(%d, %d)\n", i, cnt);
            return ret;
        }

        ret = sotbCipherDESEncTest(fd);
        if (ret != HSM_OK) {
            ELOG("Error sotbCipherDESEncTest(%d, %d)\n", i, cnt);
            return ret;
        }

        ret = sotbCipherTDESDecTest(fd);
        if (ret != HSM_OK) {
            ELOG("Error sotbCipherTDESDecTest(%d, %d)\n", i, cnt);
            return ret;
        }

        ret = sotbCipherTDESEncTest(fd);
        if (ret != HSM_OK) {
            ELOG("Error sotbCipherTDESEncTest(%d, %d)\n", i, cnt);
            return ret;
        }

        ret = sotbCipherCSA2DecTest(fd);
        if (ret != HSM_OK) {
            ELOG("Error sotbCipherCSA2DecTest(%d, %d)\n", i, cnt);
            return ret;
        }

        ret = sotbCipherCSA3DecTest(fd);
        if (ret != HSM_OK) {
            ELOG("Error sotbCipherCSA3DecTest(%d, %d)\n", i, cnt);
            return ret;
        }

        ret = sotbCipherCMACTest(fd);
        if (ret != HSM_OK) {
            ELOG("Error sotbCipherCMACTest(%d, %d)\n", i, cnt);
            return ret;
        }
    }

    if (cnt > 1) {
        DLOG("Success tccHSMAgingTest(%d)\n", cnt);
    } else {
        DLOG("Success tccHSMFullTest\n");
    }

    return ret;
}

uint32_t main(void)
{
	uint32_t cmd = 0, core_type = 0;
	int32_t fd = -1;
	uint32_t ret = HSM_GENERIC_ERR;

	DLOG("hsm Version:%d.%d\n", HSM_MAJOR, HSM_MINOR);

	fd = open(HSM_DEVICE, O_RDWR);
	if (fd < 0) {
        ELOG("[HSM] Err Can't open tcc_hsm\n");
        return ret;
    }

	/* Select core type */
	BLOG("Input Core Type(A53 = 1 or A7 = 2):");
	scanf("%d", &core_type);
	if (core_type == CORE_TYPE_A53) {
		key_idx = 0x00;
	} else if (core_type == CORE_TYPE_A7) {
		key_idx = 0x01;
	} else {
		ELOG("Invalid core type\n");
		return 0;
	}

	while (1) {
		tccHSMPrintCmd();
        BLOG("Input test number:");
        scanf("%d", &cmd);

        switch (cmd) {
        case TCCHSM_GET_VER_TEST:
            ret = tccHSMGetVerTest(fd);
            break;
        case TCCHSM_AES_TEST:
            ret = tccHSMAESTest(fd);
            break;
        case TCCHSM_DES_TEST:
            ret = tccHSMDESTest(fd);
            break;
        case TCCHSM_TDES_TEST:
            ret = tccHSMTDESTest(fd);
            break;
        case TCCHSM_CSA2_TEST:
            ret = tccHSMCSA2Test(fd);
            break;
        case TCCHSM_CSA3_TEST:
            ret = tccHSMCSA3Test(fd);
            break;
        case TCCHSM_CMAC_TEST:
            ret = tccHSMCMACTest(fd);
            break;
        case TCCHSM_KLWITHKDF_TEST:
            ret = tccHSMKLWithKDFTest(fd);
            break;
        case TCCHSM_KLWITHRK_TEST:
            ret = tccHSMKLWithRKTest(fd);
            break;
        case TCCHSM_OTP_TEST:
            ret = tccHSMOTPTest(fd);
            break;
        case TCCHSM_RNG_TEST:
            ret = tccHSMRNGTest(fd);
            break;
        case TCCHSM_OTP_WRITE_FOR_KDF_TEST:
            ret = tccHSMOTPWriteForKLWithKDF(fd);
            break;
        case TCCHSM_OTP_WRITE_FOR_RK_TEST:
            ret = tccHSMOTPWriteForKLWithRK(fd);
            break;
        case TCCHSM_FULL_TEST:
            ret = tccHSMFullTest(fd, 1);
            break;
        case TCCHSM_AGING_TEST:
            ret = tccHSMFullTest(fd, 10000);
            break;
        case TCCHSM_EXIT:
            ret = HSM_OK;
            goto out;
            break;
        default:
            ELOG("Error invalid command!\n");
            ret = HSM_ERR_INVALID_PARAM;
            goto out;
            break;
        }
    }

out:
    if (fd > 0) {
        close(fd);
        fd = -1;
    }

    return ret;
}
