#!/bin/sh
# Usage : . build.sh [32/64] [803x/805x]

TARGET_BIT=$1
ENABLE_OPENSSL_BUILD=0 # Do not change, Opensl Lib has already been built.

if [ "${ENABLE_OPENSSL_BUILD}" == 1 ]; then
	# Decompress openssl library
	if [ -e "hsm_openssl" ]; then
		echo "Skip the openssl build"
	else
		echo "Decompressing openssl library(Only once)"
		tar xzf hsm_openssl.tgz
	fi

	# Build openssl library
	if [ "${TARGET_BIT}" == 32 ]; then
		echo "Building openssl library(${TARGET_BIT})"
		cd ./hsm_openssl
		if [ ! -e "32" ]; then
			rm -rf 64
			touch 32
			make clean
		fi
		./Configure hsm-generic32
		make -j8
		cd -
	else
		echo "Building openssl library(${TARGET_BIT})"
		cd ./hsm_openssl
		if [ ! -e "64" ]; then
			rm -rf 32
			touch 64
			make clean
		fi
		./Configure hsm-generic64
		make -j8
		cd -
	fi
fi

CHIP=$2
if [ "${CHIP}" != 803x ] && [ "${CHIP}" != 805x ]; then
	CHIP=805x
fi

echo "Build option : ${TARGET_BIT}bit / TCC${CHIP}"

make -C tcc${CHIP} TARGET_BIT=${TARGET_BIT} CHIP=${CHIP} YOCTO_BUILD=n clean
make -C tcc${CHIP} TARGET_BIT=${TARGET_BIT} CHIP=${CHIP} YOCTO_BUILD=n
