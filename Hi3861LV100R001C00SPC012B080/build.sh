#!/bin/bash
#
# Copyright (c) HiSilicon Technologies Co., Ltd. 2019-2019. All rights reserved.
# Description: Menuconfig entry
# Author: HiSilicon
# Create: 2019-12-31
#
set -e
CROOT=$(pwd)

BUILD_SELECT=$1

if [ "$BUILD_SELECT" = "menuconfig" ]; then
	python3 $CROOT/tools/menuconfig/usr_config.py
elif [ "$BUILD_SELECT" = "clean" ]; then
	scons -c
elif [ "$BUILD_SELECT" = "all" ]; then
	scons -c
	mkdir -p $CROOT/build/build_tmp/logs
	scons -Q -j8 2>&1 | tee $CROOT/build/build_tmp/logs/build_kernel.log
	echo See build log from: $CROOT/build/build_tmp/logs/build_kernel.log
elif [ -z $BUILD_SELECT ]; then
	if [ -d "output/bin" ]; then
		rm -rf output/bin
	fi
	mkdir -p $CROOT/build/build_tmp/logs
	scons -Q -j8 2>&1 | tee $CROOT/build/build_tmp/logs/build_kernel.log
	echo See build log from: $CROOT/build/build_tmp/logs/build_kernel.log
else
	mkdir -p $CROOT/build/build_tmp/logs
	scons -Q -j8 app=$BUILD_SELECT 2>&1 | tee $CROOT/build/build_tmp/logs/build_kernel.log
	echo See build log from: $CROOT/build/build_tmp/logs/build_kernel.log
fi

