#!/usr/bin/env python3
#coding=utf-8
#
# Copyright (c) HiSilicon Technologies Co., Ltd. 2019-2019. All rights reserved.
# Description: Menuconfig entry
# Author: HiSilicon
# Create: 2019-12-31
#

import os
from kconfiglib import Kconfig
from menuconfig import menuconfig

def mconf_set_env(style, conf, header):
    """
    These parameters would not be effect unless kconflib supported these.
    """
    os.environ["MENUCONFIG_STYLE"] = style
    os.environ["KCONFIG_CONFIG"] = conf
    os.environ["KCONFIG_CONFIG_HEADER"] = header

def hi_mconfig():
    kconfig = os.path.join("tools", "menuconfig", "Kconfig")
    display_style = "default selection=fg:white,bg:red"
    target_conf = os.path.join("build", "config", "usr_config.mk")
    header = "# Generated by HiSilicon menuconfig tool"
    mconf_set_env(display_style, target_conf, header)
    kconf = Kconfig(filename=kconfig)
    menuconfig(kconf)

if __name__ == "__main__":
    hi_mconfig()
