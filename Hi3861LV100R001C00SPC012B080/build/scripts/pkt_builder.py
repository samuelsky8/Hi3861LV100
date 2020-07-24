#!/usr/bin/env python3
# coding=utf-8

'''
* Copyright (C) HiSilicon Technologies Co., Ltd. 2019-2020. All rights reserved.
* Description: hupg main build scripts
'''

import os
import time
import sys
import make_upg_file as MAKE_IMAGE
from packet_create import packet_bin
from scons_utils import scons_get_cfg_val

class ImageBuild:
    def __init__(self, app_name="Hi3861_demo", sign_alg=0x3F, kernel_file_ver=0, flashboot_file_ver=0, chip_product="Hi3861", usr_realtive_output=''):
        root_path = os.getcwd()
        self.__app_name = app_name
        self.__bootBinPath = os.path.join(root_path, usr_realtive_output, 'output', 'flashboot', 'Hi3861_flash_boot.bin')
        self.__kernelBinPath = os.path.join(root_path, usr_realtive_output, 'output', 'bin', '%s_non_rom.bin'%self.__app_name)
        self.__normalNvPath = os.path.join(root_path, usr_realtive_output, 'build', 'build_tmp', 'nv', '%s_normal.hnv'%app_name)
        self.__factoryNvPath = os.path.join(root_path, usr_realtive_output, 'build', 'build_tmp', 'nv', '%s_factory.hnv'%app_name)
        self.__pktPath = os.path.join(root_path, usr_realtive_output, 'output', 'bin')
        self.__key_dir_path = os.path.join(root_path, usr_realtive_output, 'tools', 'sign_tool')
        self.__lzma_tool_path = os.path.join(root_path, usr_realtive_output, r'tools', r'lzma_tool', r'lzma_tool')
        self.__build_tmp_path = os.path.join(root_path, usr_realtive_output, 'output', 'bin')
        self.__image_id = 0x3C78961E
        self.__kernel_file_ver = kernel_file_ver
        self.__flashboot_file_ver = flashboot_file_ver
        self.__encrypt_flag = 0x42
        self.__sign_alg = sign_alg
        self.__boot_bin_max_size = 32*1024 #32K
        self.__kernel_1st_bin_max_size = 912*1024 #912K
        self.__kernel_2nd_bin_max_size = 968*1024 #968K
        self.__kernel_bin_max_size = self.__kernel_1st_bin_max_size
        self.__kernel_upg_max_size = (912 + 968) * 1024
        self.__chip_product_name = chip_product
        self.__file_attr_encrypt = 0x2 # encrypt
        self.__kernel_file_attr_ota = 0x4 # compression ota
        self.__flashboot_file_attr_ota = 0x4 # compression ota

    def set_file_attr_encrypt(self, attr_encrypt):
        self.__file_attr_encrypt = attr_encrypt

    def set_kernel_file_attr_ota(self, attr_ota):
        self.__kernel_file_attr_ota = attr_ota

    def set_flashboot_file_attr_ota(self, attr_ota):
        self.__flashboot_file_attr_ota = attr_ota

    def set_chip_product_name(self, name):
        self.__chip_product_name = name

    def set_kernel_max_size(self, signature):
        if signature == 1:
            self.__kernel_bin_max_size = self.__kernel_1st_bin_max_size
        elif signature == 2:
            self.__kernel_bin_max_size = self.__kernel_2nd_bin_max_size
        elif signature == 0:
            self.__kernel_bin_max_size = self.__kernel_upg_max_size
        else:
            sys.exit("[ERR]signature err: < %s >, from: %s"%(signature, os.path.realpath(__file__)))

    def set_src_path(self, boot_bin_path = None, kernel_bin_path = None, normal_nv_path = None, factory_nv_path = None):
        self.__bootBinPath = boot_bin_path if boot_bin_path is not None else self.__bootBinPath
        self.__kernelBinPath = kernel_bin_path if kernel_bin_path is not None else self.__kernelBinPath
        self.__normalNvPath = normal_nv_path if normal_nv_path is not None else self.__normalNvPath
        self.__factoryNvPath = factory_nv_path if factory_nv_path is not None else self.__factoryNvPath

    def set_pkt_path(self, pkt_dir_path):
        self.__pktPath = pkt_dir_path

    def set_build_temp_path(self, build_temp_path):
        self.__build_tmp_path = build_temp_path

    def set_app_name(self, app_name):
        self.__app_name = app_name

    def set_image_id(self, image_id):
        self.__image_id = image_id

    def set_kernel_file_ver(self, file_version):
        self.__kernel_file_ver = file_version

    def set_flashboot_file_ver(self, file_version):
        self.__flashboot_file_ver = file_version

    def set_encrypt_flag(self, encrypt_flag):
        self.__encrypt_flag = encrypt_flag

    def set_sign_alg(self, sign_alg):
        self.__sign_alg = sign_alg

    def dual_partion_ota_work(self, signature = None):
        self.BuildUpgBoot()
        #制作升级文件和烧写文件先后顺序不能调整
        self.BuildUpgBin()
        self.BuildHiburnBin()

    def compress_ota_work(self, signature = None):
        app_name = self.__app_name
        pkt_dir_path = self.__pktPath
        ota_ori_file = os.path.join(pkt_dir_path, '%s_ota_tmp.bin'%app_name)
        self.BuildUpgBoot()
        #制作升级文件和烧写文件先后顺序不能调整
        self.BuildUpgBin(target = ota_ori_file)
        self.BuildHiburnBin(ota_file = ota_ori_file)
        self.BuildCompressUpgBin(ota_file = ota_ori_file)

    def BuildUpgBoot(self, target = None, source = None):
        app_name = self.__app_name
        pkt_dir_path = self.__pktPath
        file_attr = (self.__file_attr_encrypt << 6) + self.__flashboot_file_attr_ota

        #bootupg配置
        flash_boot_file = self.__bootBinPath
        if not os.path.exists(flash_boot_file):
            print("flash_boot_file from: ", flash_boot_file)
            sys.exit("[ERR]flash boot file is not exist, from: %s"%os.path.realpath(__file__))

        # 构造输出文件名 #
        image_file = os.path.join(pkt_dir_path, '%s_flash_boot_ota.bin'%app_name) if target is None else target
        print("********************package boot upgrade file********************")
        MAKE_IMAGE.make_bootupg(self.__image_id, self.__flashboot_file_ver, self.__encrypt_flag, flash_boot_file, image_file, self.__key_dir_path, self.__boot_bin_max_size, self.__sign_alg, self.__chip_product_name, file_attr)
        return image_file

    def BuildUpgBin(self, target = None):
        app_name = self.__app_name
        pkt_dir_path = self.__pktPath
        file_attr = (self.__file_attr_encrypt << 6) + self.__kernel_file_attr_ota

        #升级文件配置
        kernel_file = self.__kernelBinPath
        normal_nv_file = self.__normalNvPath
        if not os.path.exists(normal_nv_file):
            print("normal_nv_file from: ", normal_nv_file)
            sys.exit("[ERR]normal nv file is not exist, from: %s"%os.path.realpath(__file__))

        if not os.path.exists(kernel_file):
            print("kernel_file from: ", kernel_file)
            sys.exit("[ERR]kernel file is not exist, from: %s"%os.path.realpath(__file__))

        # 构造输出文件名 #
        image_file = os.path.join(pkt_dir_path, '%s_ota.bin'%app_name) if target is None else target
        print("********************package kernel&nv upgrade file********************")
        MAKE_IMAGE.make_hupg(self.__image_id, self.__kernel_file_ver, self.__encrypt_flag, kernel_file, normal_nv_file, image_file, self.__key_dir_path, self.__kernel_bin_max_size, self.__sign_alg, self.__chip_product_name, file_attr)
        return image_file

    def BuildHiburnBin(self, burn_bin = None, ota_file = None):
        app_name = self.__app_name
        pkt_dir_path = self.__pktPath

        #烧写文件配置
        flash_boot_file = self.__bootBinPath
        factory_nv_file = self.__factoryNvPath
        normal_nv_file = self.__normalNvPath
        upg_file = os.path.join(pkt_dir_path, '%s_%s.%s'%(app_name, 'ota', 'bin')) if ota_file is None else ota_file

        if not os.path.exists(flash_boot_file):
            print("flash_boot_file from: ", flash_boot_file)
            sys.exit("[ERR]flash boot file is not exist, from: %s"%os.path.realpath(__file__))

        if not os.path.exists(factory_nv_file):
            print("factory_nv_file from: ", factory_nv_file)
            sys.exit("[ERR]factory nv file is not exist, from: %s"%os.path.realpath(__file__))

        if not os.path.exists(normal_nv_file):
            print("normal_nv_file from: ", normal_nv_file)
            sys.exit("[ERR]normal nv file is not exist, from: %s"%os.path.realpath(__file__))

        if not os.path.exists(upg_file):
            print("ota file from: ", upg_file)
            sys.exit("[ERR]ota file is not exist, from: %s"%os.path.realpath(__file__))

        # 构造输出文件名 #
        image_file = os.path.join(pkt_dir_path, '%s_burn.bin'%app_name) if burn_bin is None else burn_bin
        print("********************package hiburn file********************")
        MAKE_IMAGE.make_hbin(flash_boot_file, factory_nv_file, normal_nv_file, upg_file, image_file)
        return image_file

    def BuildCompressUpgBin(self, compress_ota_bin = None, ota_file = None):
        app_name = self.__app_name
        pkt_dir_path = self.__pktPath
        file_attr = (self.__file_attr_encrypt << 6) + self.__kernel_file_attr_ota

        #制作压缩升级文件依赖文件
        upg_file = os.path.join(pkt_dir_path, '%s_%s.%s'%(app_name, 'ota', 'bin')) if ota_file == None else ota_file

        if not os.path.exists(upg_file):
            print("compress ota file from: ", upg_file)
            sys.exit("[ERR]ota file is not exist, from: %s"%os.path.realpath(__file__))

        # 构造输出文件名 #
        image_file = os.path.join(pkt_dir_path, '%s_ota.bin'%app_name) if compress_ota_bin == None else compress_ota_bin
        print("********************package compress upgrade file********************")
        MAKE_IMAGE.make_compress_hupg(self.__image_id, self.__kernel_file_ver, self.__encrypt_flag, upg_file, image_file, self.__key_dir_path, self.__kernel_upg_max_size, self.__sign_alg, self.__lzma_tool_path, self.__build_tmp_path, self.__chip_product_name, file_attr)
        return image_file

# main function #
if __name__ == '__main__':
    root_path = os.getcwd()
    args = len(sys.argv)
    list = ['boot_ota', 'ota', 'burn_bin', 'ota_compress']
    if args >= 6 and sys.argv[1] in list:
        type = sys.argv[1]
        app_name = sys.argv[2]
        sign_alg = int(sys.argv[3], 16)
        kernel_file_ver = int(sys.argv[4])
        flashboot_file_ver = int(sys.argv[5])
        target = sys.argv[6]
        usr_output = sys.argv[7].split('=')[1] if len(sys.argv[7].split('='))==2 else ''
        usr_output = os.path.join('..', '..', usr_output)
        fu = ImageBuild(app_name, sign_alg, kernel_file_ver, flashboot_file_ver, usr_realtive_output=usr_output)
        fu.set_pkt_path(os.path.join(root_path, usr_output, 'output', 'bin'))
        bootBinPath = os.path.join(root_path, usr_output, 'output', 'bin', 'Hi3861_boot_signed.bin')
        fu.set_src_path(bootBinPath)
        fu.set_file_attr_encrypt(0x1) if scons_get_cfg_val('CONFIG_FLASH_ENCRYPT_SUPPORT') != 'y' else None
        fu.set_flashboot_file_attr_ota(0x3) if scons_get_cfg_val('CONFIG_COMPRESSION_OTA_SUPPORT') != 'y' else None
        if type == 'boot_ota':
            print('boot_ota')
            fu.BuildUpgBoot(target)
        elif type == 'ota':
            print('ota')
            kernelBinPath = sys.argv[8]
            sign = 1 if sys.argv[9]=='A' else 2
            fu.set_src_path(kernel_bin_path = kernelBinPath)
            fu.set_kernel_max_size(sign) if scons_get_cfg_val('CONFIG_COMPRESSION_OTA_SUPPORT') != 'y' else fu.set_kernel_max_size(0)
            fu.set_kernel_file_attr_ota(sign) if scons_get_cfg_val('CONFIG_COMPRESSION_OTA_SUPPORT') != 'y' else None
            fu.BuildUpgBin(target)
        elif type == 'burn_bin':
            print('burn_bin')
            ota_bin = sys.argv[8]
            fu.BuildHiburnBin(target, ota_bin)

            allinone = os.path.join(os.path.dirname(target), '%s_allinone.bin'%app_name)
            loader_bin = os.path.join(os.path.dirname(target), '%s_loader_signed.bin'%app_name[:6])
            efuse_bin = os.path.join(root_path, 'build', 'basebin', 'efuse_cfg.bin')
            efuse_bin = None if not os.path.exists(efuse_bin) else efuse_bin
            boot_b = os.path.join(os.path.dirname(target), "%s_boot_signed_B.bin"%(app_name[:6]))
            boot_b_size = os.path.getsize(boot_b)
            list = ['%s|0|0|0'%loader_bin, '%s|0|0|3'%efuse_bin, '%s|0|%d|1'%(target, 0x200000), '%s|%d|%d|1'%(boot_b, 0x200000 - boot_b_size, boot_b_size)] if efuse_bin!=None else ['%s|0|0|0'%loader_bin, '%s|0|%d|1'%(target, 0x200000), '%s|%d|%d|1'%(boot_b, 0x200000 - boot_b_size, boot_b_size)]
            packet_bin(allinone, list)
        elif type == 'ota_compress':
            print('ota_compress')
            ota_bin = sys.argv[8]
            fu.set_kernel_file_attr_ota(0x4)
            fu.set_kernel_max_size(0) #(912+968)KB
            fu.set_build_temp_path(build_temp_path = os.path.dirname(ota_bin))
            fu.BuildCompressUpgBin(target, ota_bin)
    elif args == 5 or args == 3:
        sign_alg = int(sys.argv[1], 16)
        dual_ota_flag = sys.argv[2]
        flashboot_file_ver = 0 if args != 5 else int(sys.argv[3])
        kernel_file_ver = 0 if args != 5 else int(sys.argv[4])
        lib_path = os.path.join(root_path, 'build', 'scripts')
        sys.path.append(lib_path)
        from hi_config_parser import UsrCfgParser

        class BaseCfgParser(UsrCfgParser):
            def get_default_config_file(self):
                return os.path.join(root_path, 'code', 'liteos', 'Huawei_LiteOS', '.config')

        options = BaseCfgParser().do_parse()
        chip_product = options.get('LOSCFG_COMPILER_CHIP_VER')
        app_name = chip_product + '_demo'
        if app_name:
            app_name = app_name.strip('"')

        t1 = time.time()
        print("&&&&&&&&&&&&&args", sign_alg, dual_ota_flag, flashboot_file_ver, kernel_file_ver)
        fu = ImageBuild(app_name, sign_alg, kernel_file_ver, flashboot_file_ver, chip_product)
        if int(dual_ota_flag) == 0:
            fu.set_kernel_max_size(0)
            fu.compress_ota_work()
        else:
            fu.set_kernel_file_attr_ota(0x1) #kernelA
            fu.set_flashboot_file_attr_ota(0x3) #kernelA|kernelB
            fu.dual_partion_ota_work()

        print ("Package finish!! \r\n")
        print('TOTAL TIME:%ss'%str(time.time() - t1))
    else:
        print('[ERROR]: build ota parameters err!!!')
        sys.exit(1)
