 /*
  * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2020. All rights reserved.
  * Description:boot start process.
  * Author: Hisilicon
  * Create: 2019-12-10
  */

#include "boot_start.h"
#include "boot_upg_kernel.h"
#include "boot_upg_check.h"
#include "boot_upg_check_secure.h"
#ifdef CONFIG_FLASH_ENCRYPT_SUPPORT
#include <crypto.h>
#endif

#define CRYPTO_FLASH_LENGTH 4096

hi_u32 g_upg_kernel_verify_addr;

hi_u32 check_hupg(hi_void)
{
    hi_u32 ret = boot_upg_check_file(g_upg_kernel_verify_addr);
    if (ret != HI_ERR_SUCCESS) {
        boot_msg2("[check hupg]fail ret-addr", ret, g_upg_kernel_verify_addr);
    }
    return ret;
}

hi_u32 check_hupg_multi_times(hi_u32 check_times)
{
    hi_u32 ret = HI_ERR_SUCCESS;
    for (hi_u32 i = 0; i < check_times; i++) {
        ret = check_hupg();
        if (ret == HI_ERR_SUCCESS) {
            return ret;
        } else {
            boot_msg2("[check hupg multi times]fail ret-index", ret, i);
        }
    }
    return ret;
}

hi_void change_area(hi_void)
{
    hi_nv_ftm_startup_cfg *cfg = boot_upg_get_cfg();

#if defined(CONFIG_COMPRESSION_OTA_SUPPORT)
    if (g_upg_kernel_verify_addr == cfg->addr_start) {
        g_upg_kernel_verify_addr = cfg->addr_write;
    } else {
        g_upg_kernel_verify_addr = cfg->addr_start;
    }
#else
    hi_flash_partition_table *partition = hi_get_partition_table();
    uintptr_t kernel_a_addr = partition->table[HI_FLASH_PARTITON_KERNEL_A].addr;
    uintptr_t kernel_b_addr = partition->table[HI_FLASH_PARTITON_KERNEL_B].addr;

    if (cfg->addr_start == kernel_a_addr) {
        cfg->addr_start = kernel_b_addr;
    } else {
        cfg->addr_start = kernel_a_addr;
    }
    g_upg_kernel_verify_addr = cfg->addr_start;
#endif
}

hi_void set_running_kernel_flag(hi_u32 offset)
{
    hi_u16 reg_val;
    hi_flash_partition_table *ptable = hi_get_partition_table();
    hi_reg_read16(CLDO_CTL_GEN_REG0, reg_val);
    reg_val &= ~(0x1 << 15); /* 15 */
    if (offset < ptable->table[HI_FLASH_PARTITON_KERNEL_B].addr) {  /* kernel B�ĵ͵�ַ������flash�������滻�� */
        reg_val |= 0x1 << 15; /* 15 */
        hi_reg_write16(CLDO_CTL_GEN_REG0, reg_val);
    } else {
        hi_reg_write16(CLDO_CTL_GEN_REG0, reg_val);
    }
}

hi_void boot_head(hi_void)
{
    hi_u32 offset = 0;
    hi_nv_ftm_startup_cfg *cfg = boot_upg_get_cfg();
    hi_u32 ret = check_hupg_multi_times(UPG_MAX_BACKUP_CNT);
    if (ret != HI_ERR_SUCCESS) {
        change_area();
#ifdef CONFIG_FLASH_ENCRYPT_SUPPORT
        crypto_check_decrypt();
#endif
        cfg->refresh_nv = ENV_REFRESH_NV;
        ret = check_hupg();
        if (ret != HI_ERR_SUCCESS) {
            boot_msg1("Check_hupg fail:", ret);
            global_reset();
        } else {
            boot_upg_save_cfg_to_nv();
        }
    }

#if defined(CONFIG_COMPRESSION_OTA_SUPPORT)
    if ((ret == HI_ERR_SUCCESS) && (g_upg_kernel_verify_addr == cfg->addr_write)) {
        ret = boot_upg_kernel_process(cfg->addr_start, cfg->addr_write);
        if (ret != HI_ERR_SUCCESS) {
            boot_msg2("[bootupg kernel process]ret-addr_start", ret, cfg->addr_start);
            global_reset();
        }
    }
#endif

    boot_get_start_addr_offset(cfg->addr_start, &offset);
    set_running_kernel_flag(offset);
#ifdef CONFIG_FLASH_ENCRYPT_SUPPORT
    boot_kernel(BOOTLOADER_FLASH_HEAD_ADDR + offset + CRYPTO_FLASH_LENGTH);
#else
    boot_kernel(BOOTLOADER_FLASH_HEAD_ADDR + offset);
#endif
    global_reset();
}

hi_void boot_upg_init_verify_addr(const hi_nv_ftm_startup_cfg *cfg)
{
    g_upg_kernel_verify_addr = cfg->addr_start;
#if defined(CONFIG_COMPRESSION_OTA_SUPPORT)
    if ((cfg->mode == HI_UPG_MODE_UPGRADE) && (cfg->file_type == HI_UPG_FILE_KERNEL)) {
        g_upg_kernel_verify_addr = cfg->addr_write;
    }
#endif
}

hi_void execute_upg_boot(hi_void)
{
    hi_nv_ftm_startup_cfg *cfg = boot_upg_get_cfg();
    boot_upg_save_key_pos();
    boot_upg_load_cfg_from_nv();
    if ((cfg->cnt_max > 0) && (cfg->mode == HI_UPG_MODE_UPGRADE)) {
        cfg->reset_cnt++;
        if (cfg->reset_cnt >= cfg->cnt_max) {
            change_area();
#ifdef CONFIG_FLASH_ENCRYPT_SUPPORT
            crypto_decrypt(KERNEL_RAM_ADDR, CRYPTO_KERNEL_LENGTH);
#endif
            cfg->mode = HI_UPG_MODE_NORMAL;
            if (boot_upg_save_cfg_to_nv() != HI_ERR_SUCCESS) {
                boot_msg0("To do");
            }
            boot_msg0("!!!Upg verify fail.");
        } else {
            if (boot_upg_save_cfg_to_nv() != HI_ERR_SUCCESS) {
                boot_msg0("To do");
            }
        }
    }

#ifdef CONFIG_FLASH_ENCRYPT_SUPPORT
    crypto_check_decrypt();
#endif

    boot_head();
}
