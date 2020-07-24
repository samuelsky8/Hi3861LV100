/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: Get upg start up info under boot.
 * Author: Hisilicon
 * Create: 2019-12-10
 */

#include <boot_upg_start_up.h>
#include "boot_start.h"

hi_nv_ftm_startup_cfg g_startup_cfg;

hi_void boot_upg_set_default_cfg(hi_void)
{
    hi_nv_ftm_startup_cfg *cfg = boot_upg_get_cfg();
    hi_flash_partition_table *partition = hi_get_partition_table();
    uintptr_t kernel_a_addr = partition->table[HI_FLASH_PARTITON_KERNEL_A].addr;
    hi_u32 cs = (uintptr_t)cfg ^ sizeof(hi_nv_ftm_startup_cfg) ^ 0 ^ sizeof(hi_nv_ftm_startup_cfg);
    if (memset_s(cfg, sizeof(hi_nv_ftm_startup_cfg), 0, sizeof(hi_nv_ftm_startup_cfg), cs) != EOK) {
        return;
    }
    cfg->addr_start = kernel_a_addr;
    cfg->cnt_max = UPG_MAX_BACKUP_CNT;
}

hi_u32 boot_upg_save_cfg_to_nv(hi_void)
{
    hi_nv_ftm_startup_cfg *cfg = boot_upg_get_cfg();
    hi_u32 ret = hi_factory_nv_write(HI_NV_FTM_STARTUP_CFG_ID, cfg, sizeof(hi_nv_ftm_startup_cfg), 0);
    if (ret != HI_ERR_SUCCESS) {
        boot_msg1("[boot upg save nv]nv write fail,ret ", ret);
        return ret;
    }
    return ret;
}

hi_u32 boot_upg_check_start_addr(hi_u32 addr)
{
    hi_flash_partition_table *partition = hi_get_partition_table();
    uintptr_t kernel_a_addr = partition->table[HI_FLASH_PARTITON_KERNEL_A].addr;
#if defined(CONFIG_COMPRESSION_OTA_SUPPORT)
    if (addr != kernel_a_addr) {
        return HI_ERR_FAILURE;
    }
#else
    uintptr_t kernel_b_addr = partition->table[HI_FLASH_PARTITON_KERNEL_B].addr;
    if ((addr != kernel_a_addr) && (addr != kernel_b_addr)) {
        return HI_ERR_FAILURE;
    }
#endif
    return HI_ERR_SUCCESS;
}

hi_void boot_upg_load_cfg_from_nv(hi_void)
{
    hi_bool set_default_nv_flag = HI_FALSE;
    hi_u32 cs;
    hi_nv_ftm_startup_cfg nv_cfg = { 0 };
    hi_nv_ftm_startup_cfg *cfg = boot_upg_get_cfg();
    hi_u32 ret = hi_factory_nv_read(HI_NV_FTM_STARTUP_CFG_ID, &nv_cfg, sizeof(hi_nv_ftm_startup_cfg), 0);
    if (ret != HI_ERR_SUCCESS) {
        set_default_nv_flag = HI_TRUE;
        boot_msg1("[bootupg load cfg]nv read fail", ret);
    } else {
        ret = boot_upg_check_start_addr(nv_cfg.addr_start);
        if (ret != HI_ERR_SUCCESS) {
            set_default_nv_flag = HI_TRUE;
            boot_msg1("[bootupg load cfg]check addr start fail", nv_cfg.addr_start);
        } else {
            cs = (uintptr_t)cfg ^ sizeof(hi_nv_ftm_startup_cfg) ^ ((uintptr_t)&nv_cfg) ^ sizeof(hi_nv_ftm_startup_cfg);
            if (memcpy_s(cfg, sizeof(hi_nv_ftm_startup_cfg), &nv_cfg, sizeof(hi_nv_ftm_startup_cfg), cs) != EOK) {
                set_default_nv_flag = HI_TRUE;
                boot_msg0("[bootupg load cfg]memcpy fail");
            }
        }
    }

    if (set_default_nv_flag == HI_TRUE) {
        boot_upg_set_default_cfg();
        boot_upg_save_cfg_to_nv();
    }
    boot_upg_init_verify_addr(cfg);
}

hi_nv_ftm_startup_cfg *boot_upg_get_cfg(hi_void)
{
    return &g_startup_cfg;
}


