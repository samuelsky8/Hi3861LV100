/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: flash partion table.
 * Author: wuxianfeng
 * Create: 2019-03-04
 */

#include <hi_nv.h>
#include <hi_ft_nv.h>
#include <hi_partition_table.h>
#include <hi_nv.h>

#define FACTORY_NV_ADDR_REG (SYSCTRL_SC_GEN_REG3_REG)

#define PRODUCT_CFG_DEFAULT_BOOT_ADDR            0x0
#define PRODUCT_CFG_DEFAULT_FNV_ADDR             0x8000
#define PRODUCT_CFG_DEFAULT_WORK_NV_ADDR         0xA000
#define PRODUCT_CFG_DEFAULT_WORK_NV_BACKUP_ADDR  0xC000
#define PRODUCT_CFG_DEFAULT_KERNEL_A_ADDR        0xD000
#define PRODUCT_CFG_DEFAULT_KERNEL_B_ADDR        0xF1000
#define PRODUCT_CFG_DEFAULT_HILINK_ADDR          0x1E3000
#define PRODUCT_CFG_DEFAULT_FILE_SYSTEM_ADDR     0x1E5000
#define PRODUCT_CFG_DEFAULT_CRASH_INFO_ADDR      0x1F7000
#define PRODUCT_CFG_DEFAULT_BOOT_BACK_ADDR       0x1F8000

#define PRODUCT_CFG_DEFAULT_BOOT_SIZE            0x8000
#define PRODUCT_CFG_DEFAULT_FNV_SIZE             0x2000
#define PRODUCT_CFG_DEFAULT_WORK_NV_SIZE         0x2000
#define PRODUCT_CFG_DEFAULT_WORK_NV_BACKUP_SIZE  0x1000 /* NV ORINGIN BACKUP */
#define PRODUCT_CFG_DEFAULT_KERNEL_A_SIZE        0xE4000
#define PRODUCT_CFG_DEFAULT_KERNEL_B_SIZE        0xF2000
#define PRODUCT_CFG_DEFAULT_HILINK_SIZE          0x2000
#define PRODUCT_CFG_DEFAULT_FILE_SYSTEM_SIZE     0x12000
#define PRODUCT_CFG_DEFAULT_CRASH_INFO_SIZE      0x1000
#define PRODUCT_CFG_DEFAULT_BOOT_BACK_SIZE       0x8000

static hi_flash_partition_table g_partition_table;
hi_flash_partition_table* hi_get_partition_table(hi_void)
{
    return &g_partition_table;
}

hi_u32 hi_flash_partition_init(hi_void)
{
    hi_u32 ret;
    hi_flash_partition_table* table = hi_get_partition_table();
    ret = hi_factory_nv_read(HI_NV_FTM_FLASH_PARTIRION_TABLE_ID, table, sizeof(hi_flash_partition_table), 0);
    if (ret != HI_ERR_SUCCESS) { /* read nv fail, set flash partition table default value */
        table->table[HI_FLASH_PARTITON_BOOT].addr = PRODUCT_CFG_DEFAULT_BOOT_ADDR;
        table->table[HI_FLASH_PARTITON_BOOT].size = PRODUCT_CFG_DEFAULT_BOOT_SIZE;
        table->table[HI_FLASH_PARTITON_FACTORY_NV].addr = PRODUCT_CFG_DEFAULT_FNV_ADDR;
        table->table[HI_FLASH_PARTITON_FACTORY_NV].size = PRODUCT_CFG_DEFAULT_FNV_SIZE;
        table->table[HI_FLASH_PARTITON_NORMAL_NV].addr = PRODUCT_CFG_DEFAULT_WORK_NV_ADDR;
        table->table[HI_FLASH_PARTITON_NORMAL_NV].size = PRODUCT_CFG_DEFAULT_WORK_NV_SIZE;
        table->table[HI_FLASH_PARTITON_KERNEL_A].addr = PRODUCT_CFG_DEFAULT_KERNEL_A_ADDR;
        table->table[HI_FLASH_PARTITON_KERNEL_A].size = PRODUCT_CFG_DEFAULT_KERNEL_A_SIZE;
        table->table[HI_FLASH_PARTITON_HILINK].addr = PRODUCT_CFG_DEFAULT_HILINK_ADDR;
        table->table[HI_FLASH_PARTITON_HILINK].size = PRODUCT_CFG_DEFAULT_HILINK_SIZE;
        table->table[HI_FLASH_PARTITON_FILE_SYSTEM].addr = PRODUCT_CFG_DEFAULT_FILE_SYSTEM_ADDR;
        table->table[HI_FLASH_PARTITON_FILE_SYSTEM].size = PRODUCT_CFG_DEFAULT_FILE_SYSTEM_SIZE;
        table->table[HI_FLASH_PARTITON_KERNEL_B].addr = PRODUCT_CFG_DEFAULT_KERNEL_B_ADDR;
        table->table[HI_FLASH_PARTITON_KERNEL_B].size = PRODUCT_CFG_DEFAULT_KERNEL_B_SIZE;
        table->table[HI_FLASH_PARTITON_CRASH_INFO].addr = PRODUCT_CFG_DEFAULT_CRASH_INFO_ADDR;
        table->table[HI_FLASH_PARTITON_CRASH_INFO].size = PRODUCT_CFG_DEFAULT_CRASH_INFO_SIZE;
        table->table[HI_FLASH_PARTITON_BOOT_BACK].addr = PRODUCT_CFG_DEFAULT_BOOT_BACK_ADDR;
        table->table[HI_FLASH_PARTITON_BOOT_BACK].size = PRODUCT_CFG_DEFAULT_BOOT_BACK_SIZE;
    }
    return ret;
}

hi_u32 hi_get_hilink_partition_table(hi_u32 *addr, hi_u32 *size)
{
    if (addr == HI_NULL || size == HI_NULL) {
        return HI_ERR_FAILURE;
    }

    hi_flash_partition_table* flash_partion_table = hi_get_partition_table();
    *addr = flash_partion_table->table[HI_FLASH_PARTITON_HILINK].addr;
    *size = flash_partion_table->table[HI_FLASH_PARTITON_HILINK].size;

    return HI_ERR_SUCCESS;
}

hi_u32 hi_get_crash_partition_table(hi_u32 *addr, hi_u32 *size)
{
    if (addr == HI_NULL || size == HI_NULL) {
        return HI_ERR_FAILURE;
    }

    hi_flash_partition_table* flash_partion_table = hi_get_partition_table();
    *addr = flash_partion_table->table[HI_FLASH_PARTITON_CRASH_INFO].addr;
    *size = flash_partion_table->table[HI_FLASH_PARTITON_CRASH_INFO].size;

    return HI_ERR_SUCCESS;
}

hi_u32 hi_get_fs_partition_table(hi_u32 *addr, hi_u32 *size)
{
    if (addr == HI_NULL || size == HI_NULL) {
        return HI_ERR_FAILURE;
    }

    hi_flash_partition_table* flash_partion_table = hi_get_partition_table();
    *addr = flash_partion_table->table[HI_FLASH_PARTITON_FILE_SYSTEM].addr;
    *size = flash_partion_table->table[HI_FLASH_PARTITON_FILE_SYSTEM].size;

    return HI_ERR_SUCCESS;
}

hi_u32 hi_get_normal_nv_partition_table(hi_u32 *addr, hi_u32 *size)
{
    if (addr == HI_NULL || size == HI_NULL) {
        return HI_ERR_FAILURE;
    }

    hi_flash_partition_table* flash_partion_table = hi_get_partition_table();
    *addr = flash_partion_table->table[HI_FLASH_PARTITON_NORMAL_NV].addr;
    *size = flash_partion_table->table[HI_FLASH_PARTITON_NORMAL_NV].size;

    return HI_ERR_SUCCESS;
}


