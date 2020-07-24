/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: flash分区.
 * Author: hisilicon
 * Create: 2019-12-27
 */

#include <load_partition_table.h>
#include <hi_nvm.h>

#define PRODUCT_CFG_DEFAULT_BOOT_ADDR            0x0
#define PRODUCT_CFG_DEFAULT_FNV_ADDR             0x8000
#define PRODUCT_CFG_DEFAULT_WORK_NV_ADDR         0xA000
#define PRODUCT_CFG_DEFAULT_KERNEL_A_ADDR        0xC000
#define PRODUCT_CFG_DEFAULT_KERNEL_B_ADDR        0xF0000
#define PRODUCT_CFG_DEFAULT_HILINK_ADDR          0x1E3000
#define PRODUCT_CFG_DEFAULT_FILE_SYSTEM_ADDR     0x1E5000
#define PRODUCT_CFG_DEFAULT_CRASH_INFO_ADDR      0x1F7000
#define PRODUCT_CFG_DEFAULT_BOOT_BACK_ADDR       0x1F8000

#define PRODUCT_CFG_DEFAULT_BOOT_SIZE            0x8000
#define PRODUCT_CFG_DEFAULT_FNV_SIZE             0x2000
#define PRODUCT_CFG_DEFAULT_WORK_NV_SIZE         0x2000
#define PRODUCT_CFG_DEFAULT_KERNEL_A_SIZE        0xE4000
#define PRODUCT_CFG_DEFAULT_KERNEL_B_SIZE        0xF3000
#define PRODUCT_CFG_DEFAULT_HILINK_SIZE          0x2000
#define PRODUCT_CFG_DEFAULT_FILE_SYSTEM_SIZE     0x12000
#define PRODUCT_CFG_DEFAULT_CRASH_INFO_SIZE      0x1000
#define PRODUCT_CFG_DEFAULT_BOOT_BACK_SIZE       0x8000

static hi_flash_partition_table g_partition_table;

hi_flash_partition_table* hi_get_partition_table(hi_void)
{
    return &g_partition_table;
}


/* Flash分区表初始化。 */
hi_u32 hi_flash_partition_init(hi_void)
{
    hi_u32 ret;
    hi_flash_partition_table* p_table = HI_NULL;
    (hi_void)hi_factory_nv_init(HI_FNV_DEFAULT_ADDR, HI_NV_DEFAULT_TOTAL_SIZE, HI_NV_DEFAULT_BLOCK_SIZE);
    p_table = hi_get_partition_table();
    ret = hi_factory_nv_read(HI_NV_FTM_FLASH_PARTIRION_TABLE_ID, p_table, sizeof(hi_flash_partition_table), 0);
    if (ret != HI_ERR_SUCCESS) { /* read nv fail, set flash partition table default value */
        p_table->table[HI_FLASH_PARTITON_BOOT].addr = PRODUCT_CFG_DEFAULT_BOOT_ADDR;
        p_table->table[HI_FLASH_PARTITON_BOOT].size = PRODUCT_CFG_DEFAULT_BOOT_SIZE;
        p_table->table[HI_FLASH_PARTITON_FACTORY_NV].addr = PRODUCT_CFG_DEFAULT_FNV_ADDR;
        p_table->table[HI_FLASH_PARTITON_FACTORY_NV].size = PRODUCT_CFG_DEFAULT_FNV_SIZE;
        p_table->table[HI_FLASH_PARTITON_WORK_NV].addr = PRODUCT_CFG_DEFAULT_WORK_NV_ADDR;
        p_table->table[HI_FLASH_PARTITON_WORK_NV].size = PRODUCT_CFG_DEFAULT_WORK_NV_SIZE;
        p_table->table[HI_FLASH_PARTITON_KERNEL_A].addr = PRODUCT_CFG_DEFAULT_KERNEL_A_ADDR;
        p_table->table[HI_FLASH_PARTITON_KERNEL_A].size = PRODUCT_CFG_DEFAULT_KERNEL_A_SIZE;
        p_table->table[HI_FLASH_PARTITON_KERNEL_B].addr = PRODUCT_CFG_DEFAULT_KERNEL_B_ADDR;
        p_table->table[HI_FLASH_PARTITON_KERNEL_B].size = PRODUCT_CFG_DEFAULT_KERNEL_B_SIZE;
        p_table->table[HI_FLASH_PARTITON_HILINK].addr = PRODUCT_CFG_DEFAULT_HILINK_ADDR;
        p_table->table[HI_FLASH_PARTITON_HILINK].size = PRODUCT_CFG_DEFAULT_HILINK_SIZE;
        p_table->table[HI_FLASH_PARTITON_FILE_SYSTEM].addr = PRODUCT_CFG_DEFAULT_FILE_SYSTEM_ADDR;
        p_table->table[HI_FLASH_PARTITON_FILE_SYSTEM].size = PRODUCT_CFG_DEFAULT_FILE_SYSTEM_SIZE;
        p_table->table[HI_FLASH_PARTITON_CRASH_INFO].addr = PRODUCT_CFG_DEFAULT_CRASH_INFO_ADDR;
        p_table->table[HI_FLASH_PARTITON_CRASH_INFO].size = PRODUCT_CFG_DEFAULT_CRASH_INFO_SIZE;
        p_table->table[HI_FLASH_PARTITON_BOOT_BACK].addr = PRODUCT_CFG_DEFAULT_BOOT_BACK_ADDR;
        p_table->table[HI_FLASH_PARTITON_BOOT_BACK].size = PRODUCT_CFG_DEFAULT_BOOT_BACK_SIZE;
    }
    return ret;
}

