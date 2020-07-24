/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: flash partion table..
 * Author: hisilicon
 * Create: 2020-03-16
 */

#include <hi_types.h>

#define SFC_BUFFER_BASE_ADDRESS 0x400000

/** @defgroup iot_flash_partiton Partition Table APIs
* @ingroup  iot_flashboot
*/
/**
 * @ingroup iot_flash_partiton
 *
 * partition number.
 */
#define HI_FLASH_PARTITON_MAX 10

/**
 * @ingroup iot_flash_partiton
 *
 * partition ID.
 */
typedef enum {
    HI_FLASH_PARTITON_BOOT = 0,
    HI_FLASH_PARTITON_FACTORY_NV,
    HI_FLASH_PARTITON_WORK_NV,
    HI_FLASH_PARTITON_KERNEL_A,
    HI_FLASH_PARTITON_KERNEL_B,
    HI_FLASH_PARTITON_HILINK,
    HI_FLASH_PARTITON_FILE_SYSTEM,
    HI_FLASH_PARTITON_CRASH_INFO,
    HI_FLASH_PARTITON_BOOT_BACK,
    HI_FLASH_PARTITON_RESERVE,
} hi_flash_partition_table_id;

/**
 *  @ingroup iot_flash_partiton
 *
 *  Flash partition management. CNcomment:Flash分区表项。CNend
 */
typedef struct {
    hi_u32  addr    :24;   /* Flash partition address. The value is 16 MB. If the address is in reverse order,
                               the value is the end low address. CNcomment:Flash分区地址，限制为16MB，
                               如果为倒序，存放为结束的低地址值 CNend */
    hi_u32  id      :7;    /* Flash partition ID. CNcomment:Flash区ID.CNend  */
    hi_u32  dir     :1;    /* Flash area storage direction. 0:regular. 1: reversed.CNcomment:Flash区存放方向。
                               0：分区内容正序；1：倒序末地址 CNend */

    hi_u32  size    :24;   /* Size of the parition(Unit:byte). CNcomment:Flash分区大小（单位：byte）CNend */
    hi_u32  reserve :8;    /* Reserved. CNcomment:保留区CNend  */

    hi_u32  addition;      /* Supplementary information about the flash partition, such as the address of the Ram.
                              CNcomment:Flash分区补充信息，如Ram对应地址等 CNend */
} hi_flash_partition_info;

/**
 *  @ingroup iot_flash_partiton
 *  Flash partiton table.
 */
typedef struct {
    hi_flash_partition_info table[HI_FLASH_PARTITON_MAX]; /**< Flash分区表项描述  */
} hi_flash_partition_table;

/**
* @ingroup  iot_flash_partiton
* @brief  Initialize flash partition table. CNcomment:初始化Flash分区表。CNend
*
* @par 描述:
*           Initialize flash partition table. CNcomment:初始化Flash分区表。CNend
*
* @attention None.
* @param  None.
*
* @retval #HI_ERR_FAILURE Failure.
* @retval #HI_ERR_SUCCESS Success.
* @par 依赖:
*            @li hi_flashboot.h：Describes FlashBoot APIs.CNcomment:文件用于描述Boot模块接口。CNend
* @see  hi_get_partition_table。
* @since Hi3861_V100R001C00
*/
hi_u32 hi_flash_partition_init(hi_void);

/**
* @ingroup  iot_flash_partiton
* @brief  Get flash partition table. CNcomment:获取Flash分区表。CNend
*
* @par 描述:
*           Get flash partition table. CNcomment:获取Flash分区表。CNend
*
* @attention None.
* @param  None.
*
* @retval #HI_NULL Failure.
* @retval #Other Success.
* @par 依赖:
*            @li hi_flashboot.h：Describes FlashBoot APIs.CNcomment:文件用于描述Boot模块接口。CNend
* @see  hi_flash_partition_init。
* @since Hi3861_V100R001C00
*/
hi_flash_partition_table* hi_get_partition_table(hi_void);
