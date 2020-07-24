/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: flash info.
 * Author: wuxianfeng
 * Create: 2019-05-30
 */

#ifndef __HI_FLASH_BASE_H__
#define __HI_FLASH_BASE_H__

#include <hi_types_base.h>

#define HI_FLASH_CMD_ADD_FUNC   0
#define HI_FLASH_CMD_GET_INFO   1  /**< IOCTL command ID for obtaining the flash information.
                                        The corresponding output parameter points to the hi_flash_info structure.
CNcomment:IOCTL��ȡFlash��Ϣ����Ӧ����ָ��ṹ��Ϊhi_flash_info.CNend */
#define HI_FLASH_CMD_IS_BUSY    2  /**< IOCTL Obtain whether the flash memory is busy. The corresponding output
                                        parameter point type is hi_bool.
CNcomment:IOCTL��ȡFlash�Ƿ�busy����Ӧ����ָ������Ϊhi_bool CNend */

#define HI_FLASH_CHIP_ID_NUM    3
#define HI_FLASH_CAPACITY_ID    2

/**
* @ingroup  iot_flash
*
* Flash information obtaining structure, used to describe the return structure of the command ID HI_FLASH_CMD_GET_INFO.
CNcomment:Flash��Ϣ��ȡ�ṹ�壬������������ID(HI_FLASH_CMD_GET_INFO)�ķ��ؽṹ�塣CNend
*/
typedef struct {
    hi_char *name;                     /**< Flash name.CNcomment:Flash����CNend  */
    hi_u8   id[HI_FLASH_CHIP_ID_NUM];  /**< Flash Id  */
    hi_u8   pad;
    hi_u32 total_size;                 /**< Flash totoal size (unit: byte).
                                          CNcomment:Flash�ܴ�С����λ��byte��CNend  */
    hi_u32 sector_size;                /**< Flash block size (unit: byte).
                                          CNcomment:Flash���С����λ��byte��CNend */
} hi_flash_info;

#endif

