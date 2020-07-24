/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: FLASH driver APIs. \n
 * Author: hisilicon
 * Create: 2019-03-04
 */

/**
* @file hi_flash.h
*
* Copyright (c) Hisilicon Technologies Co., Ltd. 2019. All rights reserved.  \n
*
* Description: FLASH driver APIs. \n
*/

/** @defgroup iot_flash  Flash
 *  @ingroup drivers
 */
#ifndef __HI_FLASH_H__
#define __HI_FLASH_H__

#include <hi_types.h>
#include <hi_flash_base.h>
/**
* @ingroup  iot_flash
* @brief  Reads the flash data to the specified cache. CNcomment:����Flash���ݵ�ָ����������CNend
*
* @par ����:
*           Reads the flash data to the specified cache. CNcomment:����Flash���ݵ�ָ����������CNend
*
* @attention None
* @param  flash_offset      [IN] type #const hi_u32��Offset of the flash address.CNcomment:ָ����Flash��ַƫ�ơ�CNend
* @param  size              [IN] type #const hi_u32��Read length (unit: byte).
CNcomment:ָ����ȡ�ĳ��ȣ���λ��byte����CNend
* @param  ram_data          [IN] type #hi_u8*��Destination cache address.CNcomment:Ŀ�Ļ����ַ��CNend
*
* @retval #HI_ERR_SUCCESS  Success.
* @retval #Other           Failure. For details, see hi_errno.h.
* @par ����:
*            @li hi_flash.h��FLASH driver APIs.CNcomment:�ýӿ��������ڵ�ͷ�ļ���CNend
* @see  None
* @since Hi3861_V100R001C00
*/
hi_u32 hi_flash_read(const hi_u32 flash_offset, const hi_u32 size, hi_u8 *ram_data);

/**
* @ingroup  iot_flash
* @brief  Writes data to the specified flash partition.CNcomment:������д��ָ����Flash����CNend
*
* @par ����:
*           Writes data to the specified flash partition.CNcomment:������д��ָ����Flash����CNend
*
* @attention
*           @li Restriction protection for the relative address of the flash memory.
CNcomment:Flash��Ե�ַ�����Ʊ�����CNend
*           @li The number of flash erase times must comply with the device data sheet.
CNcomment:Flash��д�������ơ�CNend
*           @li Determine whether to erase the flash before the write based on the actual control scenario.
CNcomment:�����û�ʵ�ʿ��Ƴ��������Ƿ��Ȳ���д��CNend
* @param  flash_offset    [IN] type #const hi_u32��Offset address for writing data to the flash memory.
CNcomment:ָ��д��Flashƫ�Ƶ�ַ��CNend
* @param  size            [IN] type #hi_u32��Length of the data to be written (unit: byte).
CNcomment:��Ҫд��ĳ��ȣ���λ��byte����CNend
* @param  ram_data        [IN] type #const hi_u8*��Cache address of the data to be written.
CNcomment:��Ҫд������ݵĻ����ַ��CNend
* @param  do_erase        [IN] type #hi_bool��HI_FALSE: Write data to the flash memory directly.
*                                             HI_TRUE:  Erase the sector space before write.
*                         The user data is written to the user operation space and the historical
*                         data is written back to other spaces.CNcomment:��ʾ�Ƿ��Զ�����������д�롣
*                         @li HI_TRUE�����ӿ����Ȳ���д��
*                         @li HI_FALSE���û��Ѿ��������ӿڣ���ֱ��д�롣CNend
*
* @retval #HI_ERR_SUCCESS  Success.
* @retval #Other           Failure. For details, see hi_errno.h.
* @par ����:
*            @li hi_flash.h��FLASH driver APIs.CNcomment:�ýӿ��������ڵ�ͷ�ļ���CNend
* @see  None
* @since Hi3861_V100R001C00
*/
hi_u32 hi_flash_write(const hi_u32 flash_offset, hi_u32 size, const hi_u8 *ram_data, hi_bool do_erase);

/**
* @ingroup  iot_flash
* @brief  Erases the data in the specified flash partition.CNcomment:��ָ����Flash�������ݲ�����CNend
*
* @par ����:
*           Erases the data in the specified flash partition.CNcomment:��ָ����Flash�������ݲ�����CNend
*
* @attention
*           @li Restriction protection for the relative address of the flash memory.
CNcomment:Flash��Ե�ַ�����Ʊ�����CNend
*           @li The number of flash erase times must comply with the device data sheet.
CNcomment:Flash��д�������ơ�CNend
*
* @param  flash_offset    [IN] type #const hi_u32��Address offset of the flash memory to be erased.
CNcomment:ָ��Ҫ����Flash�ĵ�ַƫ�ơ�CNend
* @param  size            [IN] type #const hi_u32��Length of the data to be erased (unit: byte).
*                         The value must be a multiple of 4 KB.
CNcomment:��Ҫ�����ĳ��ȣ���λ��byte����������4K�ı�����CNend
*
* @retval #HI_ERR_SUCCESS  Success.
* @retval #Other           Failure. For details, see hi_errno.h.
* @par ����:
*            @li hi_flash.h��FLASH driver APIs.CNcomment:�ýӿ��������ڵ�ͷ�ļ���CNend
* @see  None
* @since Hi3861_V100R001C00
*/
hi_u32 hi_flash_erase(const hi_u32 flash_offset, const hi_u32 size);

/**
* @ingroup  iot_flash
* @brief   Initializes the flash device. CNcomment:��ʼ��Flash�豸��CNend
*
* @par ����:
*           Initializes the flash device. CNcomment:��ʼ��Flash�豸��CNend
*
* @attention Initialize the flash module during system boot.
CNcomment:Flashģ���ʼ����һ����ϵͳ����ʱ���á�CNend
* @param  None
*
* @retval #HI_ERR_SUCCESS  Success.
* @retval #Other           Failure. For details, see hi_errno.h.
* @par ����:
*            @li hi_flash.h��FLASH driver APIs.CNcomment:�ýӿ��������ڵ�ͷ�ļ���CNend
* @see  None
* @since Hi3861_V100R001C00
*/
hi_u32 hi_flash_init(hi_void);

/**
* @ingroup  iot_flash
* @brief  Deinitializes the flash device.CNcomment:ȥ��ʼ��Flash�豸��CNend
*
* @par ����:
*           Deinitializes the flash device.CNcomment:ȥ��ʼ��Flash�豸��CNend
*
* @attention None
* @param  None
*
* @retval #HI_ERR_SUCCESS  Success.
* @retval #Other           Failure. For details, see hi_errno.h.
* @par ����:
*            @li hi_flash.h��FLASH driver APIs.CNcomment:�ýӿ��������ڵ�ͷ�ļ���CNend
* @see  None
* @since Hi3861_V100R001C00
*/
hi_u32 hi_flash_deinit(hi_void);
/**
* @ingroup  iot_flash
* @brief  Sets or reads flash information.CNcomment:��ȡFlash��Ϣ��CNend
*
* @par ����:
*          Sets or reads flash information.CNcomment:��ȡFlash��Ϣ��CNend
*
* @attention None
* @param  cmd             [IN]     type #hi_u16��Command ID, currently supports HI_FLASH_CMD_GET_INFO and
*                         HI_FLASHI_FLASH_CMD_IS_BUSY.
CNcomment:����ID����ǰ֧��HI_FLASH_CMD_GET_INFO �� HI_FLASH_CMD_IS_BUSY��CNend
* @param  data            [IN/OUT] type #hi_void*, Information set or obtained. cmd is HI_FLASH_CMD_GET_INFO, data is
*                         a pointer of hi_flash_info struct; cmd is HI_FLASH_CMD_IS_BUSY, data is a pointer of type
*                         hi_bool.CNcomment:������Ϣ��cmd����ΪHI_FLASH_CMD_GET_INFO��dataΪhi_flash_info�ṹָ�룻
*                         cmdΪHI_FLASH_CMD_IS_BUSY��dataΪhi_bool����ָ�롣CNend
*
* @retval #HI_ERR_SUCCESS  Success.
* @retval #Other           Failure. For details, see hi_errno.h.
* @par ����:
*            @li hi_flash.h��FLASH driver APIs.CNcomment:�ýӿ��������ڵ�ͷ�ļ���CNend
* @see  None
* @since Hi3861_V100R001C00
*/
hi_u32 hi_flash_ioctl(HI_IN hi_u16 cmd, HI_INOUT hi_void *data);

#endif

