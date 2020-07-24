/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2012-2019. All rights reserved.
 * Description: LoaderFlash api head file.
 * Author: Hisilicon
 * Create: 2012-12-22
 */

#ifndef __HI_LOADERBOOT_FLASH_H__
#define __HI_LOADERBOOT_FLASH_H__
#include "hi_boot_rom.h"

/**
* @ingroup  hct_boot_flash
* @brief   Flash��ʼ��
*
* @par ����:
* ��ʼ��Flashģ�顣
* @attention
* @retval #0      success.
* @retval #��0    failed.���hi_errno.h
*
* @par Dependency:
* <ul><li>hi_loaderboot_flash.h: �ýӿ��������ڵ�ͷ�ļ�.</li></ul>
* @see
* @since Hi3861_V100R001C00
*/
hi_u32 hi_flash_init(hi_void);

/**
* @ingroup  hct_boot_flash
* @brief  flash����ɾ��
*
* @par ����:
* ɾ��flash�ϵ��������ݡ�
* @attention
*
* @param  flash_addr [IN] ���� #hi_u32  ��ɾ��Flash����ʼ��ַ
* @param  flash_erase_size [IN] ���� #hi_u32   ��ɾ����Flash���ݳ���
*
* @retval #0      success.
* @retval #��0     failed.���hi_errno.h
*
* @par Dependency:
* <ul><li>hi_loaderboot_flash.h: �ýӿ��������ڵ�ͷ�ļ�.</li></ul>
* @see  hi_flash_write|hi_flash_read
* @since Hi3861_V100R001C00
*/
hi_u32 hi_flash_erase(const hi_u32 flash_addr, hi_u32 flash_erase_size);

/**
* @ingroup  hct_boot_flash
* @brief  flash����д��
*
* @par ����:
* ��flash�ϵ�д���������ݡ�
* @attention
* @li ֻ����flash��ʼ��ʱ������flash�ض��ȽϿռ�ſ���ʹ��do_eraseΪHI_TRUE��ѡ��������÷����ο�kernel��hi_flash_initʵ�֡�
*
* @param  flash_addr [IN] ���� #hi_u32  Flash����ʼ��ַ
* @param  flash_write_size [IN] ���� #hi_u32   ��д��Flash�����ݳ���
* @param  flash_write_data [IN] ���� #hi_u8*   ��д��Flash����������
* @param  do_erase [IN] ���� #hi_bool  HI_FALSE:ֱ��дFLASH HI_TRUE:д֮ǰ�������������Ӧ��sector�ռ䣬�û������ռ�д�û����������ռ��д��ʷ���ݡ�
*
* @retval #0      success.
* @retval #��0     failed.���hi_errno.h
*
* @par Dependency:
* <ul><li>hi_loaderboot_flash.h: �ýӿ��������ڵ�ͷ�ļ�.</li></ul>
* @see  hi_flash_erase|hi_flash_read
* @since Hi3861_V100R001C00
*/
hi_u32 hi_flash_write(hi_u32 flash_addr, hi_u32 flash_write_size, const hi_u8 *flash_write_data, hi_bool do_erase);

/**
* @ingroup  hct_boot_flash
* @brief  flash���ݶ�ȡ
*
* @par ����:
* ��flash�ϵĶ�ȡ�������ݡ�
* @attention
*
* @param  flash_addr [IN] ���� #hi_u32  Flash����ʼ��ַ
* @param  flash_read_size [IN] ���� #hi_u32   ����ȡ�����ݳ���
* @param  flash_read_data [OUT] ���� #hi_u8*   �������ݻ����������ڴ�Ŵ�Flash�ж�ȡ��������
*
* @retval #0      success.
* @retval #��0     failed.���hi_errno.h
*
* @par Dependency:
* <ul><li>hi_loaderboot_flash.h: �ýӿ��������ڵ�ͷ�ļ�.</li></ul>
* @see  hi_flash_write|hi_flash_erase
* @since Hi3861_V100R001C00
*/
hi_u32 hi_flash_read(hi_u32 flash_addr, hi_u32 flash_read_size, hi_u8 *flash_read_data);
#endif

