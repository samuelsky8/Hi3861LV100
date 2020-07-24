/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: Upgrade APIs, which are used to implement the upgrade function.
 * Author: Hisilicon
 * Create: 2019-10-25
 */

/**
 * @defgroup upg Upgrade
 * @ingroup system
*/

#ifndef __HI_UPG_API_H__
#define __HI_UPG_API_H__
#include "hi_upg_file.h"
#include <hi_types.h>

/**
 * @ingroup upg
 * Kernel upgrade file. CNcomment:Kernel�����ļ���CNend
 */
#define HI_UPG_FILE_KERNEL    0xF0

/**
 * @ingroup upg
 * FlashBoot upgrade file. CNcomment:FlashBoot�����ļ���CNend
 */
#define HI_UPG_FILE_BOOT       0xE1

/**
 * @ingroup upg
 * Kernel upgrade file of area A. CNcomment:A�������ļ���CNend
 */
#define HI_UPG_FILE_FOR_AREA_A        1

/**
 * @ingroup upg
 * Kernel upgrade file of area B/Compress kernel upgrade file. CNcomment:B�������ļ�/ѹ�������ļ���CNend
 */
#define HI_UPG_FILE_FOR_AREA_B        2

/**
* @ingroup upg
* @brief  Upgrade module initialization.CNcomment:����ģ���ʼ����CNend
*
* @par   ����:
            Upgrade module initialization.CNcomment:����ģ���ʼ����CNend
* @attention
* @li Must be called immediately after NV initialization. CNcomment:�������NV��ʼ������á�CNend
* @li This interface does not support multiple calls. CNcomment:�ýӿڲ�֧�ֶ�ε��á�CNend
* @param  None.
* @retval #HI_ERR_SUCCESS Success.CNcomment:����ģ���ʼ���ɹ���CNend
* @retval #Other Failure.CNcomment:����ֵ ����ģ���ʼ��ʧ�ܡ�CNend
* @par ����:
*            @li hi_upg_api.h��Describe Upgrade usage APIs.CNcomment:�ļ�����������������ӿڡ�CNend
* @see None.CNcomment:�ޡ�CNend
* @since Hi3861_V100R001C00
*/
hi_u32 hi_upg_init(hi_void);

/**
* @ingroup upg
* @brief  Get upgrade file from the backup flash.CNcomment:�ӱ�������ȡ�����ļ���CNend
*
* @par   ����:
            Used to get upgrade data from the backup flash.CNcomment:�ú����ӱ������������ļ���CNend
* @attention
* @li Ensure that the actual buffer size is the same as the value of buf_len.
*   CNcomment:�û��豣֤bufʵ�ʴ�С��buf_len��ȡ�CNend
* @li Must be called after calling interface hi_upg_transmit.CNcomment:�����ڵ��������ļ�����ӿ�֮����á�CNend
* @li Must be called before calling interface hi_upg_transmit_finish.CNcomment:�����ڵ��������ļ��������֮ǰ���á�CNend
* @param  offset  [IN] type #hi_u32 Offset relative to the start address of the upgrade cache.
*   CNcomment:���������������ʼ��ַ��ƫ�Ƶ�ַ��CNend
* @param  buf     [IN/OUT] type #hi_u8* Pointer to the upgrade data package.CNcomment:�������ݰ�ָ�롣CNend
* @param  buf_len [IN] type #hi_u32 Length of the upgrade data package.Unit: byte.
*   CNcomment:�������ݰ����ȣ���λ��byte��CNend
* @retval #HI_ERR_SUCCESS Success.CNcomment:���ɹ���CNend
* @retval #Other Failure.CNcomment:����ֵ ��ʧ�ܡ�CNend
* @par ����:
*            @li hi_upg_api.h��Describe Upgrade usage APIs.CNcomment:�ļ�����������������ӿڡ�CNend
* @see None.CNcomment:�ޡ�CNend
* @since Hi3861_V100R001C00
*/
hi_u32 hi_upg_get_content(hi_u32 offset, hi_u8* buf, hi_u32 buf_len);

/**
* @ingroup upg
* @brief  Transmit upgrade file.CNcomment:���������ļ���CNend
*
* @par   ����:
            Transmit upgrade file.CNcomment:���������ļ���CNend
* @attention
* @li The first packet transmitted is not less than 96 bytes.CNcomment:����ĵ�1����С��96�ֽڡ�CNend
* @param  offset  [IN] type #hi_u32 Offset relative to the head of the upgrade file.CNcomment:��������ļ�ͷ��ƫ�Ƶ�ַ��CNend
* @param  buf     [IN] type #hi_u8* Upgrade file data.CNcomment:�������ݰ���CNend
* @param  buf_len [IN] type #hi_u32 Length of the upgrade file data.Unit:byte.CNcomment:�������ݰ����ȣ���λ��byte��CNend
* @retval #HI_ERR_SUCCESS Success.CNcomment:�ɹ���CNend
* @retval #Other Failure.CNcomment:����ֵ ʧ�ܡ�CNend
* @par ����:
*            @li hi_upg_api.h��Describe Upgrade usage APIs.CNcomment:�ļ�����������������ӿڡ�CNend
* @see None.CNcomment:�ޡ�CNend
* @since Hi3861_V100R001C00
*/
hi_u32 hi_upg_transmit(hi_u32 offset, hi_u8* buf, hi_u32 buf_len);

/**
* @ingroup upg
* @brief  Upgrade restart.CNcomment:����������CNend
*
* @par   ����:
            This interface is used to restart.CNcomment:�ýӿ�ʵ������������CNend
* @attention None.
* @param  None.
* @retval None.
* @par ����:
*            @li hi_upg_api.h��Describe Upgrade usage APIs.CNcomment:�ļ�����������������ӿڡ�CNend
* @see None.CNcomment:�ޡ�CNend
* @since Hi3861_V100R001C00
*/
hi_void hi_upg_finish(hi_void);

/**
* @ingroup upg
* @brief  Notify file transfer end.CNcomment:�ļ����������CNend
*
* @par   ����:
            Used to notify file transfer end.CNcomment:�ļ����������CNend
* @attention None.
* @param  None.
* @retval #HI_ERR_SUCCESS Success.CNcomment:�ɹ���CNend
* @retval #Other Failure.CNcomment:����ֵ ʧ�ܡ�CNend
* @par ����:
*            @li hi_upg_api.h��Describe Upgrade usage APIs.CNcomment:�ļ�����������������ӿڡ�CNend
* @see None.CNcomment:�ޡ�CNend
* @since Hi3861_V100R001C00
*/
hi_u32 hi_upg_transmit_finish(hi_void);

/**
* @ingroup upg
* @brief  Get the maximum upgrade file length.CNcomment:��ȡ��������ļ����ȡ�CNend
*
* @par   ����:
            Used to get the maximum upgrade file length.CNcomment:��ȡ��������ļ����ȡ�CNend
* @attention None.
* @param  file_type [IN] type #hi_u8 Upgrade file type.CNcomment:�����ļ����͡�CNend
* @param  file_len  [IN/OUT] type #hi_u32* Max file length.CNcomment:��������ļ���С��CNend
* @retval #HI_ERR_SUCCESS Success.CNcomment:�ɹ���CNend
* @retval #Other Failure.CNcomment:����ֵ ʧ�ܡ�CNend
* @par ����:
*            @li hi_upg_api.h��Describe Upgrade usage APIs.CNcomment:�ļ�����������������ӿڡ�CNend
* @see None.CNcomment:�ޡ�CNend
* @since Hi3861_V100R001C00
*/
hi_u32 hi_upg_get_max_file_len(hi_u8 file_type, hi_u32 *file_len);

/**
* @ingroup upg
* @brief  Get the upgrade file index.CNcomment:��ȡ�����ļ���š�CNend
*
* @par   ����:
            Get the upgrade file index.CNcomment:��ȡ�����ļ���š�CNend
* @attention None.CNcomment:�ޡ�CNend
* @param  index [IN/OUT] type #hi_u8* Upgrade file index.CNcomment:�����ļ���š�CNend
* @retval #1 Upg file for area A.CNcomment:1 A�������ļ���CNend
* @retval #2 Upg file for area B.CNcomment:2 B�������ļ���CNend
* @par ����:
*            @li hi_upg_api.h��Describe Upgrade usage APIs.CNcomment:�ļ�����������������ӿڡ�CNend
* @see None.CNcomment:�ޡ�CNend
* @since Hi3861_V100R001C00
*/
hi_u32 hi_upg_get_file_index(hi_u8 *index);

/**
* @ingroup upg
* @brief  Stop the upgrade process.CNcomment:ֹͣ������CNend
*
* @par   ����:
            Used to stop the upgrade process.CNcomment:ֹͣ������CNend
* @attention None.
* @param  None.
* @retval #HI_ERR_SUCCESS Success.CNcomment:�ɹ���CNend
* @retval #Other Failure.CNcomment:����ֵ ʧ�ܡ�CNend
* @par ����:
*            @li hi_upg_api.h��Describe Upgrade usage APIs.CNcomment:�ļ�����������������ӿڡ�CNend
* @see None.CNcomment:�ޡ�CNend
* @since Hi3861_V100R001C00
*/
hi_u32 hi_upg_stop(hi_void);

/**
* @ingroup upg
* @brief  Register upgrade file validity check interface.CNcomment:ע�������ļ��Ϸ���У��ӿڡ�CNend
*
* @par   ����:
            Register upgrade file validity check interface.CNcomment:ע�������ļ��Ϸ���У��ӿڡ�CNend
* @attention Called during the initialization process.CNcomment:��ʼ�������е��á�CNend
* @param  upg_file_check_fn [IN]User-defined upgrade file verification interface.CNcomment:�û��Զ���ӿڡ�CNend
* @param  param [IN]Passed back to callback function when callback.CNcomment:�û��Զ���ӿڲ�����CNend
* @retval #HI_ERR_SUCCESS Success.CNcomment:�ɹ���CNend
* @retval #Other Failure.CNcomment:����ֵ ʧ�ܡ�CNend
* @par ����:
*            @li hi_upg_api.h��Describe Upgrade usage APIs.CNcomment:�ļ�����������������ӿڡ�CNend
* @see None.CNcomment:�ޡ�CNend
* @since Hi3861_V100R001C00
*/
hi_u32 hi_upg_register_file_verify_fn(
    hi_u32 (*upg_file_check_fn)(const hi_upg_user_info *info, hi_void *param),
    hi_void *param);

#endif


