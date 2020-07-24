/**
* @file hi_mux.h
*
* Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2019. All rights reserved.  \n
* Description: Mutex APIs.   \n
* Author: Hisilicon   \n
* Create: 2019-01-17
*/

/**
 * @defgroup iot_mux Mutex
 * @ingroup osa
 */

#ifndef __HI_MUX_H__
#define __HI_MUX_H__
#include <hi_types_base.h>

/**
* @ingroup  iot_mux
* @brief  Creates a mutex.CNcomment:������������CNend
*
* @par ����:
*           Creates a mutex.CNcomment:������������CNend
*
* @attention None
* @param  mux_id  [OUT] type #hi_u32*��Mutex handle.CNcomment:�����������CNend
*
* @retval #0      Success
* @retval #Other  Failure. For details, see hi_errno.h.
* @par ����:
*            @li hi_mux.h��Describes mutex APIs.CNcomment:�ļ�����������������ؽӿڡ�CNend
* @see  hi_mux_delete��
* @since Hi3861_V100R001C00
*/
hi_u32 hi_mux_create (hi_u32 *mux_id);

/**
* @ingroup  iot_mux
* @brief  Deletes a mutex.CNcomment:ɾ����������CNend
*
* @par ����:
*           Deletes a mutex.CNcomment:ɾ����������CNend
*
* @attention None
*
* @param  mux_id  [IN] type #hi_u32*��Mutex handle.CNcomment:�����������CNend
*
* @retval #0      Success
* @retval #Other  Failure. For details, see hi_errno.h.
* @par ����:
*            @li hi_mux.h��Describes mutex APIs.CNcomment:�ļ�����������������ؽӿڡ�CNend
* @see  hi_mux_create��
* @since Hi3861_V100R001C00
*/
hi_u32 hi_mux_delete(hi_u32 mux_id);

/**
* @ingroup  iot_mux
* @brief  Waits for a mutex.CNcomment:�ȴ���������CNend
*
* @par ����:
*           Waits for a mutex.CNcomment:�ȴ���������CNend
*
* @attention Mutexes support priority inversion.CNcomment:������֧�����ȼ���ת��CNend
* @param  mux_id     [IN] type #hi_u32*��Mutex handle.CNcomment:�����������CNend
* @param  timeout_ms [IN] type #hi_u32��Timeout period (unit: ms). HI_SYS_WAIT_FOREVER indicates permanent waiting.
CNcomment:��ʱʱ�䣨��λ��ms����HI_SYS_WAIT_FOREVERΪ���õȴ���CNend
*
* @retval #0      Success
* @retval #Other  Failure. For details, see hi_errno.h.
* @par ����:
*            @li hi_mux.h��Describes mutex APIs.CNcomment:�ļ�����������������ؽӿڡ�CNend
* @see  hi_mux_post��
* @since Hi3861_V100R001C00
*/
hi_u32 hi_mux_pend(hi_u32 mux_id, hi_u32 timeout_ms);

/**
* @ingroup  iot_mux
* @brief  Releases a mutex.CNcomment:�ͷŻ�������CNend
*
* @par ����:
*           Releases a mutex.CNcomment:�ͷŻ�������CNend
*
* @attention A mutex can be released only in the task that has obtained the mutex.
CNcomment:������ֻ���ڻ�ȡ�����������������ͷš�CNend
*
* @param  mux_id  [IN] type #hi_u32*��Mutex handle.CNcomment:�����������CNend
*
* @retval #0      Success
* @retval #Other  Failure. For details, see hi_errno.h.
* @par ����:
*            @li hi_mux.h��Describes mutex APIs.CNcomment:�ļ�����������������ؽӿڡ�CNend
* @see  hi_mux_pend��
* @since Hi3861_V100R001C00
*/
hi_u32 hi_mux_post(hi_u32 mux_id);

#endif

