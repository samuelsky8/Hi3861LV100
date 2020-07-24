/**
* @file hi_timer.h
*
* Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2019. All rights reserved.  \n
* Description: timer APIs.   \n
* Author: Hisilicon   \n
* Create: 2019-05-29
*/

/**
 * @defgroup iot_systimer System Timer
 * @ingroup osa
 */
#ifndef __INTERFACE_ROM_HI_TIMER_H__
#define __INTERFACE_ROM_HI_TIMER_H__
#include <hi_types_base.h>


/**
 * @ingroup iot_systimer
 *
 * Specifies the type of the timer to be created.CNcomment:���������������Ķ�ʱ�����͡�CNend
 */
typedef enum {
    HI_TIMER_TYPE_ONCE,     /**< Single-period timer.CNcomment:��ʾ���ζ�ʱ�� CNend */
    HI_TIMER_TYPE_PERIOD,   /**< Periodic timer.CNcomment:��ʾ���ڶ�ʱ�� CNend */
    HI_TIMER_TYPE_MAX       /**< Maximum value, which cannot be used.CNcomment:���ֵ������ʹ�� CNend */
} hi_timer_type;

/**
* @ingroup  iot_systimer
* @brief  Defines the type of the timer callback function.CNcomment:���嶨ʱ���ص����������͡�CNend
*
* @par ������
*           Defines the type of the timer callback function.CNcomment:���嶨ʱ���ص����������͡�CNend
*
* @attention None
* @param  data [IN] type #hi_u32��callback input parameter.CNcomment:�ص���Ρ�CNend
*
* @retval None
* @par ����:
*            @li hi_timer.h��Describes the timer APIs.CNcomment:�ļ�����������ʱ����ؽӿڡ�CNend
* @see hi_timer_start | hi_timer_stop
* @since Hi3861_V100R001C00
*/
typedef hi_void (*hi_timer_callback_f)(hi_u32 data);

/**
* @ingroup  iot_systimer
* @brief  Creates the system timer.CNcomment:��ȡ��ʱ�������CNend
*
* @par ����:
*           Creates the system timer.CNcomment:��ȡ�߾���ʱ�������CNend
*
* @attention None
* @param  timer_handle [OUT] type #hi_u32*��handle.CNcomment:��ȡ���ľ����CNend
*
* @retval #0           Success.
* @retval #Other       Failure. For details, see hi_errno.h.
*
* @par ����:
*          @li hi_timer.h��Describes the timer APIs.CNcomment:�ļ�����������ʱ����ؽӿڡ�CNend
* @see  hi_timer_delete��
* @since Hi3861_V100R001C00
*/
hi_u32 hi_timer_create(hi_u32 *timer_handle);

/**
* @ingroup  iot_systimer
* @brief  Starts the system timer.CNcomment:����ϵͳ��ʱ����CNend
*
* @par ����:
*            This API is used in the following scenarios:CNcomment:��API�ӿ�ʹ�÷�Ϊ���¼���������CNend
*            @li If no timer is created, create and start a timer.
CNcomment:���δ������ʱ������ֱ��������CNend
*            @li If the timer expires and is called again, start the timer directly.
CNcomment:����ö�ʱ�����ں���ã���ֱ��������ʱ����CNend
*            @li If the timer does not expire, stop and restart the timer.
CNcomment:�����ʱ��û�е��ڣ���ֹͣ�ö�ʱ��������������ʱ����CNend
*
* @attention This timer callback function is executed in the interrupt context. Therefore, the callback function should
*            be as simple as possible and the functions such as sleep and wait semaphores that trigger scheduling
*            cannot be used.CNcomment:����ʱ���ص�����ִ�����ж������ģ��ص����������򵥣�����ʹ��˯�ߡ�
�ȴ��ź�����������ȵĺ�����CNend
*
* @param  timer_handle  [OUT]  type #hi_u32*��handle.CNcomment:�����CNend
* @param  type          [IN]   type #hi_timer_type��timer type.CNcomment:��ʱ�����͡�CNend
* @param  expire        [IN]   type #hi_u32��timeout period of the timer (unit: ms). If this parameter is set to 0,
*                       the default value is 10 ms.CNcomment:��ʱ����ʱʱ�䣨��λ��ms��������Ϊ0ʱ��Ĭ��Ϊ10ms��CNend
* @param  timer_func    [IN]   type #timer_proc_func��timer callback function.CNcomment:��ʱ���ص�������CNend
* @param  data          [IN]   type #hi_u32��callback input parameter.CNcomment:�ص��������Ρ�CNend
*
* @retval #0           Success.
* @retval #Other       Failure. For details, see hi_errno.h.
*
* @par ����:
*          @li hi_timer.h��Describes the timer APIs.CNcomment:�ļ�����������ʱ����ؽӿڡ�CNend
* @see hi_timer_stop
* @since Hi3861_V100R001C00
*/
hi_u32 hi_timer_start(hi_u32 timer_handle, hi_timer_type type, hi_u32 expire,
                      hi_timer_callback_f timer_func, hi_u32 data);

/**
* @ingroup  iot_systimer
* @brief  Stops the system timer.CNcomment:ֹͣϵͳ��ʱ����CNend
*
* @par ����:
*          Stops the system timer.CNcomment:ֹͣϵͳ��ʱ����CNend
*
* @attention This API only stops the timer and does not delete the timer.CNcomment:���ӿڽ�ֹͣ��ʱ����
����ɾ���ö�ʱ����CNend
* @param  timer_handle [IN] type #hi_u32��handle.CNcomment:�����CNend
*
* @retval #0           Success.
* @retval #Other       Failure. For details, see hi_errno.h.
*
* @par ����:
*          @li hi_timer.h��Describes the timer APIs.CNcomment:�ļ�����������ʱ����ؽӿڡ�CNend
* @see hi_timer_start | hi_timer_delete
* @since Hi3861_V100R001C00
*/
hi_u32 hi_timer_stop(hi_u32 timer_handle);

/**
* @ingroup  iot_systimer
* @brief  Deletes the timer.CNcomment:ɾ����ʱ����CNend
*
* @par ����:
*           Deletes the timer.CNcomment:ɾ����ʱ����CNend
*
* @attention
*            @li If the timer does not expire, stop the timer before deleting it.
CNcomment:�����ʱ��δ���ڣ�����ֹͣ�ö�ʱ����ɾ����CNend
*
* @param  timer_handle [IN] type #hi_u32��handle.CNcomment:�����CNend
*
* @retval #0           Success.
* @retval #Other       Failure. For details, see hi_errno.h.
*
* @par ����:
*          @li hi_timer.h��Describes the timer APIs.CNcomment:�ļ�����������ʱ����ؽӿڡ�CNend
* @see hi_timer_start | hi_timer_stop
* @since Hi3861_V100R001C00
*/
hi_u32 hi_timer_delete(hi_u32 timer_handle);

#endif

