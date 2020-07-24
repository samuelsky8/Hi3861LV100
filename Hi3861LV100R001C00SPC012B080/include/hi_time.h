/**
* @file hi_time.h
*
* Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2019. All rights reserved.  \n
* Description: time APIs.CNcomment:ʱ��ӿ�����CNend
* @li System time of the hi_get_tick, hi_get_tick64, hi_get_milli_seconds, and hi_get_seconds operations. The system
*     time is calculated starting from kernel startup and cannot be modified through APIs.
CNcomment:hi_get_tick, hi_get_tick64,hi_get_milli_seconds, hi_get_seconds������ϵͳʱ�䣬
ϵͳʱ���kernel������ʼ��ʱ��������ͨ���ӿڽ����޸ġ�CNend
* @li The hi_get_real_time and hi_set_real_time APIs are about real-time operations. The real time is calculated
*     starting from kernel startup and can be modified by hi_set_real_time.CNcomment:hi_get_real_time��
hi_set_real_time��������ʵʱʱ�䣬ʵʱʱ���kernel������ʼ��ʱ������ͨ��hi_set_real_time�����޸ġ�CNend   \n
* Author: Hisilicon   \n
* Create: 2019-05-29
*/

/**
 * @defgroup iot_time System Clock
 * @ingroup osa
 */
#ifndef __HI_TIME_H__
#define __HI_TIME_H__
#include <hi_types_base.h>

/**
* @ingroup  iot_time
* @brief  Delay, in microseconds.CNcomment:��ʱ��΢�뼶��CNend
*
* @par ����:
*           Delay operation implemented by software based on the system clock, blocking the CPU.
CNcomment:��ʱ����������CPU��CNend
*
* @attention This API cannot be used for a long time in an interrupt.CNcomment:�������ж���ʹ�á�CNend
*
* @param  us                [IN] type #hi_u32��delay period (unit: microsecond).
CNcomment:��ʱʱ�䣨��λ����s����CNend
*
* @retval  None
* @par ����:
*            @li hi_time.h��Describes system time APIs.CNcomment:�ļ�����ϵͳʱ����ؽӿڡ�CNend
* @see  None
* @since Hi3861_V100R001C00
*/
hi_void hi_udelay(hi_u32 us);

/**
* @ingroup  iot_time
* @brief  Obtains the tick value of the system (32-bit).CNcomment:��ȡϵͳtickֵ��32bit����CNend
*
* @par ����:
*           Obtains the tick value of the system (32-bit).CNcomment:��ȡϵͳtickֵ��32bit����CNend
*
* @attention None
* @param None
*
* @retval #hi_u32 Tick value of the system.CNcomment:ϵͳtickֵ��CNend
* @par ����:
*            @li hi_time.h��Describes system time APIs.CNcomment:�ļ�����ϵͳʱ����ؽӿڡ�CNend
* @since Hi3861_V100R001C00
*/
hi_u32 hi_get_tick(hi_void);

/**
* @ingroup  iot_time
* @brief  Obtains the tick value of the system (64-bit).CNcomment:��ȡϵͳtickֵ��64bit����CNend
*
* @par ����:
*           Obtains the tick value of the system (64-bit).CNcomment:��ȡϵͳtickֵ��64bit����CNend
*
* @attention The hi_mdm_time.h file must be included where the API is called. Otherwise, the API is considered not
*            declared, and the tick value is returned as an int type, resulting in a truncation error.
CNcomment:�ýӿڵ��ô��������ͷ�ļ�hi_time.h��������δ�����ӿڴ����Ὣtickֵ����int���ͷ��أ������ضϴ���CNend
* @param None
*
* @retval  #hi_u64 Tick value of the system.CNcomment:ϵͳtickֵ��CNend
* @par ����:
*            @li hi_time.h��Describes system time APIs.CNcomment:�ļ�����ϵͳʱ����ؽӿڡ�CNend
* @since Hi3861_V100R001C00
*/
hi_u64 hi_get_tick64(hi_void);

/**
* @ingroup  iot_time
* @brief  Obtains the system time (unit: ms).CNcomment:��ȡϵͳʱ�䣨��λ��ms����CNend
*
* @par ����:
*           Obtains the system time (unit: ms).CNcomment:��ȡϵͳʱ�䣨��λ��ms����CNend
*
* @attention None
* @param None
*
* @retval #hi_u32 System time.CNcomment:ϵͳʱ�䡣CNend
* @par ����:
*            @li hi_time.h��Describes system time APIs.CNcomment:�ļ�����ϵͳʱ����ؽӿڡ�CNend
* @since Hi3861_V100R001C00
*/
hi_u32 hi_get_milli_seconds(hi_void);

/**
* @ingroup  iot_time
* @brief  Obtains the system time (unit: s).CNcomment:��ȡϵͳʱ�䣨��λ��s����CNend
*
* @par ����:
*           Obtains the system time (unit: s).CNcomment:��ȡϵͳʱ�䣨��λ��s����CNend
*
* @attention None
* @param None
*
* @retval #hi_u32 System time.CNcomment:ϵͳʱ�䡣CNend
* @retval #HI_ERR_FAILURE failed to be obtained. CNcomment:��ȡʱ��ʧ�ܡ�CNend
* @par ����:
*            @li hi_time.h��Describes system time APIs.CNcomment:�ļ�����ϵͳʱ����ؽӿڡ�CNend
* @since Hi3861_V100R001C00
*/
hi_u32 hi_get_seconds(hi_void);

/**
* @ingroup  iot_time
* @brief  Obtains the system time (unit: us).CNcomment:��ȡϵͳʱ�䣨��λ��us����CNend
*
* @par ����:
*           Obtains the system time (unit: us).CNcomment:��ȡϵͳʱ�䣨��λ��us����CNend
*
* @attention None
* @param None
*
* @retval #hi_u64 System time.CNcomment:ϵͳʱ�䡣CNend
* @retval #HI_ERR_FAILURE failed to be obtained. CNcomment:��ȡʱ��ʧ�ܡ�CNend
* @par ����:
*            @li hi_time.h��Describes system time APIs.CNcomment:�ļ�����ϵͳʱ����ؽӿڡ�CNend
* @since Hi3861_V100R001C00
*/
hi_u64 hi_get_us(hi_void);

/**
* @ingroup  iot_time
* @brief  Obtains the real time of the system (unit: s).CNcomment:��ȡϵͳʵʱʱ�䣨��λ��s����CNend
*
* @par ����:
*           Obtains the real time of the system (unit: s).CNcomment:��ȡϵͳʵʱʱ�䣨��λ��s����CNend
*
* @attention None
* @param None
*
* @retval #hi_u32 Real time of the system.CNcomment: ϵͳʵʱʱ�䡣CNend
* @retval #HI_ERR_FAILURE failed to be obtained. CNcomment:��ȡʱ��ʧ�ܡ�CNend
* @par ����:
*            @li hi_time.h��Describes system time APIs.CNcomment:�ļ�����ϵͳʱ����ؽӿڡ�CNend
* @since Hi3861_V100R001C00
*/
hi_u32 hi_get_real_time(hi_void);

/**
* @ingroup  iot_time
* @brief  Sets the real time of the system.CNcomment:����ϵͳʵʱʱ�䡣CNend
*
* @par ����:
*           Sets the real time of the system.CNcomment:����ϵͳʵʱʱ�䡣CNend
*
* @attention None
* @param  seconds            [IN] type #hi_u32��set the real time of the system to this value.
CNcomment:��ϵͳʵʱʱ������Ϊ��ֵ��CNend
*
* @retval #HI_ERR_SUCCESS    Success.
* @retval #HI_ERR_FAILURE    Failure.
* @par ����:
*            @li hi_time.h��Describes system time APIs.CNcomment:�ļ�����ϵͳʱ����ؽӿڡ�CNend
* @since Hi3861_V100R001C00
*/
hi_u32 hi_set_real_time(hi_u32 seconds);

extern hi_void_callback g_tick_callback;

/**
* @ingroup  iot_task
* @brief Regiseter system tick callback.CNcomment:ע��tick �ж���Ӧ�ص�������CNend
*
* @par ����:
*          Regiseter system tick callback, if callback is NULL, means cancel registration.
CNcomment:ע��tick�жϻص�����������ص�����Ϊ�գ���ʾȡ��ע�ᡣCNend
*
* @attention
*           @li cb should not excute in FLASH, must excute in RAM or ROM. u can specify BSP_RAM_TEXT_SECTION before func
to set func excute in RAM.
CNcomment:�ص�����������FLASH�����У����������RAM��ROM�У�����ͨ����
������ǰ���BSP_RAM_TEXT_SECTION ��ͷָ��������RAM�����С�CNend
* @param  cb      [IN] type #hi_void_callback, callback in tick interrupt.CNcomment:tick�жϵĻص�������CNend
*
* @retval #None
* @par ����:
*            @li hi_time.h��Describes system time APIs.CNcomment:�ļ�����ϵͳʱ����ؽӿڡ�CNend
* @since Hi3861_V100R001C00
*/
hi_void hi_tick_register_callback(hi_void_callback cb);

#endif

