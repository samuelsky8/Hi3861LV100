/**
* @file hi_hrtimer.h
*
* Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2019. All rights reserved.  \n
* Description: 1��In scenarios where the precision is not high, do not use hrtimer. Instead, use a system timer,
*                 because each hrtimer startup, stop, and expiration may increase the error of other high-precision
*                 timers in the queue. CNcomment:�ھ���Ҫ�󲻸ߵĳ����£������ܲ�Ҫʹ��hrtimer��
*                 Ӧʹ��ϵͳ��ʱ���������Ϊÿ��hrtimer��������ֹͣ�����ڶ����ܻ����Ӷ���������
*                 �߾��ȶ�ʱ������CNend
*              2��The callback function of hrtimer is executed in the interrupt context, so you need to comply with
*                 the programming precautions for the interrupt context.CNcomment:hrtimer�Ļص�����ִ�����ж������ģ�
*                 �����Ҫ�����ж������ĵı��ע�����CNend   \n
* Author: Hisilicon   \n
* Create: 2019-07-03
*/

/**
 * @defgroup hrtimer High Resolution Timer
 * @ingroup drivers
 */
#ifndef __HI_HRTIMER_H__
#define __HI_HRTIMER_H__
#include <hi_types_base.h>

/**
* @ingroup  hrtimer
* @brief  High resolution timer callback function.CNcomment:�߾��ȶ�ʱ���ص�������CNend
*
* @par ����:
*           High resolution timer callback function. When a high resolution timer expires, the high resolution timer
*           module calls this function to notify the user.CNcomment:�߾��ȶ�ʱ���ص����������߾��ȶ�ʱ������ʱ��
*           �߾��ȶ�ʱ��ģ����øú���֪ͨʹ���ߡ�CNend
*
* @attention None
* @param  data [IN] type #hi_u32��Callback function parameter input when the user starts the timer.
CNcomment:�û�������ʱ��ʱ����Ļص�����������CNend
*
* @retval None
* @par ����:
*           @li hi_hrtimer.h��Describes timer APIs.CNcomment:�ļ�����������ʱ����ؽӿڡ�CNend
* @see  None
* @since Hi3861_V100R001C00
*/
typedef hi_void(*hi_hrtimer_callback_f) (hi_u32 data);

/**
* @ingroup  hrtimer
* @brief  Obtains the high resolution timer module handler.CNcomment:��ȡ�߾���ʱ�������CNend
*
* @par ����:
*           Obtains the high resolution timer module handler.CNcomment:��ȡ�߾���ʱ�������CNend
*
* @attention None
* @param  timer_handle [OUT] type #hi_u32*��handler obtained. CNcomment:��ȡ���ľ����CNend
*
* @retval #0           Success.
* @retval #Other       Failure. For details, see hi_errno.h
*
* @par ����:
*           @li hi_hrtimer.h��Describes timer APIs.CNcomment:�ļ�����������ʱ����ؽӿڡ�CNend
*
* @see  hi_hrtimer_delete��
* @since Hi3861_V100R001C00
*/
hi_u32 hi_hrtimer_create(hi_u32 *timer_handle);

/**
* @ingroup  hrtimer
* @brief  Delete the high resolution timer module handle.CNcomment:ɾ���߾���ʱ�������CNend
*
* @par ����:
*           Delete the high resolution timer module handle.CNcomment:ɾ���߾���ʱ�������CNend
*
* @attention None
* @param  timer_handle [IN] type #hi_u32��Timer handle, which would be released.
CNcomment:Ҫ�ͷŵĶ�ʱ�������CNend
*
* @retval #0           Success.
* @retval #Other       Failure. For details, see hi_errno.h
*
* @par ����:
*           @li hi_hrtimer.h��Describes timer APIs.CNcomment:�ļ�����������ʱ����ؽӿڡ�CNend
*
* @see  hi_hrtimer_create��
* @since Hi3861_V100R001C00
*/
hi_u32 hi_hrtimer_delete(hi_u32 timer_handle);
/**
* @ingroup  hrtimer
* @brief  Starts a high resolution timer.CNcomment:�����߾��ȶ�ʱ����CNend
*
* @par ����:
*           Starts the high resolution timer. If the timer has been started, the current timer is stopped and
*           restarted when this API is called.CNcomment:���øýӿ������߾��ȶ�ʱ���������ʱ���Ѿ�������
���øýӿ�ʱ��ֹͣ��ǰ��ʱ������������CNend
*
* @attention None
* @param  timer_handle [IN] type #hi_u32��Timer handle.CNcomment:��ʱ�������CNend
* @param  expire       [IN] type #hi_u32��Expiration time of the timer (unit: microsecond).When the clock is set to
24M,the maximum of the expiration time is 178s.When the clock is set to 40M,the maximum of the expiration time is 107s.
The expiration time of the timer must be set to a value smaller than the maximum.
CNcomment:��ʱ����ʱʱ�䣨��λ����s����24Mʱ�ӿ����õ����ʱʱ��Ϊ178s��40Mʱ�ӿ����õ����ʱʱ��Ϊ107s��
          ��ʱʱ���������ΪС�����ʱʱ���ֵ��CNend
* @param  hrtimer_func [IN] type #hi_hrtimer_callback_f��Callback function when the timer expires.
CNcomment:��ʱ�����ڻص�������CNend
* @param  data         [IN] type #hi_u32��Input parameter of the timer callback function.
CNcomment:��ʱ���ص���������Ρ�CNend
*
* @retval #0           Success.
* @retval #Other       Failure. For details, see hi_errno.h
*
* @par ����:
*           @li hi_hrtimer.h��Describes timer APIs.CNcomment:�ļ�����������ʱ����ؽӿڡ�CNend
* @see  hi_hrtimer_stop��
* @since Hi3861_V100R001C00
*/
hi_u32 hi_hrtimer_start(hi_u32 timer_handle, hi_u32 expire, hi_hrtimer_callback_f hrtimer_func, hi_u32 data);

/**
* @ingroup  hrtimer
* @brief  Stops a high resolution timer.CNcomment:ֹͣ�߾��ȶ�ʱ����CNend
*
* @par ����:
*           Stops a high resolution timer. If the timer is stopped when the API is called, no effect is achieved.
CNcomment:���øýӿ�ֹͣ�߾��ȶ�ʱ����������øýӿ�ʱ��ʱ���Ѿ�ֹͣ���������κ�Ч����CNend
*
* @attention None
* @param  timer_handle [IN] type #hi_u32��Timer handle.CNcomment:��ʱ��handle��CNend
*
* @retval #0           Success.
* @retval #Other       Failure. For details, see hi_errno.h
*
* @par ����:
*           @li hi_hrtimer.h��Describes timer APIs.CNcomment:�ļ�����������ʱ����ؽӿڡ�CNend
* @see  hi_hrtimer_start��
* @since Hi3861_V100R001C00
*/
hi_u32 hi_hrtimer_stop(hi_u32 timer_handle);

#endif
