/**
* @file hi_sem.h
*
* Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2019. All rights reserved.  \n
* Description: Semaphore APIs.CNcomment:�ӿڡ�CNend
*
* @li Wait semaphore. In the interrupt function, disable interrupt context, and lock task context, this API must not be
*     called. Otherwise, uncontrollable exception scheduling may result.CNcomment:�ȴ��ź���:���жϡ����жϡ�
�����������Ľ�ֹ���õȴ��ź����ӿڣ������������ɿص��쳣���ȡ�CNend
* @li Release semaphore.In the disable interrupt context, this API must not be called. Otherwise, uncontrollable
*     exception scheduling may result.CNcomment:�ͷ��ź���:�ڹ��ж������Ľ�ֹ�����ͷ��ź����ӿڣ�
�����������ɿص��쳣���ȡ�CNend   \n
* Author: Hisilicon   \n
* Create: 2019-05-29
*/

/**
 * @defgroup iot_sem Semaphore
 * @ingroup osa
 */
#ifndef __HI_SEM_H__
#define __HI_SEM_H__
#include <hi_types_base.h>

#define HI_SEM_ONE  ((hi_u8)1) /**< ucInit Obtained value of the input: Critical resource protection.
                                 CNcomment:�����ȡֵ: �ٽ���Դ���� CNend */
#define HI_SEM_ZERO ((hi_u8)0) /**< ucInit Obtained value of the input: Synchronization
                                 CNcomment:�����ȡֵ: ͬ�� CNend */

/**
* @ingroup  iot_sem
* @brief  Creates a semaphore.CNcomment:�����ź�����CNend
*
* @par ����:
*           Creates a semaphore.CNcomment:�����ź�����CNend
*
* @attention The blocking mode (permanent blocking or timing blocking) of the semaphore application operation cannot
*            be used in the interrupt, and the interrupt cannot be blocked.CNcomment:�ź����������������ģʽ
�����������Ͷ�ʱ�������������ж���ʹ�ã��жϲ��ܱ�������CNend
*
* @param  sem_id          [OUT] type #hi_u32*��semaphore ID.CNcomment:�ź���ID�š�CNend
* @param  init_value      [IN]  type #hi_u16��Number of initialized valid signals. The value range is [0, 0xFFFF].
CNcomment:��Ч�źŵĳ�ʼ����������ΧΪ:[0, 0xFFFF]CNend
*
* @retval #0      Success.
* @retval #Other  Failure, for details, see hi_errno.h
* @par ����:
*            @li hi_sem.h��Describes the semaphore APIs.CNcomment:�ļ����������ź�����ؽӿڡ�CNend
* @see  hi_sem_delete��
* @since Hi3861_V100R001C00
*/
hi_u32 hi_sem_create(hi_u32 *sem_id, hi_u16 init_value);


/**
* @ingroup  iot_sem
* @brief  Creates a two-value semaphore(0/1).CNcomment:������ֵ�ź�����0/1����CNend
*
* @par ����:
*           Creates a two-value semaphore(0/1).CNcomment:������ֵ�ź�����0/1����CNend
*
* @attention The blocking mode (permanent blocking or timing blocking) of the semaphore application operation cannot
*            be used in the interrupt, and the interrupt cannot be blocked.CNcomment:�ź����������������ģʽ
�����������Ͷ�ʱ�������������ж���ʹ�ã��жϲ��ܱ�������CNend
*
* @param  sem_id      [OUT] type #hi_u32*��semaphore ID.CNcomment:�ź���ID�š�CNend
* @param  init_value  [IN]  type #hi_u8��initial value. Generally, when the value is HI_SEM_ONE, the API is used for
*                     critical resource protection. When the value is HI_SEM_ZERO, the API is used for synchronization.
CNcomment:��ʼֵ��һ������£���ֵΪHI_SEM_ONEʱ�������ٽ���Դ��������ֵΪHI_SEM_ZEROʱ������ͬ����CNend
*
* @retval #0      Success.
* @retval #Other  Failure, for details, see hi_errno.h
* @par ����:
*            @li hi_sem.h��Describes the semaphore APIs.CNcomment:�ļ����������ź�����ؽӿڡ�CNend
* @see  hi_sem_delete��
* @since Hi3861_V100R001C00
*/
hi_u32 hi_sem_bcreate(hi_u32 *sem_id, hi_u8 init_value);

/**
* @ingroup  iot_sem
* @brief  Deletes the semaphore.CNcomment:ɾ���ź�����CNend
*
* @par ����:
*           Deletes the semaphore.CNcomment:ɾ���ź�����CNend
*
* @attention The blocking mode (permanent blocking or timing blocking) of the semaphore application operation cannot
*            be used in the interrupt, and the interrupt cannot be blocked.CNcomment:�ź����������������ģʽ
�����������Ͷ�ʱ�������������ж���ʹ�ã��жϲ��ܱ�������CNend
*
* @param  sem_id    [IN] type #hi_u32*��semaphore ID.CNcomment:�ź���ID�š�CNend
*
* @retval #0      Success.
* @retval #Other  Failure, for details, see hi_errno.h
* @par ����:
*            @li hi_sem.h��Describes the semaphore APIs.CNcomment:�ļ����������ź�����ؽӿڡ�CNend
* @see  hi_sem_bcreate��
* @since Hi3861_V100R001C00
*/
hi_u32 hi_sem_delete(hi_u32 sem_id);

/**
* @ingroup  iot_sem
* @brief  Obtains the semaphore.CNcomment:��ȡ�ź�����CNend
*
* @par ����:
*           Obtains the semaphore.CNcomment:��ȡ�ź�����CNend
*
*
* @attention The blocking mode (permanent blocking or timing blocking) of the semaphore application operation cannot
*            be used in the interrupt, and the interrupt cannot be blocked.CNcomment:�ź����������������ģʽ
�����������Ͷ�ʱ�������������ж���ʹ�ã��жϲ��ܱ�������CNend
*
* @param  sem_id     [IN] type #hi_u32*��semaphore ID.CNcomment:�ź���ID�š�CNend
* @param  timeout_ms [IN] type #hi_u32��timeout period (unit: ms). HI_SYS_WAIT_FOREVER indicates permanent wait.
CNcomment:��ʱʱ�䣨��λ��ms����HI_SYS_WAIT_FOREVERΪ���õȴ���CNend
*
* @retval #0      Success.
* @retval #Other  Failure, for details, see hi_errno.h
* @par ����:
*            @li hi_sem.h��Describes the semaphore APIs.CNcomment:�ļ����������ź�����ؽӿڡ�CNend
* @see  hi_sem_signal��
* @since Hi3861_V100R001C00
*/
hi_u32 hi_sem_wait(hi_u32 sem_id, hi_u32 timeout_ms);

/**
* @ingroup  iot_sem
* @brief  Releases the semaphore.CNcomment:�ͷ��ź�����CNend
*
* @par ����:
*           Releases the semaphore.CNcomment:�ͷ��ź�����CNend
*
* @attention The blocking mode (permanent blocking or timing blocking) of the semaphore application operation cannot
*            be used in the interrupt, and the interrupt cannot be blocked.CNcomment:�ź����������������ģʽ
�����������Ͷ�ʱ�������������ж���ʹ�ã��жϲ��ܱ�������CNend
*
* @param  sem_id    [IN] type #hi_u32*��semaphore ID.CNcomment:�ź���ID�š�CNend
*
* @retval #0      Success.
* @retval #Other  Failure, for details, see hi_errno.h
* @par ����:
*            @li hi_sem.h��Describes the semaphore APIs.CNcomment:�ļ����������ź�����ؽӿڡ�CNend
* @see  hi_sem_wait��
* @since Hi3861_V100R001C00
*/
hi_u32 hi_sem_signal(hi_u32 sem_id);

#endif

