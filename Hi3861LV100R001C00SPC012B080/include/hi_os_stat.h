/**
* @file hi_os_stat.h
*
* Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2019. All rights reserved.  \n
* Description: OS status APIs.   \n
* Author: Hisilicon   \n
* Create: 2019-12-18
*/

/**
 * @defgroup os_stat OS Status
 * @ingroup osa
 */

#ifndef __HI_OS_STAT_H__
#define __HI_OS_STAT_H__

#include <hi_types_base.h>

#define HI_OS_STAT_MSG_WAIT_FAIL     0x1   /**< Used in the interrupt context.CNcomment:�ж�������ʹ��CNend */
#define HI_OS_STAT_MSG_SEND_FAIL     0x2   /**< The timeout period of the interrupt context configuration is not 0,
                                              and the queue is full.CNcomment:�ж����������ó�ʱʱ�䲻Ϊ0��
                                              ������ CNend */
#define HI_OS_STAT_SEM_WAIT_FAIL     0x4   /**< Used in the interrupt context.CNcomment:�ж�������ʹ��CNend */
#define HI_OS_STAT_SEM_SIGNAL_FAIL   0x8   /**< Repeated release.CNcomment:�ظ��ͷ�CNend */
#define HI_OS_STAT_MUX_PEND_FAIL     0x10  /**< Used in the interrupt context.CNcomment:�ж�������ʹ��CNend  */
#define HI_OS_STAT_MUX_POST_FAIL     0x20  /**< Cross-task use, not created.CNcomment:������ʹ�ã�δ����CNend  */
#define HI_OS_STAT_EVENT_WAIT_FAIL   0x40  /**< Used in the interrupt context.CNcomment:�ж�������ʹ�� CNend */
#define HI_OS_STAT_EVENT_SEND_FAIL   0x80  /**< Initialized EVT resources used up.
                                              CNcomment:��ʼ��EVT��Դ�Ѿ����� CNend */
#define HI_OS_STAT_EVENT_CLR_FAIL    0x100 /**< Invalid input argument.CNcomment:��δ��� CNend */
#define HI_OS_STAT_SLEEP_FAIL        0x200 /**< Used in the interrupt context.CNcomment:�ж�������ʹ��CNend  */
#define HI_OS_STAT_START_TIMER_FAIL  0x400 /**< Invalid input argument.CNcomment:��δ��� CNend */
#define HI_OS_STAT_CREATE_TIMER_FAIL 0x800 /**< WorkQueue used up.CNcomment:������ʱ�����ʧ�� CNend */

/**
 * @ingroup os_stat
 * System resource usage statistic.CNcomment:ϵͳ��Դʹ��ͳ������CNend
 */
typedef struct {
    hi_u8 timer_usage;  /**< Number of used system timers.CNcomment:��ǰʹ��ϵͳ��ʱ������ CNend */
    hi_u8 task_usage;   /**< Number of used tasks.CNcomment:��ǰʹ��������� CNend */
    hi_u8 sem_usage;    /**< Number of used semaphores.CNcomment:��ǰʹ���ź������� CNend */
    hi_u8 queue_usage;  /**< Number of used message queues.CNcomment:��ǰʹ����Ϣ���и��� CNend */
    hi_u8 mux_usage;    /**< Number of used mutexes.CNcomment:��ǰʹ�û��������� CNend */
    hi_u8 event_usage;  /**< Number of used events.CNcomment:��ǰʹ���¼����� CNend */
    hi_u16 err_info;    /**< Error statistic HI_OS_STAT_XXX, used to log occurred errors.
                           CNcomment:����ͳ����HI_OS_STAT_XXX�����ڼ�¼�������ֹ��Ĵ��� CNend */
}hi_os_resource_use_stat;

/**
* @ingroup  os_stat
* @brief  Obtains the system resource usage.CNcomment:��ȡ��ǰϵͳ��Դʹ�������CNend
*
* @par ����:
*           Obtains the system resource usage.CNcomment:��ȡ��ǰϵͳ��Դʹ�������CNend
*
* @attention None
* @param  os_resource_stat [OUT] type #hi_os_resource_use_stat*��System resource usage statistic.
CNcomment:ϵͳ��Դʹ��ͳ������CNend
*
* @retval #0               Success.
* @retval #Other           Failure. For details, see hi_errno.h
* @par ����:
*            @li hi_os_stat.h��Describes system resource usage APIs.
CNcomment:�ļ�����������ʱ����ؽӿڡ�CNend
* @see  None
* @since Hi3861_V100R001C00
*/
hi_u32 hi_os_get_resource_status(hi_os_resource_use_stat *os_resource_stat);

#endif

