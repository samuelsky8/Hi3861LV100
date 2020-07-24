/**
* @file hi_msg.h
*
*  Copyright (c) Hisilicon Technologies Co., Ltd. 2018-2019. All rights reserved.  \n
*
* Description: message APIs.CNcomment:��Ϣ�ӿڡ�CNend
* @li Wait message: the wait message API cannot be called, to avoid uncontrollable exception scheduling.
CNcomment:�ȴ���Ϣ:���жϡ����жϡ������������Ľ�ֹ���õȴ���Ϣ�ӿڣ������������ɿص��쳣���ȡ�CNend
* @li TX message: In the interrupt off context, the message TX API cannot be called, to avoid uncontrollable exception
*     scheduling.CNcomment:������Ϣ:�ڹ��ж������Ľ�ֹ���÷�����Ϣ�ӿڣ������������ɿص��쳣���ȡ�CNend
* @li TX message (the timeout period is not 0): In the interrupt and task locked context, the message TX API cannot be
*     called, to avoid uncontrollable exception scheduling.CNcomment:������Ϣ(��ʱʱ���0):���жϡ������������Ľ�ֹ����
��ʱʱ���0������Ϣ�ӿڣ������������ɿص��쳣���ȡ�CNend  \n
* Author: Hisilicon   \n
* Create: 2019-12-18
*/

/**
 * @defgroup iot_msgqueue Message Queue
 * @ingroup osa
 */
#ifndef __HI_MSG_H__
#define __HI_MSG_H__
#include <hi_types_base.h>

/**
 * @ingroup iot_msgqueue
 *
 * Failed to read the message queue.CNcomment:��ȡ��Ϣ���г���CNend
 */
#define HI_MSG_INVALID_MSG_NUM 0xFFFFFFFF
#define HI_SYS_MSG_PARAM_NUM_MAX 4

typedef struct {
    hi_u32 msg_id; /* < Message ID.CNcomment:��ϢID CNend */
    uintptr_t param[HI_SYS_MSG_PARAM_NUM_MAX]; /* < Message parameter.CNcomment:��Ϣ���� CNend */
} hi_sys_queue_msg;

/**
* @ingroup  iot_msgqueue
* @brief   Creates a message queue.CNcomment:������Ϣ���С�CNend
*
* @par ����:
*           Creates a message queue.CNcomment:������Ϣ���С�CNend
*
* @attention The number of message queues supported by the system needs to be set during initialization.
CNcomment:ϵͳ֧�ֵ�����Ϣ���и�������Ҫ�ڳ�ʼ���׶����á�CNend
*
* @param  id           [OUT] type  #hi_u32*��Handle of the created message queue.
CNcomment:����������Ϣ���о����CNend
* @param  queue_len    [IN]  type  #hi_u16��Message queue length, that is, the number of messages that can be stored
*                      in the message queue.CNcomment:��Ϣ���г��ȣ�������Ϣ����֧�ִ洢��������Ϣ��CNend
* @param  msg_size     [IN]  type  #hi_u32��Size of each message in the message queue (unit: byte)
CNcomment:��Ϣ������һ����Ϣ��С����λ��byte����CNend
*
* @retval #HI_ERR_SUCCESS           Success
* @retval #HI_ERR_MSG_INVALID_PARAM An input argument is incorrect, the handle pointer is null, the name address is
*         null, or the message queue length is 0.CNcomment:��δ��󡢾��ָ��Ϊ�ա����ֵ�ַΪ�ա���Ϣ���г���Ϊ0��CNend
* @retval #HI_ERR_MSG_CREATE_Q_FAIL An error occurred when creating the message queue, for example, insufficient
*         memory or insufficient message queue resources.
CNcomment:������Ϣ���д��󣬱��磺�ڴ治�㡢��Ϣ������Դ���㡣CNend
* @par ����:
*            @li hi_msg.h��Describes message queue APIs.CNcomment:�ļ�����������Ϣ������ؽӿڡ�CNend
*            @li hi_config.h��Describes the message queue configuration.CNcomment:�ļ�������Ϣ�������á�CNend
*            @li hi_errno.h��Describes file configuration error codes.CNcomment:�ļ����ô����롣CNend
* @see hi_msg_queue_delete��
* @since Hi3861_V100R001C00
*/
hi_u32 hi_msg_queue_create(HI_OUT hi_u32 *id, hi_u16 queue_len, hi_u32 msg_size);

/**
* @ingroup  iot_msgqueue
* @brief  Deletes a message queue.CNcomment:ɾ����Ϣ���С�CNend
*
* @par ����:
*          Deletes a message queue.CNcomment:ɾ����Ϣ���С�CNend
*
* @attention None
* @param  id           [OUT] type  #hi_u32*��Handle of the created message queue.CNcomment:��Ϣ���о����CNend
*
* @retval #HI_ERR_SUCCESS           Success
* @retval #HI_ERR_MSG_Q_DELETE_FAIL An error occurred with the message queue, for example, the ID is out of
*         range, the message queue is not created, or the message queue is in use.CNcomment:ɾ����Ϣ���д���
���磺IDԽ�硢��Ϣ����δ��������Ϣ��������ʹ�����޷�ɾ���ȡ�CNend
* @par ����:
*            @li hi_msg.h��Describes message queue APIs.CNcomment:�ļ�����������Ϣ������ؽӿڡ�CNend
*            @li hi_config.h��Describes the message queue configuration.CNcomment:�ļ�������Ϣ�������á�CNend
*            @li hi_errno.h��Describes file configuration error codes.CNcomment:�ļ����ô����롣CNend
 @see hi_msg_queue_create��
* @since Hi3861_V100R001C00
*/
hi_u32 hi_msg_queue_delete(hi_u32 id);

/**
* @ingroup  iot_msgqueue
* @brief   Sends a message.CNcomment:������Ϣ��CNend
*
* @par ����:
*           Sends a message.������Ϣ��CNend
*
* @attention None
* @param  id           [IN] type #hi_u32��Message queue handle.CNcomment:��Ϣ���о����CNend
* @param  msg          [IN] type #hi_pvoid��Message content pointer.CNcomment:��Ϣ����ָ�롣CNend
* @param  timeout_ms   [IN] type #hi_u32��Timeout period for sending a message. The value 0 indicates
*                      that the message is sent immediately.CNcomment:��Ϣ���͵����ʱʱ��(��λ��ms)��
��������ʱд0��CNend
* @param  msg_size     [IN] type #hi_u32��Size of the sent message (unit: byte).
CNcomment:������Ϣ��С����λ��byte����CNend
*
* @retval #HI_ERR_SUCCESS           Success.
* @retval #HI_ERR_MSG_SEND_FAIL     An error occurs with the message queue, for example, an input argument is
*                                   incorrect, the message queue is not created, the size of the sent data is
*                                   greater than the configured size when the queue is created, or the API is
*                                   used in an interrupt but the timeout period is not 0.
CNcomment:������Ϣ���д��󣬰�������δ�����Ϣ����δ�������������ݴ��ڶ��д���ʱ���ô�С��
�ж���ʹ�õ���ʱʱ�䲻Ϊ0��CNend
*
* @retval #HI_ERR_MSG_INVALID_PARAM An input argument is incorrect or the message queue pointer is null.
CNcomment:��δ�����Ϣ����ָ��Ϊ�ա�CNend
*
* @par ����:
*            @li hi_msg.h��Describes message queue APIs.CNcomment:�ļ�����������Ϣ������ؽӿڡ�CNend
*            @li hi_config.h��Describes the message queue configuration.CNcomment:�ļ�������Ϣ�������á�CNend
*            @li hi_errno.h��Describes file configuration error codes.CNcomment:�ļ����ô����롣CNend
* @see hi_msg_queue_wait��
* @since Hi3861_V100R001C00
*/
hi_u32 hi_msg_queue_send(hi_u32 id, hi_pvoid msg, hi_u32 timeout_ms, hi_u32 msg_size);

/**
* @ingroup  iot_msgqueue
* @brief  Receives a message.CNcomment:������Ϣ��CNend
*
* @par ����:
*           Receives a message.CNcomment:������Ϣ��CNend
*
* @attention None
* @param  id          [IN]   type #hi_u32��Message queue handle.CNcomment:��Ϣ���о����CNend
* @param  msg         [OUT]  type #hi_pvoid��Message content pointer.CNcomment:��Ϣ����ָ�롣CNend
* @param  timeout_ms  [IN]   type #hi_u32��Timeout period for receiving a message. The value #HI_SYS_WAIT_FOREVER
*                     indicates permanent wait.CNcomment:��Ϣ���ճ�ʱʱ��(��λ��ms)��
�����ʾ���õȴ�ʹ��#HI_SYS_WAIT_FOREVER��CNend
* @param  msg_size    [IN]   type #hi_u32*��Expected message length (unit: byte),if wait msg success, this val will fill
with actually size of msg.
CNcomment:������������Ϣ���ȣ���λ��byte��������ȴ���Ϣ�ɹ�����ֵ������ֵΪʵ�ʽ��յ�����Ϣ���ȡ�CNend
*
* @retval #HI_ERR_SUCCESS           Success.CNcomment:��Ϣ���ճɹ���CNend
* @retval #HI_ERR_MSG_WAIT_FAIL     An error occurs with the message queue, for example, an input argument is incorrect,
*                                   the message queue is not created, the size of the waiting message is smaller than
*                                   the size set when the queue is created, or the API is used in an interrupt but the
*                                   timeout period is not 0.CNcomment:�ȴ���Ϣ���д��󣬱��磺��β���ȷ����Ϣ����δ
�������ȴ���Ϣ��СС�ڶ��д���ʱ���ô�С���ж��еȴ���ʱ�������Ϣ���С�CNend
* @retval #HI_ERR_MSG_INVALID_PARAM An input argument is incorrect or the message queue pointer is null.
CNcomment:��δ�����Ϣ����ָ��Ϊ�ա�CNend
* @retval #HI_ERR_MSG_WAIT_TIME_OUT No message is received when the waiting times out.
CNcomment:�ȴ���ʱδ�յ���Ϣ��CNend
* @par ����:
*            @li hi_msg.h��Describes message queue APIs.CNcomment:�ļ�����������Ϣ������ؽӿڡ�CNend
*            @li hi_config.h��Describes the message queue configuration.CNcomment:�ļ�������Ϣ�������á�CNend
*            @li hi_errno.h��Describes file configuration error codes.CNcomment:�ļ����ô����롣CNend
* @see hi_msg_queue_send��
* @since Hi3861_V100R001C00
*/
hi_u32 hi_msg_queue_wait(hi_u32 id, HI_OUT hi_pvoid msg, hi_u32 timeout_ms, hi_u32* msg_size);

/**
* @ingroup  iot_msgqueue
* @brief   Checks whether the message queue is full.CNcomment:�����Ϣ�����Ƿ�������CNend
*
* @par ����:
*           Checks whether the message queue is full.CNcomment:�����Ϣ�����Ƿ�������CNend
*
* @attention None
* @param  id        [IN] type #hi_u32��Message queue handle.CNcomment:��Ϣ���о����CNend
*
* @retval #HI_TRUE  The message queue is full or the message queue information fails to be obtained.
CNcomment:��Ϣ�����������ȡ��Ϣ������Ϣʧ�ܡ�CNend
* @retval #HI_FALSE The message queue is not full.CNcomment:��Ϣ����δ����CNend
* @par ����:
*            @li hi_msg.h��Describes message queue APIs.CNcomment:�ļ�����������Ϣ������ؽӿڡ�CNend
* @see None
* @since Hi3861_V100R001C00
*/
hi_bool hi_msg_queue_is_full(hi_u32 id);

/**
* @ingroup  iot_msgqueue
* @brief   Obtains the number of used message queues.CNcomment:��ȡ��ǰ�Ѿ�ʹ�õ���Ϣ���и�����CNend
*
* @par ����:
*           Obtains the number of used message queues.CNcomment:��ȡ��ǰ�Ѿ�ʹ�õ���Ϣ���и�����CNend
*
* @attention None
* @param  id       [IN] #hi_u32*��Handle of the created message queue.CNcomment:��Ϣ���о����CNend
*
* @retval #HI_ERR_MSG_INVALID_MSG_NUM  Failed to read the message queue.CNcomment:��ȡ��Ϣ���г���CNend
* @retval value                        Number of used message queues.CNcomment:��Ϣ����ʹ�ø�����CNend
* @par ����:
*            @li hi_msg.h��Describes message queue APIs.CNcomment:�ļ�����������Ϣ������ؽӿڡ�CNend
* @see None
* @since Hi3861_V100R001C00
*/
hi_u32 hi_msg_queue_get_msg_num(hi_u32 id);

/**
* @ingroup  iot_msgqueue
* @brief  Obtains the number of message queues.CNcomment:��ȡ��Ϣ�����ܸ�����CNend
*
* @par ����:
*           Obtains the number of message queues.CNcomment:��ȡ��Ϣ�����ܸ�����CNend
*
* @attention None
* @param  id       [IN] #hi_u32*��Handle of the created message queue.CNcomment:��Ϣ���о����CNend
*
* @retval #HI_ERR_MSG_INVALID_MSG_NUM  An error occurs with the message queue. For example: An input argument is
*         incorrect, or the message queue is not created.
CNcomment:��ȡ��Ϣ���г�����δ�����Ϣ����δ������CNend
* @retval value                        Number of message queues.CNcomment:��Ϣ�����ܸ�����CNend
* @par ����:
*            @li hi_msg.h��Describes message queue APIs.CNcomment:�ļ�����������Ϣ������ؽӿڡ�CNend
* @see None
* @since Hi3861_V100R001C00
*/
hi_u32 hi_msg_queue_get_msg_total(hi_u32 id);

#endif

