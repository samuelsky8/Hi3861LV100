/**
* @file hi_sdio_slave.h
*
* Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2019. All rights reserved.  \n
* Description: sdio slave mode APIs.   \n
* Author: Hisilicon   \n
* Create: 2019-01-17
*/

/**
 * @defgroup iot_sdio SDIO Slave
 * @ingroup drivers
 */

#ifndef __HI_SDIO_SLAVE_H__
#define __HI_SDIO_SLAVE_H__

#include <hi_types_base.h>

/**
 * @ingroup iot_sdio
 *
 * SDIO definition.CNcomment:SDIO����CNend
 */
#define CHAN_TX_BUSY                            1
#define CHAN_TX_IDLE                            0
#define CHAN_RX_BUSY                            1
#define CHAN_RX_IDLE                            0

#define HISDIO_EXTENDREG_COUNT                  64
#define HISDIO_BLOCK_SIZE                       512

/**
 * @ingroup iot_sdio
 *
 * Device to Host sdio message type, The name can be modified according to product.
CNcomment:�豸��������SDIO��Ϣ���ͣ��������ƿ��Ը��ݲ�Ʒʵ��Ӧ�ó������ġ�CNend
 */
typedef enum {
    D2H_MSG_WLAN_READY     = 0,
    D2H_MSG_WOW_COMPLETE   = 1,  /**< wow complete. */
    D2H_MSG_FLOWCTRL_OFF   = 2,  /**< can't send data */
    D2H_MSG_FLOWCTRL_ON    = 3,  /**< can send data */
    D2H_MSG_WAKEUP_SUCC    = 4,  /**< wakeup done */
    D2H_MSG_ALLOW_SLEEP    = 5,  /**< allow sleep */
    D2H_MSG_DISALLOW_SLEEP = 6,  /**< disalow sleep */
    D2H_MSG_DEVICE_PANIC   = 7,  /**< device panic */
    D2H_MSG_POWEROFF_ACK   = 8,  /**< poweroff cmd ack */
    D2H_MSG_CREDIT_UPDATE  = 11, /**< update high priority buffer credit value */
    D2H_MSG_HIGH_PKT_LOSS  = 12, /**< high pri pkts loss count */
    D2H_MSG_HEARTBEAT      = 14, /**< send heartbeat */
    D2H_MSG_WOW_WIFI_REDAY = 15, /**< device ready for host sleep */
    D2H_MSG_COUNT          = 32, /**< max support msg count */
} hi_sdio_d2h_msg_type_e;

/**
 * @ingroup iot_sdio
 *
 * Host to Device sdio message type, The name can be modified according to product.
CNcomment:�������豸��SDIO��Ϣ���ͣ��������ƿ��Ը��ݲ�Ʒʵ��Ӧ�ó������ġ�CNend
 */
typedef enum {
    H2D_MSG_FLOWCTRL_ON         = 0,
    H2D_MSG_DEVICE_INFO_DUMP    = 1,
    H2D_MSG_DEVICE_MEM_DUMP     = 2,
    H2D_MSG_TEST                = 3,
    H2D_MSG_PM_WLAN_OFF         = 4,
    H2D_MSG_SLEEP_REQ           = 5,
    H2D_MSG_PM_DEBUG            = 6,
    H2D_MSG_QUERY_RF_TEMP       = 8,
    H2D_MSG_HCC_SLAVE_THRUPUT_BYPASS = 9,
    H2D_MSG_DEVICE_MEM_INFO     = 10,
    H2D_MSG_STOP_SDIO_TEST      = 11,
    H2D_MSG_FORCESLP_REQ        = 13,
    H2D_MSG_WOW_WIFI_SUSPEND    = 14,
    H2D_MSG_WOW_WIFI_RESUME     = 15,
    H2D_MSG_COUNT               = 32, /**< max support msg value count */
} hi_sdio_h2d_msg_type_e;

/**
 * @ingroup iot_sdio
 *
 * max message value between Host and Device.
 */
typedef enum {
    SDIO_DEVICE_MSG_WLAN_READY = 0,
    SDIO_DEVICE_MSG_COUNT = 32, /**< max support msg count */
    SDIO_DEVICE_MSG_BUTT
} hi_sdio_msg_e;

/**
 * @ingroup iot_sdio
 *
 * SDIO ADMA table.
 */
typedef struct {
    hi_u16                      param;
    hi_u16                      len;
    uintptr_t                   address;
} hi_sdio_admatable;

/**
 * @ingroup iot_sdio
 *
 * SDIO extend function structure.
 */
typedef struct {
    hi_u32                   int_stat;
    hi_u32                   msg_stat;
    hi_u32                   xfer_count;
    hi_u32                   credit_info;
    hi_s8                    credit_isvalid;
    hi_u8                    comm_reg[HISDIO_EXTENDREG_COUNT];
    hi_s8                    commreg_isvalid;
    hi_s32                   valid_commreg_cnt;
} hi_sdio_extendfunc;

/**
 * @ingroup iot_sdio
 *
 * use this callback to notify host msg event occurs.
 */
typedef hi_void (*notify_host_message_event)(hi_void);

/**
 * @ingroup iot_sdio
 *
 * SDIO interrupt callback structure.
 */
typedef struct {
    hi_s32 (*rdstart_callback)(hi_u32 len, hi_u8 *admatable); /**< Callback function for HOST reading.
                                                                 CNcomment:DEV��֪��HOST�����˶����� CNend */
    hi_s32 (*rdover_callback)(hi_void);                       /**< Callback function for HOST reading over.
                                                                 CNcomment:DEV��֪��HOST���������� CNend */
    hi_void (*rderr_callback)(hi_void);                       /**< Callback function for HOST read error.
                                                                 CNcomment:DEV��֪��HOST�����ݴ��� CNend */
    hi_s32 (*wrstart_callback)(hi_u32 len, hi_u8 *admatable); /**< Callback function for HOST writting.
                                                                 CNcomment:DEV��֪��HOST������д���� CNend */
    hi_s32 (*wrover_callback)(hi_void);                       /**< Callback function for HOST write over.
                                                                 CNcomment:DEV��֪��HOSTд�������� CNend */
    hi_void (*processmsg_callback)(hi_u32 msg);               /**< Callback function for HOST getting message.
                                                                 CNcomment:DEV���յ�HOST��������Ϣ CNend */
    hi_void (*soft_rst_callback)(hi_void);                    /**< Callback function for HOST getting reset
                                                                 interruption.CNcomment:DEV���յ�HOST������
                                                                 ��λ�ж� CNend */
} hi_sdio_intcallback;

/**
* @ingroup  iot_sdio
* @brief  sdio init function
*
* @par ����:
*         sdio initialization function.CNcomment:sdio ��ʼ��������CNend
*
* @attention None
* @param  None
*
* @retval #0       Success.
* @retval #Other   Failure. For details, see hi_errno.h.

* @par ����:
*           @li hi_sdio_slave.h��Describe sdio slave APIs.CNcomment:�ýӿ��������ڵ�ͷ�ļ���CNend
* @see  None��
* @since Hi3861_V100R001C00
*/
hi_u32 hi_sdio_init(hi_void);

/**
* @ingroup  iot_sdio
* @brief  sdio reinit function
*
* @par ����:
*         sdio Reinitialize the function.CNcomment:sdio ���³�ʼ��������CNend
*
* @attention None
* @param  None
*
* @retval #0       Success.
* @retval #Other   Failure. For details, see hi_errno.h.

* @par ����:
*           @li hi_sdio_slave.h��Describe sdio slave APIs.CNcomment:�ýӿ��������ڵ�ͷ�ļ���CNend
* @see  None��
* @since Hi3861_V100R001C00
*/
hi_u32 hi_sdio_reinit(hi_void);

/**
* @ingroup  iot_sdio
* @brief  sdio soft reset function
*
* @par ����:
*         sdio software reset function.CNcomment:sdio �����λ������CNend
*
* @attention None
* @param  None
*
* @retval None
*
* @par ����:
*           @li hi_sdio_slave.h��Describe sdio slave APIs.CNcomment:�ýӿ��������ڵ�ͷ�ļ���CNend
* @see  None
* @since Hi3861_V100R001C00
*/
hi_void hi_sdio_soft_reset(hi_void);

/**
* @ingroup  iot_sdio
* @brief  sdio register interrupt callback function
*
* @par ����:
*         sdio register interrupt callback function.CNcomment:sdio ע���жϻص� ������CNend
*
* @attention��
* @param  callback_func [IN] type #const hi_sdio_intcallback��sdio callback function.
*
* @retval #0       Success.
* @retval #Other   Failure. For details, see hi_errno.h.

* @par ����:
*           @li hi_sdio_slave.h��Describe sdio slave APIs.CNcomment:�ýӿ��������ڵ�ͷ�ļ���CNend
* @see  None��
* @since Hi3861_V100R001C00
*/
hi_u32 hi_sdio_register_callback(const hi_sdio_intcallback *callback_func);

/**
* @ingroup  iot_sdio
* @brief  sdio complete send function
*
* @par ����:
*         sdio complete send function.CNcomment:sdio �������ͽӿں�����CNend
*
* @attention��
* @param  admatable [IN] type #hi_u8 *, adma table first address. One channel occupies eight bytes. Ensure that the
*          buffer space is sufficient to prevent memory overwriting. CNcomment:adma table�׵�ַ��һ��ͨ��ռ��8�ֽڣ�ʹ
*          ��ʱ��ȷ���㹻
�Ļ���ռ䣬��ֹ�ڴ�Խ����ʡ�CNend
* @param  adma_index [IN] type hi_u32, adma_index  adma Transmission channel number, range: [0-130].CNcomment:adma
*          ����ͨ����,��Χ[0-130]��CNend
*
* @retval #0       Success.
* @retval #Other   Failure. For details, see hi_errno.h.

* @par ����:
*           @li hi_sdio_slave.h��Describe sdio slave APIs.CNcomment:�ýӿ��������ڵ�ͷ�ļ���CNend
* @see  None��
* @since Hi3861_V100R001C00
*/
hi_u32 hi_sdio_complete_send(hi_u8 *admatable, hi_u32 adma_index);

/**
* @ingroup  iot_sdio
* @brief  set sdio pad adma table function
*
* @par ����:
*         set sdio pad adma table function.CNcomment:sdio �������ݶ�����ADMA��CNend
*
* @attention��
* @param  padlen [IN] type #hi_u32, Length of data to be sent after data alignment.
CNcomment:���ݶ����Ҫ���͵����ݳ��ȡ�CNend
* @param  admatable [IN] type #hi_u8 *, adma table first address. One channel occupies eight bytes. Ensure that the
*         buffer space is sufficient to prevent memory overwriting.
CNcomment:adma table�׵�ַ��һ��ͨ��ռ��8�ֽڣ�ʹ��ʱ��ȷ���㹻�Ļ���ռ䣬��ֹ�ڴ�Խ����ʡ�CNend
* @param  adma_index [IN] type #hi_u32, adma Transmission channel number, range: [0-130].
CNcomment:adma����ͨ����,��Χ[0-130]��CNend
*
* @retval #0       Success.
* @retval #Other   Failure. For details, see hi_errno.h.

* @par ����:
*           @li hi_sdio_slave.h��Describe sdio slave APIs.CNcomment:�ýӿ��������ڵ�ͷ�ļ���CNend
* @see  None��
* @since Hi3861_V100R001C00
*/
hi_u32 hi_sdio_set_pad_admatab(hi_u32 padlen, hi_u8 *admatable, hi_u32 adma_index);

/**
* @ingroup  iot_sdio
* @brief  write extend information function
*
* @par ����:
*         write extend information function.CNcomment:д��չ��Ϣ�ӿ�CNend
*
* @attention��
* @param  extfunc [IN] type #hi_sdio_extendfunc, Extended information pointer.CNcomment:��չ��Ϣָ��.CNend
*
* @retval #0       Success.
* @retval #Other   Failure. For details, see hi_errno.h.

* @par ����:
*           @li hi_sdio_slave.h��Describe sdio slave APIs.CNcomment:�ýӿ��������ڵ�ͷ�ļ���CNend
* @see  None��
* @since Hi3861_V100R001C00
*/
hi_u32 hi_sdio_write_extinfo(hi_sdio_extendfunc *extfunc);

/**
* @ingroup  iot_sdio
* @brief  start to send data
*
* @par ����:
*         start to send data.CNcomment:�������ݷ��ͽӿ�CNend
*
* @attention��
* @param  xfer_bytes [IN] type #hi_u32, Length of sent data.CNcomment:�������ݳ���.CNend
*
* @retval #0       Success.
* @retval #Other   Failure. For details, see hi_errno.h.

* @par ����:
*           @li hi_sdio_slave.h��Describe sdio slave APIs.CNcomment:�ýӿ��������ڵ�ͷ�ļ���CNend
* @see  None��
* @since Hi3861_V100R001C00
*/
hi_void hi_sdio_send_data(hi_u32 xfer_bytes);

/**
* @ingroup  iot_sdio
* @brief  set adma table
*
* @par ����:
*         set adma table.CNcomment:����adma����ͨ��CNend
*
* @attention��
* @param  admatable [IN] type #hi_u8*, adma table first address. One channel occupies eight bytes. Ensure that the
*         buffer space is sufficient to prevent memory overwriting. CNcomment:adma table�׵�ַ��һ��ͨ��ռ��8�ֽڣ�ʹ
��ʱ��ȷ���㹻�Ļ���ռ䣬��ֹ�ڴ�Խ����ʡ�CNend
* @param  adma_index [IN] type #hi_u32, adma Transmission channel number, range: [0-130].CNcomment:adma����ͨ����,
��Χ[0-130]��CNend
* @param  data_addr [IN] type #const hi_u32 *, dama transmission destination address.CNcomment:dama ����Ŀ�ĵ�ַCNend
* @param  data_len [IN] type #hi_u32, adma Transmission data length.CNcomment:adma �������ݳ���CNend
*
* @retval #0       Success.
* @retval #Other   Failure. For details, see hi_errno.h.

* @par ����:
*           @li hi_sdio_slave.h��Describe sdio slave APIs.CNcomment:�ýӿ��������ڵ�ͷ�ļ���CNend
* @see  None��
* @since Hi3861_V100R001C00
*/
hi_u32 hi_sdio_set_admatable(hi_u8 *admatable, hi_u32 adma_index, const hi_u32 *data_addr, hi_u32 data_len);

/**
* @ingroup  iot_sdio
* @brief  schedule sdio pending message.
*
* @par ����:
*         schedule sdio message.CNcomment:�������sdio��Ϣ���ͳ�ȥCNend
*
* @attention��
* @param    None
*
* @retval    #true  if there is no pending msg or send pending msg success, retun true.
CNcomment:���û�й������Ϣ�����߽��������Ϣ���ͳɹ�������true.CNend
* @retval    #false if sdio not in work status or there is msg sending, return false.
CNcomment:���sdio���ڹ���״̬������sdio���ڷ�����Ϣ������false.CNend
*
* @par ����:
*           @li hi_sdio_slave.h��Describe sdio slave APIs.CNcomment:�ýӿ��������ڵ�ͷ�ļ���CNend
* @see  None��
* @since Hi3861_V100R001C00
*/
hi_bool hi_sdio_sched_msg(hi_void);

/**
* @ingroup  iot_sdio
* @brief  sync send message.
*
* @par ����:
*         put msg in pending msg and send.CNcomment:����Ϣ������Ϣ���в�����CNend
*
* @attention��
* @param  msg [IN] type #hi_u32, The message, range [0-31].CNcomment:������Ϣ����Χ[0-31].CNend
*
* @retval    #true    Success.
* @retval    #false   Failure.
*
* @par ����:
*           @li hi_sdio_slave.h��Describe sdio slave APIs.CNcomment:�ýӿ��������ڵ�ͷ�ļ���CNend
* @see  None��
* @since Hi3861_V100R001C00
*/
hi_bool hi_sdio_send_sync_msg(hi_u32 msg);

/**
* @ingroup  iot_sdio
* @brief  send given message ack
*
* @par ����:
*         Sending a Specified Signal Message.CNcomment:����ָ����ϢCNend
*
* @attention:
          the current sending msg will be overwrite by this msg.
          CNcomment: ��ǰ���ڷ��͵���Ϣ������Ϣ���ǢCNend
* @param   msg [IN] type #hi_u32, The message, range [0-31].CNcomment:������Ϣ����Χ[0-31].CNend
*
* @retval    #true    Success.
* @retval    #false   Failure.
*
* @par ����:
*           @li hi_sdio_slave.h��Describe sdio slave APIs.CNcomment:�ýӿ��������ڵ�ͷ�ļ���CNend
* @see  None��
* @since Hi3861_V100R001C00
*/
hi_bool hi_sdio_send_msg_ack(hi_u32 msg);

/**
* @ingroup  iot_sdio
* @brief  Clear given msg and add new msg to pending msg and send.
*
* @par ����:
*         Clear given msg and add new msg in pending msg and send.
CNcomment:�����Ϣ�����й����ָ����Ϣ��������Ϣ������Ϣ���в�����CNend
* @attention��
* @param   send_msg [IN] type #hi_u32, Message in range [0~31] which will be sent.
CNcomment:ָ�����͵���Ϣ�ţ���Χ[0-31]CNend
* @param   clear_msg [IN] type #hi_u32, Message in range [0~31] which will be cleard.
CNcomment:ָ���������Ϣ�ţ���Χ[0-31]CNend
*
* @retval    #true    Success.
* @retval    #false   Failure.
*
* @par ����:
*           @li hi_sdio_slave.h��Describe sdio slave APIs.CNcomment:�ýӿ��������ڵ�ͷ�ļ���CNend
* @see  None��
* @since Hi3861_V100R001C00
*/
hi_bool hi_sdio_process_msg(hi_u32 send_msg, hi_u32 clear_msg);

/**
* @ingroup  iot_sdio
* @brief  sdio is pending given message
*
* @par ����:
*         sdio is pending given message.CNcomment:�ж�sdio�Ƿ����ָ������ϢCNend
*
* @attention��
* @param   msg [IN] type #hi_u32, The message, range [0-31].CNcomment:������Ϣ����Χ[0-31].CNend
*
* @retval    #true    message at pending status.CNcomment:ָ����Ϣ���ڹ���״̬CNend
* @retval    #false   message at other status. CNcomment:ָ����Ϣ�����ڹ���״̬CNend
*
* @par ����:
*           @li hi_sdio_slave.h��Describe sdio slave APIs.CNcomment:�ýӿ��������ڵ�ͷ�ļ���CNend
* @see  None��
* @since Hi3861_V100R001C00
*/
hi_u32 hi_sdio_is_pending_msg(hi_u32 msg);

/**
* @ingroup  iot_sdio
* @brief  Check whether the sdio is sending a specified message.
*
* @par ����:
*         Check whether the sdio is sending a specified message.CNcomment:�ж�sdio�Ƿ����ڷ���ָ������ϢCNend
*
* @attention��
* @param   msg [IN] type #hi_u32, The message, range [0-31].CNcomment:������Ϣ����Χ[0-31].CNend
*
* @retval    #true    The message at sending status.CNcomment:ָ����Ϣ���ڷ���״̬CNend
* @retval    #false   The message at other status.CNcomment:ָ����Ϣ�����ڷ���״̬CNend
*
* @par ����:
*           @li hi_sdio_slave.h��Describe sdio slave APIs.CNcomment:�ýӿ��������ڵ�ͷ�ļ���CNend
* @see  None��
* @since Hi3861_V100R001C00
*/
hi_u32 hi_sdio_is_sending_msg(hi_u32 msg);

/**
* @ingroup  iot_sdio
* @brief  get sdio extend configuration.
*
* @par ����:
*         get sdio extend configuration.CNcomment:��ȡ��չ��������ϢCNend
*
* @attention None
* @param     None
*
* @retval    hi_sdio_extendfunc*  pointer to extend info buffer.
*
* @par ����:
*           @li hi_sdio_slave.h��Describe sdio slave APIs.CNcomment:�ýӿ��������ڵ�ͷ�ļ���CNend
* @see  None��
* @since Hi3861_V100R001C00
*/
hi_sdio_extendfunc *hi_sdio_get_extend_info(hi_void);

/**
* @ingroup  iot_sdio
* @brief  register callback to notify host msg or data event occurs.
*
* @par ����:
*         register callback to notify host msg or data event occurs.
CNcomment:ע��֪ͨHost��������Ϣ�����ݵĻص�������CNend
*
* @attention None
* @param  msg_event_callback [IN] type #notify_host_message_event, notify_host_message_event callback function when
*         sending msg or data.
CNcomment:��Ϣ�����ݷ���ʱ���õĻص�����CNend
*
* @retval    None
*
* @par ����:
*           @li hi_sdio_slave.h��Describe sdio slave APIs.CNcomment:�ýӿ��������ڵ�ͷ�ļ���CNend
* @see  None��
* @since Hi3861_V100R001C00
*/
hi_void hi_sdio_register_notify_message_callback(notify_host_message_event msg_event_callback);

/**
* @ingroup  iot_sdio
* @brief  set sdio powerdown or not when system enter deep_sleep.
*
* @par ����:
*         set sdio powerdown or not when system enter deep_sleep.
CNcomment:����ϵͳ��˯ģʽ�£�SDIOģ���Ƿ���硣CNend
*
* @attention default powerdown.CNcomment:Ĭ�ϵ���.CNend
* @param   power_down [IN] type #hi_bool, powerdown or not.CNcomment:�Ƿ����.CNend
*
* @retval    None
*
* @par ����:
*           @li hi_sdio_slave.h��Describe sdio slave APIs.CNcomment:�ýӿ��������ڵ�ͷ�ļ���CNend
* @see  None��
* @since Hi3861_V100R001C00
*/
hi_void hi_sdio_set_powerdown_when_deep_sleep(hi_bool power_down);

#endif /* end of hi_sdio_slave.h */
