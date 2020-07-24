/*
 * Copyright (C) Hisilicon Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: sdio slave mode inner APIs.
 * Author: hisilicon
 * Create: 2019-01-17
 */

/**
 * @defgroup iot_sdio SDIO Slave
 * @ingroup drivers
 */

#ifndef __SDIO_SLAVE_INNER_H__
#define __SDIO_SLAVE_INNER_H__

#include <hi_types_base.h>
#include <hi_sdio_slave.h>

/* The max scatter buffers when host to device */
#define HISDIO_HOST2DEV_SCATT_MAX               64
#define HISDIO_HOST2DEV_SCATT_SIZE              64

/* The max scatter buffers when device to host */
#define HISDIO_DEV2HOST_SCATT_MAX               64
#define HISDIO_DEV2HOST_SCATT_SIZE              64

/* 64B used to store the scatt info,1B means 1 pkt. */
#define HISDIO_H2D_SCATT_BUFFLEN_ALIGN_BITS     3
#define HISDIO_H2D_SCATT_BUFFLEN_ALIGN          8

#define HISDIO_D2H_SCATT_BUFFLEN_ALIGN_BITS     5
#define HISDIO_D2H_SCATT_BUFFLEN_ALIGN          512

#define HSDIO_HOST2DEV_PKTS_MAX_LEN             1544

/**
 * @ingroup iot_sdio
 *
 * SDIO sleep stage.
 */
typedef enum {
    SLEEP_REQ_WAITING       = 0,
    SLEEP_ALLOW_SND         = 1,
    SLEEP_DISALLOW_SND      = 2,
} hi_sdio_host_sleep_stage_e;

/**
 * @ingroup iot_sdio
 *
 * SDIO wakeup stage.
 */
typedef enum {
    WAKEUP_HOST_INIT        = 0,
    WAKEUP_REQ_SND          = 1,
    WAKEUP_RSP_RCV          = 2,
} hi_sdio_host_wakeupstage_e;

/**
 * @ingroup iot_sdio
 *
 * SDIO works status.
 */
typedef enum {
    SDIO_CHAN_ERR    = 0x0,
    SDIO_CHAN_RESET,
    SDIO_CHAN_INIT,
    SDIO_CHAN_SLEEP,
    SDIO_CHAN_WAKE,
    SDIO_CHAN_WORK,
    /* Status Number */
    SDIO_CHAN_BUTT
} hi_sdio_chanstatus;

/**
 * @ingroup iot_sdio
 *
 * SDIO status info.
 */
typedef struct {
    hi_u8     allow_sleep;
    hi_u8     tx_status;       /* point to g_chan_tx_status variable address */
    hi_u8     sleep_status;    /* point to g_sleep_stage variable address */
    hi_sdio_chanstatus  work_status; /* point to g_chan_work_status variable address */
} hi_sdio_status_info;

/**
 * @ingroup iot_sdio
 *
 * SDIO status structure.
 */
typedef struct {
    hi_u16          rd_arg_invalid_cnt;
    hi_u16          wr_arg_invlaid_cnt;
    hi_u16          unsupport_int_cnt;
    hi_u16          mem_int_cnt;
    hi_u16          fn1_wr_over;
    hi_u16          fn1_rd_over;
    hi_u16          fn1_rd_error;
    hi_u16          fn1_rd_start;
    hi_u16          fn1_wr_start;
    hi_u16          fn1_rst;
    hi_u16          fn1_msg_rdy;
    hi_u16          fn1_ack_to_arm_int_cnt;
    hi_u16          fn1_adma_end_int;
    hi_u16          fn1_suspend;
    hi_u16          fn1_resume;
    hi_u16          fn1_adma_int;
    hi_u16          fn1_adma_err;
    hi_u16          fn1_en_int;
    hi_u16          fn1_msg_isr;                 /**< device�յ�msg�жϴ��� */
    hi_u16          soft_reset_cnt;
} hi_sdio_status;

/**
 * @ingroup iot_sdio
 *
 * SDIO transfer channel structure.
 */
typedef struct {
    hi_u32                 send_data_len;
    hi_u16                 last_msg;
    hi_u16                 panic_forced_timeout;
    hi_u16                 chan_msg_cnt[D2H_MSG_COUNT];
} hi_sdio_chan_info;

/**
 * @ingroup iot_sdio
 *
 * SDIO message structure.
 */
typedef struct {
    hi_u32        pending_msg;
    hi_u32        sending_msg;
} hi_sdio_message;

/**
 * @ingroup iot_sdio
 *
 * SDIO infomation structure.
 */
typedef struct {
    hi_u8                volt_switch_flag;        /**< Sdio voltage conversion flag.
                                                          CNcomment:SDIO��ѹת����־CNend */
    hi_u8                host_to_device_msg_flag; /**< MSG_FLAG_ON indicates that the DEVICE receives the allowed
                                                     sleep msg. CNcomment:MSG_FLAG_ON��ʾDEVICE�յ�����˯��msg.CNend */
    hi_u16               reinit_times;
    hi_u16               gpio_int_times;
    hi_u16               pad;
    hi_sdio_status       sdio_status;             /**< Sdio statistics.CNcomment:SDIOͳ��CNend */
    hi_sdio_chan_info    chan_info;
    hi_sdio_message      chan_msg_stat;
} hi_sdio_info;

/**
* @ingroup  iot_sdio
* @brief  sdio data init function
*
* @par ����:
*         sdio data initialization function.CNcomment:sdio ���ݳ�ʼ��������CNend
*
* @attention None
* @param  None
*
* @retval  None
*
* @par ����:
*           @li hi_sdio_slave.h��Describe sdio slave APIs.CNcomment:�ýӿ��������ڵ�ͷ�ļ���CNend
* @see  None��
* @since Hi3861_V100R001C00
*/
hi_void hi_sdio_data_init(hi_void);

/**
* @ingroup  iot_sdio
* @brief  sdio memory init function
*
* @par ����:
*         sdio memory initialization function.CNcomment:sdio �ڴ��ʼ��������CNend
*
* @attention None
* @param  None
*
* @retval # None
*
* @par ����:
*           @li hi_sdio_slave.h��Describe sdio slave APIs.CNcomment:�ýӿ��������ڵ�ͷ�ļ���CNend
* @see  None��
* @since Hi3861_V100R001C00
*/
hi_void hi_sdio_memory_init(hi_void);

/**
* @ingroup  iot_sdio
* @brief  sdio wakeup host function
*
* @par ����:
*         sdio wakeup host function.CNcomment:sdio ����Host ������CNend
*
* @attention None
* @param  None
*
* @retval #0          Success.

* @par ����:
*           @li hi_sdio_slave.h��Describe sdio slave APIs.CNcomment:�ýӿ��������ڵ�ͷ�ļ���CNend
* @see  None��
* @since Hi3861_V100R001C00
*/
hi_u32 hi_sdio_wakeup_host(hi_void);

/**
* @ingroup  iot_sdio
* @brief  sdio proc memory malloc fail function
*
* @par ����:
*         sdio proc memory malloc fail function.CNcomment:sdio Proc �ڴ�����ʧ�ܺ�����CNend
*
* @attention None
* @param  [IN] mem_type type #hi_u8, memory type. see enum _hcc_netbuf_queue_type_ CNend.
          CNcomment:�ڴ����ͣ��ο�enum _hcc_netbuf_queue_type_ ����CNend
* @param  [IN] resv_buf type #hi_void**, Memory address assigned to the rx_buf after a failure.
CNcomment:ʧ�ܺ�ֵ��rx_buf���ڴ��ַCNend
* @param  [OUT] rx_buf  type #hi_void*, Indicates the returned reserved memory address.
CNcomment:���صı����ڴ��ַCNend
*
* @retval #0       Success.
* @retval #Other   Failure. For details, see hi_errno.h.

* @par ����:
*           @li hi_sdio_slave.h��Describe sdio slave APIs.CNcomment:�ýӿ��������ڵ�ͷ�ļ���CNend
* @see  None��
* @since Hi3861_V100R001C00
*/
hi_u32 hi_sdio_procmem_alloc_fail(hi_u8 mem_type, hi_void **rx_buf, hi_void *resv_buf);

/**
* @ingroup  iot_sdio
* @brief  sdio flow ctronl function
*
* @par ����:
*         sdio flow ctronl function.CNcomment:sdio ���ؿ��ƺ�����CNend
*
* @attention��
* @param  [IN] enable       Indicates whether to enable flow control. The value true indicates that flow control is
*         enabled, and the value false indicates that flow control is disabled.CNcomment:ʹ������λ��trueΪ�����أ�
falseΪ�ر�����CNend
* @param  [IN] free_pkts    Current free_pkts value.CNcomment:��ǰfree_pktsֵ��CNend
* @param  [IN] mem_level    Enables or disables the memory threshold for flow control.
CNcomment:�򿪻�ر����ص��ڴ�ˮ�ߡ�CNend
* @param  [INOUT] ctl_flag  Current flow control status.CNcomment:��ǰ����״̬��CNend
*
* @retval  None
*
* @par ����:
*           @li hi_sdio_slave.h��Describe sdio slave APIs.CNcomment:�ýӿ��������ڵ�ͷ�ļ���CNend
* @see  None��
* @since Hi3861_V100R001C00
*/
hi_void hi_sdio_flow_ctrl(hi_bool enable, hi_u32 free_pkts, hi_u8 *ctl_flag, hi_u16 mem_level);

/**
* @ingroup  iot_sdio
* @brief  start to read data
*
* @par ����:
*         start to read data.CNcomment:����������CNend
*
* @attention��
* @param   [IN] read_bytes Number of bytes read.CNcomment:��ȡ���ֽ���CNend
*
* @retval    None
*
* @par ����:
*           @li hi_sdio_slave.h��Describe sdio slave APIs.CNcomment:�ýӿ��������ڵ�ͷ�ļ���CNend
* @see  None��
* @since Hi3861_V100R001C00
*/
hi_void hi_sdio_read_err_retry(hi_u32 read_bytes);

/**
* @ingroup  iot_sdio
* @brief  pad transfer data Len
*
* @par ����:
*         Byte alignment for transmitted data.CNcomment:�Դ������ݽ����ֽڶ���CNend
*
* @attention��
* @param   [IN] txdata_len      Number of transmitted bytes.CNcomment:������ֽ���CNend
*
* @retval  Number of bytes to be transmitted in the returned byte. If the value is greater than 512, the byte is 512
*          bytes. If the value is smaller than 512 bytes, the byte is aligned with 4 bytes.CNcomment:�����ֽڶ����
�Ĵ����ֽ���������512��512�ֽڶ��䣬С����4�ֽڶ���CNend
*
* @par ����:
*           @li hi_sdio_slave.h��Describe sdio slave APIs.CNcomment:�ýӿ��������ڵ�ͷ�ļ���CNend
* @see  None��
* @since Hi3861_V100R001C00
*/
hi_u32 hi_sdio_padding_xfercnt(hi_u32 txdata_len);

/**
* @ingroup  iot_sdio
* @brief  send device panic message
*
* @par ����:
*         send device panic message.CNcomment:����Device ������Ϣ������device.CNend
*
* @attention��
* @param    None
*
* @retval    None
*
* @par ����:
*           @li hi_sdio_slave.h��Describe sdio slave APIs.CNcomment:�ýӿ��������ڵ�ͷ�ļ���CNend
* @see  None��
* @since Hi3861_V100R001C00
*/
hi_void hi_sdio_send_panic_msg(hi_void);

/**
* @ingroup  iot_sdio
* @brief  get current sdio status.
*
* @par ����:
*         get current sdio status.CNcomment:��ȡ��ǰSDIOͨ��״̬��ϢCNend
*
* @attention��
* @param    [IN]  hi_sdio_status_info*   Storage status information BUFFER pointer.
CNcomment:�洢״̬��ϢBUFFERָ��CNend
*
* @retval    #HI_ERR_SUCCESS    Success
* @retval    #HI_ERR_FAILURE    Failure
*
* @par ����:
*           @li hi_sdio_slave.h��Describe sdio slave APIs.CNcomment:�ýӿ��������ڵ�ͷ�ļ���CNend
* @see  None��
* @since Hi3861_V100R001C00
*/
hi_u32 hi_sdio_get_status(hi_sdio_status_info *satus_info);

/**
* @ingroup  iot_sdio
* @brief  set current sdio status.
*
* @par ����:
*         set current sdio status.CNcomment:���õ�ǰSDIOͨ��״̬��ϢCNend
*
* @attention��
* @param    [IN]  const hi_sdio_status_info*   Pointing to the storage status information buffer.
CNcomment:ָ��洢״̬��Ϣbuffer.Nend
*
* @retval    #HI_ERR_SUCCESS    Success
* @retval    #HI_ERR_FAILURE    Failure
*
* @par ����:
*           @li hi_sdio_slave.h��Describe sdio slave APIs.CNcomment:�ýӿ��������ڵ�ͷ�ļ���CNend
* @see  None��
* @since Hi3861_V100R001C00
*/
hi_u32 hi_sdio_set_status(const hi_sdio_status_info *satus_info);

/**
* @ingroup  iot_sdio
* @brief  Check sdio whether is sending/pending message.
*
* @par ����:
*         Check sdio whether is sending/pending message.CNcomment:��ǰSDIOͨ���Ƿ����ڹ�����CNend
*
* @attention��
* @param    None
*
* @retval    #true    If the sdio is sending or receiving a message, true is returned.
CNcomment:���sdio���ڷ��ͻ��߽�����Ϣ���򷵻�true.CNend
* @retval    #false   If the sdio does not process the message, the value false is returned.
CNcomment:���sdio���ڴ�����Ϣ������false.CNend
*
* @par ����:
*           @li hi_sdio_slave.h��Describe sdio slave APIs.CNcomment:�ýӿ��������ڵ�ͷ�ļ���CNend
* @see  None��
* @since Hi3861_V100R001C00
*/
hi_bool hi_sdio_is_busy(hi_void);

/**
* @ingroup  iot_sdio
* @brief  get sdio statistics information.
*
* @par ����:
*         Obtains currect sdio status.CNcomment:��ǰSDIO״̬��ϢCNend
*
* @attention��
* @param     None.
*
* @retval    hi_sdio_info_s*  pointer to sdio information buffer.
*
* @par ����:
*           @li hi_sdio_slave.h��Describe sdio slave APIs.CNcomment:�ýӿ��������ڵ�ͷ�ļ���CNend
* @see  None��
* @since Hi3861_V100R001C00
*/
hi_sdio_info *hi_sdio_get_info(hi_void);

#endif /* end of sdio_slave_inner.h */
