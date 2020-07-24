/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description:  UART Port APIs. \n
 * Author: hisilicon
 * Create: 2019-03-04
 */

/**
* @file hi_uart.h
*
* Copyright (c) Hisilicon Technologies Co., Ltd. 2019. All rights reserved.  \n
*
* Description: UART Port APIs. \n
*/
/** @defgroup iot_uart UART Port
 *  @ingroup drivers
 */
#ifndef __HI_UART_H__
#define __HI_UART_H__

#include <hi_types.h>
#include "hi_mdm_types.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @ingroup iot_uart
 *
 * UART serial number. CNcomment:UART��š�CNend
 */
typedef enum {
    HI_UART_IDX_0,    /**< Physical port number 0.CNcomment:����˿ں�0 CNend */
    HI_UART_IDX_1,    /**< Physical port number 1.CNcomment:����˿ں�1 CNend */
    HI_UART_IDX_2,    /**< Physical port number 2.CNcomment:����˿ں�2 CNend */
    HI_UART_IDX_MAX   /**< Maximum physical port number, which cannot be used. CNcomment:����˿ں����ֵ��
                         ����ʹ��CNend */
} hi_uart_idx;

/**
 * @ingroup iot_uart
 *
 * UART data bit. CNcomment:UART����λ��CNend
 */
typedef enum {
    HI_UART_DATA_BIT_5 = 5, /**< Data bit: support option 5bit.CNcomment:����λ��֧������5bit.CNend */
    HI_UART_DATA_BIT_6,     /**< Data bit: support option 6bit.CNcomment:����λ��֧������6bit.CNend */
    HI_UART_DATA_BIT_7,     /**< Data bit: support option 7bit.CNcomment:����λ��֧������7bit.CNend */
    HI_UART_DATA_BIT_8,     /**< Data bit: support option 8bit.CNcomment:����λ��֧������8bit.CNend */
} hi_uart_data_bit;

/**
 * @ingroup iot_uart
 *
 * UART stop bit. CNcomment:UARTֹͣλ��CNend
 */
typedef enum {
    HI_UART_STOP_BIT_1 = 1, /**< Stop bit, 1bit.CNcomment:ֹͣλ��1bitֹͣλ.CNend */
    HI_UART_STOP_BIT_2 = 2, /**< Stop bit, 2bit.CNcomment:ֹͣλ��2bitֹͣλ.CNend */
} hi_uart_stop_bit;

/**
 * @ingroup iot_uart
 *
 * UART parity bit. CNcomment:UARTУ��λ��CNend
 */
typedef enum {
    HI_UART_PARITY_NONE = 0, /**< Parity bit, None. CNcomment:У��λ����У��CNend */
    HI_UART_PARITY_ODD = 1,  /**< Parity bit, odd. CNcomment:У��λ����У��CNend */
    HI_UART_PARITY_EVEN = 2, /**< Parity bit, even. CNcomment:У��λ��żУ��CNend */
} hi_uart_parity;

/**
 * @ingroup iot_uart
 *
 * UART FIFO interruption limitation. CNcomment:UART FIFO�ж����ޡ�CNend
 */
typedef enum {
    HI_FIFO_LINE_ONE_EIGHT = 1,  /**< FIFO interruption limitation, FIFO LINE = 1/8full.
                                    CNcomment:FIFO�ж����ޣ�FIFO LINE = 1/8full CNend */
    HI_FIFO_LINE_ONE_QUARTER,    /**< FIFO interruption limitation, FIFO LINE = 1/4full.
                                    CNcomment:FIFO�ж����ޣ�FIFO LINE = 1/4full CNend */
    HI_FIFO_LINE_HALF,           /**< FIFO interruption limitation, FIFO LINE = 1/2full.
                                    CNcomment:FIFO�ж����ޣ�FIFO LINE = 1/2full CNend */
    HI_FIFO_LINE_THREE_QUARTERS, /**< FIFO interruption limitation, FIFO LINE = 3/4full.
                                    CNcomment:FIFO�ж����ޣ�FIFO LINE = 3/4full CNend */
    HI_FIFO_LINE_SEVEN_EIGHTS,   /**< FIFO interruption limitation, FIFO LINE = 7/8full.
                                    CNcomment:FIFO�ж����ޣ�FIFO LINE = 7/8full CNend */
} hi_uart_fifo_line;

/**
 * @ingroup iot_uart
 *
 * UART block mode. CNcomment:UART ����ģʽ��CNend
 */
typedef enum {
    HI_UART_BLOCK_STATE_NONE_BLOCK = 1, /**< block mode, none-block. CNcomment:UART����ģʽ������������ CNend */
    HI_UART_BLOCK_STATE_BLOCK,          /**< block mode, block. CNcomment:UART����ģʽ���������� CNend */
} hi_uart_block_state;

/**
 * @ingroup iot_uart
 *
 * UART DMA transmation mode. CNcomment:UART DMA����ģʽ��CNend
 */
typedef enum {
    HI_UART_NONE_DMA = 1, /**< None-DMA mode. CNcomment:DMA���䣬��ʹ��DMA CNend */
    HI_UART_USE_DMA,      /**< DMA mode. CNcomment:DMA���䣬ʹ��DMA CNend */
} hi_uart_dma_state;

/**
 * @ingroup iot_uart
 *
 * UART hardware flow control mode. CNcomment:UART Ӳ�����ؿ���ģʽ��CNend
 */
typedef enum {
    HI_FLOW_CTRL_NONE,     /**< hardware flow ctrl: disable flow ctrl.CNcomment:��ʹ�á�CNend */
    HI_FLOW_CTRL_RTS_CTS,  /**< hardware flow ctrl: enable rts and cts.CNcomment:ʹ��RTS��CTS CNend */
    HI_FLOW_CTRL_RTS_ONLY, /**< hardware flow ctrl: enable rts only.CNcomment:ֻʹ��RTS CNend */
    HI_FLOW_CTRL_CTS_ONLY, /**< hardware flow ctrl: enable cts only.CNcomment:ֻʹ��CTS CNend */
} hi_flow_ctrl;

/**
 * @ingroup iot_uart
 *
 * UART basic settings. CNcomment:UART�˿ڻ������ò�����CNend
 */
typedef struct {
    hi_u32 baud_rate; /**< Baud Rate.CNcomment:�����ʡ�CNend */
    hi_u8 data_bits;  /**< Data bit. CNcomment:����λ��CNend */
    hi_u8 stop_bits;  /**< Stop bit. CNcomment:ֹͣλ��CNend */
    hi_u8 parity;     /**< Parity check flag. CNcomment:��żУ��λ��CNend */
    hi_u8 pad;        /**< reserved pad */
} hi_uart_attribute;

/**
 * @ingroup iot_uart
 *
 * UART extra attributes.CNcomment:UART�˿ڶ���������á�CNend
 */
typedef struct {
    hi_uart_fifo_line tx_fifo_line;
    hi_uart_fifo_line rx_fifo_line;
    hi_uart_fifo_line flow_fifo_line;
    hi_uart_block_state tx_block;
    hi_uart_block_state rx_block;
    hi_u16 tx_buf_size;
    hi_u16 rx_buf_size;
    hi_uart_dma_state tx_use_dma;
    hi_uart_dma_state rx_use_dma;
} hi_uart_extra_attr;

/**
* @ingroup  iot_uart
* @brief  UART initialization. CNcomment:UART��ʼ����CNend
*
* @par ����:
*           Set UART with configuration. CNcomment:���ݲ�������ָ��UART��CNend
*
* @attention 1.If extra_attr is set to HI_NULL, all optimization parameters of the notification driver use the default
*            values.CNcomment:extra_attrΪHI_NULL��ʾ֪ͨ���������Ż�����ʹ��Ĭ��ֵ��CNend
*            2.If the value of the member parameter in extra_attr is 0, it indicates that the member parameter
*            is notified to the driver. The member parameter uses the default value.
*            CNcomment:extra_attr�г�Ա����ֵΪ0��ʾ֪ͨ�����ó�Ա����ʹ��Ĭ��ֵ��CNend
*            3.After the UART initialization is complete, if you want to change the UART optimization parameter
*            configuration, you need to call hi_uart_deinit to deinitialize the UART before calling hi_uart_init
*            to change the optimization parameter configuration. CNcomment:UART��ʼ����ɺ���Ҫ���UART
�Ż��������ã����ȵ���hi_uart_deinitȥ��ʼ��UART���ٵ���hi_uart_init����Ż��������á�CNend
*
* @param  id            [IN] type #hi_uart_idx��UART port id. CNcomment:UART�˿ںš�CNend
* @param  param         [IN] type #const hi_uart_attribute*��UART base settings.CNcomment:UART����������CNend
* @param  extra_attr    [IN] type #const hi_uart_extra_attr*��UART extra settings. CNcomment:UART�Ż�������CNend
*
* @retval #HI_ERR_SUCCESS  Success.
* @retval #HI_ERR_FAILURE  Failure.
* @par ����:
*            @li hi_uart.h��Describes UART APIs.CNcomment:UART��ؽӿڡ�CNend
* @see  hi_uart_deinit��
* @since Hi3861_V100R001C00
*/
hi_u32 hi_uart_init(hi_uart_idx id, const hi_uart_attribute *param, const hi_uart_extra_attr *extra_attr);

/**
* @ingroup  iot_uart
* @brief  Reads data.CNcomment:�����ݡ�CNend
*
* @par ����:
*           Reads the data received by the UART. CNcomment:��UART���յ������ݶ�ȡ������CNend
*
* @attention This API must be used after the hi_uart_open function is called.
CNcomment:���ڵ�����hi_uart_init����֮��ʹ�á�CNend
* @param  id        [IN] type #hi_uart_idx��UART port id. CNcomment:UART�˿ںš�CNend
* @param  data      [IN] type #hi_u8*��Start address of the data to be read.CNcomment:�������ݵ��׵�ַ��CNend
* @param  data_len  [IN] type #hi_u32��Number of bytes to be read.CNcomment:Ҫ��ȡ���ݵ��ֽ�����CNend
*
* @retval #>=0 Number of bytes that are actually read.CNcomment:ʵ�ʶ������ݵ��ֽ�����CNend
* @retval #HI_ERR_FAILURE  Data read error.CNcomment:������ʧ�ܡ�CNend
* @par ����:
*            @li hi_uart.h��Describes UART APIs.CNcomment:UART��ؽӿڡ�CNend
* @see  hi_uart_write��
* @since Hi3861_V100R001C00
*/
hi_s32 hi_uart_read(hi_uart_idx id, hi_u8 *data, hi_u32 data_len);

/**
* @ingroup  iot_uart
* @brief  Writes data.CNcomment:д���ݡ�CNend
*
* @par ����:
*           Writes the data to be sent to the UART. The block mode is used by default.
CNcomment:�������͵�����д��UART��CNend
*
* @attention This API must be used after the hi_uart_init function is called.
CNcomment:���ڵ�����hi_uart_init����֮��ʹ�á�CNend
* @param  id        [IN] type #hi_uart_idx��UART port id. CNcomment:UART�˿ںš�CNend
* @param  data   [IN] type #const hi_u8*��Start address of the data to be written.CNcomment:��д���ݵ��׵�ַ��CNend
* @param  data_len   [IN] type #hi_u32��Number of bytes to be written.CNcomment:��д���ݵ��ֽ�����CNend
*
* @retval #>=0 Number of bytes to be sent.CNcomment:ʵ�ʷ������ݵ��ֽ�����CNend
* @retval #HI_ERR_FAILURE  Data send failure. CNcomment:��������ʧ�ܡ�CNend
* @par ����:
*            @li hi_uart.h��Describes UART APIs.CNcomment:UART��ؽӿڡ�CNend
* @see  hi_uart_read��
* @since Hi3861_V100R001C00
*/
hi_s32 hi_uart_write(hi_uart_idx id, const hi_u8 *data, hi_u32 data_len);

/**
* @ingroup  iot_uart
* @brief  Deinitializes UART.CNcomment:ȥ��ʼ��UART��CNend
*
* @par ����:
*           Deinitializes UART.CNcomment:ȥ��ʼ��UART��CNend
*
* @attention This API is used together with hi_uart_init.CNcomment:��hi_uart_init�ɶ�ʹ�á�CNend
* @param  id        [IN] type #hi_uart_idx��UART port id. CNcomment:UART�˿ںš�CNend
*
* @retval #HI_ERR_SUCCESS  Success.
* @retval #Other     Failure. For details, see hi_errno.h.
* @par ����:
*            @li hi_uart.h��Describes UART APIs.CNcomment:UART��ؽӿڡ�CNend
* @see  hi_uart_init��
* @since Hi3861_V100R001C00
*/
hi_u32 hi_uart_deinit(hi_uart_idx id);

/**
* @ingroup  iot_uart
* @brief  Set UART hardware flow control.CNcomment:����UARTӲ�����ع��ܡ�CNend
*
* @par ����:
*           Set UART hardware flow control.CNcomment:����UARTӲ�����ع��ܡ�CNend
*
* @attention This API must be used after the hi_uart_init function is called. UART0 doesn't support flow control.
CNcomment:���ڵ�����hi_uart_init����֮��ʹ��;UART0��֧�����ع��ܡ�CNend
*
* @param  id        [IN] type #hi_uart_idx��UART port id. CNcomment:UART�˿ںš�CNend
* @param  flow_ctrl [IN] type #hi_flow_ctrl��haredware flow control mode.
CNcomment:Ӳ�����ع��ܿ���ģʽ��CNend
*
* @retval #HI_ERR_SUCCESS  Success.
* @retval #Other     Failure. For details, see hi_errno.h.
* @par ����:
*            @li hi_uart.h��Describes UART APIs.CNcomment:UART��ؽӿڡ�CNend
* @see  �ޡ�
* @since Hi3861_V100R001C00
*/
hi_u32 hi_uart_set_flow_ctrl(hi_uart_idx id, hi_flow_ctrl flow_ctrl);

/**
* @ingroup  iot_uart
* @brief  Write data by polling. CNcomment:��ѯд���ݡ�CNend
*
* @par ����:
*           Write data by polling. CNcomment:ͨ����ѯ�ķ�ʽ�������͵�����д��UART��CNend
*
* @attention This API must be used after the hi_uart_init function is called.
CNcomment:���ڵ�����hi_uart_init����֮��ʹ�á�CNend
*
* @param  id        [IN] type #hi_uart_idx��UART port id. CNcomment:UART�˿ںš�CNend
* @param  data   [IN] type #const hi_u8*��Start address of the data to be written.CNcomment:��д���ݵ��׵�ַ��CNend
* @param  data_len   [IN] type #hi_u32��Number of bytes to be written.CNcomment:��д���ݵ��ֽ�����CNend
*
* @retval #>=0 Number of bytes to be sent.CNcomment:ʵ�ʷ������ݵ��ֽ�����CNend
* @retval #HI_ERR_FAILURE  Data send failure. CNcomment:��������ʧ�ܡ�CNend
* @par ����:
*            @li hi_uart.h��Describes UART APIs.CNcomment:UART��ؽӿڡ�CNend
* @see  None
* @since Hi3861_V100R001C00
*/
hi_s32 hi_uart_write_immediately(hi_uart_idx id, const hi_u8 *data, hi_u32 data_len);

/**
* @ingroup  iot_uart
* @brief  Obtains UART settings. CNcomment:��ȡUART���ò�����CNend
*
* @par ����:
*           Obtains UART settings. CNcomment:��ȡָ��UART��ǰ���ò�����CNend
*
* @attention If extra_attr is HI_NULL, the current UART optimization parameters are not requested. This parameter
*            must be used after the hi_uart_init function is invoked.CNcomment:extra_attrΪHI_NULL��ʾ������
��ǰUART���Ż�����;���ڵ�����hi_uart_init����֮��ʹ�á�CNend
*
* @param  id            [IN] type #hi_uart_idx��UART port id. CNcomment:UART�˿ںš�CNend
* @param  param         [IN] type #hi_uart_attribute*��UART base settings.CNcomment:UART����������CNend
* @param  extra_attr    [IN] type #hi_uart_extra_attr*��UART extra settings. CNcomment:UART�Ż�������CNend
*
* @retval #HI_ERR_SUCCESS  Success.
* @retval #HI_ERR_FAILURE  Failure.
* @par ����:
*            @li hi_uart.h��Describes UART APIs.CNcomment:UART��ؽӿڡ�CNend
* @see  hi_uart_init��
* @since Hi3861_V100R001C00
*/
hi_u32 hi_uart_get_attribute(hi_uart_idx id, hi_uart_attribute *attr, hi_uart_extra_attr *extra_attr);

/**
* @ingroup  iot_uart
* @brief  Determine FIFO and soft buf is empty. CNcomment:�ж�FIFO�����BUF�Ƿ�Ϊ�ա�CNend
*
* @par ����:
*           Determine FIFO and soft buf is empty. CNcomment:�ж�ָ��UART��FIFO�����BUF�Ƿ�Ϊ�ա�CNend
*
* @attention This API must be used after the hi_uart_init function is called.
CNcomment:���ڵ�����hi_uart_init����֮��ʹ�á�CNend
*
* @param  id            [IN] type #hi_uart_idx��UART port id. CNcomment:UART�˿ںš�CNend
* @param  empty         [IN] type #hi_bool*��Store query result, HI_TRUE means empty, HI_FALSE means non-empty.
CNcomment:�洢��ѯ��������ΪHI_TRUE����FIFO�����BUF��Ϊ�գ����ΪHI_FALSE��ʾ�ǿա�CNend
*
* @retval #HI_ERR_SUCCESS  Success.
* @retval #HI_ERR_FAILURE  Failure.
* @par ����:
*            @li hi_uart.h��Describes UART APIs.CNcomment:UART��ؽӿڡ�CNend
* @see  hi_uart_init��
* @since Hi3861_V100R001C00
*/
BSP_RAM_TEXT_SECTION hi_u32 hi_uart_is_buf_empty(hi_uart_idx id, hi_bool *empty);

/**
* @ingroup  iot_uart
* @brief  Determine UART is busy. CNcomment:�ж�UART�Ƿ�æ��CNend
*
* @par ����:
*           Determine UART is busy. CNcomment:�ж�ָ��UART�Ƿ�æ��CNend
*
* @attention This API must be used after the hi_uart_init function is called.
CNcomment:���ڵ�����hi_uart_init����֮��ʹ�á�CNend
*
* @param  id            [IN] type #hi_uart_idx��UART port id. CNcomment:UART�˿ںš�CNend
* @param  busy          [IN] type #hi_bool*��Store query result, HI_TRUE means busy, HI_FALSE means not busy.
CNcomment:�洢��ѯ��������ΪHI_TRUE����UART��æ�����ΪHI_FALSE��ʾ���С�CNend
*
* @retval #HI_ERR_SUCCESS  Success.
* @retval #HI_ERR_FAILURE  Failure.
* @par ����:
*            @li hi_uart.h��Describes UART APIs.CNcomment:UART��ؽӿڡ�CNend
* @see  hi_uart_init��
* @since Hi3861_V100R001C00
*/
BSP_RAM_TEXT_SECTION hi_u32 hi_uart_is_busy(hi_uart_idx id, hi_bool *busy);

/**
* @ingroup  iot_uart
* @brief  Quits Read data.CNcomment:�˳����������ݡ�CNend
*
* @par ����:
*           Quits Read data. CNcomment:�˳����������ݡ�CNend
*
* @attention Only apply in block read mode.
CNcomment:�ýӿڽ�Ӧ��������������ģʽ�¡�CNend
* @param  id        [IN] type #hi_uart_idx��UART port id. CNcomment:UART�˿ںš�CNend
*
* @retval #HI_ERR_SUCCESS  Success.
* @retval #Other  Failure.
* @par ����:
*            @li hi_uart.h��Describes UART APIs.CNcomment:UART��ؽӿڡ�CNend
* @see  hi_uart_quit_read��
* @since Hi3861_V100R001C00
*/
hi_u32 hi_uart_quit_read(hi_uart_idx id);

/**
* @ingroup  iot_uart
* @brief  Save register-related values before going to deep sleep.CNcomment:��˯ǰ������ؼĴ������ݡ�CNend
*
* @par ����:
*       Regs-related values are saved before entering deep sleep to facilitate sleep recovery.
CNcomment:��˯ǰ������ؼĴ������ݣ��Ա���˯�ѻָ�UART��CNend
*
* @attention Called before deep sleep.
CNcomment:����˯ǰ���á�CNend
* @param  id        [IN] type #hi_uart_idx��UART port id. CNcomment:UART�˿ںš�CNend
*
* @retval #HI_ERR_SUCCESS  Success.
* @retval #Other  Failure.
* @par ����:
*            @li hi_uart.h��Describes UART APIs.CNcomment:UART��ؽӿڡ�CNend
* @see  hi_uart_lp_save��
* @since Hi3861_V100R001C00
*/
hi_u32 hi_uart_lp_save(hi_uart_idx id);

/**
* @ingroup  iot_uart
* @brief  Restore register related values after deep sleep wake up.CNcomment:��˯���Ѻ�ָ��Ĵ������ݡ�CNend
*
* @par ����:
*      Restore register related values after deep sleep wake up.CNcomment:��˯���Ѻ�ָ��Ĵ������ݡ�CNend
*
* @attention Called after deep sleep wake up.
CNcomment:��˯���Ѻ���á�CNend
* @param  id        [IN] type #hi_uart_idx��UART port id. CNcomment:UART�˿ںš�CNend
*
* @retval #HI_ERR_SUCCESS  Success.
* @retval #Other  Failure.
* @par ����:
*            @li hi_uart.h��Describes UART APIs.CNcomment:UART��ؽӿڡ�CNend
* @see  hi_uart_lp_restore��
* @since Hi3861_V100R001C00
*/
hi_u32 hi_uart_lp_restore(hi_uart_idx id);

#ifdef __cplusplus
}
#endif

#endif
