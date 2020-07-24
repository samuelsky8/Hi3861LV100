/**
* @file hi_diag.h
*
* Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2019. All rights reserved.  \n
* Description: Diagnosis (DIAG) Interaction APIs. \n
* Author: Hisilicon \n
* Create: 2019-4-3
*/

/** @defgroup iot_diag Diagnostic
 *  @ingroup dfx
 */

#ifndef __HI_DIAG_H__
#define __HI_DIAG_H__

#include <hi_types.h>
#include <hi_uart.h>

/**
* @ingroup  iot_diag
* @brief Registers the callback function for DIAG channel status changes.
CNcomment:ע��DIAGͨ��״̬����ص�������CNend
*
* @par ����:
*           Registers the callback function for DIAG channel status changes. That is, when the DIAG channel is
*           connected or disconnected, the function registered by this API is called back.
CNcomment:ע��DIAGͨ������ص�������������DIAGͨ�����ӻ�Ͽ�ʱ����ص����ӿ�ע��ĺ�������CNend
*
* @attention None
* @param  connect_notify_func [IN] type #hi_diag_connect_f��User function. CNcomment:�û�������CNend
*
* @retval #0                 Success.
* @retval #Other             Failure. For details, see hi_errno.h.
* @par ����:
*           @li hi_diag.h��Describes DIAG APIs.
CNcomment:�ļ���������DIAG��ؽӿڡ�CNend
* @see  None
* @since Hi3861_V100R001C00
*/
HI_EXTERN hi_u32 hi_diag_register_connect_notify(hi_diag_connect_f connect_notify_func);

/**
* @ingroup  iot_diag
* @brief Checks the connection status of the DIAG channel. CNcomment:���DIAGͨ������״̬�ĺ�����CNend
*
* @par ����:
*           Checks the connection status of the DIAG channel. CNcomment:���DIAGͨ���Ƿ�������״̬�ĺ��� ��CNend
*
* @attention None
* @param None
*
* @retval HI_FALSE disconnected. CNcomment:���ڷ�����״̬��CNend
* @retval HI_TRUE  connected. CNcomment:��������״̬��CNend
* @par ����:
*           @li hi_diag.h��Describes DIAG APIs.
CNcomment:�ļ���������DIAG��ؽӿڡ�CNend
* @see  None
* @since Hi3861_V100R001C00
*/
HI_EXTERN hi_bool hi_diag_is_connect(hi_void);

/**
* @ingroup  iot_diag
* @brief  Registers the command handling function. CNcomment:ע�����������CNend
*
* @par ����:
*           @li Called at initialize stage, does NOT support multiable task calls.
CNcomment:�ڳ�ʼ���׶ε���, ��֧�ֶ�������á�CNend
*           @li The DIAG subsystem supports a maximum of 10 different command tables.
CNcomment:�����ע��10����ͬ�������CNend
*
* @attention None
* @param  p_cmd_tbl  [IN] type #const hi_diag_cmd_reg_obj*��Command table, which must be declared as a constant array
*                              and transmitted to this parameter.
CNcomment:�������������Ϊ�������鴫���ò�����CNend
* @param  cmd_num    [IN] type #hi_u16��Number of commands. The value cannot be 0. CNcomment:���������
���usCmdNumΪ0��pstCmdTbl��Ϊ0����ȡ��ע�ᡣCNend
*
* @retval #0                 Success.
* @retval #Other             Failure. For details, see hi_errno.h.
* @par ����:
*           @li hi_diag.h��Describes DIAG APIs.
CNcomment:�ļ���������DIAG��ؽӿڡ�CNend
* @see  None
* @since Hi3861_V100R001C00
*/
HI_EXTERN hi_u32 hi_diag_register_cmd(const hi_diag_cmd_reg_obj* cmd_tbl, hi_u16 cmd_num);

/**
* @ingroup  iot_diag
* @brief  Reports DIAG packets. CNcomment:DIAG���ϱ���CNend
*
* @par ����:
*           Reports DIAG channel packets to the DIAG client.
CNcomment:�ú������ڽ�DIAGͨ�������ϱ���DIAG�ͻ��ˡ�CNend
*
* @attention
*         This API can not be used in interrupt when report data synchronously.
CNcomment:��ͬ���ϱ�����ʱ���ýӿڲ�֧�����ж��е��á�CNend
* @param  cmd_id       [IN] type #hi_u16��DIAG data packet ID. CNcomment:DIAGӦ���ID��CNend
* @param  instance_id  [IN] type #hi_u8��Command type.This parameter is used to obtain the command type in the
*                           option parameter of the command callback function hi_diag_cmd_f.currently only support
*                           HI_DIAG_CMD_INSTANCE_LOCAL.
CNcomment:�������͡�������ص�����hi_diag_cmd_f��option�����л�ȡ�������ͣ��ں�����ʹ��
�˽ӿڻظ�����ʱ��ͨ�����������ݡ���ǰ��֧��HI_DIAG_CMD_INSTANCE_LOCAL��CNend
* @param  buffer       [IN] type #hi_pbyte��Buffer address of the data packet. This function does not release the
*                      pointer. CNcomment:���ݰ���buffer��ַ���ú��������ͷŸ�ָ�롣CNend
* @param  buffer_size  [IN] type #hi_u16��Data packet size (unit: byte), range[0, 65507]
CNcomment:���ݰ���С����λ��byte����ȡֵ��Χ[0, 65507]��CNend
* @param  sync         [IN] type #hi_bool��Synchronous or asynchronous DIAG packet pushing. TRUE indicates that the
*                           packets are pushed synchronously and the operation is blocked. FALSE indicates the packets
*                           are pushed asynchronously (with the memory allocated, the packet is cashed by the OS queue
*                           before being pushed), and the operation is not blocked.
CNcomment:DIAG��ͬ��/�첽�ϱ����á�TRUE��ʾͬ���ϱ�, ��������; FALSE��ʾ�첽
��ͨ�������ڴ��, ��OS���л������ϱ�), ������������CNend
*
*
* @retval #0                 Success.
* @retval #Other             Failure. For details, see hi_errno.h.
* @par ����:
*           @li hi_diag.h��Describes DIAG APIs.
CNcomment:�ļ���������DIAG��ؽӿڡ�CNend
* @see  None
* @since Hi3861_V100R001C00
*/
HI_EXTERN hi_u32 hi_diag_report_packet(hi_u16 cmd_id, hi_u8 instance_id, hi_pbyte buffer,
                                       hi_u16 buffer_size, hi_bool sync);

/**
* @ingroup  iot_diag
* @brief  Sends ACK packets to the DIAG client. CNcomment:Ӧ��ظ���CNend
*
* @par ����:
*           Sends ACK packets to the DIAG client. CNcomment:�ú������ڻظ����Ļ�ACK��DIAG�ͻ��ˡ�CNend
*
* @attention
*         This API can not be used in interrupt.CNcomment:�ýӿڲ�֧�����ж��е��á�CNend
* @param  cmd_id       [IN] type #hi_u16��DIAG ACK packet ID. CNcomment:DIAG��ID��CNend
* @param  instance_id  [IN] type #hi_u8��Command type.This parameter is used to obtain the command type in the
*                           option parameter of the command callback function hi_diag_cmd_f.currently only support
*                           HI_DIAG_CMD_INSTANCE_LOCAL.
CNcoment:������ص�����HI_DIAG_CMD_F��option�����л�ȡ�������ͣ��ں�����ʹ�ô˽ӿڻظ�
����ʱ��ͨ�����������ݡ���ǰ��֧��HI_DIAG_CMD_INSTANCE_LOCAL��CNend
* @param  buffer       [IN] type #hi_pbyte��Buffer address of the data packet. This function does not release the
*                      pointer. CNcomment:���ݰ���buffer��ַ���ú��������ͷŸ�ָ�롣CNend
* @param  buffer_size  [IN] type #hi_u16��Data packet size(unit: byte), range[0, 1024]
CNcomment:���ݰ���С����λ��byte����ȡֵ��Χ[0, 1024]��CNend
*
* @retval #HI_ERR_CONSUMED   Success.
* @retval #Other             Failure. For details, see hi_errno.h.
* @par ����:
*           @li hi_diag.h��Describes DIAG APIs.
CNcomment:�ļ���������DIAG��ؽӿڡ�CNend
* @see  None
* @since Hi3861_V100R001C00
*/
HI_EXTERN hi_u32 hi_diag_send_ack_packet(hi_u16 cmd_id, hi_u8 instance_id, hi_pvoid buffer, hi_u16 buffer_size);

/**
* @ingroup  iot_diag
* @brief  Registers the callback function for notifying DIAG operations.
CNcomment:ע��DIAG����֪ͨ�ص�������CNend
*
* @par ����:
*           Carbon copies data to the app layer by using a callback function in the case of data interaction between
*           the host and the board.CNcommand:�ú������ڵ���λ���뵥�������ݽ�������ʱ��
������ͨ���ص��������͸�Ӧ�ò㡣CNend
*
* @attention None
* @param  cmd_notify_func  [IN] type #hi_diag_cmd_notify_f*��When data interaction occurs between the HSO and the board,
*                                    this API is used to notify the app layer.
CNcomment:��HSO�뵥�������ݽ�������ʱ��ͨ���ýӿ�֪ͨӦ�ò㡣CNend
*
*
* @retval #0                 Success.
* @retval #Other             Failure. For details, see hi_errno.h.
* @par ����:
*           @li hi_diag.h��Describes DIAG APIs.
CNcomment:�ļ���������DIAG��ؽӿڡ�CNend
* @see  None
* @since Hi3861_V100R001C00
*/
HI_EXTERN hi_u32 hi_diag_register_cmd_notify(hi_diag_cmd_notify_f cmd_notify_func);

/**
* @ingroup  iot_diag
* @brief  Sets the UART parameters of the DIAG channel. CNcomment:�������ͨ��UART������CNend
*
* @par ����:
*           Sets the UART parameters of the used by the DIAG subsystem before the DIAG subsystem is initialized.
CNcomment:�ú��������������ϵͳ��ʼ��֮ǰ�����������ϵͳʹ�õ�UART����ز�����CNend
*
* @attention The parameters must be set before the initialization of the DIAG subsystem.
CNcomment:�����������ϵͳ��ʼ��֮ǰ���òſ���Ч��CNend
* @param  uart_port [IN] type #hi_uart_idx��UART port number used by the DIAG subsystem.
CNcomment:�����ϵͳʹ�õ�UART�˿ںš�CNend
* @param  uart_cfg  [IN] type #hi_uart_attribute��UART configuration used by the DIAG subsystem.
CNcomment:�����ϵͳʹ�õ�UART���á�CNend
*
* @retval #0                 Success.
* @retval #Other             Failure. For details, see hi_errno.h.
* @par ����:
*           @li hi_diag.h��Describes DIAG APIs.
CNcomment:�ļ���������DIAG��ؽӿڡ�CNend
* @see  None
* @since Hi3861_V100R001C00
*/
HI_EXTERN hi_u32 hi_diag_set_uart_param(hi_uart_idx uart_port, hi_uart_attribute uart_cfg);

/**
* @ingroup  iot_diag
* @brief  Initializes the DIAG subsystem. CNcomment:�����ϵͳ��ʼ����CNend
*
* @par ����:
*           Initializes the DIAG subsystem. CNcomment:�ú������ڳ�ʼ�������ϵͳ��CNend
*
* @attention The initialization of the DIAG subsystem needs to be performed only once. Repeated initialization is
*            invalid. CNcomment:�����ϵͳ��ʼ��ֻ��ִ��һ�Σ���γ�ʼ����Ч��CNend
* @param None
*
* @retval #0                 Success.
* @retval #Other             Failure. For details, see hi_errno.h.
* @par ����:
*           @li hi_diag.h��Describes DIAG APIs.
CNcomment:�ļ���������DIAG��ؽӿڡ�CNend
* @see  None
* @since Hi3861_V100R001C00
*/
HI_EXTERN hi_u32 hi_diag_init(hi_void);

/**
* @ingroup  iot_diag
*
* Structure for querying the number of command tables and statistic object tables.
CNcomment:����ע���б��ͳ��������ע���б������ѯ�ṹ�塣CNend
*/
typedef struct {
    hi_u8 cmd_list_total_cnt;    /**< Number of command registration tables can be registered.
                                    CNcomment:�ܹ�֧��ע��������б���� CNend */
    hi_u8 cmd_list_used_cnt;     /**< Number of registered command tables.
                                    CNcomment:�Ѿ�ע��������б���� CNend */
    hi_u8 stat_list_total_cnt;   /**< Number of statistic object tables can be registered. Currently not support.
                                    CNcomment:�ܹ�֧��ע���ͳ���������б��������ǰ�ݲ�֧�֡� CNend */
    hi_u8 stat_list_used_cnt;    /**< Number of registered statistic object tables. Currently not support.
                                    CNcomment:�Ѿ�ע���ͳ���������б��������ǰ�ݲ�֧�֡� CNend */
} hi_diag_cmd_stat_reg_info;

/**
* @ingroup  iot_diag
* @brief  Queries the registration status of the command tables and statistic tables of the DIAG subsystem.
CNcomment:��ѯ�����ϵͳ�����б��ͳ�����б�ע�������CNend
*
* @par ����:
*      Queries the registration status of the command tables and statistic tables of the DIAG subsystem.
*      Number of registered command tables and number of command tables can be registered/ Number of registered
*      statistic object tables
CNcomment:��ѯ�ܹ�֧��ע��/�Ѿ�ע��������б�������ܹ�֧��ע��/�Ѿ�ע���ͳ���������б������CNend
*
* @attention None
* @param     None
*
* @retval #hi_diag_cmd_stat_reg_info Structure of the number of registered command tables and statistic tables.
CNcomment:�����б��ͳ�����б�ע�������Ϣ�ṹ�塣CNend
* @par ����:
*           @li hi_diag.h��Describes DIAG APIs.
CNcomment:�ļ���������DIAG��ؽӿڡ�CNend
* @see  None
* @since Hi3861_V100R001C00
*/
HI_EXTERN hi_diag_cmd_stat_reg_info hi_diag_get_cmd_stat_reg_info(hi_void);

typedef struct {
    hi_u32 data0;
    hi_u32 data1;
    hi_u32 data2;
    hi_u32 data3;
}diag_log_msg;

/**
* @ingroup  iot_diag
* @brief  Reports usr packets. CNcomment:�ϱ��û���־��CNend
*
* @par ����:
*      Reports usr packets. CNcomment:�ϱ��û���־��Ϣ��CNend
*
* @attention None
* @param  diag_usr_msg   [IN] type #hi_diag_layer_msg��log message. CNcomment:��־��Ϣ��CNend
* @param  msg_level      [IN] type #hi_u16��level of log message, [HI_MSG_USR_L0, HI_MSG_USR_L4].
CNcomment:��־��Ϣ����ȡֵ��:HI_MSG_USR_L0- HI_MSG_USR_L4��CNend
*
* @retval #0                 Success.
* @retval #Other             Failure. For details, see hi_errno.h.
* @par ����:
*           @li hi_diag.h��Describes DIAG APIs.
CNcomment:�ļ���������DIAG��ؽӿڡ�CNend
* @see  None
* @since Hi3861_V100R001C00
*/
hi_u32 hi_diag_report_usr_msg(const hi_diag_layer_msg* diag_usr_msg, hi_u16 msg_level);

/**
* @ingroup  iot_diag
* @brief  Reports simple packet that without data. CNcomment:�ϱ�����־����Я���������ݡ�CNend
*
* @par ����:
*      Reports simple packets, fixed module ID. CNcomment:�ϱ�����־��Ϣ���̶�ģ��ID��
*
* @attention None
* @param  msg_id         [IN] type #hi_u32��log message ID. CNcomment:��־��ϢID��CNend
* @param  msg_level      [IN] type #hi_u16��log message level, [HI_MSG_SYS_L0, HI_MSG_SYS_L2]
CNcomment:��־��Ϣ����ȡֵ��:HI_MSG_SYS_L0- HI_MSG_SYS_L2��CNend
*
* @retval #0                 Success.
* @retval #Other             Failure. For details, see hi_errno.h.
* @par ����:
*           @li hi_diag.h��Describes DIAG APIs.
CNcomment:�ļ���������DIAG��ؽӿڡ�CNend
* @see  None
* @since Hi3861_V100R001C00
*/
hi_u32 hi_diag_log_msg0(hi_u32 msg_id, hi_u16 msg_level);

/**
* @ingroup  iot_diag
* @brief  Reports simple packet that with one word data. CNcomment:�ϱ�����־��Я��1�����ݡ�CNend
*
* @par ����:
*      Reports simple packets, fixed module ID. CNcomment:�ϱ�����־��Ϣ���̶�ģ��ID��CNend
*
* @attention None
* @param  msg_id         [IN] type #hi_u32��log message ID. CNcomment:��־��ϢID��CNend
* @param  d0             [IN] type #hi_u32��first data. CNcomment:Я���ĵ�1�����ݡ�Cnend
* @param  msg_level      [IN] type #hi_u16��log message level, [HI_MSG_SYS_L0, HI_MSG_SYS_L2]
CNcomment:��־��Ϣ����ȡֵ��:HI_MSG_SYS_L0- HI_MSG_SYS_L2��CNend
*
* @retval #0                 Success.
* @retval #Other             Failure. For details, see hi_errno.h.
* @par ����:
*           @li hi_diag.h��Describes DIAG APIs.
CNcomment:�ļ���������DIAG��ؽӿڡ�CNend
* @see  None
* @since Hi3861_V100R001C00
*/
hi_u32 hi_diag_log_msg1(hi_u32 msg_id, hi_u32 d0, hi_u16 msg_level);

/**
* @ingroup  iot_diag
* @brief  Reports simple packet that with 2 words data. CNcomment:�ϱ�����־��Я��2�����ݡ�CNend
*
* @par ����:
*      Reports simple packets, fixed module ID. CNcomment:�ϱ�����־��Ϣ���̶�ģ��ID��CNend
*
* @attention None
* @param  msg_id         [IN] type #hi_u32��log message ID. CNcomment:��־��ϢID��CNend
* @param  d0             [IN] type #hi_u32��first data. CNcomment:Я���ĵ�1�����ݡ�CNend
* @param  d1             [IN] type #hi_u32��second data. CNcomment:Я���ĵ�2�����ݡ�CNend
* @param  msg_level      [IN] type #hi_u16��log message level, [HI_MSG_SYS_L0, HI_MSG_SYS_L2]
CNcomment:��־��Ϣ����ȡֵ��:HI_MSG_SYS_L0- HI_MSG_SYS_L2��CNend
*
* @retval #0                 Success.
* @retval #Other             Failure. For details, see hi_errno.h.
* @par ����:
*           @li hi_diag.h��Describes DIAG APIs.
CNcomment:�ļ���������DIAG��ؽӿڡ�CNend
* @see  None
* @since Hi3861_V100R001C00
*/
hi_u32 hi_diag_log_msg2(hi_u32 msg_id, hi_u32 d0, hi_u32 d1, hi_u16 msg_level);

/**
* @ingroup  iot_diag
* @brief  Reports simple packet that with three words data. CNcomment:�ϱ�����־��Я��3�����ݡ�CNend
*
* @par ����:
*      Reports simple packets, fixed module ID. CNcomment:�ϱ�����־��Ϣ���̶�ģ��ID��CNend
*
* @attention None
* @param  msg_id         [IN] type #hi_u32��log message ID. CNcomment:��־��ϢID��CNend
* @param  d0             [IN] type #hi_u32��first data. CNcomment:Я���ĵ�1�����ݡ�Cnend
* @param  d1             [IN] type #hi_u32��second data. CNcomment:Я���ĵ�2�����ݡ�CNend
* @param  d2             [IN] type #hi_u32��third data. CNcomment:Я���ĵ�3�����ݡ�CNend
* @param  msg_level      [IN] type #hi_u16��log message level, [HI_MSG_SYS_L0, HI_MSG_SYS_L2]
CNcomment:��־��Ϣ����ȡֵ��:HI_MSG_SYS_L0- HI_MSG_SYS_L2��CNend
*
* @retval #0                 Success.
* @retval #Other             Failure. For details, see hi_errno.h.
* @par ����:
*           @li hi_diag.h��Describes DIAG APIs.
CNcomment:�ļ���������DIAG��ؽӿڡ�CNend
* @see  None
* @since Hi3861_V100R001C00
*/
hi_u32 hi_diag_log_msg3(hi_u32 msg_id, hi_u32 d0, hi_u32 d1, hi_u32 d2, hi_u16 msg_level);

/**
* @ingroup  iot_diag
* @brief  Reports simple packet that with four words data. CNcomment:�ϱ�����־��Я��4�����ݡ�CNend
*
* @par ����:
*      Reports simple packets, fixed module ID. CNcomment:�ϱ�����־��Ϣ���̶�ģ��ID��CNend
*
* @attention None
* @param  msg_id         [IN] type #hi_u32��log message ID. CNcomment:��־��ϢID��CNend
* @param  log_msg        [IN] type #diag_log_msg��four words. CNcomment:Я��4�����ݡ�CNend
* @param  msg_level      [IN] type #hi_u16��log message level, [HI_MSG_SYS_L0, HI_MSG_SYS_L2]
CNcomment:��־��Ϣ����ȡֵ��:HI_MSG_SYS_L0- HI_MSG_SYS_L2��CNend
*
* @retval #0                 Success.
* @retval #Other             Failure. For details, see hi_errno.h.
* @par ����:
*           @li hi_diag.h��Describes DIAG APIs.
CNcomment:�ļ���������DIAG��ؽӿڡ�CNend
* @see  None
* @since Hi3861_V100R001C00
*/
hi_u32 hi_diag_log_msg4(hi_u32 msg_id, diag_log_msg log_msg, hi_u16 msg_level);

/**
* @ingroup  iot_diag
* @brief  Reports simple packet that with one buffer data. CNcomment:�ϱ�����־��Я������buffer��CNend
*
* @par ����:
*      Reports simple packets, fixed module ID. CNcomment:�ϱ�����־��Ϣ���̶�ģ��ID��CNend
*
* @attention A maximum of 99 bytes can be send in one diag packet, so param size cannot be greater than 99.
CNcomment:diag��������ܷ�99�ֽ����ݣ�����size���ܴ���99��CNend
* @param  msg_id         [IN] type #hi_u32��log message ID. CNcomment:��־��ϢID��CNend
* @param  buffer         [IN] type #hi_pvoid��address of the data. CNcomment:Я��������buffer�׵�ַ��CNend
* @param  size           [IN] type #hi_16��buffer size (unit byte).
CNcomment:Я��������buffer����(��λbyte)��CNend
* @param  msg_level      [IN] type #hi_u16��log message level, [HI_MSG_SYS_L0, HI_MSG_SYS_L2]
CNcomment:��־��Ϣ����ȡֵ��:HI_MSG_SYS_L0- HI_MSG_SYS_L2��CNend
*
* @retval #0                 Success.
* @retval #Other             Failure. For details, see hi_errno.h.
* @par ����:
*           @li hi_diag.h��Describes DIAG APIs.
CNcomment:�ļ���������DIAG��ؽӿڡ�CNend
* @see  None
* @since Hi3861_V100R001C00
*/
hi_u32 hi_diag_log_msg_buffer(hi_u32 msg_id, hi_pvoid buffer, hi_u16 size, hi_u16 msg_level);

/**
* @ingroup  iot_diag
* @brief  Reports layer log that without data. CNcomment:�ϱ�������־����Я���������ݡ�CNend
*
* @par ����:
*      Reports layer log that without data. CNcomment:�ϱ�������־����Я���������ݡ�CNend
*
* @attention None
* @param  msg_id         [IN] type #hi_u32��log message ID. CNcomment:��־��ϢID��CNend
* @param  module_id      [IN] type #hi_u16��message module ID��describe which module the log belongs to.
CNcomment:��Ϣģ��ID��������־�����ĸ�ģ�顣CNend
*
* @retval #0                 Success.
* @retval #Other             Failure. For details, see hi_errno.h.
* @par ����:
*           @li hi_diag.h��Describes DIAG APIs.
CNcomment:�ļ���������DIAG��ؽӿڡ�CNend
* @see  None
* @since Hi3861_V100R001C00
*/
hi_u32 hi_diag_layer_msg0(hi_u32 msg_id, hi_u16 module_id);

/**
* @ingroup  iot_diag
* @brief  Reports layer log that with one word data. CNcoment:�ϱ�������־��Я��1�����ݡ�CNend
*
* @par ����:
*      Reports layer log that with one word data. CNcoment:�ϱ�������־��Я��1�����ݡ�CNend
*
* @attention None
* @param  msg_id         [IN] type #hi_u32��log message ID. CNcomment:��־��ϢID��CNend
* @param  module_id      [IN] type #hi_u16��message module ID��describe which module the log belongs to.
CNcomment:��Ϣģ��ID��������־�����ĸ�ģ�顣CNend
* @param  d0             [IN] type #hi_u32��first data. CNcomment:Я���ĵ�1�����ݡ�CNend
*
* @retval #0                 Success.
* @retval #Other             Failure. For details, see hi_errno.h.
* @par ����:
*           @li hi_diag.h��Describes DIAG APIs.
CNcomment:�ļ���������DIAG��ؽӿڡ�CNend
* @see  None
* @since Hi3861_V100R001C00
*/
hi_u32 hi_diag_layer_msg1(hi_u32 msg_id, hi_u16 module_id, hi_u32 d0);

/**
* @ingroup  iot_diag
* @brief  Reports layer log that with two words data. CNcoment:�ϱ�������־��Я��2�����ݡ�CNend
*
* @par ����:
*      Reports layer log that with two words data. CNcoment:�ϱ�������־��Я��2�����ݡ�CNend
*
* @attention None
* @param  msg_id         [IN] type #hi_u32��log message ID. CNcomment:��־��ϢID��CNend
* @param  module_id      [IN] type #hi_u16��message module ID��describe which module the log belongs to.
CNcomment:��Ϣģ��ID��������־�����ĸ�ģ�顣CNend
* @param  d0             [IN] type #hi_u32��first data. CNcomment:Я���ĵ�1�����ݡ�CNend
* @param  d1             [IN] type #hi_u32��second data. CNcomment:Я���ĵ�2�����ݡ�CNend
*
* @retval #0                 Success.
* @retval #Other             Failure. For details, see hi_errno.h.
* @par ����:
*           @li hi_diag.h��Describes DIAG APIs.
CNcomment:�ļ���������DIAG��ؽӿڡ�CNend
* @see  None
* @since Hi3861_V100R001C00
*/
hi_u32 hi_diag_layer_msg2(hi_u32 msg_id, hi_u16 module_id, hi_u32 d0, hi_u32 d1);

/**
* @ingroup  iot_diag
* @brief  Reports layer log that with 3 words data. CNcoment:�ϱ�������־��Я��3�����ݡ�CNend
*
* @par ����:
*      Reports layer log that with 3 words data. CNcoment:�ϱ�������־��Я��3�����ݡ�CNend
*
* @attention None
* @param  msg_id         [IN] type #hi_u32��log message ID. CNcomment:��־��ϢID��CNend
* @param  module_id      [IN] type #hi_u16��message module ID��describe which module the log belongs to.
CNcomment:��Ϣģ��ID��������־�����ĸ�ģ�顣CNend
* @param  d0             [IN] type #hi_u32��first data. CNcomment:Я���ĵ�1�����ݡ�CNend
* @param  d1             [IN] type #hi_u32��second data. CNcomment:Я���ĵ�2�����ݡ�CNend
* @param  d2             [IN] type #hi_u32��third data. CNcomment:Я���ĵ�3�����ݡ�CNend
*
* @retval #0                 Success.
* @retval #Other             Failure. For details, see hi_errno.h.
* @par ����:
*           @li hi_diag.h��Describes DIAG APIs.
CNcomment:�ļ���������DIAG��ؽӿڡ�CNend
* @see  None
* @since Hi3861_V100R001C00
*/
hi_u32 hi_diag_layer_msg3(hi_u32 msg_id, hi_u16 module_id, hi_u32 d0, hi_u32 d1, hi_u32 d2);

/**
* @ingroup  iot_diag
* @brief  Reports layer log that with 4 words data. CNcoment:�ϱ�������־��Я��4�����ݡ�CNend
*
* @par ����:
*      Reports layer log that with 4 words data. CNcoment:�ϱ�������־��Я��4�����ݡ�CNend
*
* @attention None
* @param  msg_id         [IN] type #hi_u32��log message ID. CNcomment:��־��ϢID��CNend
* @param  module_id      [IN] type #hi_u16��message module ID��describe which module the log belongs to.
CNcomment:��Ϣģ��ID��������־�����ĸ�ģ�顣CNend
* @param  log_msg        [IN] type #diag_log_msg��four data to report. CNcomment:Я��4�����ݡ�CNend
*
* @retval #0                 Success.
* @retval #Other             Failure. For details, see hi_errno.h.
* @par ����:
*           @li hi_diag.h��Describes DIAG APIs.
* @since Hi3861_V100R001C00
*/
hi_u32 hi_diag_layer_msg4(hi_u32 msg_id, hi_u16 module_id, diag_log_msg log_msg);

/**
* @ingroup  iot_diag
* @brief  Reports layer log that with one buffer data. CNcomment:�ϱ�������־��Я������buffer��CNend
*
* @par ����:
*      Reports layer log that with one buffer data. CNcomment:�ϱ�������־��Я������buffer��CNend
*
* @attention A maximum of 99 bytes can be send in one diag packet, so param size cannot be greater than 99.
CNcomment:diag��������ܷ�99�ֽ����ݣ�����size���ܴ���99��CNend
* @param  msg_id         [IN] type #hi_u32��log message ID. CNcomment:��־��ϢID��CNend
* @param  module_id      [IN] type #hi_u16��message module ID��describe which module the log belongs to.
CNcomment:��Ϣģ��ID��������־�����ĸ�ģ�顣CNend
* @param  buffer         [IN] type #const hi_pvoid��address of the data. CNcomment:Я��������buffer�׵�ַ��CNend
* @param  size           [IN] type #hi_16��buffer size (unit byte).
CNcomment:Я��������buffer����(��λbyte)��CNend
*
* @retval #0                 Success.
* @retval #Other             Failure. For details, see hi_errno.h.
* @par ����:
*           @li hi_diag.h��Describes DIAG APIs.
CNcomment:�ļ���������DIAG��ؽӿڡ�CNend
* @see  None
* @since Hi3861_V100R001C00
*/
hi_u32 hi_diag_layer_msg_buffer(hi_u32 msg_id, hi_u16 module_id, const hi_void *buffer, hi_u16 size);

typedef struct {
    hi_u16 size1;
    hi_u16 size2;
} diag_buffer_size;

/**
* @ingroup  iot_diag
* @brief  Reports layer log that with two buffer data. CNcomment:�ϱ�������־��֧��Я����������buffer��CNend
*
* @par ����:
*      Reports layer log that with two buffer data. CNcomment:�ϱ�������־��֧��Я����������buffer��CNend
*
* @attention A maximum of 99 bytes can be send in one diag packet.A space is reserved between two buffers.
             Therefore, the sum of buffer_size.size1 and buffer_size.size2 cannot be greater than 98.
CNcomment:diag��������ܷ�99�ֽ����ݣ�����buffer֮���Ԥ��һ���ո����Բ���buffer_size.size1��buffer_size.size2�ĺͲ��ܴ���98��CNend
* @param  msg_id         [IN] type #hi_u32��log message ID. CNcomment:��־��ϢID��CNend
* @param  module_id      [IN] type #hi_u16��message module ID��describe which module the log belongs to.
CNcomment:��Ϣģ��ID��������־�����ĸ�ģ�顣CNend
* @param  buf1           [IN] type #const hi_void *��address of the first buffer.
CNcomment:Я��������buffer1�׵�ַ��CNend
* @param  buf1           [IN] type #const hi_void *��address of the second buffer.
CNcomment:Я��������buffer2�׵�ַ��CNend
* @param  buffer_size    [IN] type #diag_buffer_size��two buffer size (unit byte).
CNcomment:Я��������buffer����(��λbyte)��CNend
*
* @retval #0                 Success.
* @retval #Other             Failure. For details, see hi_errno.h.
* @par ����:
*           @li hi_diag.h��Describes DIAG APIs.
* @since Hi3861_V100R001C00
*/
hi_u32 hi_diag_layer_two_buffer(hi_u32 msg_id, hi_u16 module_id, const hi_void *buf1,
                                const hi_void *buf2, diag_buffer_size buffer_size);

/**
* @ingroup  iot_diag
* @brief  Set whether to check the UART busy status when low power vote.
CNcomment:���õ͹���ͶƱʱ�Ƿ���UART busy״̬��CNend
*
* @par ����:
*      Set whether to check the UART busy status when low power vote.
CNcomment:���õ͹���ͶƱʱ�Ƿ���UART busy״̬��CNend
*
* @attention UART busy status is not checked by default.
CNcomment:Ĭ�ϵ͹���˯��ͶƱʱ�����UART busy״̬��CNend
* @param  enable         [IN] type #hi_bool��enable status. CNcomment:�����Ƿ���UART busy״̬��CNend
*
* @retval None
* @par ����:
*           @li hi_diag.h��Describes DIAG APIs.
CNcomment:�ļ���������DIAG��ؽӿڡ�CNend
* @since Hi3861_V100R001C00
*/
hi_void hi_diag_set_check_uart_busy(hi_bool enable);

typedef  hi_s32 (*hi_diag_input_func)(hi_u8 *data, hi_u32 data_len);
typedef  hi_s32 (*hi_diag_output_func)(const hi_u8 *data, hi_u32 data_len);

/**
* @ingroup  iot_diag
* @brief  Register diag input function to replace uart input.
CNcomment:ע��DIAG���뺯��������Ĭ�ϴ�UART��ȡDIAG�������ݡ�CNend
*
* @par ����:
*      Register diag input function to replace uart input.
CNcomment:ע��DIAG���뺯��������Ĭ�ϴ�UART��ȡDIAG�������ݡ�CNend
*
* @attention None.
* @param  diag_input_func      [IN] type #hi_diag_input_func��diag input function.
CNcomment:DIAG���뺯����CNend
*
* @retval #0                 Success.
* @retval #Other             Failure. For details, see hi_errno.h.
* @par ����:
*           @li hi_diag.h��Describes DIAG APIs.
CNcomment:�ļ���������DIAG��ؽӿڡ�CNend
* @since Hi3861_V100R001C00
*/
hi_u32 hi_diag_register_input_func(hi_diag_input_func diag_input_func);

/**
* @ingroup  iot_diag
* @brief  Register diag output function to replace uart output.
CNcomment:ע��DIAG�������������Ĭ�ϴ�UART���DIAG������ݡ�CNend
*
* @par ����:
*      Register diag output function to replace uart output.
CNcomment:ע��DIAG�������������Ĭ�ϴ�UART���DIAG������ݡ�CNend
*
* @attention None.
* @param  diag_output_func      [IN] type #hi_diag_output_func��diag output function.
CNcomment:DIAG���������CNend
*
* @retval None
* @par ����:
*           @li hi_diag.h��Describes DIAG APIs.
CNcomment:�ļ���������DIAG��ؽӿڡ�CNend
* @since Hi3861_V100R001C00
*/
hi_void hi_diag_register_output_func(hi_diag_output_func diag_output_func);

/**
* @ingroup  iot_diag
* @brief  Set taks size of DIAG. CNcomment:����DIAG�������ջ��С��CNend
*
* @par ����:
*         Set taks size of DIAG. CNcomment:����DIAG�������ջ��С��CNend
*
* @attention task size should not smaller than 0x400.
CNcomment:����ջ��С������0x400��CNend
* @param  channel_task_size      [IN] type #hi_u16 channel task size.CNcomment:ͨ������ջ��С��CNend
* @param  process_task_size      [IN] type #hi_u16 process task size.CNcomment:��������ջ��С��CNend
*
* @retval None
* @par ����:
*           @li hi_diag.h��Describes DIAG APIs.
CNcomment:�ļ���������DIAG��ؽӿڡ�CNend
* @since Hi3861_V100R001C00
*/
hi_void hi_diag_set_task_size(hi_u16 channel_task_size, hi_u16 process_task_size);

#endif
