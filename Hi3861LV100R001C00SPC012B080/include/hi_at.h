/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: AT command interfaces.
 * Author: hisilicon
 * Create: 2019-10-15
 */

/**
* @file hi_at.h
*
* Copyright (c) Hisilicon Technologies Co., Ltd. 2019. All rights reserved.  \n
*
* Description: AT command interfaces.
*/

/** @defgroup iot_at  AT Command
 *  @ingroup dfx
 */
#ifndef __HI_AT_H__
#define __HI_AT_H__
#include <hi_types.h>

typedef hi_u32 (*at_call_back_func)(hi_s32 argc, const hi_char **argv);

typedef struct {
    hi_char *at_cmd_name;
    hi_s8   at_cmd_len;
    at_call_back_func at_test_cmd;
    at_call_back_func at_query_cmd;
    at_call_back_func at_setup_cmd;
    at_call_back_func at_exe_cmd;
} at_cmd_func;

typedef enum {
    AT_IDLE,
    AT_CMD_PROCESS,
    AT_DATA_RECVING,
    AT_DATA_SENDING,
    AT_TRANSPARENT,
} at_state_machine;

typedef struct {
    at_state_machine at_state;
    hi_u16 send_len;
    hi_u16 trans_len;
    hi_bool is_first_recv_data;
    hi_bool is_first_over_data;
    hi_u16 is_recv_end_char_flag;
} at_cmd_ctrl;

typedef  hi_s32 (*hi_at_input_func)(hi_u8 *data, hi_u32 data_len);
typedef  hi_s32 (*hi_at_output_func)(const hi_u8 *data, hi_u32 data_len);
/**
* @ingroup  iot_at
* @brief  Get at register output function.
CNcomment:��ȡע��AT�������������CNend
*
* @par ����:
*      Get at register output function.
CNcomment:ע��AT�����������������Ĭ�ϴ�UART���AT������ݡ�CNend
*
* @attention None.
* @param  None.
CNcomment:AT���������CNend
* @retval None
* @par ����:
*           @li hi_at.h��Describes at command APIs. CNcomment:�ļ���������atָ����ؽӿڡ�CNend
* @see  None
* @since Hi3861_V100R001C00
*/
hi_at_output_func hi_at_get_register_output_func(hi_void);

/**
* @ingroup  iot_at
* @brief  Registration command processing function.CNcomment:ע�����������CNend
*
* @par ����:
*           @li This command is invoked during initialization and cannot be invoked by multiple tasks.
CNcomment:�ڳ�ʼ���׶ε���, ��֧�ֶ�������á�CNend
*           @li A maximum of 20 different command tables can be registered.
CNcomment:�����ע��20����ͬ�������CNend
*
* @attention None
* @param  cmd_tbl    [IN] type #at_cmd_func*��Command table, which must be declared as a constant array and
*                    transferred to this parameter.CNcomment:�����
��������Ϊ�������鴫���ò�����CNend
* @param  cmd_num    [IN] type #hi_u16��The number of commands. The value must be equal to the actual number of
*                    commands in the command table. If it is less than the actual command number, only the number of
*                    commands equal to this value is registered. If it is greater than the actual command number,
*                    the command table will be accessed out of bounds.
CNcomment:�����������ĸ�������ֵ��������������ʵ�ʵ�������������С��ʵ������������ֻע����ڸ�ֵ�����������
          ����ʵ������������ᵼ��Խ����������CNend
*
* @retval #HI_ERR_SUCCESS         Success.
* @retval #Other     Failure. For details, see hi_errno.h.
* @par ����:
*           @li hi_at.h��Describes at command APIs. CNcomment:�ļ���������atָ����ؽӿڡ�CNend
* @see  None
* @since Hi3861_V100R001C00
*/
hi_u32 hi_at_register_cmd(HI_CONST at_cmd_func *cmd_tbl, hi_u16 cmd_num);

/**
* @ingroup  iot_at
* @brief  Register system AT command. CNcomment:ע��ϵͳAT���CNend
*
* @par ����:
*           Register system AT command. CNcomment:�ú�������ע��ϵͳAT���CNend
* @param None
* @retval None
*
* @par ����:
*           @li hi_at.h��Describes at command APIs. CNcomment:�ļ���������atָ����ؽӿڡ�CNend
* @see  None
* @since Hi3861_V100R001C00
*/
hi_void hi_at_sys_cmd_register(hi_void);

/**
* @ingroup  iot_at
* @brief  Register factory test AT command. CNcomment:ע��������AT���CNend
*
* @par ����:
*           Register factory test AT command. CNcomment:�ú�������ע��������AT���CNend
* @param None
* @retval None
*
* @par ����:
*           @li hi_at.h��Describes at command APIs. CNcomment:�ļ���������atָ����ؽӿڡ�CNend
* @see  None
* @since Hi3861_V100R001C00
*/
hi_void hi_at_factory_test_cmd_register(hi_void);

/**
* @ingroup  iot_at
* @brief  Formats the data and outputs it to AT command terminal.
CNcomment:�����ݸ�ʽ�������AT�����նˡ�CNend
*
* @par ����: Formats the data and outputs it to AT command terminal.
CNcomment:�����ݸ�ʽ�������AT�����նˡ�CNend
* @attention None
*
* @param fmt      [IN]  type #const hi_char *�� Formatting control string.CNcomment:��ʽ�������ַ�����CNend
* @param ...      [IN]  Optional parameter CNcomment:��ѡ������CNend
*
* @retval #>=0 Return the number of bytes stored in terminal, not counting the terminating null character.
CNcomment:����������ն˵��ֽ�����������������CNend
* @retval #-1 Failure
*
* @par ����:
*           @li hi_at.h��Describes at command APIs. CNcomment:�ļ���������atָ����ؽӿڡ�CNend
* @see None
* @since Hi3861_V100R001C00
*/
hi_s32 hi_at_printf(const hi_char *fmt, ...);

/**
* @ingroup  iot_at
* @brief  Initializes the AT task. CNcomment:AT���������ʼ����CNend
*
* @par ����:
*           Initializes the AT task. CNcomment:�ú������ڳ�ʼ��AT��������CNend
* @param None
* @retval #HI_ERR_SUCCESS         Success.
* @retval #Other     Failure. For details, see hi_errno.h.
*
* @par ����:
*           @li hi_at.h��Describes at command APIs. CNcomment:�ļ���������atָ����ؽӿڡ�CNend
* @see  None
* @since Hi3861_V100R001C00
*/
hi_u32 hi_at_init(hi_void);

/**
* @ingroup  iot_at
* @brief  Set taks size of AT. CNcomment:����AT�������ջ��С��CNend
*
* @par ����:
*         Set taks size of AT. CNcomment:����AT�������ջ��С��CNend
*
* @attention task size should not smaller than 0x400.
CNcomment:����ջ��С������0x400��CNend
* @param  channel_task_size      [IN] type #hi_u16 channel task size.CNcomment:ͨ������ջ��С��CNend
* @param  process_task_size      [IN] type #hi_u16 process task size.CNcomment:��������ջ��С��CNend
*
* @retval None
* @par ����:
*           @li hi_at.h��Describes at command APIs. CNcomment:�ļ���������atָ����ؽӿڡ�CNend
* @see  None
* @since Hi3861_V100R001C00
*/
hi_void hi_at_set_task_size(hi_u16 channel_task_size, hi_u16 process_task_size);

/**
* @ingroup  iot_at
* @brief  Set whether to check the UART busy status when low power vote.
CNcomment:���õ͹���ͶƱʱ�Ƿ���UART busy״̬��CNend
*
* @par ����:
*      Set whether to check the UART busy status when low power vote.
CNcomment:���õ͹���ͶƱʱ�Ƿ���UART busy״̬��CNend
*
* @attention UART busy status is checked by default.
CNcomment:Ĭ�ϵ͹���˯��ͶƱʱ���UART busy״̬��CNend
* @param  enable         [IN] type #hi_bool��enable status. CNcomment:�����Ƿ���UART busy״̬��CNend
*
* @retval None
* @par ����:
*           @li hi_at.h��Describes at command APIs. CNcomment:�ļ���������atָ����ؽӿڡ�CNend
* @see  None
* @since Hi3861_V100R001C00
*/
hi_void hi_at_set_check_uart_busy(hi_bool enable);

/**
* @ingroup  iot_at
* @brief  Register at input function to replace uart input.
CNcomment:ע��AT���뺯��������Ĭ�ϴ�UART��ȡAT�������ݡ�CNend
*
* @par ����:
*      Register at input function to replace uart input.
CNcomment:ע��AT���뺯��������Ĭ�ϴ�UART��ȡAT�������ݡ�CNend
*
* @attention None.
* @param  at_input_func      [IN] type #hi_at_input_func��at input funciton.
CNcomment:AT���뺯����CNend
* @retval #0                 Success.
* @retval #Other             Failure. For details, see hi_errno.h.
* @par ����:
*           @li hi_at.h��Describes at command APIs. CNcomment:�ļ���������atָ����ؽӿڡ�CNend
* @see  None
* @since Hi3861_V100R001C00
*/
hi_u32 hi_at_register_input_func(hi_at_input_func at_input_func);

/**
* @ingroup  iot_at
* @brief  Register at output function to replace uart output.
CNcomment:ע��AT�����������������Ĭ�ϴ�UART���AT������ݡ�CNend
*
* @par ����:
*      Register at output function to replace uart output.
CNcomment:ע��AT�����������������Ĭ�ϴ�UART���AT������ݡ�CNend
*
* @attention None.
* @param  at_output_func      [IN] type #hi_at_output_func��at output function.
CNcomment:AT���������CNend
* @retval None
* @par ����:
*           @li hi_at.h��Describes at command APIs. CNcomment:�ļ���������atָ����ؽӿڡ�CNend
* @see  None
* @since Hi3861_V100R001C00
*/
hi_void hi_at_register_output_func(hi_at_output_func at_output_func);

#endif
