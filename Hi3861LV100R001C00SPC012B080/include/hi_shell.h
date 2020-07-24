/**
* @file hi_shell.h
*
* Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2020. All rights reserved.  \n
* Description: Shell Interaction APIs. \n
* Author: HiSilicon \n
* Create: 2020-2-16
*/

/** @defgroup iot_shell Shell
 *  @ingroup dfx
 */

#ifndef __HI_SHELL_H__
#define __HI_SHELL_H__

#include <hi_types.h>
#include <hi_uart.h>

typedef  hi_s32 (*hi_shell_input_func)(hi_u8 *data, hi_u32 data_len);
typedef  hi_s32 (*hi_shell_output_func)(const hi_u8 *data, hi_u32 data_len);
/**
* @ingroup  iot_shell
* @brief  Shell initialization function.
CNcomment:SHELL��ʼ��������CNend
*
* @par ����:
*      Shell initialization function.
CNcomment:SHELL��ʼ��������CNend
*
* @attention None.
* @param None.
*
* @retval #0                 Success.
* @retval #Other             Failure. For details, see hi_errno.h.
* @par ����:
*           @li hi_shell.h��Describes SHELL APIs.
CNcomment:�ļ���������SHELL��ؽӿڡ�CNend
* @since Hi3861_V100R001C00
*/
hi_u32 hi_shell_init(hi_void);

/**
* @ingroup  iot_shell
* @brief  Set taks size of SHELL. CNcomment:����SHELL�������ջ��С��CNend
*
* @par ����:
*         Set taks size of SHELL. CNcomment:����SHELL�������ջ��С��CNend
*
* @attention task size should not smaller than 0x400.
CNcomment:����ջ��С������0x400��CNend
* @param  channel_task_size      [IN] type #hi_u16 channel task size.CNcomment:ͨ������ջ��С��CNend
* @param  process_task_size      [IN] type #hi_u16 process task size.CNcomment:��������ջ��С��CNend
*
* @retval None
* @par ����:
*           @li hi_shell.h��Describes SHELL APIs.
CNcomment:�ļ���������SHELL��ؽӿڡ�CNend
* @since Hi3861_V100R001C00
*/
hi_void hi_shell_set_task_size(hi_u16 channel_task_size, hi_u16 process_task_size);

/**
* @ingroup  iot_shell
* @brief  Get shell register output function.
CNcomment:��ȡSHELLע������������CNend
*
* @par ����:
*      Get shell register output function.
CNcomment:��ȡSHELLע��������������CNend
*
* @attention None.
* @param  None.
*
* @retval #g_shell_output_func   Shell output function.
* @par ����:
*           @li hi_shell.h��Describes SHELL APIs.
CNcomment:�ļ���������SHELL��ؽӿڡ�CNend
* @since Hi3861_V100R001C00
*/
hi_shell_output_func hi_shell_get_register_output_func(hi_void);

/**
* @ingroup  iot_shell
* @brief  Register shell input function to replace uart input.
CNcomment:ע��SHELL���뺯��������Ĭ�ϴ�UART��ȡSHELL�������ݡ�CNend
*
* @par ����:
*      Register shell input function to replace uart input.
CNcomment:ע��SHELL���뺯��������Ĭ�ϴ�UART��ȡSHELL�������ݡ�CNend
*
* @attention None.
* @param  shell_input_func      [IN] type #hi_shell_input_func��shell input function.
CNcomment:SHELL���뺯����CNend
*
* @retval #0                 Success.
* @retval #Other             Failure. For details, see hi_errno.h.
* @par ����:
*           @li hi_shell.h��Describes SHELL APIs.
CNcomment:�ļ���������SHELL��ؽӿڡ�CNend
* @since Hi3861_V100R001C00
*/
hi_u32 hi_shell_register_input_func(hi_shell_input_func shell_input_func);

/**
* @ingroup  iot_shell
* @brief  Register shell output function to replace uart output.
CNcomment:ע��SHELL�������������Ĭ�ϴ�UART���SHELL������ݡ�CNend
*
* @par ����:
*      Register shell output function to replace uart output.
CNcomment:ע��SHELL�������������Ĭ�ϴ�UART���SHELL������ݡ�CNend
*
* @attention None.
* @param  shell_output_func      [IN] type #hi_shell_output_func��shell output function.
CNcomment:SHELL���������CNend
*
* @retval None
* @par ����:
*           @li hi_shell.h��Describes SHELL APIs.
CNcomment:�ļ���������SHELL��ؽӿڡ�CNend
* @since Hi3861_V100R001C00
*/
hi_void hi_shell_register_output_func(hi_shell_output_func shell_output_func);

#endif
