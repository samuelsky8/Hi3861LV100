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
CNcomment:SHELL初始化函数。CNend
*
* @par 描述:
*      Shell initialization function.
CNcomment:SHELL初始化函数。CNend
*
* @attention None.
* @param None.
*
* @retval #0                 Success.
* @retval #Other             Failure. For details, see hi_errno.h.
* @par 依赖:
*           @li hi_shell.h：Describes SHELL APIs.
CNcomment:文件用于描述SHELL相关接口。CNend
* @since Hi3861_V100R001C00
*/
hi_u32 hi_shell_init(hi_void);

/**
* @ingroup  iot_shell
* @brief  Set taks size of SHELL. CNcomment:设置SHELL相关任务栈大小。CNend
*
* @par 描述:
*         Set taks size of SHELL. CNcomment:设置SHELL相关任务栈大小。CNend
*
* @attention task size should not smaller than 0x400.
CNcomment:任务栈大小不低于0x400。CNend
* @param  channel_task_size      [IN] type #hi_u16 channel task size.CNcomment:通道任务栈大小。CNend
* @param  process_task_size      [IN] type #hi_u16 process task size.CNcomment:处理任务栈大小。CNend
*
* @retval None
* @par 依赖:
*           @li hi_shell.h：Describes SHELL APIs.
CNcomment:文件用于描述SHELL相关接口。CNend
* @since Hi3861_V100R001C00
*/
hi_void hi_shell_set_task_size(hi_u16 channel_task_size, hi_u16 process_task_size);

/**
* @ingroup  iot_shell
* @brief  Get shell register output function.
CNcomment:获取SHELL注册的输出函数。CNend
*
* @par 描述:
*      Get shell register output function.
CNcomment:获取SHELL注册的输出函数。。CNend
*
* @attention None.
* @param  None.
*
* @retval #g_shell_output_func   Shell output function.
* @par 依赖:
*           @li hi_shell.h：Describes SHELL APIs.
CNcomment:文件用于描述SHELL相关接口。CNend
* @since Hi3861_V100R001C00
*/
hi_shell_output_func hi_shell_get_register_output_func(hi_void);

/**
* @ingroup  iot_shell
* @brief  Register shell input function to replace uart input.
CNcomment:注册SHELL输入函数，代替默认从UART读取SHELL输入数据。CNend
*
* @par 描述:
*      Register shell input function to replace uart input.
CNcomment:注册SHELL输入函数，代替默认从UART读取SHELL输入数据。CNend
*
* @attention None.
* @param  shell_input_func      [IN] type #hi_shell_input_func，shell input function.
CNcomment:SHELL输入函数。CNend
*
* @retval #0                 Success.
* @retval #Other             Failure. For details, see hi_errno.h.
* @par 依赖:
*           @li hi_shell.h：Describes SHELL APIs.
CNcomment:文件用于描述SHELL相关接口。CNend
* @since Hi3861_V100R001C00
*/
hi_u32 hi_shell_register_input_func(hi_shell_input_func shell_input_func);

/**
* @ingroup  iot_shell
* @brief  Register shell output function to replace uart output.
CNcomment:注册SHELL输出函数，代替默认从UART输出SHELL相关数据。CNend
*
* @par 描述:
*      Register shell output function to replace uart output.
CNcomment:注册SHELL输出函数，代替默认从UART输出SHELL相关数据。CNend
*
* @attention None.
* @param  shell_output_func      [IN] type #hi_shell_output_func，shell output function.
CNcomment:SHELL输出函数。CNend
*
* @retval None
* @par 依赖:
*           @li hi_shell.h：Describes SHELL APIs.
CNcomment:文件用于描述SHELL相关接口。CNend
* @since Hi3861_V100R001C00
*/
hi_void hi_shell_register_output_func(hi_shell_output_func shell_output_func);

#endif
