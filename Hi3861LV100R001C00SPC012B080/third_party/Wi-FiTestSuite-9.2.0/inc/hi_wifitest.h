/*
 *Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2019. All rights reserved.
 *Description: Wi-Fi sigma test environment setup
 *Create: 2019-04-22
 */

#ifndef __HI_WIFITEST_H__
#define __HI_WIFITEST_H__

extern hi_u32 g_wait_sta_associate_sem;
extern hi_bool g_is_associate_by_sigma_flag;

/**
* @ingroup  iot_sigma
* @brief  Init of sigma. CNcomment:SIGMA初始化。CNend
*
* @par 描述:
*         Init of sigma. CNcomment:SIGMA初始化。CNend
*
* @attention None.
* @param  None.
*
* @retval None
* @par 依赖:
*           @li hi_diag.h：Describes SIGMA APIs.
CNcomment:文件用于描述SIGMA相关接口。CNend
* @since Hi3861_V100R001C00
*/
hi_u32 hi_sigma_init(void);

/**
* @ingroup  iot_sigma
* @brief  Set taks size of sigma. CNcomment:设置SIGMA相关任务栈大小。CNend
*
* @par 描述:
*         Set taks size of sigma. CNcomment:设置SIGMA相关任务栈大小。CNend
*
* @attention task size should not smaller than 0x400.
CNcomment:任务栈大小不低于0x400。CNend
* @param  channel_task_size      [IN] type #hi_u16 channel task size.CNcomment:通道任务栈大小。CNend
*
* @retval None
* @par 依赖:
*           @li hi_diag.h：Describes SIGMA APIs.
CNcomment:文件用于描述SIGMA相关接口。CNend
* @since Hi3861_V100R001C00
*/
hi_void hi_sigma_set_channel_task_size(hi_u16 channel_task_size);

typedef  hi_s32 (*hi_sigma_input_func)(hi_u8 *data, hi_u32 data_len);
typedef  hi_s32 (*hi_sigma_output_func)(const hi_u8 *data, hi_u32 data_len);

/**
* @ingroup  iot_sigma
* @brief  Register sigma input function to replace uart input.
CNcomment:注册SIGMA输入函数，代替默认从UART读取SIGMA输入数据。CNend
*
* @par 描述:
*      Register sigma input function to replace uart input.
CNcomment:注册SIGMA输入函数，代替默认从UART读取SIGMA输入数据。CNend
*
* @attention None.
* @param  sigma_input_func      [IN] type #hi_sigma_input_func，sigma input function.
CNcomment:SIGMA输入函数。CNend
*
* @retval #0                 Success.
* @retval #Other             Failure. For details, see hi_errno.h.
* @par 依赖:
*           @li hi_sigma.h：Describes SIGMA APIs.
CNcomment:文件用于描述SIGMA相关接口。CNend
* @since Hi3861_V100R001C00
*/
hi_u32 hi_sigma_register_input_func(hi_sigma_input_func sigma_input_func);

/**
* @ingroup  iot_sigma
* @brief  Register sigma output function to replace uart output.
CNcomment:注册SIGMA输出函数，代替默认从UART输出SIGMA相关数据。CNend
*
* @par 描述:
*      Register sigma output function to replace uart output.
CNcomment:注册SIGMA输出函数，代替默认从UART输出SIGMA相关数据。CNend
*
* @attention None.
* @param  sigma_output_func      [IN] type #hi_sigma_output_func，sigma output function.
CNcomment:SIGMA输出函数。CNend
*
* @retval None
* @par 依赖:
*           @li hi_sigma.h：Describes SIGMA APIs.
CNcomment:文件用于描述SIGMA相关接口。CNend
* @since Hi3861_V100R001C00
*/
hi_void hi_sigma_register_output_func(hi_sigma_output_func sigma_output_func);

#endif

