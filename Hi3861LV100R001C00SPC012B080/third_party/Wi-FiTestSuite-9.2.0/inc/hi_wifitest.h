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
* @brief  Init of sigma. CNcomment:SIGMA��ʼ����CNend
*
* @par ����:
*         Init of sigma. CNcomment:SIGMA��ʼ����CNend
*
* @attention None.
* @param  None.
*
* @retval None
* @par ����:
*           @li hi_diag.h��Describes SIGMA APIs.
CNcomment:�ļ���������SIGMA��ؽӿڡ�CNend
* @since Hi3861_V100R001C00
*/
hi_u32 hi_sigma_init(void);

/**
* @ingroup  iot_sigma
* @brief  Set taks size of sigma. CNcomment:����SIGMA�������ջ��С��CNend
*
* @par ����:
*         Set taks size of sigma. CNcomment:����SIGMA�������ջ��С��CNend
*
* @attention task size should not smaller than 0x400.
CNcomment:����ջ��С������0x400��CNend
* @param  channel_task_size      [IN] type #hi_u16 channel task size.CNcomment:ͨ������ջ��С��CNend
*
* @retval None
* @par ����:
*           @li hi_diag.h��Describes SIGMA APIs.
CNcomment:�ļ���������SIGMA��ؽӿڡ�CNend
* @since Hi3861_V100R001C00
*/
hi_void hi_sigma_set_channel_task_size(hi_u16 channel_task_size);

typedef  hi_s32 (*hi_sigma_input_func)(hi_u8 *data, hi_u32 data_len);
typedef  hi_s32 (*hi_sigma_output_func)(const hi_u8 *data, hi_u32 data_len);

/**
* @ingroup  iot_sigma
* @brief  Register sigma input function to replace uart input.
CNcomment:ע��SIGMA���뺯��������Ĭ�ϴ�UART��ȡSIGMA�������ݡ�CNend
*
* @par ����:
*      Register sigma input function to replace uart input.
CNcomment:ע��SIGMA���뺯��������Ĭ�ϴ�UART��ȡSIGMA�������ݡ�CNend
*
* @attention None.
* @param  sigma_input_func      [IN] type #hi_sigma_input_func��sigma input function.
CNcomment:SIGMA���뺯����CNend
*
* @retval #0                 Success.
* @retval #Other             Failure. For details, see hi_errno.h.
* @par ����:
*           @li hi_sigma.h��Describes SIGMA APIs.
CNcomment:�ļ���������SIGMA��ؽӿڡ�CNend
* @since Hi3861_V100R001C00
*/
hi_u32 hi_sigma_register_input_func(hi_sigma_input_func sigma_input_func);

/**
* @ingroup  iot_sigma
* @brief  Register sigma output function to replace uart output.
CNcomment:ע��SIGMA�������������Ĭ�ϴ�UART���SIGMA������ݡ�CNend
*
* @par ����:
*      Register sigma output function to replace uart output.
CNcomment:ע��SIGMA�������������Ĭ�ϴ�UART���SIGMA������ݡ�CNend
*
* @attention None.
* @param  sigma_output_func      [IN] type #hi_sigma_output_func��sigma output function.
CNcomment:SIGMA���������CNend
*
* @retval None
* @par ����:
*           @li hi_sigma.h��Describes SIGMA APIs.
CNcomment:�ļ���������SIGMA��ؽӿڡ�CNend
* @since Hi3861_V100R001C00
*/
hi_void hi_sigma_register_output_func(hi_sigma_output_func sigma_output_func);

#endif

