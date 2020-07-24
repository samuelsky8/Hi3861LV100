/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: watchdog internal interface.
 * Author: hisilicon
 * Create: 2019-03-04
 */


 /**
 * @file watchdog.h
 *
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019. All rights reserved.  \n
 *
 * Description: watchdog interfaces. \n
 */

#ifndef __BSP_INC_WATCHDOG_H__
#define __BSP_INC_WATCHDOG_H__

#include <hi3861_platform_base.h>
#include <hi_watchdog.h>

/**
* @ingroup  hct_watchdog
* @brief Watchdog callback function. CNcomment:���Ź����ڻص�������CNend
*
* @par ����:
*           Watchdog callback function. CNcomment:���Ź����ڻص�������CNend
*
* @attention None.
* @param  data [IN] type #hi_u32��Callback function parameter passing.CNcomment:�ص������������ݡ�CNend
*
* @retval None.
* @par ����:
*            @li watchdog.h���ļ������������Ź���ؽӿڡ�
* @see �ޡ�
* @since Hi3861_V100R001C00
*/
typedef hi_void (*hi_watchdog_func)(hi_u32 data);

/**
 * @ingroup hct_watchdog
 *
 * Watchdog mode. CNcomment:���Ź�ģʽ��CNend
 */
typedef enum {
    HI_WDG_MODE_NORMAL = 0,  /**< ��ͨģʽ�����Ź�����ʱ��λоƬ  */
    HI_WDG_MODE_INTER = 1,   /**< �ж�ģʽ�����Ź���һ�ε���ʱ����ע��Ļص����������Ź��ڶ��ε���ʱ��λоƬ  */
    HI_WDG_MODE_ERR,         /**< ������Σ�����ʹ��  */
} hi_wdg_mode;

/**
* @ingroup  hct_watchdog
* @brief  Clear the watchdog interrupt.CNcomment:������Ź��жϡ�CNend
*
* @par ����:
*           Clear the watchdog interrupt.CNcomment:������Ź��жϡ�CNend
*
* @attention �ޡ�
* @param  �ޡ�
*
* @retval �ޡ�
* @par ����:
*            @li watchdog.h���ļ������������Ź���ؽӿڡ�
* @see  �ޡ�
* @since Hi3861_V100R001C00
*/
HI_EXTERN hi_void hi_watchdog_int_clear(hi_void);

/**
* @ingroup  hct_watchdog
* @brief  Configure to enable the watchdog. CNcomment:����ʹ�ܿ��Ź���CNend
*
* @par ����:
*           Configure to enable the watchdog. CNcomment:����ʹ�ܿ��Ź���CNend
*
* @attention �ޡ�
* @param  mode         [IN] type #hi_wdg_mode ��Watchdog mode. CNcomment:���Ź�ģʽ��CNend
* @param  p_func       [IN] type #hi_watchdog_func��Configure the watchdog to interrupt mode and the function will be
called to notify the user when the watchdog first expires.
CNcomment:���ÿ��Ź�Ϊ�ж�ģʽʱ�����Ź���һ�ε���ʱ����øú���֪ͨ�û���CNend
* @param  data         [IN] type #hi_u32 Callback function enter parameter. CNcomment:�ص�������Ρ�CNend
* @param  over_time_ms [IN] type #hi_u32��Watchdog expiration time (unit: ms).
                        Expiration time calculation method: expiration time t = 2^(top+16)*1000/wd_clk,
                        where wd_clk is the watchdog clock frequency and top range is 0~15.
                        Therefore, there is a certain error between the expected expiration time and
                        the actual expiration time.
                        CNcomment:���Ź�����ʱ�䣨��λ��ms����
*                           ����ʱ����㷽��:����ʱ��t = 2^(top+16)*1000/wd_clk,����wd_clkΪ���Ź�ʱ��Ƶ�ʣ�topȡֵΪ0~15��
*                           ��������ĵ���ʱ����ʵ�ʵ���ʱ����һ����CNend
*
* @retval #0           Sunccess.
* @retval #��0         Failure. For details, see hi_errno.h.
* @par ����:
*            @li watchdog.h���ļ������������Ź���ؽӿڡ�
* @see  �ޡ�
* @since Hi3861_V100R001C00
*/
HI_EXTERN hi_u32 hi_watchdog_register(hi_wdg_mode mode, hi_watchdog_func p_func, hi_u32 data, hi_u32 over_time_ms);

HI_EXTERN hi_void watchdog_irq_handler(hi_u32 data);

#endif

