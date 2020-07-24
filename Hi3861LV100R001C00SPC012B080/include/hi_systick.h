/**
* @file hi_systick.h
*
* Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2019. All rights reserved.  \n
* Description: system tick APIs.   \n
* Author: Hisilicon   \n
* Create: 2019-07-03
*/

/**
 * @defgroup systick System Tick Status
 * @ingroup drivers
 */
#ifndef __HI_SYSTICK_H__
#define __HI_SYSTICK_H__
#include <hi_types_base.h>

/**
* @ingroup  systick
* @brief  Obtains systick currect value. CNcomment:��ȡsystick��ǰ����ֵ��CNend
*
* @par ����:
* @li   Obtains the current count value of systick. The time of each value is determined by the systick clock source.
*       The systick clock is 32Khz, and the tick value is 1/32000 seconds.CNcomment:��ȡsystick��ǰ����ֵ��
ÿ��ֵ��ʱ����systickʱ��Դ������systickʱ��Ϊ32Khz��һ��tickֵΪ1/32000�롣CNend
* $li   After the system is powered on, systick immediately adds a count from 0.CNcomment:ϵͳ�ϵ����к�
systick���̴�0��ʼ������һ������CNend
*
* @attention The delay interface is invoked in the interface. Therefore, it is prohibited to invoke this interface in
*            the interrupt context.CNcomment:�ӿ��ڵ�������ʱ�ӿڣ����Խ�ֹ���ж��������е��øýӿڡ�CNend
* @param  None
*
* @retval #hi_u64 Indicates the obtained current count value.CNcomment:��ȡ���ĵ�ǰ����ֵ��CNend
*
* @par ����:
*           @li hi_systick.h��Describes systick APIs.CNcomment:�ļ���������SYSTICK��ؽӿڡ�CNend
* @see  hi_systick_clear��
* @since Hi3861_V100R001C00
*/
hi_u64 hi_systick_get_cur_tick(hi_void);

/**
* @ingroup  systick
* @brief  The value of systick is cleared.CNcomment:��systick����ֵ���㡣CNend
*
* @par ����:
*         The value of systick is cleared.CNcomment:��systick����ֵ���㡣CNend
*
* @attention After the interface is returned, the clock cycles of three systick clocks need to be cleared.
CNcomment:�ӿڷ��غ���Ҫ������systick��ʱ�����ڲŻ�������㡣CNend
* @param  None
*
* @retval None
* @par ����:
*           @li hi_systick.h��Describes systick APIs.CNcomment:�ļ���������SYSTICK��ؽӿڡ�CNend
* @see  hi_systick_get_cur_tick��
* @since Hi3861_V100R001C00
*/
hi_void hi_systick_clear(hi_void);

#endif
