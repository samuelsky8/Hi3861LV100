/**
* @file hi_watchdog.h
*
* Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2019. All rights reserved.  \n
* Description: Watchdog interfaces.   \n
* Author: Hisilicon   \n
* Create: 2019-07-03
*/

/**
 * @defgroup iot_watchdog Watchdog
 * @ingroup drivers
 */
#ifndef __HI_WATCHDOG_H__
#define __HI_WATCHDOG_H__

#include <hi_types_base.h>

/**
* @ingroup  iot_watchdog
* @brief Enables the watchdog.CNcomment:ʹ�ܿ��Ź���CNend
*
* @par ����:
*          Enables the watchdog.CNcomment:ʹ�ܿ��Ź���CNend
*
* @attention None
* @param  None
*
* @retval None
* @par ����:
*            @li hi_watchdog.h��describes the watchdog APIs.CNcomment:�ļ������������Ź���ؽӿڡ�CNend
* @see None
* @since Hi3861_V100R001C00
*/
hi_void hi_watchdog_enable(hi_void);

/**
* @ingroup  iot_watchdog
* @brief Feeds the watchdog.CNcomment:ι����CNend
*
* @par ����: Feeds the watchdog.CNcomment:ι����CNend
*
* @attention None
* @param  None
*
* @retval None
* @par ����:
*            @li hi_watchdog.h��describes the watchdog APIs.CNcomment:�ļ������������Ź���ؽӿڡ�CNend
* @see None
* @since Hi3861_V100R001C00
*/
hi_void hi_watchdog_feed(hi_void);

/**
* @ingroup  iot_watchdog
* @brief Disables the watchdog.CNcomment:�رտ��Ź���CNend
*
* @par ����:
*           @li Disable the clock enable control of the watchdog.CNcomment:��ֹWatchDogʱ��ʹ�ܿ���λ��CNend
*           @li Mask the watchdog reset function.CNcomment:����WatchDog��λ���ܡ�CNend
*
* @attention None
* @param  None
*
* @retval None
* @par ����:
*            @li hi_watchdog.h��describes the watchdog APIs.CNcomment:�ļ������������Ź���ؽӿڡ�CNend
* @see None
* @since Hi3861_V100R001C00
*/
hi_void hi_watchdog_disable(hi_void);

#endif
