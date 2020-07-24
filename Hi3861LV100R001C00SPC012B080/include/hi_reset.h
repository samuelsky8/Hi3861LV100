/**
* @file hi_reset.h
*
* Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2019. All rights reserved.  \n
* Description: Active reset. CNcomment:������λ.CNend   \n
* Author: Hisilicon   \n
* Create: 2019-12-18
*/

/** @defgroup iot_sys  Active Reset
 * @ingroup system
 */

#ifndef __HI_RESET_H__
#define __HI_RESET_H__
#include <hi_types.h>
#include <hi_mdm_types.h>
#include <hi_ft_nv.h>

#ifdef __cplusplus
extern "C" {
#endif

#define HI_SYS_REBOOT_CAUSE_USR_BEGIN   0x8000
#define HI_SYS_REBOOT_CAUSE_USR_END     0x9FFF


/**
* @ingroup  iot_sys
*
* Cause for active restart. CNcomment:��������ԭ��CNend
*/
typedef enum {
    HI_SYS_REBOOT_CAUSE_UNKNOWN = 0,
    HI_SYS_REBOOT_CAUSE_CMD = 0x1,          /**< system reset begin. */
    HI_SYS_REBOOT_CAUSE_UPG = 0x100,        /**< upgrade reset begin. */
    HI_SYS_REBOOT_CAUSE_UPG_B,              /**< upgrade backup image reset. */
    HI_SYS_REBOOT_CAUSE_WIFI_MODE = 0x200,  /**< wifi module reset begin. */
    HI_SYS_REBOOT_CAUSE_USR_NROMAL_REBOOT = HI_SYS_REBOOT_CAUSE_USR_BEGIN, /**< user reset begin. */
    HI_SYS_REBOOT_CAUSE_USR0,
    HI_SYS_REBOOT_CAUSE_USR1,
    HI_SYS_REBOOT_CAUSE_MAX = HI_SYS_REBOOT_CAUSE_USR_END + 1,
} hi_sys_reboot_cause;

/**
* @ingroup  iot_sys
* @brief  System hard reboot. CNcomment:ϵͳӲ������CNend
*
* @par ����:
*          System Hard reboot:reset whole chip. CNcomment:Ӳ���� ����оƬ��λ��CNend
*
* @attention  None
*
* @param  cause         [IN] type #hi_sys_reboot_cause , reboot cause, see hi_sys_reboot_cause.
CNcomment:����ԭ��ȡֵ�μ�hi_sys_reboot_cause��CNend
*
*
* @retval None.
*
* @par ����:
*            @li hi_reset.h: Describes the APIs for obtaining system information.
CNcomment:�ļ���������ϵͳ��λ��ؽӿڡ�CNend
* @see None
* @since Hi3861_V100R001C00
*/
hi_void hi_hard_reboot(hi_sys_reboot_cause cause);

/**
* @ingroup  iot_sys
* @brief  System soft reboot. CNcomment:ϵͳ��������CNend
*
* @par ����:
*          System Soft reboot:part of peripheral won't reset(such as GPIO/PWM).
CNcomment:���������������費��λ����GPIO/PWM��CNend
* @attention
*           @li only GPIO and PWM are the default peripherals that won't reset when soft reboot. 
other peripherase need another setting.
CNcomment:��GPIO/PWM��������ʱĬ�ϲ���λ������������Ҫ��������CNend
*
* @param  cause         [IN] type #hi_sys_reboot_cause ,  reboot cause, see hi_sys_reboot_cause.
CNcomment:����ԭ��ȡֵ�μ�hi_sys_reboot_cause��CNend
*
*
* @retval None.
*
* @par ����:
*            @li hi_reset.h: Describes the APIs for obtaining system information.
CNcomment:�ļ���������ϵͳ��λ��ؽӿڡ�CNend
* @see None
* @since Hi3861_V100R001C00
*/
hi_void hi_soft_reboot(hi_sys_reboot_cause cause);

/**
* @ingroup  iot_sys
* @brief  Enables or disables the function of recording the reset times.
CNcomment:ʹ��(ȥʹ��)��¼��λ�������ܡ�CNend
*
* @par ����:
*     @li Enables or disables the function of recording the reset times. When the function of recording the reset times
*         is enabled, in order to avoid the issue that fast flash life exhaustion caused by writing NV when the system
*         is frequently powered on and off, NV will be written 30 seconds after the system is started.
CNcomment:ʹ��(ȥʹ��)��¼��λ�������ܡ�ʹ�ܸ�λ������¼���ܺ�
Ϊ����ϵͳ����Ƶ�����µ�ʱдNV����flash�������ٺľ����⣬ÿ������ʱ�����ϵ��30��ʱдNV,����������λ������CNend
*     @li When the number of reset times is updated, the flash memory needs to be written. Generally, when the system
*         frequently powers on and off and power-on NV write greatly hurts the flash service life, set enable to
*         HI_FALSE and check whether the service function is affected.
CNcomment:��λ����������Ҫִ��дFlash������ͨ����ϵͳ����Ƶ�����µ磬
���ܽ����ϵ�дNV����flash�������ٺľ��ĳ���ʱ����enable����ΪHI_FALSE��
ͬʱҪ�����Ƿ��ҵ�������Ӱ�졣CNend
*     @li Set enable takes effect after the next reset, and set disable takes effect when write NV next time.
CNcomment:���ÿ��������´θ�λ����Ч�����ùر������´�дNVʱ��Ч��CNend
*
* @attention
*   @li This feature should be enabled by default. CNcomment:�ù���Ĭ��ʹ�ܡ�CNend
*   @li It should be called in the initialization function of the app layer.
CNcomment:Ӧ����Ӧ�ò��ʼ�������е��á�CNend
*   @li Disabling this function may result in some influences. You are advised to disable it in scenarios where the
*       system is frequently powered on and off.CNcomment:�رոù�����Ҫ���Ƕ�ʹ�ø�λ����ҵ����
��Ӱ�죬������ϵͳ����Ƶ�����µ�ĳ����رոù��ܣ����������򿪸ù��ܡ�CNend
*
* @param enable [IN] type #hi_bool Enable/Disable. CNcomment:�Ƿ�ʹ�ܼ������ܡ�CNend
*
* @retval #0               Success.
* @retval #Other           Failure. For details, see hi_errno.h.
*
* @par ����:
*            @li hi_reset.h: Describes the APIs for obtaining system information.
CNcomment:�ļ���������ϵͳ��λ��ؽӿڡ�CNend
* @see None
* @since Hi3861_V100R001C00
*/
hi_u32 hi_enable_reset_times_save(hi_bool enable);

/**
* @ingroup  iot_sys
* @brief  Obtains reset times recorded in NV. CNcomment:��ȡNV�м�¼��ϵͳ��λ������CNend
*
* @par ����:
*          Obtains reset times recorded in NV. CNcomment:��ȡNV�м�¼��ϵͳ��λ������CNend
*
* @attention  None
*
* @param None
*
* @retval #HI_ERR_FAILURE  Read NV Failure.
* @retval #Other           Reboot times number. CNcomment:ϵͳ��λ������CNend
*
* @par ����:
*            @li hi_reset.h: Describes the APIs for obtaining system information.
CNcomment:�ļ���������ϵͳ��λ��ؽӿڡ�CNend
* @see None
* @since Hi3861_V100R001C00
*/
hi_u32 hi_get_reset_times(hi_void);

#ifdef __cplusplus
}
#endif

#endif /* __HI_RESET_H__ */

