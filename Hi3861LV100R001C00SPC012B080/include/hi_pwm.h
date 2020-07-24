/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: PWM driver interfaces.
 * Author: hisilicon
 * Create: 2019-03-04
 */
/**
* @file hi_pwm.h
*
* Copyright (c) Hisilicon Technologies Co., Ltd. 2019. All rights reserved.  \n
*
* Description: PWM driver interfaces.
*/

/** @defgroup iot_pwm PWM
 *  @ingroup drivers
 */
#ifndef __HI_PWM_H__
#define __HI_PWM_H__

#include <hi_types.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @ingroup iot_pwm
 *
 * Enumerates the PWM clock sources.CNcomment:PWMʱ��Դö�١�CNend
 */
typedef enum {
    PWM_CLK_160M, /**< 160M APB clock.CNcomment:160M ����ʱ�� CNend */
    PWM_CLK_XTAL, /**< 25M External crystal.CNcomment:24M��40M �ⲿ���� CNend */
    PWM_CLK_MAX   /**< Maximum value, which cannot be used.CNcomment:���ֵ������ʹ��CNend */
} hi_pwm_clk_source;

/**
 * @ingroup iot_pwm
 *
 * Enumerates the PWM ports.CNcomment:PWM�˿�ö�١�CNend
 */
typedef enum {
    HI_PWM_PORT_PWM0 = 0, /**< PWM port0. Register base address: 0x40040000, multiplexed with GPIOX.
                             CNcomment:PWM0�˿ڡ��Ĵ�����ַ:0x40040000������GPIOX��CNend */
    HI_PWM_PORT_PWM1 = 1, /**< PWM port1. Register base address: 0x40040100, multiplexed with GPIOX.
                             CNcomment:PWM1�˿ڡ��Ĵ�����ַ:0x40040100������GPIOX��CNend */
    HI_PWM_PORT_PWM2 = 2, /**< PWM port2. Register base address: 0x40040200, multiplexed with GPIOX.
                             CNcomment:PWM2�˿ڡ��Ĵ�����ַ:0x40040200������GPIOX��CNend */
    HI_PWM_PORT_PWM3 = 3, /**< PWM port3. Register base address: 0x40040300, multiplexed with GPIOX.
                             CNcomment:PWM3�˿ڡ��Ĵ�����ַ:0x40040300������GPIOX��CNend */
    HI_PWM_PORT_PWM4 = 4, /**< PWM port4. Register base address: 0x40040400, multiplexed with GPIOX.
                             CNcomment:PWM4�˿ڡ��Ĵ�����ַ:0x40040400������GPIOX��CNend */
    HI_PWM_PORT_PWM5 = 5, /**< PWM port5. Register base address: 0x40040500, multiplexed with GPIOX.
                             CNcomment:PWM5�˿ڡ��Ĵ�����ַ:0x40040500������GPIOX��CNend */
    HI_PWM_PORT_MAX   /**< Maximum value, which cannot be used.CNcomment:���ֵ������ʹ��CNend */
} hi_pwm_port;

/**
* @ingroup iot_pwm
* @brief  Initializes the PWM module.CNcomment:PWM��ʼ����CNend
*
* @par   ����:
*            Initializes the PWM module.CNcomment:PWM��ʼ����CNend
* @attention
*        @li Before using the PWM function, ensure that the GPIO multiplexing relationship has been configured.
CNcomment:ʹ��PWM����ǰ��Ҫȷ��������GPIO���ù�ϵ��CNend
*        @li For details, see Hi3861 V100 API Development Guide.
CNcomment:�������÷�����μ�<Hi3861V100 API����ָ��>Demo����С�����˵����CNend
*        @li For details about the multiplexed GPIO, see the Hi3861 V100 Data Sheet.
CNcomment:���帴�õ�GPIO��μ�<Hi3861 оƬ Ӳ���û�ָ��>��CNend
*        @li Before using the PWM function, initialize the PWM.CNcomment:ʹ��PWM����ǰ��Ҫ�ȳ�ʼ����CNend
*
* @param  port [IN]  type #hi_pwm_port PWM port number.CNcomment:PWM�˿ںš�CNend
*
* @retval #HI_ERR_SUCCESS Success.
* @retval #Other          Failure. For details, see hi_errno.h.
* @par ����:
*            @li hi_pwm.h: Describes the APIs of the PWM module.CNcomment:�ļ���������PWM����ӿڡ�CNend
* @see hi_pwm_deinit | hi_pwm_start | hi_pwm_stop��
* @since Hi3861_V100R001C00
*/
hi_u32 hi_pwm_init(hi_pwm_port port);

/**
* @ingroup iot_pwm
* @brief  Deinitializes the PWM module.CNcomment:PWMȥ��ʼ����CNend
*
* @par   ����:
*            Deinitializes the PWM module.CNcomment:PWMȥ��ʼ����CNend
*
* @attention Deinitialize the PWM module when the function iss not used.
CNcomment:��ʹ��PWM����ʱȥ��ʼ����CNend
*
* @param  port [IN]  type #hi_pwm_port PWM port number.CNcomment:PWM�˿ںš�CNend
*
* @retval #HI_ERR_SUCCESS Success.
* @retval #Other          Failure. For details, see hi_errno.h.
* @par ����:
*            @li hi_pwm.h: Describes the APIs of the PWM module.CNcomment:�ļ���������PWM����ӿڡ�CNend
* @see hi_pwm_init��
* @since Hi3861_V100R001C00
*/
hi_u32 hi_pwm_deinit(hi_pwm_port port);

/**
* @ingroup iot_pwm
* @brief  Sets the clock type of the PWM module.CNcomment:����PWMģ��ʱ�����͡�CNend
*
* @par   ����:
*            This function is used to set the clock type of the PWM module.
CNcomment:�ú�����������PWMģ��ʱ�����͡�CNend
*
* @attention This setting takes effect for all PWM modules. The 150 MHz clock is used by default.
CNcomment:�����ö�����PWMģ�����Ч��Ĭ��Ϊ150Mʱ�ӡ�CNend
*
* @param  clk_type [IN] type #hi_pwm_clk_source Clock type. CNcomment:ʱ�����͡�CNend
*
* @retval #HI_ERR_SUCCESS Success.
* @retval #Other          Failure. For details, see hi_errno.h.
* @par ����:
*            @li hi_pwm.h: Describes the APIs of the PWM module.CNcomment:�ļ���������PWM����ӿڡ�CNend
* @see None
* @since Hi3861_V100R001C00
*/
hi_u32 hi_pwm_set_clock(hi_pwm_clk_source clk_type);

/**
* @ingroup iot_pwm
* @brief  Outputs the PWM signal according to the configured parameter.
*         PWM signal duty cycle = duty/freq Frequency = Clock source frequency/freq.
CNcomment:�����õĲ������PWM�źš�PWM�ź�ռ�ձ�=duty/freq��Ƶ��=ʱ��ԴƵ��/freq��CNend
*
* @par   ����:
*            Starts the PWM signal output.CNcomment:����PWM�ź������CNend
*
* @attention This API cannot be called in an interrupt.CNcomment:��֧�����ж��е��á�CNend
*
* @param  port [IN] type #hi_pwm_port PWM port number.CNcomment:PWM�˿ںš�CNend
* @param  duty [IN] type #hi_u16 PWM duty cycle count. Value range: [1, 65535]. The default value is 750.
CNcomment:PWMռ�ձȼ���ֵ��ȡֵ��ΧΪ:[1, 65535]��Ĭ��ֵΪ750��CNend
* @param  freq [IN] type #hi_u16 Frequency division multiple. Value range: [1, 65535]. The default value is 1500.
CNcomment:��Ƶ������ȡֵ��ΧΪ:[1, 65535]��Ĭ��ֵΪ1500��CNend
*
* @retval #HI_ERR_SUCCESS Success.
* @retval #Other          Failure. For details, see hi_errno.h.
* @par ����:
*            @li hi_pwm.h: Describes the APIs of the PWM module.CNcomment:�ļ���������PWM����ӿڡ�CNend
* @see  hi_pwm_init | hi_pwm_stop��
* @since Hi3861_V100R001C00
*/
hi_u32 hi_pwm_start(hi_pwm_port port, hi_u16 duty, hi_u16 freq);

/**
* @ingroup iot_pwm
* @brief  Stops the PWM signal output.CNcomment:ֹͣPWM�ź������CNend
*
* @par   ����:
*          Stops the PWM signal output.CNcomment: ֹͣPWM�ź������CNend
*
* @attention This API cannot be called in an interrupt.CNcomment:��֧�����ж��е��á�CNend
*
* @param  port [IN] type #hi_pwm_port PWM port number.CNcomment:PWM�˿ںš�CNend
*
* @retval #HI_ERR_SUCCESS Success.
* @retval #Other          Failure. For details, see hi_errno.h.
* @par ����:
*            @li hi_pwm.h: Describes the APIs of the PWM module.CNcomment:�ļ���������PWM����ӿڡ�CNend
* @see  hi_pwm_init | hi_pwm_start��
* @since Hi3861_V100R001C00
*/
hi_u32 hi_pwm_stop(hi_pwm_port port);

#ifdef __cplusplus
}
#endif
#endif
