/**
* @file hi_gpio.h
*
* Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2019. All rights reserved. \n
* Description: IO interface. \n
* Author: Hisilicon \n
* Create: 2019-07-13
*/

/**
* @defgroup iot_gpio GPIO
* @ingroup drivers
*/
#ifndef __HI_GPIO_H__
#define __HI_GPIO_H__


#include <hi_types_base.h>

/**
* @ingroup iot_gpio
*
* GPIO ID.
*/
typedef enum {
    HI_GPIO_IDX_0,     /**< GPIO0*/
    HI_GPIO_IDX_1,     /**< GPIO1*/
    HI_GPIO_IDX_2,     /**< GPIO2*/
    HI_GPIO_IDX_3,     /**< GPIO3*/
    HI_GPIO_IDX_4,     /**< GPIO4*/
    HI_GPIO_IDX_5,     /**< GPIO5*/
    HI_GPIO_IDX_6,     /**< GPIO6*/
    HI_GPIO_IDX_7,     /**< GPIO7*/
    HI_GPIO_IDX_8,     /**< GPIO8*/
    HI_GPIO_IDX_9,     /**< GPIO9*/
    HI_GPIO_IDX_10,    /**< GPIO10*/
    HI_GPIO_IDX_11,    /**< GPIO11*/
    HI_GPIO_IDX_12,    /**< GPIO12*/
    HI_GPIO_IDX_13,    /**< GPIO13*/
    HI_GPIO_IDX_14,    /**< GPIO14*/
    HI_GPIO_IDX_MAX,   /**< Maximum value, which cannot be used.CNcomment:���ֵ����������ʹ��CNend*/
} hi_gpio_idx;


/**
* @ingroup iot_gpio
*
* I/O level. CNcomment:GPIO��ƽ״̬��CNend
*/
typedef enum {
    HI_GPIO_VALUE0 = 0,      /**< Low level.CNcomment:�͵�ƽCNend*/
    HI_GPIO_VALUE1           /**< High level.CNcomment:�ߵ�ƽCNend*/
} hi_gpio_value;

/**
* @ingroup iot_gpio
*
* I/O direction. CNcomment:GPIO����CNend
*/
typedef enum {
    HI_GPIO_DIR_IN = 0,       /**< Input.CNcomment:���뷽��CNend*/
    HI_GPIO_DIR_OUT           /**< Output.CNcomment:�������CNend*/
} hi_gpio_dir;

/**
* @ingroup iot_gpio
*
* I/O interrupt trigger mode. This bit is used with HI_GPIO_INT_POLARITY.
CNcomment:GPIO�жϴ�����ʽ����hi_gpio_int_polarity���ʹ�á�CNend
*/
typedef enum {
    HI_INT_TYPE_LEVEL = 0, /**< The interrupt is triggered in level-sensitive mode. CNcomment:��ƽ�����ж�CNend */
    HI_INT_TYPE_EDGE   /**< Interrupt triggered at the rising edge or falling edge.CNcomment:���ش����ж�CNend */
} hi_gpio_int_type;

/**
* @ingroup iot_gpio
*
* I/O interrupt polarity. This pin is used with HI_GPIO_INT.
CNcomment:IO�жϼ��ԣ���hi_gpio_int_type���ʹ�á�CNend
*/
typedef enum {
    HI_GPIO_EDGE_FALL_LEVEL_LOW = 0,  /**< Interrupt triggered at low level or falling edge.
                                         CNcomment:�͵�ƽ���½��ش����ж�CNend */
    HI_GPIO_EDGE_RISE_LEVEL_HIGH      /**< Interrupt triggered at high level or rising edge.
                                         CNcomment:�ߵ�ƽ�������ش����ж�CNend */
} hi_gpio_int_polarity;


/**
* @ingroup  iot_gpio
* @brief  Callback function when GPIO interruption happens.CNcomment:GPIO�жϻص�������CNend
*
* @par ����:
*           Callback function when GPIO interruption happens.CNcomment:GPIO�жϻص�������CNend
*
* @attention None
*
* @param  arg     [IN] type #hi_void *��arg of interrupt callback function. CNcomment:�жϻص�������Ρ�CNend
*
* @retval None
* @par ����:
*           @li hi_gpio.h��Describes GPIO APIs.�ļ���������GPIO��ؽӿڡ�
* @see  None
* @since Hi3861_V100R001C00
*/
typedef hi_void (*gpio_isr_callback) (hi_void *arg);

/**
* @ingroup  iot_gpio
* @brief  Initializes GPIO module.CNcomment:GPIOģ���ʼ����CNend
*
* @par ����:
*           Initializes GPIO module.CNcomment:GPIOģ���ʼ����CNend
*
* @attention
* @li This API needs to be invoked during initialization to enable the GPIO interrupt so that the I/O interrupt
*     can be responded.CNcomment:��Ҫ�ڳ�ʼ���׶ε��øýӿ�ʹ��GPIO�жϣ�ʹ��IO�жϿ��Եõ���Ӧ��CNend
* @li This interface cannot be invoked repeatedly. It can be invoked only once in the initialization phase.
CNcomment:�ýӿڲ�֧���ظ����ã�ֻ���ڳ�ʼ���׶ε���һ�Ρ�CNend
*
* @param  None
*
* @retval #0       Success.
* @retval #Other   Failure. For details, see hi_errno.h.
* @par ����:
*           @li hi_gpio.h��Describes GPIO APIs.�ļ���������GPIO��ؽӿڡ�
* @see  None
* @since Hi3861_V100R001C00
*/
hi_u32 hi_gpio_init(hi_void);

/**
* @ingroup  iot_gpio
* @brief  Deinitializes GPIO module. CNcomment:GPIOģ��ȥ��ʼ����CNend
*
* @par ����:
*           Deinitializes GPIO module. CNcomment:GPIOģ��ȥ��ʼ����CNend
*
* @attention
* @li This interface is used to disable the GPIO interrupt. After the GPIO interrupt is called, the GPIO interrupt
*     cannot be responded.CNcomment:�ýӿڹ���Ϊȥʹ��GPIO�жϣ����ú�GPIO�жϽ��ò�����Ӧ��CNend
*
* @param  None
*
* @retval #0       Success.
* @retval #Other   Failure. For details, see hi_errno.h.
* @par ����:
*           @li hi_gpio.h��Describes GPIO APIs.�ļ���������GPIO��ؽӿڡ�
* @see  None
* @since Hi3861_V100R001C00
*/
hi_u32 hi_gpio_deinit(hi_void);

/**
* @ingroup  iot_gpio
* @brief  Sets the direction of a single I/O pin.CNcomment:����ĳ��GPIO�ܽŷ���CNend
*
* @par ����:
*           Sets the direction of a single I/O pin.CNcomment:����ĳ��GPIO�ܽŷ���CNend
*
* @attention None
* @param  id [IN]    type #hi_gpio_idx��I/O index.CNcomment:GPIO������CNend
* @param  dir   [IN] type #hi_gpio_dir��I/O direction.CNcomment:GPIO����CNend
*
* @retval #0       Success.
* @retval #Other   Failure. For details, see hi_errno.h.
* @par ����:
*           @li hi_gpio.h��Describes GPIO APIs.�ļ���������GPIO��ؽӿڡ�
* @see  hi_gpio_get_dir
* @since Hi3861_V100R001C00
*/
hi_u32 hi_gpio_set_dir(hi_gpio_idx id, hi_gpio_dir dir);

/**
* @ingroup  iot_gpio
* @brief  Gets the direction of a single I/O pin.CNcomment:��ȡĳ��GPIO�ܽŷ���CNend
*
* @par ����:
*           Gets the direction of a single I/O pin.CNcomment:��ȡĳ��GPIO�ܽŷ���CNend
*
* @attention None
* @param  id    [IN]  type #hi_gpio_idx��I/O index.CNcomment:GPIO������CNend
* @param  dir   [OUT] type #hi_gpio_dir*��I/O direction.CNcomment:GPIO����CNend
*
* @retval #0       Success.
* @retval #Other   Failure. For details, see hi_errno.h.
* @par ����:
*           @li hi_gpio.h��Describes GPIO APIs.�ļ���������GPIO��ؽӿڡ�
* @see  hi_gpio_set_dir
* @since Hi3861_V100R001C00
*/
hi_u32 hi_gpio_get_dir(hi_gpio_idx id, hi_gpio_dir *dir);

/**
* @ingroup  iot_gpio
* @brief  Sets the output level of a single I/O pin.CNcomment:���õ���GPIO�ܽ������ƽ״̬��CNend
*
* @par ����:
*           Sets the output level of a single I/O pin.CNcomment:���õ���GPIO�ܽ������ƽ״̬��CNend
*
* @attention None
*
* @param  id [IN]    type #hi_gpio_idx��I/O index.CNcomment:GPIO������CNend
* @param  val [IN] type #hi_gpio_value��output value. CNcomment:���ֵ��CNend
*                 @li 0��low level.CNcomment:�͵�ƽ��CNend
*                 @li 1��high level.CNcomment:�ߵ�ƽ��CNend
*
* @retval #0       Success.
* @retval #Other   Failure. For details, see hi_errno.h.
* @par ����:
*           @li hi_gpio.h��Describes GPIO APIs.�ļ���������GPIO��ؽӿڡ�
* @see  hi_gpio_get_input_val��
* @since Hi3861_V100R001C00
*/
hi_u32 hi_gpio_set_ouput_val(hi_gpio_idx id, hi_gpio_value val);

/**
* @ingroup  iot_gpio
* @brief  Obtains the input level of a single I/O pin.CNcomment:��ȡĳ��IO�ܽ������ƽ״̬��CNend
*
* @par ����:
*           Obtains the input level of a single I/O pin.CNcomment:��ȡĳ��IO�ܽ������ƽ״̬��CNend
*
* @attention None
* @param  id  [IN]  type #hi_gpio_idx��I/O index.CNcomment:GPIO������CNend
* @param  val [OUT] type #hi_gpio_value*��Output value.CNcomment:���ֵ��CNend
*                 @li 0��low level.CNcomment:�͵�ƽ��CNend
*                 @li 1��high level.CNcomment:�ߵ�ƽ��CNend
*
* @retval #0       Success.
* @retval #Other   Failure. For details, see hi_errno.h.
* @par ����:
*           @li hi_gpio.h��Describes GPIO APIs.�ļ���������GPIO��ؽӿڡ�
* @see  hi_gpio_set_ouput_val��
* @since Hi3861_V100R001C00
*/
hi_u32 hi_gpio_get_output_val(hi_gpio_idx id, hi_gpio_value* val);

/**
* @ingroup  iot_gpio
* @brief  Obtains the input level of a single I/O pin.CNcomment:��ȡĳ��IO�ܽ������ƽ״̬��CNend
*
* @par ����:
*           Obtains the input level of a single I/O pin.CNcomment:��ȡĳ��IO�ܽ������ƽ״̬��CNend
*
* @attention None
* @param  id  [IN]  type #hi_gpio_idx��I/O index.CNcomment:GPIO������CNend
* @param  val [OUT] type #hi_gpio_value*��Output value.CNcomment:���ֵ��CNend
*                 @li 0��low level.CNcomment:�͵�ƽ��CNend
*                 @li 1��high level.CNcomment:�ߵ�ƽ��CNend
*
* @retval #0       Success.
* @retval #Other   Failure. For details, see hi_errno.h.
* @par ����:
*           @li hi_gpio.h��Describes GPIO APIs.�ļ���������GPIO��ؽӿڡ�
* @see  None
* @since Hi3861_V100R001C00
*/
hi_u32 hi_gpio_get_input_val(hi_gpio_idx id, hi_gpio_value *val);

/**
* @ingroup  iot_gpio
* @brief  Enable GPIO interruption.CNcomment:ʹ��ĳ��GPIO���жϹ��ܡ�CNend
*
* @par ����:
*           Enable GPIO interruption.CNcomment:ʹ��ĳ��GPIO���жϹ��ܡ�CNend
*
* @attention None
* @param  id            [IN] type #hi_gpio_idx��I/O index.CNcomment:GPIO������CNend
* @param  int_type      [IN] type #hi_gpio_int_type��Interruption type.CNcomment:�ж����͡�CNend
* @param  int_polarity  [IN] type #hi_gpio_int_polarity��Interruption polarity.CNcomment:�жϼ��ԡ�CNend
* @param  func          [IN] type #gpio_isr_callback_func��Callback function of interruption.
CNcomment:�жϻص�������CNend
* @param  arg           [IN] type #hi_void *��arg of interrupt callback function. CNcomment:�жϻص�������Ρ�CNend
*
* @retval #0       Success.
* @retval #Other   Failure. For details, see hi_errno.h.
* @par ����:
*           @li hi_gpio.h��Describes GPIO APIs.�ļ���������GPIO��ؽӿڡ�
* @see  hi_gpio_unregister_isr_function��
* @since Hi3861_V100R001C00
*/
hi_u32 hi_gpio_register_isr_function(hi_gpio_idx id, hi_gpio_int_type int_type, hi_gpio_int_polarity int_polarity,
                                     gpio_isr_callback func, hi_void *arg);

/**
* @ingroup  iot_gpio
* @brief  Disable GPIO interruption.CNcomment:ȥʹ��ĳ��GPIO���жϹ��ܡ�CNend
*
* @par ����:
*           Disable GPIO interruption.CNcomment:ȥʹ��ĳ��GPIO���жϹ��ܡ�CNend
*
* @attention None
* @param  id [IN] type #hi_gpio_idx��I/O index.CNcomment:GPIO������CNend
*
* @retval #0       Success.
* @retval #Other   Failure. For details, see hi_errno.h.
* @par ����:
*           @li hi_gpio.h��Describes GPIO APIs.�ļ���������GPIO��ؽӿڡ�
* @see  hi_gpio_register_isr_function��
* @since Hi3861_V100R001C00
*/
hi_u32 hi_gpio_unregister_isr_function(hi_gpio_idx id);

/**
* @ingroup  iot_gpio
* @brief  Mask GPIO interruption.CNcomment:����ĳ��GPIO���жϹ��ܡ�CNend
*
* @par ����:
*           Mask GPIO interruption.CNcomment:����ĳ��GPIO���жϹ��ܡ�CNend
*
* @attention None
* @param  id            [IN] type #hi_gpio_idx��I/O index.CNcomment:GPIO������CNend
* @param  is_mask       [IN] type #hi_bool��Interruption type.CNcomment:�ж����͡�CNend
*                            @li HI_FALSE��Unmask I/O interruption.CNcomment:������GPIO�жϡ�CNend
*                            @li HI_TRUE�� Mask I/O interruption.CNcomment:����GPIO�жϡ�CNend
*
* @retval #0       Success.
* @retval #Other   Failure. For details, see hi_errno.h.
* @par ����:
*           @li hi_gpio.h��Describes GPIO APIs.�ļ���������GPIO��ؽӿڡ�
* @see  None
* @since Hi3861_V100R001C00
*/
hi_u32 hi_gpio_set_isr_mask(hi_gpio_idx id, hi_bool is_mask);

/**
* @ingroup  iot_gpio
* @brief  Set GPIO interruption type and polarity.CNcomment:����ĳ��GPIO���жϴ�����ʽ��CNend
*
* @par ����:
*           Set GPIO interruption type and polarity.CNcomment:����ĳ��GPIO���жϴ�����ʽ��CNend
*
* @attention None
* @param  id            [IN] type #hi_gpio_idx��I/O index.CNcomment:GPIO������CNend
* @param  int_type      [IN] type #hi_gpio_int_type��Interruption type.CNcomment:�ж����͡�CNend
* @param  int_polarity  [IN] type #hi_gpio_int_polarity��Interruption polarity.CNcomment:�жϼ��ԡ�CNend
*
* @retval #0       Success.
* @retval #Other   Failure. For details, see hi_errno.h.
* @par ����:
*           @li hi_gpio.h��Describes GPIO APIs.�ļ���������GPIO��ؽӿڡ�
* @see  None
* @since Hi3861_V100R001C00
*/
hi_u32 hi_gpio_set_isr_mode(hi_gpio_idx id, hi_gpio_int_type int_type, hi_gpio_int_polarity int_polarity);

#endif
