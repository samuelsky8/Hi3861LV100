/**
* @file hi_adc.h
*
*  Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2019. All rights reserved.  \n
*
* ������Analog-to-digital conversion (ADC) module interface.
* @li Provides 8 ADC channels.
CNcomment:�ṩ8��ADCͨ����ͨ��7Ϊ�ο���ѹ������adcת����CNend
* @li LSADC reading rate is slow, please avoid used in interruption.
CNcomment: LSADC�������ʽ�������������ж�ʹ�á�CNend
* @li Data format in 12bit, [0:11] are data bits, [0:1] are decimal fractions,
[12:15] reserved. CNcomment:���ݸ�ʽ16bit��
[0:11]������λ������[0:1]��С��λ��[12:15]������CNend \n
* Author: Hisilicon \n
* Create: 2019-4-3
*/

/**
* @defgroup iot_ls_adc ADC
* @ingroup drivers
*/

#ifndef __HI_ADC_H__
#define __HI_ADC_H__

#include <hi_types.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @ingroup iot_ls_adc
 *
 * channel ID��CNcomment:ͨ�����.CNend
 */
typedef enum {
    HI_ADC_CHANNEL_0,
    HI_ADC_CHANNEL_1,
    HI_ADC_CHANNEL_2,
    HI_ADC_CHANNEL_3,
    HI_ADC_CHANNEL_4,
    HI_ADC_CHANNEL_5,
    HI_ADC_CHANNEL_6,
    HI_ADC_CHANNEL_7,
    HI_ADC_CHANNEL_BUTT,
} hi_adc_channel_index;

/**
 * @ingroup iot_ls_adc
 *
 * Analog power control. CNcomment:ģ���Դ���ơ�CNend
 */
typedef enum {
    HI_ADC_CUR_BAIS_DEFAULT,       /**< 0��Auto control.
                                      CNcomment:�Զ�ʶ��ģʽ */
    HI_ADC_CUR_BAIS_AUTO,          /**< 1��Auto control.
                                      CNcomment:�Զ�ʶ��ģʽ */
    HI_ADC_CUR_BAIS_1P8V,          /**< 2��Manual control, AVDD=1.8V.
                                      CNcomment:�ֶ����ƣ�AVDD=1.8V */
    HI_ADC_CUR_BAIS_3P3V,          /**< 3��Manual control, AVDD=3.3V.
                                      CNcomment:�ֶ����ƣ�AVDD=3.3V */
    HI_ADC_CUR_BAIS_BUTT,
} hi_adc_cur_bais;

/**
 * @ingroup iot_ls_adc
 *
 * Average algorithm mode CNcoment:ƽ���㷨ģʽ��CNend
 */
typedef enum {
    HI_ADC_EQU_MODEL_1,            /**< 0��The average value is not used.
                                      CNcomment:1��ƽ������������
                                      ƽ�� CNend */
    HI_ADC_EQU_MODEL_2,            /**< 1��2-time average algorithm mode.
                                      CNcomment:2��ƽ���㷨ģʽ CNend */
    HI_ADC_EQU_MODEL_4,            /**< 2��4-time average algorithm mode.
                                      CNcomment:4��ƽ���㷨ģʽ CNend */
    HI_ADC_EQU_MODEL_8,            /**< 3��8-time average algorithm mode.
                                      CNcomment:8��ƽ���㷨ģʽ CNend */
    HI_ADC_EQU_MODEL_BUTT,
} hi_adc_equ_model_sel;

/**
* @ingroup  iot_ls_adc
* @brief  Read one data in single ADC channel. CNcomment:��һ��ADCͨ����һ�����ݡ�CNend
*
* @par ����:
*           Read one data in single ADC channel.
CNcomment:��һ��ADCͨ����һ�����ݡ�CNend
*
* @attention None
* @param  channel      [IN] type #hi_adc_channel_index��channel to be read. CNcomment:Ҫ����channel��CNend
* @param  data         [IN] type #hi_u16 * ��data point to store the data.
CNcomment:��ȡ��ADC���ݱ����ַ��CNend
* @param  equ_model    [IN] type #hi_adc_equ_model_sel ��Average algorithm mode.
CNcomment:ƽ���㷨ģʽ��CNend
* @param  cur_bais     [IN] type #hi_adc_cur_bais ��Analog power control.
CNcomment:ģ���Դ���ơ�CNend
* @param  rst_cnt      [IN] type #hi_u16 ��Countings from reset to conversion start��One count is 334ns��[0, 0xFF0].
CNcomment:�Ӹ�λ����ʼת����ʱ�������һ�μ�����334ns����ֵ����0~0xFF0֮�䡣CNend
* @retval #HI_ERR_SUCCESS  Success.
* @retval #Other          Failure. See hi_errno.h for details.
* @par ����:
*            @li hi_adc.h��Describes ADC APIs.
CNcomment:�ļ���������ADC��ؽӿڡ�CNend
* @see  hi_adc_read��
* @since Hi3861_V100R001C00
*/
hi_u32 hi_adc_read(hi_adc_channel_index channel, hi_u16 *data, hi_adc_equ_model_sel equ_model,
    hi_adc_cur_bais cur_bais, hi_u16 rst_cnt);

#ifdef __cplusplus
}
#endif
#endif
