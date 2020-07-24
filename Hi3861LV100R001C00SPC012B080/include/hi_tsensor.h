/**
* @file hi_tsensor.h
*
* Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2019. All rights reserved.  \n
* Description: Tsensor APIs.   \n
* Author: Hisilicon   \n
* Create: 2019-12-18
*/

/**
 * @defgroup iot_tsensor Tsensor
 * @ingroup drivers
 */

#ifndef __HI_TSENSOR_H__
#define __HI_TSENSOR_H__
#include <hi_types_base.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
* @ingroup  iot_tsensor
* @brief Callback function of Tsensor interruption. CNcomment:Tsensor�жϻص�������CNend
*
* @par ����:
*           Callback function of Tsensor interruption. CNcomment:Tsensor�ص�������CNend
*
* @attention None
* @param  data [IN] type #hi_s16��Parameter transfer of the callback function, indicating the temperature when the
*              interrupt is reported.CNcomment:�ص������������ݣ���ʾ�ж��ϱ�ʱ���¶�ֵ��CNend
*
* @retval None
* @par ����:
*            @li hi_tsensor.h��Tsensor APIs.CNcomment:�ļ�����������ȡtsensor��ؽӿڡ�CNend
* @see None
* @since Hi3861_V100R001C00
*/
typedef hi_void (*hi_tsensor_callback_func)(hi_s16);

/**
 * @ingroup iot_tsensor
 *
 * Tsensor report mode.CNcomment:Tsensor�ϱ�ģʽ��CNend
 */
typedef enum {
    HI_TSENSOR_MODE_16_POINTS_SINGLE = 0, /**< Mode: 16 points single.CNcomment:ģʽ��16��ƽ�������ϱ� CNend */
    HI_TSENSOR_MODE_16_POINTS_LOOP = 1,   /**< Mode: 16 points loop.CNcomment:ģʽ��16��ƽ��ѭ���ϱ� CNend */
    HI_TSENSOR_MODE_1_POINT_LOOP = 2,     /**< Mode: 1 point loop.CNcomment:ģʽ������ѭ���ϱ� CNend */
    HI_TSENSOR_MODE_MAX,                  /**< Invalid input parameter, which cannot be used.
                                             CNcomment:������Σ�����ʹ�� CNend */
}hi_tsensor_mode;

#define HI_TSENSOR_INVALID_CODE 0xFFFF    /* Tsensor ��Ч�¶��룬��Ч�¶���Ϊ(0-255) */
#define HI_TSENSOR_INVALID_TEMP (-1000)   /* Tsensor ��Ч�¶�, ��Ч�¶���Ϊ(-40-140) */

/**
* @ingroup  iot_tsensor
* @brief tsensor module start.CNcomment:tsensorģ��������CNend
*
* @par ����:
*           tsensor module start.CNcomment:tsensor�����¶Ȳɼ���CNend
*
* @attention Period is valid when mode = #HI_TSENSOR_MODE_16_POINTS_LOOP or HI_TSENSOR_MODE_1_POINT_LOOP.
*            By default, the tsensor HI_TSENSOR_MODE_16_POINTS_SINGLE temperature collection mode is enabled for the
*            Wi-Fi module. If this function is repeatedly called, the default mode used by the Wi-Fi module will be
*            overwritten. If you want to use the tsensor module for other services, you can register the
*            corresponding interrupt callback function in the service.
CNcomment:period����modeΪHI_TSENSOR_MODE_16_POINTS_SINGLE��Ч, period��Χ: period * 31.25us > 16 * 192us;
WiFiģ��Ĭ������tsensor HI_TSENSOR_MODE_16_POINTS_SINGLE�¶Ȳɼ�ģʽ���ظ����ô˺����Ḳ��WiFiģ��ʹ
�õ�Ĭ��ģʽ�� ��Ҫ��tsensorģ����������ҵ�񣬿�ֱ���ڸ�ҵ����ע���Ӧ���жϻص�������CNend
*
* @param  mode             [IN] type #hi_tsensor_mode��Mode of Tsensor temperature acquisition.
CNcomment:Tsensor�¶Ȳɼ�ģʽ��CNend
* @param  period           [IN] type #hi_u16*��Acquisition period, it is the multiple of 2 ms.
CNcomment:�¶��Զ�������ڣ�Ϊ32Kʱ������CNend
*
* @retval #0           Success.
* @retval #Other       Failure. For details, see hi_errno.h.
* @par ����:
*            @li hi_tsensor.h��for Tsensor APIs.CNcomment:�ļ���������tsensor��ؽӿڡ�CNend
* @see None
* @since Hi3861_V100R001C00
*/
hi_u32 hi_tsensor_start(hi_tsensor_mode mode, hi_u16 period);

/**
* @ingroup  iot_tsensor
* @brief Read temperature data.CNcomment:��ȡ�¶�ֵ��CNend
*
* @par ����:
*          Read temperature data.CNcomment:������tsensor�¶Ȳɼ��󣬶�ȡ�¶�ֵ��CNend
*
* @attention None
* @param  temperature      [IN] type #hi_s16*��address wait to be writed the temperature value.
CNcomment:��д���¶�ֵ�ĵ�ַ��CNend
*
* @retval #0           Success.
* @retval #Other       Failure. For details, see hi_errno.h.
* @par ����:
*            @li hi_tsensor.h��for Tsensor APIs.CNcomment:�ļ���������tsensor��ؽӿڡ�CNend
* @see None
* @since Hi3861_V100R001C00
*/
hi_u32 hi_tsensor_read_temperature(hi_s16* temperature);

/**
* @ingroup  iot_tsensor
* @brief Tsensor module stop.CNcomment:ֹͣtsensor�¶Ȳɼ���CNend
*
* @par ����:
*          Tsensor module stop.CNcomment:ֹͣtsensor�¶Ȳɼ���CNend
*
* @attention By default, the tsensor function is enabled for the Wi-Fi module. If this function is invoked, the
*            temperature threshold protection function of the Wi-Fi module registration will be affected.
CNcomment:WiFiģ��Ĭ������tsensor�����ô˺�������Ӱ��WiFi����ע����¶���ֵ�����ȹ��ܡ�CNend
* @param  None
*
* @retval None
* @par ����:
*            @li hi_tsensor.h��for Tsensor APIs.CNcomment:�ļ���������tsensor��ؽӿڡ�CNend
* @see None
* @since Hi3861_V100R001C00
*/
hi_void hi_tsensor_stop(hi_void);

/**
* @ingroup  iot_tsensor
* @brief Destroy Tsensor module.CNcomment:����tsensorģ�顣CNend
*
* @par ����:
*          On the basis of hi_tsensor_stop, this interface disables the reporting of tsensor interrupts and clears
*          the callback functions registered by users.CNcomment:��hi_tsensor_stop�Ļ����ϣ��˽ӿ�ͬʱ������
tsensor���ж��ϱ���������û�ע��Ļص�������CNend
*
* @attention After this API is called, if the interrupt callback function is used, you need to invoke the corresponding
*            interface to set the interrupt function before starting the interrupt, and enable the interrupt reporting
*            function.By default, the tsensor function is enabled for the Wi-Fi module. If this function is invoked,
*            the temperature threshold protection function of the Wi-Fi module registration will be affected.
CNcomment:���ô˽ӿں󣬶���ʹ���жϻص��ĳ�������start֮ǰ�����ٴε�����Ӧ�ӿ������жϺ����������ж��ϱ���
WiFiģ��Ĭ������tsensor�����ô˺�������Ӱ��WiFi����ע����¶���ֵ�����ȹ��ܡ�CNend
*
* @param None
*
* @retval None
* @par ����:
*            @li hi_tsensor.h��for Tsensor APIs.CNcomment:�ļ���������tsensor��ؽӿڡ�CNend
* @see None
* @since Hi3861_V100R001C00
*/
hi_void hi_tsensor_destroy(hi_void);

/**
* @ingroup  iot_tsensor
* @brief Sets the temperature calibration.CNcomment:�¶�У׼���á�CNend
*
* @par ����:
*          Sets the temperature calibration.CNcomment:�¶�У׼���á�CNend
*
* @attention None
* @param  trim_code          [IN] type #hi_u8��Low 4bit valid. The corresponding temperature calibration values are
*                            as follows:CNcomment:��4bit��Ч����Ӧ���¶�У׼ֵ������ʾ:CNend
*                            0000 ����  0.000 ��
*                            0001 ����  1.410 ��
*                            0010 ����  2.820 ��
*                            0011 ����  4.230 ��
*                            0100 ����  5.640 ��
*                            0101 ����  7.050 ��
*                            0110 ����  8.460 ��
*                            0111 ����  9.870 ��
*                            1000 ����  0.000��
*                            1001 ���� -1.410 ��
*                            1010 ���� -2.820 ��
*                            1011 ���� -4.230 ��
*                            1100 ���� -5.640 ��
*                            1101 ���� -7.050 ��
*                            1110 ���� -8.460 ��
*                            1111 ���� -9.870 ��
* @param  trim_sel           [IN] type #hi_bool��0��The temp_trim of the Tsensor IP is directly loaded by the efuse.
CNcomment:ѡ��Tsensor IP��temp_trim��efuseֱ�Ӽ��أ�CNend
*                                                1��The temp_trim of the Tsensor IP is configured by the register.
CNcomment:ѡ��Tsensor IP��temp_trim�ɼĴ������á�CNend
*
* @retval None
* @par ����:
*            @li hi_tsensor.h��for Tsensor APIs.CNcomment:�ļ���������tsensor��ؽӿڡ�CNend
* @see None
* @since Hi3861_V100R001C00
*/
hi_void hi_tsensor_set_temp_trim(hi_u8 trim_code, hi_bool trim_sel);

/**
* @ingroup  iot_tsensor
* @brief Converts the temperature code into a temperature value.CNcomment:�¶���ת�����¶�ֵ��CNend
*
* @par ����:
*          Converts the temperature code into a temperature value.CNcomment:���¶���ת�����¶�ֵ��CNend
*
* @attention None
* @param  code        [IN] type #hi_u8��temperature value.CNcomment:�¶��롣CNend
*
* @retval #hi_s16 Valid temperature value or invalid data (HI_TSENSOR_INVALID_TEMP).
CNcomment:��Ч���¶�ֵ����Ч����(HI_TSENSOR_INVALID_TEMP)��CNend
*
* @par ����:
*            @li hi_tsensor.h��for Tsensor APIs.CNcomment:�ļ���������tsensor��ؽӿڡ�CNend
* @see None
* @since Hi3861_V100R001C00
*/
hi_s16 hi_tsensor_code_to_temperature(hi_u8 code);

/**
* @ingroup  iot_tsensor
* @brief Converts the temperature into a temperature code.CNcomment:�¶�ֵת�����¶��롣CNend
*
* @par ����:
*          Converts the temperature into a temperature code.CNcomment:���¶�ֵת�����¶��롣CNend
*
* @attention None
* @param  temp       [IN] type #hi_float��temperature code.CNcomment:�¶�ֵ��CNend
*
* @retval #hi_u16 Valid temperature value or invalid data (HI_TSENSOR_INVALID_TEMP).
CNcomment:��Ч���¶�ֵ����Ч����(HI_TSENSOR_INVALID_TEMP)��CNend
* @par ����:
*            @li hi_tsensor.h��for Tsensor APIs.CNcomment:�ļ���������tsensor��ؽӿڡ�CNend
* @see None
* @since Hi3861_V100R001C00
*/
hi_u16 hi_tsensor_temperature_to_code(hi_s16 temp);

/**
* @ingroup  iot_tsensor
* @brief Sets the temperature threshold.CNcomment:�����¶���ֵ���ޡ�CNend
*
* @par ����:
*          Sets the temperature threshold.CNcomment:�����¶���ֵ���ޡ�CNend
*
* @attention This function is invoked before tsensor temperature collection is started. This function is invoked to
*            enable the function of reporting the temperature threshold interrupt. A maximum of three temperature
*            threshold interrupt callback functions can be registered at the same time. When the Wi-Fi service is
*            started, this interface is invoked to set the default high and low temperature thresholds. Before other
*            services use this interface, check whether the default high and low temperature thresholds need to be
*            changed. CNcomment:������tsensor�¶Ȳɼ�֮ǰ���ã����ô˺�����ʹ���¶���ֵ�����ж��ϱ�, ����ͬʱע��
3���¶���ֵ�����жϻص�����;WiFiҵ������ʱ����ô˽ӿ�����Ĭ�ϵĸߵ������ޣ��˺�����ҵ��ʹ�ô˽ӿ�ǰ��
��ȷ���Ƿ�Ҫ�޸�Ĭ�ϵĸߵ�������ֵ��CNend
*
* @param  low_temp            [IN] type #hi_s16��Low Temperature Threshold.CNcomment:�������ޡ�CNend
* @param  high_temp           [IN] type #hi_s16��High Temperature Threshold.CNcomment:�������ޡ�CNend
* @param  callback_func       [IN] type #hi_tsensor_callback_func��Indicates the callback function when the temperature
*                             exceeds the threshold.CNcomment:�¶ȳ���ֵ�жϻص�������CNend
*
* @retval #0           Success.
* @retval #Other       Failure. For details, see hi_errno.h.
* @par ����:
*            @li hi_tsensor.h��for Tsensor APIs.CNcomment:�ļ���������tsensor��ؽӿڡ�CNend
* @see None
* @since Hi3861_V100R001C00
*/
hi_u32 hi_tsensor_set_outtemp_threshold(hi_s16 low_temp, hi_s16 high_temp,
                                        hi_tsensor_callback_func callback_func);

/**
* @ingroup  iot_tsensor
* @brief To set the threshold for the over-high temperature threshold.CNcomment:���ó�������ֵ���ޡ�CNend
*
* @par ����:
*          To set the threshold for the over-high temperature threshold.CNcomment:���ó�������ֵ���ޡ�CNend
*
* @attention This function is invoked before tsensor temperature collection is started. This function is invoked to
*            enable the function of reporting the temperature threshold interrupt. A maximum of three temperature
*            threshold interrupt callback functions can be registered at the same time. When the Wi-Fi service is
*            started, this interface is invoked to set the default high and low temperature thresholds. Before other
*            services use this interface, check whether the default high and low temperature thresholds need to be
*            changed. CNcomment:������tsensor�¶Ȳɼ�֮ǰ���ã����ô˺�����ʹ���¶���ֵ�����ж��ϱ�, ����ͬʱע��
3���¶���ֵ�����жϻص�����;WiFiҵ������ʱ����ô˽ӿ�����Ĭ�ϵĸߵ������ޣ��˺�����ҵ��ʹ�ô˽ӿ�ǰ��
��ȷ���Ƿ�Ҫ�޸�Ĭ�ϵĸߵ�������ֵ��CNend
*
* @param  over_temp           [IN] type #hi_s16��Ultra-high temperature threshold.CNcomment:���������ޡ�CNend
* @param  callback_func       [IN] type #hi_tsensor_callback_func��Interrupt callback function when the temperature
*                             exceeds the upper temperature threshold. CNcomment:�¶ȳ��������������жϻص�������CNend
*
* @retval #0           Success.
* @retval #Other       Failure. For details, see hi_errno.h.
* @par ����:
*            @li hi_tsensor.h��for Tsensor APIs.CNcomment:�ļ���������tsensor��ؽӿڡ�CNend
* @see None
* @since Hi3861_V100R001C00
*/
hi_u32 hi_tsensor_set_overtemp_threshold(hi_s16 over_temp, hi_tsensor_callback_func callback_func);

/**
* @ingroup  iot_tsensor
* @brief Sets the overtemperature power-off threshold.CNcomment:���ù��µ�����ֵ���ޡ�CNend
*
* @par ����:
*          Sets the overtemperature power-off threshold.CNcomment:���ù��µ�����ֵ���ޡ�CNend
*
* @attention This function is invoked before tsensor temperature collection is started. This function is invoked to
*            enable the function of reporting the temperature threshold interrupt. A maximum of three temperature
*            threshold interrupt callback functions can be registered at the same time. When the Wi-Fi service is
*            started, this interface is invoked to set the default high and low temperature thresholds. Before other
*            services use this interface, check whether the default high and low temperature thresholds need to be
*            changed. CNcomment:������tsensor�¶Ȳɼ�֮ǰ���ã����ô˺�����ʹ���¶���ֵ�����ж��ϱ�, ����ͬʱע��
3���¶���ֵ�����жϻص�����;WiFiҵ������ʱ����ô˽ӿ�����Ĭ�ϵĸߵ������ޣ��˺�����ҵ��ʹ�ô˽ӿ�ǰ��
��ȷ���Ƿ�Ҫ�޸�Ĭ�ϵĸߵ�������ֵ��CNend
*
* @param  pd_temp            [IN] type #hi_s16��Indicates the threshold of the overtemperature power-off threshold.
CNcomment:���µ�����ֵ���ޡ�CNend
*
* @retval #0           Success.
* @retval #Other       Failure. For details, see hi_errno.h.
* @par ����:
*            @li hi_tsensor.h��for Tsensor APIs.CNcomment:�ļ���������tsensor��ؽӿڡ�CNend
* @see None
* @since Hi3861_V100R001C00
*/
hi_u32 hi_tsensor_set_pdtemp_threshold(hi_s16 pd_temp);

/**
* @ingroup  iot_tsensor
* @brief Registers the callback function for the temperature collection completion interrupt.
CNcomment:ע���¶Ȳɼ�����жϻص�������CNend
*
* @par ����:
*          Registers the callback function for the temperature collection completion interrupt.
CNcomment:ע���¶Ȳɼ�����жϻص�������CNend
*
* @attention This function is invoked before tsensor temperature collection is started. This function is invoked to
*            enable the function of reporting the temperature threshold interrupt. A maximum of three temperature
*            threshold interrupt callback functions can be registered at the same time. The tsensor temperature
*            collection period is short. In HI_TSENSOR_MODE_16_POINTS_LOOP and HI_TSENSOR_MODE_1_POINT_LOOP modes,
*            the collection completion interrupt is frequently triggered, occupying a large number of CPU resources.
*            As a result, other services may fail to be scheduled. In HI_TSENSOR_MODE_16_POINTS_SINGLE mode, a large
*            period can be set to avoid this problem, however, if the value of period is too large, the temperature
*            monitoring density decreases. Therefore, it is recommended that you do not read the temperature by
*            collecting data. CNcomment:������tsensor�¶Ȳɼ�֮ǰ���ã����ô˺�����ʹ���¶Ȳɼ�����ж��ϱ�,
����ͬʱע��3���¶Ȳɼ�����жϻص�����;tsensor�¶Ȳɼ����ں̣ܶ�HI_TSENSOR_MODE_16_POINTS_LOOP��
HI_TSENSOR_MODE_1_POINT_LOOPģʽ�²ɼ�����жϻ�Ƶ��������ռ�ô���cpu��Դ�����ܻᵼ������ҵ��ò������ȣ�
HI_TSENSOR_MODE_16_POINTS_SINGLEģʽ��Ȼ����ͨ�����ýϴ��period������������⣬�������periodֵ���ᵼ���¶ȼ���ܶ�
���½�����˽��龡����Ҫͨ���ɼ�����жϵķ�ʽ��ȡ�¶ȡ�CNend
*
* @param  callback_func       [IN] type #hi_tsensor_callback_func��Temperature collection completion interrupt callback
*                             function.CNcomment:�¶Ȳɼ�����жϻص�������CNend
*
* @retval #0           Success.
* @retval #Other       Failure. For details, see hi_errno.h.
* @par ����:
*            @li hi_tsensor.h��for Tsensor APIs.CNcomment:�ļ���������tsensor��ؽӿڡ�CNend
* @see None
* @since Hi3861_V100R001C00
*/
hi_u32 hi_tsensor_register_temp_collect_finish_int_callback(hi_tsensor_callback_func callback_func);


#ifdef __cplusplus
}
#endif

#endif
