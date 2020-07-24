/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: ADC driver header file.
 * Author: wangjian
 * Create: 2019-4-16
 */

#ifndef __ADC_DRV_H__
#define __ADC_DRV_H__

#include <hi_adc.h>
#include <hi_mdm_types.h>
#include <hi3861_platform_base.h>

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif  /* __cplusplus */

#ifdef ADC_DEBUG
#define adc_print(fmt...)       \
    do {                        \
        printf(fmt);            \
        printf("\n"); \
    } while (0)
#else
#define adc_print(fmt...)
#endif

#define LS_ADC_CLK_DIV1_REG     CLDO_CTL_CLK_DIV1_REG
#define LS_ADC_CLK_DIV1_OFFSET  9

#define HI_LS_ADC_REG_BASE      0x40070000 /* LD ADC base address */
#define REG_ADC_CFG      (HI_LS_ADC_REG_BASE + 0x00)
#define REG_ADC_FIFO_CFG (HI_LS_ADC_REG_BASE + 0x04)
#define REG_ADC_IMSC     (HI_LS_ADC_REG_BASE + 0x08)
#define REG_ADC_CR       (HI_LS_ADC_REG_BASE + 0x0C)
#define REG_ADC_SR       (HI_LS_ADC_REG_BASE + 0x10)
#define REG_ADC_RIS      (HI_LS_ADC_REG_BASE + 0x14)
#define REG_ADC_MIS      (HI_LS_ADC_REG_BASE + 0x18)
#define REG_ADC_START    (HI_LS_ADC_REG_BASE + 0x1C)
#define REG_ADC_STOP     (HI_LS_ADC_REG_BASE + 0x20)
#define REG_ADC_DR       (HI_LS_ADC_REG_BASE + 0x24)
#define REG_ADC_CTRL     (HI_LS_ADC_REG_BASE + 0x28)
#define REG_ADC_EN       (HI_LS_ADC_REG_BASE + 0x2C)

#define ADC_INT_FIFO_WATER_LINE (1 << 1)
#define ADC_INT_FIFO_OVER_FLOW  (1 << 0)

#define ADC_SR_RNE (1 << 0) /* FIFO not empty flag: 0:empty 1:not empty */
#define ADC_SR_RFF (1 << 1) /* FIFO full flag 0:not full 1:full */
#define ADC_SR_BSY (1 << 2) /* ADC busy flag 0:idle 1:busy */

#define ADC_SCAN_START  1
#define ADC_SCAN_STOP   1
#define ADC_POWER_ON    0
#define ADC_POWER_OFF   1
#define ADC_ISR_DISABLE 0
#define ADC_DATA_BIT_WIDTH 12

/*
 * The longest time to get 1 data is ((0xfff+(18*8)+3)*334)ns
 * The unit of this cnt is about 5us
 */
#define ADC_PER_DATA_TIMEOUT_CNT 500
#define ADC_LOOP_DELAY_US        5

typedef void (*adc_clken_callback)(hi_void);

/**
* @ingroup  iot_ls_adc
* @brief  Callback function of ADC read data done.
CNcomment:ADC������ɺ�ص����������͡�CNend
*
* @par ����:
*           Callback function of ADC read data done.
CNcomment:ADC������ɺ�ص����������͡�CNend
*
* @attention Can NOT be called in the interruption.
CNcomment:�������ж���Ӧ���޷������á�CNend
* @param  data_buf [IN] type #hi_u16 *��received data.
CNcomment:�ص����,���������ݡ�CNend
* @param  length   [IN] type #hi_u32��length of the received data.
CNcomment:��ȡ���ݵĳ��ȡ�CNend
*
* @retval None
* @par ����:
*            @li hi_adc.h��Describes ADC APIs.
CNcomment:�ļ���������ADC��ؽӿڡ�CNend
* @see None
* @since Hi3861_V100R001C00
*/
typedef hi_void(*adc_read_cb) (const hi_u16 *data_buf, hi_u32 length);

typedef struct {
    hi_u32 ch_vld : 8;
    hi_u32 equ_model : 2;
    hi_u32 reserved0 : 2;
    hi_u32 rst_cnt : 12;
    hi_u32 cur_bais : 2;
    hi_u32 reserved1 : 6;
} adc_cfg_reg_s;

typedef struct {
    volatile hi_u32 buf_pos; /* offset of data buffer */
    hi_u32 is_init;          /* init flag */
    hi_u32 buf_length;       /* length of data buffer length */
    hi_u16 *data_buf;        /* point of data buffer */
    adc_read_cb adc_cb;      /* callback function after read data finish */
} adc_data;


/**
 * @ingroup iot_ls_adc
 *
 * Settings: ADC RX threshold. CNcomment:���ò�����ADC����ˮ�ߡ�CNend
 */
typedef enum {
    HI_ADC_FIFO_WATER_LINE_127,
    HI_ADC_FIFO_WATER_LINE_124,
    HI_ADC_FIFO_WATER_LINE_64,
    HI_ADC_FIFO_WATER_LINE_32,
    HI_ADC_FIFO_WATER_LINE_16,
    HI_ADC_FIFO_WATER_LINE_8,
    HI_ADC_FIFO_WATER_LINE_4,
    HI_ADC_FIFO_WATER_LINE_1,
} hi_adc_fifo_water_line;

/**
 * @ingroup iot_ls_adc
 *
 * ADC settings. CNcomment:ADC���ò�����CNend
 */
typedef struct {
    hi_u16 rst_cnt;                     /**< Countings from reset to conversion start, [0xF, 0xFF].
                                           CNcomment:�Ӹ�λ����ʼת����ʱ���������ֵ����
                                           0xF~0xFFF֮�� CNend */
    hi_adc_equ_model_sel equ_model_sel; /**< Average algorithm mode.
                                           CNcomment:ƽ���㷨ģʽ CNend */
    hi_adc_cur_bais cur_bais;           /**< ADC Analog power control.
                                           CNcomment:ģ���Դ���� CNend */
    hi_adc_fifo_water_line fifo_water_line;  /**< FIFO threshold interruption settings. Not use in sync rx mode.
                                                CNcomment:FIFOˮ���ж����ã�ͬ����ȡʱ�������� CNend */
} hi_adc_cfg;

/**
 * @ingroup iot_ls_adc
 *
 * Data format in 16bit, [0:11] are data bits, [0:2] are decimal fractions, [12:24] are channel number, [15] reserved.
 CNcomment:��ȡ����ADC���ݸ�ʽ��[0:11]������λ������[0:1]��С��λ��[12:14]��ͨ����ţ�
 [15]������CNend
 */
typedef struct {
    hi_u16 val:12;          /**< Data bit, [0:1] are decimal fractions.
                               CNcomment:����λ������[0:1]��С��λ CNend */
    hi_u16 ch_id:3;         /**< Channel number. CNcomment:ͨ����� CNend */
    hi_u16 reserved:1;
} hi_adc_data_format;

/**
* @ingroup  iot_ls_adc
* @brief  Initializes the data acquisition control module.
CNcomment:ADCģ���ʼ����CNend
*
* @par ����:
*           Initializes the data acquisition control module, apply for interrupt, enable the module.
CNcomment:ADCģ���ʼ������ADCģ���ʼ���������жϣ�ʹ��ADCģ�顣CNend
*
* @attention None
* @param  None
* @retval #HI_ERR_SUCCESS  Success.
* @retval #Other          Failure. See hi_errno.h for details.
* @par ����:
*            @li hi_adc.h��Describes ADC APIs.
CNcomment:�ļ���������ADC��ؽӿڡ�CNend
* @see  hi_adc_shutdown��
* @since Hi3861_V100R001C00
*/
hi_u32 hi_adc_init(hi_void);

/**
* @ingroup  iot_ls_adc
* @brief   ADC settings. CNcomment:����ADC������CNend
*
* @par ����:
*          Set ADC parameters. CNcomment:����ADC������CNend
*
* @attention None
* @param adc_cfg           [IN] type #hi_adc_cfg��ADC settings. CNcomment:ADCģ����ز�����CNend
*
* @retval #HI_ERR_SUCCESS  Success.
* @retval #Other          Failure. See hi_errno.h for details.
* @par ����:
*            @li hi_adc.h��Describes ADC APIs.
CNcomment:�ļ���������ADC��ؽӿڡ�CNend
* @see  hi_adc_set_basic_info��
* @since Hi3861_V100R001C00
*/
hi_u32 hi_adc_set_basic_info(const hi_adc_cfg *adc_cfg);

/**
* @ingroup  iot_ls_adc
* @brief   Read ADC received data synchronously. CNcomment:ͬ����ȡADC���ݡ�CNend
*
* @par ����:
*          Read ADC received data synchronously. CNcomment:ͬ����ȡADC���ݡ�CNend
*
* @attention None
* @param  channel          [IN] type #hi_u8 ��channel to be read. CNcomment:Ҫʹ�ܵ�channel��CNend
* @param  data_buf         [IN] type #hi_u16 * ��data buffer to store the data.
CNcomment:��ȡ��ADC���ݱ���buf��ַ��CNend
* @param  get_len          [IN] type #hi_u32 ��length to read, do NOT longer than the buffer size.
CNcomment:Ҫ�������ݳ��ȣ����ݴ���data_buf�����ܴ���data_buf���ȡ�CNend
*
* @retval #HI_ERR_SUCCESS  Success.
* @retval #Other          Failure. See hi_errno.h for details.
* @par ����:
*            @li hi_adc.h��Describes ADC APIs.
CNcomment:�ļ���������ADC��ؽӿڡ�CNend
* @since Hi3861_V100R001C00
* @see  hi_adc_get_data��
*/
hi_u32 hi_adc_read_sync(hi_u8 channel, hi_u16 *data_buf, hi_u32 get_len);

/**
* @ingroup  iot_ls_adc
* @brief   Asynchronously reading ADC data. CNcomment:�첽��ȡADC���ݡ�CNend
*
* @par ����:
*          Asynchronously reading ADC data. CNcomment:�첽��ȡADC���ݡ�CNend
*
* @attention None
* @param  channel          [IN] type #hi_u8 ��channel to be read. CNcomment:Ҫʹ�ܵ�channel��CNend
* @param  data_buf         [IN] type #hi_u16 * ��data buffer to store the data.
CNcomment:��ȡ��ADC���ݱ���buf��ַ��CNend
* @param  get_len          [IN] type #hi_u32 ��length to read, do NOT longer than the buffer size.
CNcomment:Ҫ�������ݳ��ȣ����ݴ���data_buf�����ܴ���data_buf���ȡ�CNend
* @param  cb               [IN] type #adc_read_cb ��Callback function when read done.
CNcomment:ADC������ɺ�ص�������CNend
*
* @retval #HI_ERR_SUCCESS  Success.
* @retval #Other          Failure. See hi_errno.h for details.
* @par ����:
*            @li hi_adc.h��Describes ADC APIs.
CNcomment:�ļ���������ADC��ؽӿڡ�CNend
* @since Hi3861_V100R001C00
* @see  hi_adc_scan_stop��
*/
hi_u32 hi_adc_read_async(hi_u8 channel, hi_u16 *data_buf, hi_u32 get_len, adc_read_cb cb);

/**
* @ingroup  iot_ls_adc
* @brief  Deinitialize ADC module. CNcomment:�ر�ADCģ�顣CNend
*
* @par ����:
*           Deinitialize ADC module, clear up FIFO, disable interruption, shutdown power.
CNcomment:�ر�ADCģ�飬���FIFO���ر��жϣ��رյ�Դ��CNend
*
* @attention None
* @param None
* @retval None
* @par ����:
*            @li hi_adc.h��Describes ADC APIs.
CNcomment:�ļ���������ADC��ؽӿڡ�CNend
* @see  hi_adc_init��
* @since Hi3861_V100R001C00
*/
hi_void hi_adc_deinit(hi_void);

#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif  /* __cplusplus */

#endif
