/**
* @file hi_i2s.h
*
* Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2019. All rights reserved.   \n
* Description: i2s driver header.   \n
* Author: Hisilicon   \n
* Create: 2019-12-18
*/

/**
 * @defgroup iot_i2s I2S
 * @ingroup drivers
 */
#ifndef __HI_I2S_H__
#define __HI_I2S_H__

/**
* @ingroup iot_i2s
*
* sample rate.
*/
typedef enum {
    HI_I2S_SAMPLE_RATE_8K = 8,
    HI_I2S_SAMPLE_RATE_16K = 16,
    HI_I2S_SAMPLE_RATE_32K = 32,
    HI_I2S_SAMPLE_RATE_48K = 48,
} hi_i2s_sample_rate;

/**
* @ingroup iot_i2s
*
* resolution.
*/
typedef enum {
    HI_I2S_RESOLUTION_16BIT = 16,
    HI_I2S_RESOLUTION_24BIT = 24,
} hi_i2s_resolution;

/**
* @ingroup iot_i2s
*
* I2S attributes.
*/
typedef struct {
    hi_i2s_sample_rate sample_rate;  /**< i2s sample rate, type hi_i2s_sample_rate.CNcomment:�����ʣ�����Ϊ
                                          hi_i2s_sample_rate��CNend */
    hi_i2s_resolution resolution;   /**< i2s resolution, type hi_i2s_resolution.CNcomment:�����ȣ�����Ϊ
                                          hi_i2s_resolution��CNend */
} hi_i2s_attribute;

/**
* @ingroup  iot_i2s
* @brief  I2S initialization. CNcomment:I2S��ʼ����CNend
*
* @par ����:
*           Set I2S with configuration. CNcomment:���ݲ�������I2S��CNend
*
* @attention Should init DMA driver before using I2S. CNcomment:ʹ��I2S����ǰ����Ҫ��ʼ��DMA������CNend
*
* @param  i2s_attribute   [IN] type #hi_i2s_attribute*��I2S configuration parameter. CNcomment:I2S���ò�����CNend
*
* @retval #HI_ERR_SUCCESS  Success.
* @retval #Other           Failure. For details, see hi_errno.h.
* @par ����:
*            @li hi_i2s.h��Describes I2S APIs.CNcomment:I2S��ؽӿڡ�CNend
* @see  hi_i2s_deinit��
* @since Hi3861_V100R001C00
*/
hi_u32 hi_i2s_init(const hi_i2s_attribute *i2s_attribute);

/**
* @ingroup  iot_i2s
* @brief  Deinitializes I2S.CNcomment:ȥ��ʼ��I2S��CNend
*
* @par ����:
*           Deinitializes I2S.CNcomment:ȥ��ʼ��I2S��CNend
*
* @attention This API is used together with hi_i2s_init.CNcomment:��hi_i2s_init�ɶ�ʹ�á�CNend
* @param  None
*
* @retval #HI_ERR_SUCCESS  Success.
* @retval #Other           Failure. For details, see hi_errno.h.
* @par ����:
*            @li hi_i2s.h��Describes I2S APIs.CNcomment:I2S��ؽӿڡ�CNend
* @see  hi_i2s_deinit��
* @since Hi3861_V100R001C00
*/
hi_u32 hi_i2s_deinit(hi_void);

/**
* @ingroup  iot_i2s
* @brief TX interface for the I2S.CNcomment:I2S���ͽӿڡ�CNend
*
* @par ����:
*           TX interface for the I2S.CNcomment:I2S���ͽӿڡ�CNend
*
* @attention None
*
* @param  wr_data         [OUT] type #hi_u8*��TX data pointer.CNcomment:��������ָ�롣CNend
* @param  wr_len          [IN]  type #hi_u32��length of the target data to be send (unit: byte).
CNcomment:�������ݳ��ȣ���λ��byte����CNend
* @param  time_out_ms     [IN]  type #hi_u32��wait timeout period.CNcomment:��ʱʱ�䡣CNend
*
* @retval #HI_ERR_SUCCESS  Success.
* @retval #Other           Failure. For details, see hi_errno.h.
* @par ����:
*            @li hi_i2s.h��Describes I2S APIs.CNcomment:I2S��ؽӿڡ�CNend
* @see  hi_i2s_read��
* @since Hi3861_V100R001C00
*/
hi_u32 hi_i2s_write(hi_u8 *wr_data, hi_u32 wr_len, hi_u32 time_out_ms);

/**
* @ingroup  iot_i2s
* @brief Read interface for the I2S.CNcomment:I2S���սӿڡ�CNend
*
* @par ����:
*           Read interface for the I2S.CNcomment:I2S���սӿڡ�CNend
*
* @attention None
*
* @param  rd_data         [OUT] type #hi_u8*��RX data pointer.CNcomment:��������ָ�롣CNend
* @param  rd_len          [IN]  type #hi_u32��length of the target data to be received (unit: byte).
CNcomment:�������ݳ��ȣ���λ��byte����CNend
* @param  time_out_ms     [IN]  type #hi_u32��wait timeout period.CNcomment:��ʱʱ�䡣CNend
*
* @retval #HI_ERR_SUCCESS  Success.
* @retval #Other           Failure. For details, see hi_errno.h.
* @par ����:
*            @li hi_i2s.h��Describes I2S APIs.CNcomment:I2S��ؽӿڡ�CNend
* @see  hi_i2s_write��
* @since Hi3861_V100R001C00
*/
hi_u32 hi_i2s_read(hi_u8 *rd_data, hi_u32 rd_len, hi_u32 time_out_ms);

#endif
