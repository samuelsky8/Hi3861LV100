/**
 * @file hi_i2c.h
 *
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2019. All rights reserved. \n
 * Description: I2C interfaces. \n
 * Author: hisilicon \n
 * Create: 2019-03-04
 */

/** @defgroup iot_i2c  I2C
 *  @ingroup drivers
 */
#ifndef __HI_I2C_H__
#define __HI_I2C_H__

#include <hi_types_base.h>

/*
 * I2C Interface
 */
#define I2C_RATE_DEFAULT  100000

typedef hi_void (*i2c_reset_func)(hi_void);
typedef hi_void (*i2c_prepare_func)(hi_void);
typedef hi_void (*i2c_restore_func)(hi_void);

/**
 * @ingroup iot_i2c
 *
 * I2C callback function. CNcomment:I2C�ص�������CNend
 */
typedef struct {
    i2c_reset_func   reset_func;    /**< This function is called back when the communication with the slave device
                                         is abnormal.CNcomment:I2C���쳣������CNend */
    i2c_prepare_func prepare_func;  /**< This function is called back before the I2C read/write operation to implement
                                         the preparations before the I2C operation.
                                         CNcomment:I2C����ǰ׼������CNend */
    i2c_restore_func restore_func;  /**< After the I2C read/write operation is performed, this function is
                                         called back to implement the recovery after the I2C operation.
                                         CNcomment:I2C������ָ�����CNend */
} hi_i2c_func;

/**
 * @ingroup iot_i2c
 *
 * I2C TX/RX data descriptor. CNcomment:I2C����/����������������CNend
 */
typedef struct {
    hi_u8*  send_buf;        /**< Data TX pointer. The user needs to ensure that no null pointer is transferred.
                                CNcomment:���ݷ���ָ��CNend */
    hi_u32  send_len;        /**< Length of sent data (unit: byte).
                                CNcomment:�������ݳ��ȣ���λ��byte��CNend */
    hi_u8*  receive_buf;     /**< Data RX pointer. CNcomment:���ݽ���ָ��CNend */
    hi_u32  receive_len;     /**< Length of received data (unit: byte).
                                CNcomment:�������ݳ��ȣ���λ��byte��CNend */
} hi_i2c_data;

/**
 * @ingroup iot_i2c
 *
 * I2C hardware index. CNComment:I2CӲ���豸ö�١�CNend
 */
typedef enum {
    HI_I2C_IDX_0,
    HI_I2C_IDX_1,
} hi_i2c_idx;

/**
* @ingroup  iot_i2c
* @brief  Set I2C baudrate. CNcomment:I2C���ò����ʡ�CNend
*
* @par ����:
*           Set I2C baudrate. CNcomment:I2C���ò����ʡ�CNend
*
* @attention Multiple tasks are not protected (multiple tasks are not supported). CNcomment:δ��
�����񱣻�����֧�ֶ����񣩡�CNend
* @param  id       [IN] type #hi_i2c_idx��I2C hardware selection. CNcomment:I2CӲ���豸ѡ��CNend
* @param  baudrate [IN] type #hi_u32��I2C baudrate. CNcomment:I2C�����ʡ�CNend
*
* @retval #0          Success.
* @retval #Other      Failure. For details, see hi_errno.h.
* @par ����:
*           @li hi_i2c.h��Declares the API.CNcomment:�ýӿ��������ڵ�ͷ�ļ���CNend
* @see  hi_i2c_write|hi_i2c_receive��
* @since Hi3861_V100R001C00
*/
hi_u32 hi_i2c_set_baudrate(hi_i2c_idx id, hi_u32 baudrate);

/**
* @ingroup  iot_i2c
* @brief  I2C data TX and RX.CNcomment:I2C������������ݡ�CNend
*
* @par ����:
*           The I2C sends data to the slave device and then receives data from the slave device.
CNcomment:I2C��ӻ��������ݣ�Ȼ����մӻ����ݡ�CNend
*
* @attention Multi-tasking is not supported. CNcomment:δ�������񱣻�����֧�ֶ����񣩡�CNend
* @param  id       [IN] type #hi_i2c_idx��I2C hardware selection. CNcomment:I2CӲ���豸ѡ��CNend
* @param  device_addr [IN] type #hi_u16��The device ID. High three bits of offset address of the I2C device on chipset.
CNcomment:�豸�ż��豸Ƭ��ƫ�Ƶ�ַ��3λ�����豸�ĸ��ط���ʼ������CNend
* @param  i2c_data  [IN] type #const hi_i2c_data*��The data descriptor to be received. The structure member data sending
*                             pointer and data receiving pointer cannot be null.
CNcomment:�������������������ṹ���Ա���ݷ���ָ������ݽ���ָ�붼��Ϊ�ա�CNend
*
* @retval #0          Success.
* @retval #Other      Failure. For details, see hi_errno.h.
* @par ����:
*           @li hi_i2c.h��Declares the API.CNcomment:�ýӿ��������ڵ�ͷ�ļ���CNend
* @see  hi_i2c_write|hi_i2c_receive��
* @since Hi3861_V100R001C00
*/
hi_u32 hi_i2c_writeread(hi_i2c_idx id, hi_u16 device_addr, const hi_i2c_data *i2c_data);

/**
* @ingroup  iot_i2c
* @brief  I2C data TX. CNcomment:I2C�������ݡ�CNend
*
* @par ����:
*           I2C data TX. CNcomment:I2C�������ݡ�CNend
*
* @attention Multiple tasks are not protected (multiple tasks are not supported). CNcomment:δ��
�����񱣻�����֧�ֶ����񣩡�CNend
* @param  id       [IN] type #hi_i2c_idx��I2C hardware selection. CNcomment:I2CӲ���豸ѡ��CNend
* @param  device_addr [IN] type #hi_u16��The device ID. High three bits of offset address of the I2C device on chipset.
CNcomment:�豸�ż��豸Ƭ��ƫ�Ƶ�ַ��3λ�����豸�ĸ��ط���ʼ������CNend
* @param  i2c_data  [IN] type #const hi_i2c_data*��The data descriptor to be received. The structure member data sending
*                             pointer and data receiving pointer cannot be null.
CNcomment:�������������������ṹ���Ա���ݷ���ָ������ݽ���ָ�붼��Ϊ�ա�CNend
*
* @retval #0          Success.
* @retval #Other      Failure. For details, see hi_errno.h.
* @par ����:
*           @li hi_i2c.h��Declares the API.CNcomment:�ýӿ��������ڵ�ͷ�ļ���CNend
* @see  hi_i2c_writeread|hi_i2c_receive��
* @since Hi3861_V100R001C00
*/
hi_u32 hi_i2c_write(hi_i2c_idx id, hi_u16 device_addr, const hi_i2c_data *i2c_data);

/**
* @ingroup  iot_i2c
* @brief  I2C data RX. CNcomment:I2C�������ݡ�CNend
*
* @par ����:
*            I2C data RX. CNcomment:I2C�������ݡ�CNend
*
* @attention Multi-tasking is not supported. CNcomment:δ�������񱣻�����֧�ֶ����񣩡�CNend
* @param  id       [IN] type #hi_i2c_idx��I2C hardware selection. CNcomment:I2CӲ���豸ѡ��CNend
* @param  device_addr [IN] type #hi_u16��The device ID. High three bits of offset address of the I2C device on chipset.
CNcomment:�豸�ż��豸Ƭ��ƫ�Ƶ�ַ��3λ�����豸�ĸ��ط���ʼ������CNend
* @param  i2c_data  [IN] type #const hi_i2c_data*��The data descriptor to be received. The structure member data sending
*                             pointer and data receiving pointer cannot be null.
CNcomment:�������������������ṹ���Ա���ݷ���ָ������ݽ���ָ�붼��Ϊ�ա�CNend
*
* @retval #0          Success.
* @retval #Other      Failure. For details, see hi_errno.h.
* @par ����:
*           @li hi_i2c.h��Declares the API.CNcomment:�ýӿ��������ڵ�ͷ�ļ���CNend
* @see  hi_i2c_write|hi_i2c_sendreceive��
* @since Hi3861_V100R001C00
*/
hi_u32 hi_i2c_read(hi_i2c_idx id, hi_u16 device_addr, const hi_i2c_data *i2c_data);

/**
* @ingroup  iot_i2c
* @brief  Initializes the I2C controller. CNcomment:I2C��ʼ����CNend
*
* @par ����:
*           Initializes the I2C controller. CNcomment:I2C��ʼ����CNend
*
* @attention None
* @param  id       [IN] type #hi_i2c_idx��I2C hardware selection. CNcomment:I2CӲ���豸ѡ��CNend
* @param  baudrate [IN] type #hi_u32��I2C baudrate. CNcomment:I2C�����ʡ�CNend
*
* @retval #0          Success.
* @retval #Other      Failure. For details, see hi_errno.h.
* @par ����:
*           @li hi_i2c.h��Declares the API.CNcomment:�ýӿ��������ڵ�ͷ�ļ���CNend
* @see  hi_i2c_deinit��
* @since Hi3861_V100R001C00
*/
hi_u32 hi_i2c_init(hi_i2c_idx id, hi_u32 baudrate);

/**
* @ingroup  iot_i2c
* @brief  Exits the I2C module.CNcomment:�˳�I2Cģ�顣CNend
*
* @par ����:
*          Exits the I2C module. CNcomment:�˳�I2Cģ�顣CNend
*
* @attention This API is called after hi_i2c_init is called. CNcomment:hi_i2c_init���ú���ʹ�á�CNend
* @param  id       [IN] type #hi_i2c_idx��I2C hardware selection. CNcomment:I2CӲ���豸ѡ��CNend
*
* @retval #0          Success.
* @retval #Other      Failure. For details, see hi_errno.h.
* @par ����:
*           @li hi_i2c.h��Declares the API.CNcomment:�ýӿ��������ڵ�ͷ�ļ���CNend
* @see  hi_i2c_init��
* @since Hi3861_V100R001C00
*/
hi_u32 hi_i2c_deinit(hi_i2c_idx id);

/**
* @ingroup  iot_i2c
* @brief  Registers the I2C callback function.CNcomment:ע��I2C�ص�������CNend
*
* @par ����:
*           Registers the I2C callback function, for extension.CNcomment:ע��I2C�ص�������������չ��CNend
*
* @attention None
* @param  id      [IN] type #hi_i2c_idx��I2C hardware selection. CNcomment:I2CӲ���豸ѡ��CNend
* @param  pfn     [IN] type #hi_i2c_func��Callback function. CNcomment:�ص�������CNend
*
* @retval #0          Success.
* @retval #Other      Failure. For details, see hi_errno.h.
* @par ����:
*           @li hi_i2c.h��Declares the API.CNcomment:�ýӿ��������ڵ�ͷ�ļ���CNend
* @see  None
* @since Hi3861_V100R001C00
*/
hi_void hi_i2c_register_reset_bus_func(hi_i2c_idx id, hi_i2c_func pfn);


#endif

