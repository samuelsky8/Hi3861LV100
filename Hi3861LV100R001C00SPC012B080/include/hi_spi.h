/**
* @file hi_spi.h
*
* Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2019. All rights reserved.  \n
*
* ������SPI SDK APIs. CNcomment:SPI SDK���ýӿڡ�CNend
* @li Supports synchronous serial communication with external devices as the master or slave.
CNcomment:֧����ΪMaster��Slave���ⲿ�豸����ͬ������ͨ�š�CNend
* @li The SPI working reference clock is 160 MHz, the maximum output of Master SPI_CLK is 40 MHz, and the maximum
*     output of Slave SPI_CLK is 20 MHz. CNcomment:SPI�����ο�ʱ��Ϊ160 MHz��
��ΪMaster SPI_CLK������Ϊ40MHz����ΪSlave SPI_CLK���֧��20MHz��CNend
* @li Provides two SPIs. The SPI0 provides one TX/RX FIFO for the 16bit��256, and the SPI1 provides one TX/RX
*     FIFO for the 16bit��64. CNcomment:�ṩ��·SPI��SPI0�ṩ16bit��256��TX/RX FIFO��һ��,
SPI1�ṩ16bit��64��TX/RX FIFO��һ����CNend
* @li Only full-duplex communication is supported. When the half-duplex mode is used, the fixed value is sent.
*     When the half-duplex mode is used, the data in the FIFO is discarded.
CNcomment:ֻ֧��ȫ˫��ͨ�ţ���˫����ʱ���͹̶���ֵ����˫����ʱ����FIFO�е����ݡ�CNend \n
* Author: Hisilicon \n
* Create: 2019-4-3
*/

/**
 * @defgroup iot_spi SPI
 * @ingroup drivers
 */

#ifndef __HI_SPI_H__
#define __HI_SPI_H__
#include <hi_types.h>

/**
* @ingroup iot_spi
*
* Channel ID, [0,1]. CNcomment:ͨ��ID��0~1��CNend
*/
typedef enum {
    HI_SPI_ID_0 = 0,
    HI_SPI_ID_1,
} hi_spi_idx;

/**
* @ingroup iot_spi
*
* Communication polarity.CNcomment:ͨ�ż��ԡ�CNend
*/
typedef enum {
    HI_SPI_CFG_CLOCK_CPOL_0, /**< Polarity 0.CNcomment:����0 CNend */
    HI_SPI_CFG_CLOCK_CPOL_1, /**< Polarity 1.CNcomment:����1 CNend */
} hi_spi_cfg_clock_cpol;

/**
* @ingroup iot_spi
*
* Communication phase.CNcomment:ͨ����λ��CNend
*/
typedef enum {
    HI_SPI_CFG_CLOCK_CPHA_0, /**< Phase 0.CNcomment:��λ0 CNend */
    HI_SPI_CFG_CLOCK_CPHA_1, /**< Phase 1.CNcomment:��λ1 CNend */
} hi_spi_cfg_clock_cpha;

/**
* @ingroup iot_spi
*
* Communication protocol type. CNcomment:ͨ��Э�����͡�CNend
*/
typedef enum {
    HI_SPI_CFG_FRAM_MODE_MOTOROLA,  /**< Motorola protocol.CNcomment:Ħ������Э��CNend */
    HI_SPI_CFG_FRAM_MODE_TI,        /**< Texas Instruments protocol.CNcomment:��������Э��CNend */
    HI_SPI_CFG_FRAM_MODE_MICROWIRE, /**< Microwire protocol.CNcomment:MicrowareЭ��CNend */
} hi_spi_cfg_fram_mode;

/**
* @ingroup iot_spi
*
* Communication bit width, that is, number of valid bits in each frame.CNcomment:ͨ��λ��
ÿ֡�ڵ���Чbit����CNend
*/
typedef enum {
    HI_SPI_CFG_DATA_WIDTH_E_4BIT = 0x3, /**< The bit width is 4 bits.CNcomment:λ��Ϊ4bit CNend */
    HI_SPI_CFG_DATA_WIDTH_E_5BIT,       /**< The bit width is 5 bits.CNcomment:λ��Ϊ5bit CNend */
    HI_SPI_CFG_DATA_WIDTH_E_6BIT,       /**< The bit width is 6 bits.CNcomment:λ��Ϊ6bit CNend */
    HI_SPI_CFG_DATA_WIDTH_E_7BIT,       /**< The bit width is 7 bits.CNcomment:λ��Ϊ7bit CNend */
    HI_SPI_CFG_DATA_WIDTH_E_8BIT,       /**< The bit width is 8 bits.CNcomment:λ��Ϊ8bit CNend */
    HI_SPI_CFG_DATA_WIDTH_E_9BIT,       /**< The bit width is 9 bits.CNcomment:λ��Ϊ9bit CNend */
    HI_SPI_CFG_DATA_WIDTH_E_10BIT,      /**< The bit width is 10 bits.CNcomment:λ��Ϊ10bit CNend */
    HI_SPI_CFG_DATA_WIDTH_E_11BIT,      /**< The bit width is 11 bits.CNcomment:λ��Ϊ11bit CNend */
    HI_SPI_CFG_DATA_WIDTH_E_12BIT,      /**< The bit width is 12 bits.CNcomment:λ��Ϊ12bit CNend */
    HI_SPI_CFG_DATA_WIDTH_E_13BIT,      /**< The bit width is 13 bits.CNcomment:λ��Ϊ13bit CNend */
    HI_SPI_CFG_DATA_WIDTH_E_14BIT,      /**< The bit width is 14 bits.CNcomment:λ��Ϊ14bit CNend */
    HI_SPI_CFG_DATA_WIDTH_E_15BIT,      /**< The bit width is 15 bits.CNcomment:λ��Ϊ15bit CNend */
    HI_SPI_CFG_DATA_WIDTH_E_16BIT,      /**< The bit width is 16 bits.CNcomment:λ��Ϊ16bit CNend */
} hi_spi_cfg_data_width;

/**
* @ingroup iot_spi
*
* Communication parameter: big-endian and little-endian transmission of each frame.
CNcomment:ͨ�Ų�����ÿ֡�Ĵ����С�ˡ�CNend
*/
typedef enum {
    HI_SPI_CFG_ENDIAN_LITTLE, /**< Little-endian transmission.CNcomment:С�˴���CNend */
    HI_SPI_CFG_ENDIAN_BIG,    /**< Big-endian transmission.CNcomment:��˴���CNend */
} hi_spi_cfg_endian;

/**
* @ingroup  iot_spi
* @brief  Type of the SPI callback function.CNcomment:SPI�ص����������͡�CNend
*
* @par ����:
*           Type of the SPI callback function.CNcomment:SPI�ص����������͡�CNend
*
* @attention None
*
* @param  None
*
* @retval None
*
* @par ����:
*            @li hi_spi.h��Describes the SPI APIs.CNcomment:�ļ���������SPI��ؽӿڡ�CNend
* @see None
* @since Hi3861_V100R001C00
*/
typedef hi_void (*hi_spi_usr_func)(hi_void);

/**
 * @ingroup iot_spi
 *
 * Data communication parameter.CNcomment:����ͨ�Ų�����CNend
 */
typedef struct {
    hi_u32 cpol:1;         /**< Communication polarity, type hi_spi_cfg_clock_cpol.CNcomment:ͨ�ż��ԣ�����
                                Ϊhi_spi_cfg_clock_cpol��CNend */
    hi_u32 cpha:1;         /**< Communication phase, type hi_spi_cfg_clock_cpha.CNcomment:ͨ����λ������
                                Ϊhi_spi_cfg_clock_cpha��CNend */
    hi_u32 fram_mode:2;    /**< Communication protocol type, type hi_spi_cfg_fram_mode.CNcomment:ͨ��Э�����ͣ�����
                                Ϊhi_spi_cfg_fram_mode��CNend */
    hi_u32 data_width:4;   /**< Communication bit width, type hi_spi_cfg_data_width.CNcomment:ͨ��λ������Ϊ
                                hi_spi_cfg_data_width�� CNend */
    hi_u32 endian:1;       /**< Big-endian and little-endian, type hi_spi_cfg_endian.CNcomment:��С�ˣ�����Ϊ
                                hi_spi_cfg_endian��CNend */
    hi_u32 pad:23;         /**< Reserve bits.CNcomment:����λ CNend */
    hi_u32 freq;           /**< Communication frequency, ranges 2460Hz-40MHz.CNcomment:ͨ��Ƶ�ʣ�ȡֵ��Χ
                                2460Hz-40MHz��CNend */
} hi_spi_cfg_basic_info;

/**
 * @ingroup iot_spi
 *
 * Data communication parameter.CNcomment:�����豸���á�CNend
 */
typedef struct {
    hi_u32 is_slave:1;
    hi_u32 pad:31;
} hi_spi_cfg_init_param;
/**
* @ingroup  iot_spi
* @brief TX interface for the SPI slave mode.CNcomment:SPI��ģʽ���ͽӿڡ�CNend
*
* @par ����:
*           TX interface for the SPI slave mode.CNcomment:SPI��ģʽ���ͽӿڡ�CNend
*
* @attention None
*
* @param  spi_id         [IN]  type #hi_spi_idx��SPI ID��
* @param  write_data     [IN]  type #hi_pvoid��TX data pointer.CNcomment;��������ָ�롣CNend
* @param  byte_len       [IN]  type #hi_u32��length of the target data to be sent (unit: byte).
CNcomment:�������ݳ��ȣ���λ��byte����CNend
* @param  time_out_ms    [IN]  type #hi_u32��wait timeout period.CNcomment:��ʱʱ�䡣CNend
*
* @retval #0               Success
* @retval #Other           Failure. For details, see hi_errno.h.
* @par ����:
*            @li hi_spi.h��Describes the SPI APIs.CNcomment:�ļ���������SPI��ؽӿڡ�CNend
* @see  None
* @since Hi3861_V100R001C00
*/
hi_u32 hi_spi_slave_write(hi_spi_idx spi_id, hi_pvoid write_data, hi_u32 byte_len, hi_u32 time_out_ms);

/**
* @ingroup  iot_spi
* @brief RX interface for the SPI slave mode.CNcomment:SPI��ģʽ���սӿڡ�CNend
*
* @par ����:
*           RX interface for the SPI slave mode.CNcomment:SPI��ģʽ���սӿڡ�CNend
*
* @attention None
*
* @param  spi_id          [IN]  type #hi_spi_idx��SPI ID��
* @param  read_data       [OUT] type #hi_pvoid��RX data pointer.CNcomment:��������ָ�롣CNend
* @param  byte_len        [IN]  type #hi_u32��length of the target data to be received (unit: byte).
CNcomment:�������ݳ��ȣ���λ��byte����CNend
* @param  time_out_ms    [IN]  type #hi_u32��wait timeout period.CNcomment:��ʱʱ�䡣CNend
*
* @retval #0               Success
* @retval #Other           Failure. For details, see hi_errno.h.
* @par ����:
*            @li hi_spi.h��Describes the SPI APIs.CNcomment:�ļ���������SPI��ؽӿڡ�CNend
* @see  None
* @since Hi3861_V100R001C00
*/
hi_u32 hi_spi_slave_read(hi_spi_idx spi_id, hi_pvoid read_data, hi_u32 byte_len, hi_u32 time_out_ms);

/**
* @ingroup  iot_spi
* @brief Half-duplex TX interface for the SPI master mode.CNcomment:SPI��ģʽ��˫�����ͽӿڡ�CNend
*
* @par ����:
*          Half-duplex TX interface for the SPI master mode.CNcomment: SPI��ģʽ��˫�����ͽӿڡ�CNend
*
* @attention None
*
* @param  spi_id         [IN]  type #hi_spi_idx��SPI ID��
* @param  write_data     [IN]  type #hi_pvoid��TX data pointer.CNcomment;��������ָ�롣CNend
* @param  byte_len       [IN]  type #hi_u32��length of the target data to be sent (unit: byte).
CNcomment:�������ݳ��ȣ���λ��byte����CNend
*
* @retval #0               Success
* @retval #Other           Failure. For details, see hi_errno.h.
* @par ����:
*            @li hi_spi.h��Describes the SPI APIs.CNcomment:�ļ���������SPI��ؽӿڡ�CNend
* @see  None
* @since Hi3861_V100R001C00
*/
hi_u32 hi_spi_host_write(hi_spi_idx spi_id, hi_pvoid write_data, hi_u32 byte_len);

/**
* @ingroup  iot_spi
* @brief Half-duplex RX interface for the SPI master mode.CNcomment:SPI��ģʽ��˫�����սӿڡ�CNend
*
* @par ����:
*           Half-duplex RX interface for the SPI master mode.CNcomment:SPI��ģʽ��˫�����սӿڡ�CNend
*
* @attention None
*
* @param  spi_id          [IN]  type #hi_spi_idx��SPI ID��
* @param  read_data       [OUT] type #hi_pvoid��RX data pointer.CNcomment:��������ָ�롣CNend
* @param  byte_len        [IN]  type #hi_u32��length of the target data to be received (unit: byte).
CNcomment:�������ݳ��ȣ���λ��byte����CNend
*
* @retval #0               Success
* @retval #Other           Failure. For details, see hi_errno.h.
* @par ����:
*            @li hi_spi.h��Describes the SPI APIs.CNcomment:�ļ���������SPI��ؽӿڡ�CNend
* @see  None
* @since Hi3861_V100R001C00
*/
hi_u32 hi_spi_host_read(hi_spi_idx spi_id, hi_pvoid read_data, hi_u32 byte_len);

/**
* @ingroup  iot_spi
* @brief Full-duplex TX/RX interface for the SPI master mode.CNcomment:SPI��ģʽȫ˫���շ��ӿڡ�CNend
*
* @par ����:
*           Full-duplex TX/RX interface for the SPI master mode.CNcomment:SPI��ģʽȫ˫���շ��ӿڡ�CNend
*
* @attention None.
*
* @param  spi_id          [IN]  type #hi_spi_idx��SPI ID��
* @param  write_data     [IN]  type #hi_pvoid��TX data pointer.CNcomment;��������ָ�롣CNend
* @param  read_data       [OUT] type #hi_pvoid��RX data pointer.CNcomment:��������ָ�롣CNend
* @param  byte_len        [IN]  type #hi_u32��length of the target data to be received (unit: byte).
CNcomment:�������ݳ��ȣ���λ��byte����CNend
*
* @retval #0               Success
* @retval #Other           Failure. For details, see hi_errno.h.
* @par ����:
*            @li hi_spi.h��Describes the SPI APIs.CNcomment:�ļ���������SPI��ؽӿڡ�CNend
* @see  None
* @since Hi3861_V100R001C00
*/
hi_u32 hi_spi_host_writeread(hi_spi_idx spi_id, hi_pvoid write_data, hi_pvoid read_data, hi_u32 byte_len);


/**
* @ingroup  iot_spi
* @brief Configures the SPI parameter.CNcomment:����SPI������CNend
*
* @par ����:
*           Configures the SPI parameter.CNcomment:����SPI������CNend
*
* @attention None
*
* @param  spi_id   [IN]  type #hi_spi_idx��SPI ID��
* @param  param    [IN]  type #hi_spi_cfg_basic_info��SPI parameters.CNcomment:SPI������CNend
*
* @retval #0               Success
* @retval #Other           Failure. For details, see hi_errno.h.
* @par ����:
*            @li hi_spi.h��Describes the SPI APIs.CNcomment:�ļ���������SPI��ؽӿڡ�CNend
* @see  None
* @since Hi3861_V100R001C00
*/
hi_u32 hi_spi_set_basic_info(hi_spi_idx spi_id, const hi_spi_cfg_basic_info *param);

/**
* @ingroup  iot_spi
* @brief  Initializes the SPI module.CNcomment:SPIģ���ʼ����CNend
*
* @par ����:
*           Initializes the SPI module.CNcomment:SPIģ���ʼ����CNend
*
* @attention To initialize the SPI module, the user needs to perform the initial configuration on the SPI
*            information as follows:CNcomment:��SPIģ���ʼ�����û���Ҫ��SPI������Ϣ���г�ʼ���ã�CNend
*            @li Clear spi_ctrl to 0.CNcomment:spi_ctrl�������Ϊ0������CNend
*            @li Configure the master/slave mode. CNcomment:����SPI[id]����/��ģʽ��CNend
*            @li Configure the transfer parameters.CNcomment:����SPI[id]�Ĵ��������CNend
*
* @param  spi_id     [IN] type #hi_spi_idx��SPI ID��
* @param  init_param [IN] type #hi_spi_cfg_init_param��initialize as a slave device.CNcomment:�Ƿ���Ϊ���豸��CNend
* @param  param      [IN] type #hi_spi_cfg_basic_info��configure parameters.CNcomment:��ʼ��SPI�豸������CNend
*
* @retval #0               Success
* @retval #Other           Failure. For details, see hi_errno.h.
* @par ����:
*            @li hi_spi.h��Describes the SPI APIs.CNcomment:�ļ���������SPI��ؽӿڡ�CNend
* @see  None
* @since Hi3861_V100R001C00
*/
hi_u32 hi_spi_init(hi_spi_idx spi_id, hi_spi_cfg_init_param init_param, const hi_spi_cfg_basic_info *param);

/**
* @ingroup  iot_spi
* @brief  Deinitializes the SPI module.CNcomment:SPIģ��ȥ��ʼ����CNend
*
* @par ����:
*           Deinitializes the SPI module.CNcomment:SPIģ��ȥ��ʼ����CNend
*
* @attention None
* @param  spi_id  [IN] type #hi_spi_idx��SPI ID��
*
* @retval #0               Success
* @retval #Other           Failure. For details, see hi_errno.h.
* @par ����:
*            @li hi_spi.h��Describes the SPI APIs.CNcomment:�ļ���������SPI��ؽӿڡ�CNend
* @see  None
 * @since Hi3861_V100R001C00
 */
hi_u32 hi_spi_deinit(hi_spi_idx spi_id);

/**
* @ingroup  iot_spi
* @brief  Set a master spi to use irq mode.CNcomment:�����Ƿ�ʹ���жϷ�ʽ�������ݡ�CNend
*
* @par ����:
*         Set a master spi to use irq mode.CNcomment:�����Ƿ�ʹ���жϷ�ʽ�������ݡ�CNend
*
* @attention None
* @param  spi_id        [IN] type #hi_spi_idx��SPI ID��
* @param  irq_en        [IN] type #hi_bool��enable irq. CNcomment:�Ƿ�ʹ���жϷ�ʽ��CNend
*
* @retval #0               Success
* @retval #Other           Failure. For details, see hi_errno.h.
* @par ����:
*            @li hi_spi.h��Describes the SPI APIs.CNcomment:�ļ���������SPI��ؽӿڡ�CNend
* @see  None
* @since Hi3861_V100R001C00
*/
hi_u32 hi_spi_set_irq_mode(hi_spi_idx id, hi_bool irq_en);

/**
* @ingroup  iot_spi
* @brief  Set a master spi to use dma mode.CNcomment:����slave ģʽ���Ƿ�ʹ��DMA��ʽ�������ݡ�CNend
*
* @par ����:
*         Set a master spi to use dma mode.CNcomment:����slaveģʽ���Ƿ�ʹ��DMA��ʽ�������ݡ�CNend
*
* @attention None
* @param  spi_id        [IN] type #hi_spi_idx��SPI ID��
* @param  dma_en        [IN] type #hi_bool��enable dma. CNcomment:�Ƿ�ʹ��DMA��ʽ��CNend
*
* @retval #0               Success
* @retval #Other           Failure. For details, see hi_errno.h.
* @par ����:
*            @li hi_spi.h��Describes the SPI APIs.CNcomment:�ļ���������SPI��ؽӿڡ�CNend
* @see  None
* @since Hi3861_V100R001C00
*/
hi_u32 hi_spi_set_dma_mode(hi_spi_idx id, hi_bool dma_en);

/**
* @ingroup  iot_spi
* @brief  Register a user to prepare or restore function.CNcomment:ע���û�׼��/�ָ�������CNend
*
* @par ����:
*           Register a user to prepare or restore function.CNcomment:ע���û�׼��/�ָ�������CNend
*
* @attention None
* @param  spi_id    [IN] type #hi_spi_idx��SPI ID��
* @param  prepare_f [IN] type #hi_spi_usr_func��user prepare function.CNcomment:�û�׼��������CNend
* @param  restore_f [IN] type #hi_spi_usr_func��user restore fucntion.CNcomment:�û��ָ�������CNend
*
* @retval #0               Success
* @retval #Other           Failure. For details, see hi_errno.h.
* @par ����:
*            @li hi_spi.h��Describes the SPI APIs.CNcomment:�ļ���������SPI��ؽӿڡ�CNend
* @see  None
* @since Hi3861_V100R001C00
*/
hi_u32 hi_spi_register_usr_func(hi_spi_idx id, hi_spi_usr_func prepare_f, hi_spi_usr_func restore_f);

/**
* @ingroup  iot_spi
* @brief  �����Ƿ�Ϊ�ػ�����ģʽ
*
* @par ����:
*          �����Ƿ�Ϊ�ػ�����ģʽ
*
* @attention �ޡ�
* @param  spi_id    [IN] ���� #hi_spi_idx��SPI ID��
* @param  lb_en     [IN] ���� #hi_bool��loop back enable
*
* @retval #0            �ɹ���
* @retval #Other          ʧ�ܡ����hi_errno.h��
* @par ����:
*            @li hi_spi.h���ļ���������SPI��ؽӿڡ�
* @see  �ޡ�
* @since Hi3861_V100R001C00
*/
hi_u32 hi_spi_set_loop_back_mode(hi_spi_idx id, hi_bool lb_en);


#endif
