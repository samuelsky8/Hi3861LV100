/**
* @file hi_dma.h
*
*  Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2019. All rights reserved.  \n
*
* ������DMA module. CNcomment:DMA���ýӿڡ�CNend
* @li The DMA transfer is realized by calling internal DMA driver.
CNcomment:ͨ�������ڲ�DMA����ʵ��DMA����CNend
* @li Supports four transmission modes: Memory to storage, memory to peripheral, peripheral to memory,
and peripheral to peripheral.CNcomment:֧�ִ洢�����洢�����洢�������衢���赽�洢����
���赽�������ִ��䷽ʽCNend
* @li The DMA has four channels. If there is no idle channel, the HI_ERR_DMA_BUSY error is returned.
CNcomment:DMA����4ͨ�����޿���ͨ��ʱ����HI_ERR_DMA_BUSY����CNend
* @li The callback function is executed in the interrupt context, so you need to comply with the programming
precautions for the interrupt context.CNcomment:�ص�����ִ�����ж������ģ�
�����Ҫ�����ж������ĵı��ע�����CNend
* @li Before enabling the DMA channel, you need to set the channel parameters. After the channel parameters
are enabled and then modified, an unpredictable result is generated.CNcomment:��DMAͨ��ʹ��ǰ��������ͨ��������
ʹ��ͨ�������޸�ͨ������������޷�Ԥ֪�Ľ����CNend \n
* Author: Hisilicon \n
* Create: 2019-4-3
*/

/** @defgroup iot_dma DMA
 *  @ingroup drivers
 */

#ifndef _HI_DMA_H
#define _HI_DMA_H

#include <hi_types.h>
#include "hi_mdm_types.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @ingroup iot_dma
 *
 * DMA Interruption type. CNcomment: DMA �ж����͡�CNend
 */
 /* ��������ж����� */
#define DMA_INT_TC  1
/* ��������ж����� */
#define DMA_INT_ERR 2

/**
 * @ingroup iot_dma
 *
 * DMA transfer bit width. CNcomment:DMA����λ��CNend
 */
typedef enum {
    WIDTH_BIT8 = 0,
    WIDTH_BIT16,
    WIDTH_BIT32,
} hi_dma_data_width;

/**
 * @ingroup iot_dma
 *
 * DMA configuration structure transferred. CNcomment:�û������DMA���ýṹ�塣CNend
 */
typedef struct hi_dma_user_para {
    hi_u32 ch_idx;         /* ����DMA����ʹ�õ�channel id�������û�����, ͨ������ɹ�ʱ��ֵ */
    uintptr_t src_addr;    /* Դ��ַ��Դ��ַ����4�ֽڶ��� */
    uintptr_t dst_addr;    /* Ŀ���ַ��Ŀ�ĵ�ַ����4�ֽڶ��� */
    hi_u32 size_bytes;     /* ���䳤�ȣ���BYTE��λ */
    hi_void (*cb)(hi_u32);  /* ��������ص�������Ϊ������ɻ������ #DMA_INT_XXX */
} hi_dma_user_para;

/**
* @ingroup  iot_dma
* @brief  Create the dma transmission linked list. CNcomment:����dma��������CNend
*
* @par ����:
*           Create the dma transmission linked list. CNcomment:����dma������������ͨ����CNend
*           After the command is executed successfully, the channel resources are allocated.
*           If the channel resources are not transmitted, the hi_dma_ch_close(usr_para->ch_idx) is invoked to
*           release the channels. CNcomment:ִ�гɹ�������ͨ����Դ�����û��ʵ�ʽ��д�����Ҫ����
hi_dma_ch_close(usr_para->ch_idx)�ͷ�ͨ����CNend
*
* @attention
* @param  usr_para         [IN/OUT] type #hi_dma_user_para��Transfer DMA transfer parameter settings
CNcomment:����DMA����������á�CNend
*
* @retval #HI_ERR_SUCCESS  Success.
* @retval #Other values    Failure. For details, see hi_errno.h.
* @par ����:
*            @li hi_dma.h��   Describes DMA driver APIs. CNcomment:DMA����ʵ�ֽӿڡ�CNend
* @see  None
* @since Hi3861_V100R001C00
 */
hi_u32 hi_dma_create_link_list(hi_dma_user_para *usr_para);

/**
* @ingroup  iot_dma
* @brief  Insert the DMA transmission linked list at behind. CNcomment:dma��������ĩβ��ӽ�㡣CNend
*
* @par ����:
*           Insert the DMA transmission linked list at behind. CNcomment:dma��������ĩβ��ӽ��CNend
*
* @attention
* @param  usr_para         [IN] type #const hi_dma_user_para��Transfer DMA transfer parameter settings.
CNcomment:����DMA����������á�CNend
*
* @retval #HI_ERR_SUCCESS  Success.
* @retval #Other values    Failure. For details, see hi_errno.h.
* @par ����:
*            @li hi_dma.h��   Describes DMA driver APIs. CNcomment:DMA����ʵ�ֽӿڡ�CNend
* @see  None
* @since Hi3861_V100R001C00
 */
hi_u32 hi_dma_add_link_list_item(const hi_dma_user_para *usr_para);

/**
* @ingroup  iot_dma
* @brief  Start DMA linked list transmission. CNcomment:����dma�����䡣CNend
*
* @par ����:
*           Start DMA linked list transmission, channel would be released, no matter about the result.
CNcomment:����dma�����䣬�ɹ���ʧ�ܺ���ͷ�ͨ����CNend
*
* @attention
* @param  ch_num           [IN]     type #hi_u32��Linked list transmission channel.
This parameter is assigned by the API when a linked list is created.
CNcomment:������ͨ������������ʱAPI�ڲ���ֵ��CNend
* @param  block            [IN]     type #hi_bool��Indicates whether to block waiting for transmission completion.
CNcomment:�Ƿ������ȴ�������ɡ�CNend
*
* @retval #HI_ERR_SUCCESS  Success.
* @retval #Other values    Failure. For details, see hi_errno.h.
* @par ����:
*            @li hi_dma.h��   Describes DMA driver APIs. CNcomment:DMA����ʵ�ֽӿڡ�CNend
* @see  None
* @since Hi3861_V100R001C00
 */
hi_u32 hi_dma_link_list_transfer(hi_u32 ch_num, hi_bool block);

/**
* @ingroup  iot_dma
* @brief  Data transmission from the memory to the memory through DMA.
CNcomment:ͨ��DMA���д洢�����洢�����ݴ��䡣CNend
*
* @par ����:
*           Data transmission from the memory to the memory through DMA.
CNcomment:ͨ��DMA���д洢�����洢�����ݴ��䡣CNend
*
* @attention
* @param  dst_addr         [IN]     type #hi_u32��Destination address, which must be 4-byte-aligned.
CNcomment:Ŀ���ַ����4�ֽڶ��롣CNend
* @param  src_addr         [IN]     type #hi_u32��Source address, which must be 4-byte-aligned.
CNcomment:Դ��ַ����4�ֽڶ��롣CNend
* @param  size_bytes       [IN]     type #hi_u32��Transmission length, in bytes.
CNcomment:���䳤�ȣ���BYTEΪ��λ��CNend
* @param  block            [IN]     type #hi_bool��Indicates whether to block waiting for transmission completion.
CNcomment:�Ƿ������ȴ�������ɡ�CNend
* @param  cb_func          [IN]     type #hi_void��Callback function for non-blocking transmission.
The parameter is the DMA interrupt type. Set this parameter to HI_NULL when blocking transmission.
CNcomment:����������Ļص�����������ΪDMA�ж����ͣ���������ʱ��ΪHI_NULL��CNend
*
* @retval #HI_ERR_SUCCESS  Success.
* @retval #HI_ERR_DMA_BUSY Channel busy. CNcomment:ͨ��ȫæ��CNend
* @retval #Other values    Failure. For details, see hi_errno.h.
* @par ����:
*            @li hi_dma.h��   Describes DMA driver APIs. CNcomment:DMA����ʵ�ֽӿڡ�CNend
* @see  None
* @since Hi3861_V100R001C00
 */
hi_u32 hi_dma_mem2mem_transfer(hi_u32 dst_addr, hi_u32 src_addr, hi_u32 size_bytes,
                               hi_bool block, hi_void (*cb_func)(hi_u32 int_type));

/**
* @ingroup  iot_dma
* @brief  Disables the DMA specified channel. CNcomment:�ر�DMAָ��ͨ����CNend
*
* @par ����:
*           Disables the DMA specified channel and release rource.
CNcomment:�ر�DMAָ��ͨ�����ͷ���Դ��CNend
*
* @attention None
* @param  ch_num           [IN]     type #hi_u32��DMA channel ID. Value range: 0-3.
CNcomment:DMAͨ��ID ȡֵ0~3��CNend
*
* @retval #HI_ERR_SUCCESS  Success.
* @retval #Other values    Failure. For details, see hi_errno.h.
* @par ����:
*            @li hi_dma.h��   Describes DMA driver APIs. CNcomment:DMA����ʵ�ֽӿڡ�CNend
* @see  hi_dma_create_link_list��
* @since Hi3861_V100R001C00
 */
hi_u32 hi_dma_ch_close(hi_u32 ch_num);

/**
* @ingroup  iot_dma
* @brief  DMA module initialization.CNcomment:DMAģ���ʼ����CNend
*
* @par ����:
*           DMA module initialization, apply for rources. CNcomment:DMAģ���ʼ��, ������Դ��CNend
*
* @attention None
* @param  None
*
* @retval #HI_ERR_SUCCESS  Success.
* @retval #Other values    Failure. For details, see hi_errno.h.
* @par ����:
*            @li hi_dma.h��   Describes DMA driver APIs. CNcomment:DMA����ʵ�ֽӿڡ�CNend
* @see  None
* @since Hi3861_V100R001C00
 */
hi_u32 hi_dma_init(hi_void);

/**
* @ingroup  iot_dma
* @brief  Deinitializes the DMA module. CNcomment:DMAģ��ȥ��ʼ����CNend
*
* @par ����:
*           Deinitializes the DMA module and release rources. CNcomment:DMAģ��ȥ��ʼ�����ͷ���Դ��CNend
*
* @attention None
* @param  None
*
* @retval None
* @par ����:
*            @li hi_dma.h��   Describes DMA driver APIs. CNcomment:DMA����ʵ�ֽӿڡ�CNend
* @see  None
* @since Hi3861_V100R001C00
*/
hi_void hi_dma_deinit(hi_void);

/**
* @ingroup  iot_dma
* @brief  Judge is DMA module init. CNcomment:DMAģ���Ƿ��ʼ����CNend
*
* @par ����:
*           Is DMA module init. CNcomment:DMAģ���Ƿ��ʼ����CNend
*
* @attention None
* @param  None
*
* @retval #HI_TURE   dma has been initialized.
* @retval #HI_FALSE  DMA has not been initialized.
* @par ����:
*            @li hi_dma.h��   Describes DMA driver APIs. CNcomment:DMA����ʵ�ֽӿڡ�CNend
* @see  None
* @since Hi3861_V100R001C00
 */
hi_bool hi_dma_is_init(hi_void);

#ifdef __cplusplus
}
#endif

#endif
