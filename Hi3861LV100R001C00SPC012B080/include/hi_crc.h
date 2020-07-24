/**
* @file hi_crc.h
*
* Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2019. All rights reserved.  \n
* Description: Cyclic redundancy check (CRC) interfaces.   \n
* Author: Hisilicon   \n
* Create: 2019-01-17
*/

/**
 * @defgroup iot_crc  CRC Verification
 * @ingroup system
 */

#ifndef __HI_CRC_H__
#define __HI_CRC_H__
#include <hi_types_base.h>

/**
* @ingroup  iot_crc
* @brief  Generates a 16-bit CRC value.CNcomment:����16λCRCУ��ֵ��CNend
*
* @par ����:
*           Generates a 16-bit CRC value.CNcomment:����16λCRCУ��ֵ��CNend
*
* @attention None
* @param  crc_start         [IN] type #hi_u16��The CRC initial value.CNcomment:CRC��ʼֵ��CNend
* @param  buf               [IN] type #const hi_u8*��Pointer to the buffer to be verified.
CNcomment:��У��Bufferָ�롣CNend
* @param  len               [IN] type #hi_u32��Length of the buffer to be verified (unit: Byte).
CNcomment:��У��Buffer���ȣ���λ��byte����CNend
* @param  crc_result        [OUT]type #hi_u16*��CRC calculation result.CNcomment:CRC��������CNend
*
* @retval #0     Success.
* @retval #Other Failure.
*
* @par ����:
*            @li hi_crc.h��Describes CRC APIs.CNcomment:�ļ�����CRCУ��ӿڡ�CNend
* @see  None
* @since Hi3861_V100R001C00
*/
hi_u32 hi_crc16(hi_u16 crc_start, const hi_u8 *buf, hi_u32 len, hi_u16 *crc_result);

/**
* @ingroup  iot_crc
* @brief  Generates a 32-bit CRC value.CNcomment:����32λCRCУ��ֵ��CNend
*
* @par ����:
*          Generates a 32-bit CRC value.CNcomment:����32λCRCУ��ֵ��CNend
*
* @attention None
* @param  crc_start         [IN] type #hi_u32��The CRC initial value.CNcomment:CRC��ʼֵ��CNend
* @param  buf               [IN] type #const hi_u8*��Pointer to the buffer to be verified.
CNcomment:��У��Bufferָ�롣CNend
* @param  len               [IN] type #hi_u32��Length of the buffer to be verified (unit: Byte).
CNcomment:��У��Buffer���ȣ���λ��byte����CNend
* @param  crc_result        [OUT]type #hi_u32*��CRC calculation result.CNcomment:CRC��������CNend
*
* @retval #0     Success.
* @retval #Other Failure.
*
* @par ����:
*            @li hi_crc.h��Describes CRC APIs.CNcomment:�ļ�����CRCУ��ӿڡ�CNend
* @see  None
* @since Hi3861_V100R001C00
*/
hi_u32 hi_crc32(hi_u32 crc_start, const hi_u8 *buf, hi_u32 len, hi_u32 *crc_result);

#endif

