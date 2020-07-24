/**
* @file hi_efuse.h
*
* Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2019. All rights reserved.  \n
* Description: Efuse configuration.   \n
* Author: Hisilicon   \n
* Create: 2019-12-18
*/

/**
 * @defgroup iot_efuse Efuse
 * @ingroup drivers
 */
#ifndef __HI_EFUSE_H__
#define __HI_EFUSE_H__
#include <hi_types_base.h>

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif /* __cplusplus */

typedef enum {
    HI_EFUSE_CHIP_RW_ID = 0,
    HI_EFUSE_DIE_RW_ID = 1,
    HI_EFUSE_PMU_FUSE1_RW_ID = 2,
    HI_EFUSE_PMU_FUSE2_RW_ID = 3,
    HI_EFUSE_FLASH_ENCPY_CNT3_RW_ID = 4,
    HI_EFUSE_FLASH_ENCPY_CNT4_RW_ID = 5,
    HI_EFUSE_FLASH_ENCPY_CNT5_RW_ID = 6,
    HI_EFUSE_DSLEEP_FLAG_RW_ID = 7,
    HI_EFUSE_ROOT_PUBKEY_RW_ID = 8,
    HI_EFUSE_ROOT_KEY_WO_ID = 9,
    HI_EFUSE_CUSTOMER_RSVD0_RW_ID = 10,
    HI_EFUSE_SUBKEY_CAT_RW_ID = 11,
    HI_EFUSE_ENCRYPT_FLAG_RW_ID = 12,
    HI_EFUSE_SUBKEY_RSIM_RW_ID = 13,
    HI_EFUSE_START_TYPE_RW_ID = 14,
    HI_EFUSE_JTM_RW_ID = 15,
    HI_EFUSE_UTM0_RW_ID = 16,
    HI_EFUSE_UTM1_RW_ID = 17,
    HI_EFUSE_UTM2_RW_ID = 18,
    HI_EFUSE_SDC_RW_ID = 19,
    HI_EFUSE_RSVD0_RW_ID = 20,
    HI_EFUSE_KDF2ECC_HUK_DISABLE_RW_ID = 21,
    HI_EFUSE_SSS_CORNER_RW_ID = 22,
    HI_EFUSE_UART_HALT_INTERVAL_RW_ID = 23,
    HI_EFUSE_TSENSOR_RIM_RW_ID = 24,
    HI_EFUSE_CHIP_BK_RW_ID = 25,
    HI_EFUSE_IPV4_MAC_ADDR_RW_ID = 26,
    HI_EFUSE_IPV6_MAC_ADDR_RW_ID = 27,
    HI_EFUSE_PG2GCCKA0_TRIM0_RW_ID = 28,
    HI_EFUSE_PG2GCCKA1_TRIM0_RW_ID = 29,
    HI_EFUSE_NVRAM_PA2GA0_TRIM0_RW_ID = 30,
    HI_EFUSE_NVRAM_PA2GA1_TRIM0_RW_ID = 31,
    HI_EFUSE_PG2GCCKA0_TRIM1_RW_ID = 32,
    HI_EFUSE_PG2GCCKA1_TRIM1_RW_ID = 33,
    HI_EFUSE_NVRAM_PA2GA0_TRIM1_RW_ID = 34,
    HI_EFUSE_NVRAM_PA2GA1_TRIM1_RW_ID = 35,
    HI_EFUSE_PG2GCCKA0_TRIM2_RW_ID = 36,
    HI_EFUSE_PG2GCCKA1_TRIM2_RW_ID = 37,
    HI_EFUSE_NVRAM_PA2GA0_TRIM2_RW_ID = 38,
    HI_EFUSE_NVRAM_PA2GA1_TRIM2_RW_ID = 39,
    HI_EFUSE_TEE_BOOT_VER_RW_ID = 40,
    HI_EFUSE_TEE_KERNEL_VER_RW_ID = 41,
    HI_EFUSE_TEE_SALT_RW_ID = 42,
    HI_EFUSE_FLASH_ENCPY_CNT0_RW_ID = 43,
    HI_EFUSE_FLASH_ENCPY_CNT1_RW_ID = 44,
    HI_EFUSE_FLASH_ENCPY_CNT2_RW_ID = 45,
    HI_EFUSE_FLASH_ENCPY_CFG_RW_ID = 46,
    HI_EFUSE_FLASH_SCRAMBLE_EN_RW_ID = 47,
    HI_EFUSE_USER_FLASH_IND_RW_ID = 48,
    HI_EFUSE_RF_PDBUFFER_GCAL_RW_ID = 49,
    HI_EFUSE_CUSTOMER_RSVD1_RW_ID = 50,
    HI_EFUSE_DIE_2_RW_ID = 51,
    HI_EFUSE_SEC_BOOT_RW_ID = 52,
    HI_EFUSE_IDX_MAX,
} hi_efuse_idx;

typedef enum {
    HI_EFUSE_LOCK_CHIP_ID = 0,
    HI_EFUSE_LOCK_DIE_ID = 1,
    HI_EFUSE_LOCK_PMU_FUSE1_FUSE2_START_TYPE_TSENSOR_ID = 2,
    HI_EFUSE_LOCK_ROOT_PUBKEY_ID = 3,
    HI_EFUSE_LOCK_ROOT_KEY_ID = 4,
    HI_EFUSE_LOCK_CUSTOMER_RSVD0_ID = 5,
    HI_EFUSE_LOCK_SUBKEY_CAT_ID = 6,
    HI_EFUSE_LOCK_ENCRYPT_RSIM_ID = 7,
    HI_EFUSE_LOCK_JTM_ID = 8,
    HI_EFUSE_LOCK_UTM0_ID = 9,
    HI_EFUSE_LOCK_UTM1_ID = 10,
    HI_EFUSE_LOCK_UTM2_ID = 11,
    HI_EFUSE_LOCK_SDC_ID = 12,
    HI_EFUSE_LOCK_RSVD0_ID = 13,
    HI_EFUSE_LOCK_SSS_CORNER_ID = 14,
    HI_EFUSE_LOCK_UART_HALT_INTERVAL_ID = 15,
    HI_EFUSE_LOCK_CHIP_BK_ID = 16,
    HI_EFUSE_LOCK_IPV4_IPV6_MAC_ADDR_ID = 17,
    HI_EFUSE_LOCK_PG2GCCKA0_PG2GCCKA1_TRIM0_ID = 18,
    HI_EFUSE_LOCK_NVRAM_PA2GA0_PA2GA1_TRIM0_ID = 19,
    HI_EFUSE_LOCK_PG2GCCKA0_PG2GCCKA1_TRIM1_ID = 20,
    HI_EFUSE_LOCK_NVRAM_PA2GA0_PA2GA1_TRIM1_ID = 21,
    HI_EFUSE_LOCK_PG2GCCKA0_PG2GCCKA1_TRIM2_ID = 22,
    HI_EFUSE_LOCK_NVRAM_PA2GA0_PA2GA1_TRIM2_ID = 23,
    HI_EFUSE_LOCK_TEE_BOOT_VER_ID = 24,
    HI_EFUSE_LOCK_TEE_KERNEL_VER_ID = 25,
    HI_EFUSE_LOCK_TEE_SALT_ID = 26,
    HI_EFUSE_LOCK_FLASH_ENCPY_CNT0_ID = 27,
    HI_EFUSE_LOCK_FLASH_ENCPY_CNT1_ID = 28,
    HI_EFUSE_LOCK_FLASH_ENCPY_CNT2_ID = 29,
    HI_EFUSE_LOCK_FLASH_ENCPY_CFG_ID = 30,
    HI_EFUSE_LOCK_FLASH_SCRAMBLE_EN_FLASH_IND_ID = 31,
    HI_EFUSE_LOCK_RF_PDBUFFER_GCAL_ID = 32,
    HI_EFUSE_LOCK_CUSTOMER_RSVD1_ID = 33,
    HI_EFUSE_LOCK_DIE_2_ID = 34,
    HI_EFUSE_LOCK_KDF2ECC_HUK_DISABLE_ID = 35,
    HI_EFUSE_LOCK_FLASH_ENCPY_CNT3_ID = 36,
    HI_EFUSE_LOCK_FLASH_ENCPY_CNT4_ID = 37,
    HI_EFUSE_LOCK_FLASH_ENCPY_CNT5_ID = 38,
    HI_EFUSE_LOCK_SEC_BOOT_ID = 39,
    HI_EFUSE_LOCK_DSLEEP_FLAG_ID = 40,
    HI_EFUSE_LOCK_MAX,
} hi_efuse_lock_id;

/**
* @ingroup  iot_efuse
* @brief Obtains the preset length of each eFUSE area.CNcomment:����EFUSE ID�Ż�ȡ��EFUSE���ݳ��ȡ�CNend
*
* @par ����:
*           Obtains the preset length of each eFUSE area.CNcomment:��ȡEFUSE���ݳ��ȡ�CNend
*
* @attention None
* @param  efuse_id  [IN]  type #hi_efuse_idx��EFUSE ID
*
* @retval #HI_ERR_EFUSE_INVALIDATE_ID Invalid ID.CNcomment: ��ЧEFUSE ID��CNend
* @retval #Other Length of EFUSE data.(Unit bytes).CNcomment: EFUSE���ݳ���(��λΪbit)��CNend
* @par ����:
*            @li hi_efuse.h��Describes the encryption and decryption APIs.
CNcomment:�ļ���������efuse�ֶβ�����ؽӿڡ�CNend
* @see  hi_efuse_get_id_size��
* @since Hi3861_V100R001C00
*/
hi_u32 hi_efuse_get_id_size(hi_efuse_idx efuse_id);

/**
* @ingroup  iot_efuse
* @brief Reads the eFUSE.CNcomment:EFUSE��ȡ���ݡ�CNend
*
* @par ����:
*           Reads the eFUSE.CNcomment:��EFUSE�ж�ȡ���ݡ�CNend
*
* @attention Ensure that the value of (data_len*8) is not less than efuse_id and the length of the efuse field is 8bit
*            aligned.CNcomment:�豣֤(data_len*8)��С��efuse_id��Ӧefuse�ֶεĳ�������8bit���롣CNend
*
* @param  efuse_id [IN]  type #hi_efuse_idx��EFUSE ID
* @param  data     [OUT] type #hi_u8*��Address for saving the read data.CNcomment:���������ݷŵ��õ�ַ��CNend
* @param  data_len [IN]  type #hi_u8 Space allocated to data, in bytes.CNcomment:��data����Ŀռ䣬��λbyte��CNend
*
* @retval #0         Success
* @retval #Other     Failure. For details, see hi_errno.h.
* @par ����:
*            @li hi_efuse.h��Describes the encryption and decryption APIs.
CNcomment:�ļ���������efuse�ֶβ�����ؽӿڡ�CNend
* @see  hi_efuse_write��
* @since Hi3861_V100R001C00
*/
hi_u32 hi_efuse_read(hi_efuse_idx efuse_id, hi_u8 *data, hi_u8 data_len);

/**
* @ingroup  iot_efuse
* @brief Writes the eFUSE.CNcomment:д���ݵ�EFUSE��CNend
*
* @par ����:
*           Writes the eFUSE.CNcomment:д���ݵ�EFUSE��CNend
*
* @attention None
* @param  efuse_id  [IN] type #hi_efuse_idx��EFUSE ID
* @param  data      [IN] type #const hi_u8*��Data to be written to the eFUSE.CNcomment:д�����ݵ�EFUSE�С�CNend
*
* @retval #0         Success
* @retval #Other     Failure. For details, see hi_errno.h.
* @par ����:
*            @li hi_efuse.h��Describes the encryption and decryption APIs.
CNcomment:�ļ���������efuse�ֶβ�����ؽӿڡ�CNend
* @see  hi_efuse_read��
* @since Hi3861_V100R001C00
*/
hi_u32 hi_efuse_write(hi_efuse_idx efuse_id, const hi_u8 *data);

/**
* @ingroup  iot_efuse
* @brief Locks an area in the eFUSE. After the lock takes effect upon reboot, the area cannot be written.
CNcomment:����EFUSE�е�ĳ�����򣬼���������������Ч���������޷���д�롣CNend
*
* @par ����:
*           Locks an area in the eFUSE. After the lock takes effect upon reboot, the area cannot be written.
CNcomment:����EFUSE�е�ĳ�����򣬼���������������Ч���������޷���д�롣CNend
*
* @attention None
* @param  lock_id  [IN] type #hi_efuse_lock_id��eFUSE ID to be locked.CNcomment:��������EFUSE ID�CNend
*
* @retval #0         Success
* @retval #Other     Failure. For details, see hi_errno.h.
* @par ����:
*            @li hi_efuse.h��Describes the encryption and decryption APIs.
CNcomment:�ļ���������efuse�ֶβ�����ؽӿڡ�CNend
* @see  hi_efuse_write��
* @since Hi3861_V100R001C00
*/
hi_u32 hi_efuse_lock(hi_efuse_lock_id lock_id);

/**
* @ingroup  iot_efuse
* @brief Obtains the lock status of the eFUSE and queries which areas are locked.
CNcomment:��ȡEFUSE����״̬����ѯ��Щ������������CNend
*
* @par ����:
*           Obtains the lock status of the eFUSE and queries which areas are locked.
CNcomment:��ȡEFUSE����״̬����ѯ��Щ������������CNend
*
* @attention None
* @param  lock_stat   [OUT] type #hi_u64*��Lock status of the eFUSE.CNcomment:��ȡEFUSE����״̬��CNend
*
* @retval #0         Success
* @retval #Other     Failure. For details, see hi_errno.h.
* @par ����:
*            @li hi_efuse.h��Describes the encryption and decryption APIs.
CNcomment:�ļ���������efuse�ֶβ�����ؽӿڡ�CNend
* @see  hi_efuse_write��
* @since Hi3861_V100R001C00
*/
hi_u32 hi_efuse_get_lockstat(hi_u64 *lock_stat);

/**
* @ingroup  iot_efuse
* @brief Reads the user eFUSE.CNcomment:EFUSE�û���ȡ���ݡ�CNend
*
* @par ����:
*            Reads a reserved area in the eFUSE.CNcomment:�û���EFUSE�ж�ȡ���ݡ�CNend
*
* @attention None
* @param  start_bit  [IN]  type #hi_u16��Start bit. The address must be 8-bit aligned.
CNcomment:��ʼbitλ���õ�ַ����8bit���롣CNend
* @param  size       [IN]  type #hi_u16��Number of bits to be read. If the input is not 8-bit aligned,
* the function performs 8-bit alignment internally. The user needs to process the read data before using it.
CNcomment:����ȡ��bitλ����������벻��8bit���������ڲ��ᴦ��Ϊ8bit���룬�û���ȡ���ݺ��账���ʹ�á�CNend
* @param  key_data  [OUT]  type #hi_u8*��Address for saving the read data.
CNcommnet:���������ݷŵ��õ�ַ��CNend
*
* @retval #0         Success
* @retval #Other     Failure. For details, see hi_errno.h.
* @par ����:
*            @li hi_efuse.h��Describes the encryption and decryption APIs.
CNcomment:�ļ���������efuse�ֶβ�����ؽӿڡ�CNend
* @see  hi_efuse_usr_write��
* @since Hi3861_V100R001C00
*/
hi_u32 hi_efuse_usr_read(hi_u16 start_bit, hi_u16 size, hi_u8 *key_data);

/**
* @ingroup  iot_efuse
* @brief Writes data to reserved area of the eFUSE.CNcomment:EFUSE�û���д�����ݡ�CNend
*
* @par ����:
*           Writes data to reserved area of the eFUSE.CNcomment:�û���EFUSEд�����ݡ�CNend
*
* @attention Generally, this API is used to write a reserved area. To write other pre-allocated areas,
*            should check the design spec to avoid conflict.CNcomment:֧���û�д�������ַ���ݣ�
�����û�ʹ���û�Ԥ���������������д����Ҫ��Ϸ����ĵ������Ƿ��г�ͻ��CNend
*
* @param  start_bit  [IN] type  #hi_u16��Start bit.CNcomment:��ʼbitλ��CNend
* @param  size       [IN] type  #hi_u16��Number of bits to be written. 1-to-256-bit write is supported.
CNcomment:��д��bit����֧�ֵ�bitд�룬���ֵΪ256bit����CNend
* @param  key_data  [IN]  type  #const hi_u8*��Address for the data to be written. The maximum length is 32 bytes.
CNcomment:��д������ݷŵ��õ�ַ���Ϊ32byte��CNend
*
* @retval #0         Success
* @retval #Other     Failure. For details, see hi_errno.h.
* @par ����:
*            @li hi_efuse.h��Describes the encryption and decryption APIs.
CNcomment:�ļ���������efuse�ֶβ�����ؽӿڡ�CNend
* @see  hi_efuse_usr_read��
* @since Hi3861_V100R001C00
*/
hi_u32 hi_efuse_usr_write(hi_u16 start_bit, hi_u16 size, const hi_u8 *key_data);

#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif /* __cplusplus */

#endif /* __HI_EFUSE_H__ */
