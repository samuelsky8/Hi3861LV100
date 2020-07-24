/**
* @file hi_flashboot.h
*
* Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2019. All rights reserved.  \n
* Description: Flash Boot APIs. \n
* Author: Hisilicon \n
* Create: 2019-02-22
*/

/** @defgroup iot_flashboot Flash Boot */
#ifndef _HI_FLASHBOOT_H_
#define _HI_FLASHBOOT_H_

#include <hi_types.h>
#include <hi_boot_rom.h>

/** @defgroup iot_nv NV Management APIs
* @ingroup  iot_flashboot
*/
/**
* @ingroup  iot_nv
* Maximum length of an NV item (unit: byte). CNcomment:NV����󳤶ȣ���λ��byte����CNend
*/
#define HNV_ITEM_MAXLEN             (256 - 4)

/**
* @ingroup  iot_nv
*/
#define PRODUCT_CFG_NV_REG_NUM_MAX  20

/**
* @ingroup  iot_nv
*/
#define HI_FNV_DEFAULT_ADDR         0x8000

/**
* @ingroup  iot_nv
*/
#define HI_NV_DEFAULT_TOTAL_SIZE    0x2000

/**
* @ingroup  iot_nv
*/
#define HI_NV_DEFAULT_BLOCK_SIZE    0x1000

/**
* @ingroup  iot_nv
*
* Factory NV area user area end ID. CNcomment:������NV����ID��CNend
*/
#define HI_NV_FACTORY_USR_ID_END    0x20

/**
* @ingroup  iot_nv
*/
#define  HI_NV_FTM_FLASH_PARTIRION_TABLE_ID  0x02

/**
* @ingroup  iot_nv
* @brief Initializes NV management in the factory partition.CNcomment:������NV��ʼ����CNend
*
* @par ����:
*          Initializes NV management in the factory partition.CNcomment: ������NV�����ʼ����CNend
*
* @attention The parameters cannot be set randomly and must match the product delivery plan.
CNcomment:���������������ã���Ҫ���Ʒ�����滮ƥ�䡣CNend
* @param  addr [IN] type #hi_u32��Start address of the NV factory partition in the flash. The address is planned by
*                   the factory and set by the boot macro #FACTORY_NV_ADDR.
CNcomment:���ù�����NV FLASH�׵�ַ���ɳ����滮��boot�궨��FACTORY_NV_ADDR ͳһ���á�CNend
* @param  total_size    [IN] type #hi_u32��total size of factory NV.
CNcomment:������NV���ܴ�С��CNend
* @param  block_size    [IN] type #hi_u32��block size of factory NV.
CNcomment:������NV�Ŀ��С��CNend
*
* @retval #0            Success.
* @retval #Other        Failure. For details, see hi_errno.h.
* @par ����:
*           @li hi_flashboot.h��Describes NV APIs.CNcomment:�ļ���������NV��ؽӿڡ�CNend
* @see hi_factory_nv_write | hi_factory_nv_read��
* @since Hi3861_V100R001C00
*/
hi_u32 hi_factory_nv_init(hi_u32 addr, hi_u32 total_size, hi_u32 block_size);

/**
* @ingroup  iot_nv
* @brief Sets the NV value in the factory partition. CNcomment:���ù�����NVֵ��CNend
*
* @par ����:
*           Sets the NV value in the factory partition.CNcomment:���ù�����NVֵ��CNend
*
* @attention None
* @param  id    [IN] type #hi_u8��NV item ID, ranging from #HI_NV_FACTORY_ID_START to #HI_NV_FACTORY_USR_ID_END.
CNcomment:NV��ID����Χ��#HI_NV_FACTORY_ID_START��#HI_NV_FACTORY_USR_ID_END��CNend
* @param  pdata [IN] type #hi_pvoid��NV item data.CNcomment:NV�����ݡ�CNend
* @param  len   [IN] type #hi_u8��Length of an NV item (unit: byte). The maximum value is #HNV_ITEM_MAXLEN.
CNcomment:NV��ȣ���λ��byte�������������HNV_ITEM_MAXLEN��CNend
* @param  flag   [IN] type #hi_u32��Reserve.CNcomment:����������CNend
*
* @retval #0            Success.
* @retval #Other        Failure. For details, see hi_errno.h.
* @par ����:
*           @li hi_flashboot.h��Describes NV APIs.CNcomment:�ļ���������NV��ؽӿڡ�CNend
* @see hi_factory_nv_read��
* @since Hi3861_V100R001C00
*/
hi_u32 hi_factory_nv_write(hi_u8 id, hi_pvoid pdata, hi_u8 len, hi_u32 flag);

/**
* @ingroup  iot_nv
* @brief Reads the NV value in the factory partition.CNcomment:��ȡ������NVֵ��CNend
*
* @par ����:
*           Reads the NV value in the factory partition.��ȡ������NVֵ��CNend
*
* @attention None
*
* @param  id      [IN] type #hi_u8��NV item ID, ranging from #HI_NV_NORMAL_ID_START to #HI_NV_NORMAL_USR_ID_END.
CNcomment:NV��ID����Χ��#HI_NV_NORMAL_ID_START��#HI_NV_NORMAL_USR_ID_END��CNend
* @param  pdata   [IN] type #hi_pvoid��NV item data.CNcomment:NV�����ݡ�CNend
* @param  len     [IN] type #hi_u8��Length of an NV item (unit: byte). The maximum value is HNV_ITEM_MAXLEN.
CNcomment:NV��ȣ���λ��byte�������������HNV_ITEM_MAXLEN��CNend
* @param  flag    [IN] type #hi_u32��Reserve.CNcomment:����������CNend
*
* @retval #0            Success.
* @retval #Other        Failure. For details, see hi_errno.h.
* @par ����:
*           @li hi_flashboot.h��Describes NV APIs.CNcomment:�ļ���������NV��ؽӿڡ�CNend
* @see hi_factory_nv_write��
* @since Hi3861_V100R001C00
*/
hi_u32 hi_factory_nv_read(hi_u8 id, hi_pvoid pdata, hi_u8 len, hi_u32 flag);

/** @defgroup iot_flash_partiton Partition Table APIs
* @ingroup  iot_flashboot
*/
/**
 * @ingroup iot_flash_partiton
 *
 * partition number.
 */
#define HI_FLASH_PARTITON_MAX 10

/**
 * @ingroup iot_flash_partiton
 *
 * partition ID.
 */
typedef enum {
    HI_FLASH_PARTITON_BOOT = 0,
    HI_FLASH_PARTITON_FACTORY_NV,
    HI_FLASH_PARTITON_WORK_NV,
    HI_FLASH_PARTITON_KERNEL_A,
    HI_FLASH_PARTITON_KERNEL_B,
    HI_FLASH_PARTITON_HILINK,
    HI_FLASH_PARTITON_FILE_SYSTEM,
    HI_FLASH_PARTITON_CRASH_INFO,
    HI_FLASH_PARTITON_BOOT_BACK,
    HI_FLASH_PARTITON_RESERVE,
} hi_flash_partition_table_id;

/**
 *  @ingroup iot_flash_partiton
 *
 *  Flash partition management. CNcomment:Flash�������CNend
 */
typedef struct {
    hi_u32  addr    :24;   /* Flash partition address. The value is 16 MB. If the address is in reverse order,
                               the value is the end low address. CNcomment:Flash������ַ������Ϊ16MB��
                               ���Ϊ���򣬴��Ϊ�����ĵ͵�ֵַ CNend */
    hi_u32  id      :7;    /* Flash partition ID. CNcomment:Flash��ID.CNend  */
    hi_u32  dir     :1;    /* Flash area storage direction. 0:regular. 1: reversed.CNcomment:Flash����ŷ���
                               0��������������1������ĩ��ַ CNend */

    hi_u32  size    :24;   /* Size of the parition(Unit:byte). CNcomment:Flash������С����λ��byte��CNend */
    hi_u32  reserve :8;    /* Reserved. CNcomment:������CNend  */

    hi_u32  addition;      /* Supplementary information about the flash partition, such as the address of the Ram.
                              CNcomment:Flash����������Ϣ����Ram��Ӧ��ַ�� CNend */
} hi_flash_partition_info;

/**
 *  @ingroup iot_flash_partiton
 *  Flash partiton table.
 */
typedef struct {
    hi_flash_partition_info table[HI_FLASH_PARTITON_MAX]; /**< Flash������������  */
} hi_flash_partition_table;

/**
* @ingroup  iot_flash_partiton
* @brief  Initialize flash partition table. CNcomment:��ʼ��Flash������CNend
*
* @par ����:
*           Initialize flash partition table. CNcomment:��ʼ��Flash������CNend
*
* @attention None.
* @param  None.
*
* @retval #HI_ERR_FAILURE Failure.
* @retval #HI_ERR_SUCCESS Success.
* @par ����:
*            @li hi_flashboot.h��Describes FlashBoot APIs.CNcomment:�ļ���������Bootģ��ӿڡ�CNend
* @see  hi_get_partition_table��
* @since Hi3861_V100R001C00
*/
hi_u32 hi_flash_partition_init(hi_void);

/**
* @ingroup  iot_flash_partiton
* @brief  Get flash partition table. CNcomment:��ȡFlash������CNend
*
* @par ����:
*           Get flash partition table. CNcomment:��ȡFlash������CNend
*
* @attention None.
* @param  None.
*
* @retval #HI_NULL Failure.
* @retval #Other Success.
* @par ����:
*            @li hi_flashboot.h��Describes FlashBoot APIs.CNcomment:�ļ���������Bootģ��ӿڡ�CNend
* @see  hi_flash_partition_init��
* @since Hi3861_V100R001C00
*/
hi_flash_partition_table* hi_get_partition_table(hi_void);

/** @defgroup iot_efuse eFuse APIs
* @ingroup iot_flashboot
*/
/**
* @ingroup  iot_efuse
*
* Efuse ID.
*/
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

/**
* @ingroup  iot_efuse
*
* Efuse Lock ID.
*/
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
* @retval #HI_ERR_SUCCESS   Success
* @retval #Other            Failure. For details, see hi_boot_err.h.
* @par ����:
*            @li hi_boot_rom.h��Describes the encryption and decryption APIs.
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
* @retval #HI_ERR_SUCCESS   Success
* @retval #Other            Failure. For details, see hi_boot_err.h.
* @par ����:
*            @li hi_boot_rom.h��Describes the encryption and decryption APIs.
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
* @retval #HI_ERR_SUCCESS   Success
* @retval #Other            Failure. For details, see hi_boot_err.h.
* @par ����:
*            @li hi_boot_rom.h��Describes the encryption and decryption APIs.
CNcomment:�ļ���������efuse�ֶβ�����ؽӿڡ�CNend
* @see  hi_efuse_write��
* @since Hi3861_V100R001C00
*/
hi_u32 hi_efuse_lock(hi_efuse_lock_id efuse_lock_id);

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
* @retval #HI_ERR_SUCCESS   Success
* @retval #Other            Failure. For details, see hi_boot_err.h.
* @par ����:
*            @li hi_boot_rom.h��Describes the encryption and decryption APIs.
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
* @retval #HI_ERR_SUCCESS   Success
* @retval #Other            Failure. For details, see hi_boot_err.h.
* @par ����:
*            @li hi_boot_rom.h��Describes the encryption and decryption APIs.
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
* @retval #HI_ERR_SUCCESS   Success
* @retval #Other            Failure. For details, see hi_boot_err.h.
* @par ����:
*            @li hi_boot_rom.h��Describes the encryption and decryption APIs.
CNcomment:�ļ���������efuse�ֶβ�����ؽӿڡ�CNend
* @see  hi_efuse_usr_read��
* @since Hi3861_V100R001C00
*/
hi_u32 hi_efuse_usr_write(hi_u16 start_bit, hi_u16 size, const hi_u8 *key_data);

/** @defgroup iot_flash Flash Driver APIs
* @ingroup  iot_flashboot
*/
/**
* @ingroup  iot_flash
* @brief   Initializes the flash device. CNcomment:��ʼ��Flash�豸��CNend
*
* @par ����:
*           Initializes the flash device. CNcomment:��ʼ��Flash�豸��CNend
*
* @attention Initialize the flash module during system boot.
CNcomment:Flashģ���ʼ����һ����ϵͳ����ʱ���á�CNend
* @param  None
*
* @retval #HI_ERR_SUCCESS  Success.
* @retval #Other           Failure. For details, see hi_errno.h.
* @par ����:
*            @li hi_flashboot.h��FLASH driver APIs.CNcomment:�ýӿ��������ڵ�ͷ�ļ���CNend
* @see  None
* @since Hi3861_V100R001C00
*/
hi_u32 hi_flash_init(hi_void);

/**
* @ingroup  iot_flash
* @brief  Erases the data in the specified flash partition.CNcomment:��ָ����Flash�������ݲ�����CNend
*
* @par ����:
*           Erases the data in the specified flash partition.CNcomment:��ָ����Flash�������ݲ�����CNend
*
* @attention
*           @li Restriction protection for the relative address of the flash memory.
CNcomment:Flash��Ե�ַ�����Ʊ�����CNend
*           @li The number of flash erase times must comply with the device data sheet.
CNcomment:Flash��д�������ơ�CNend
*
* @param  flash_offset    [IN] type #hi_u32��Address offset of the flash memory to be erased.
CNcomment:ָ��Ҫ����Flash�ĵ�ַƫ�ơ�CNend
* @param  size            [IN] type #hi_u32��Length of the data to be erased (unit: byte).
*                         The value must be a multiple of 4 KB.
CNcomment:��Ҫ�����ĳ��ȣ���λ��byte����������4K�ı�����CNend
*
* @retval #HI_ERR_SUCCESS  Success.
* @retval #Other           Failure. For details, see hi_errno.h.
* @par ����:
*            @li hi_flashboot.h��FLASH driver APIs.CNcomment:�ýӿ��������ڵ�ͷ�ļ���CNend
* @see  None
* @since Hi3861_V100R001C00
*/
hi_u32 hi_flash_erase(const hi_u32 flash_addr, hi_u32 flash_erase_size);

/**
* @ingroup  iot_flash
* @brief  Writes data to the specified flash partition.CNcomment:������д��ָ����Flash����CNend
*
* @par ����:
*           Writes data to the specified flash partition.CNcomment:������д��ָ����Flash����CNend
*
* @attention
*           @li Restriction protection for the relative address of the flash memory.
CNcomment:Flash��Ե�ַ�����Ʊ�����CNend
*           @li The number of flash erase times must comply with the device data sheet.
CNcomment:Flash��д�������ơ�CNend
*           @li Determine whether to erase the flash before the write based on the actual control scenario.
CNcomment:�����û�ʵ�ʿ��Ƴ��������Ƿ��Ȳ���д��CNend
* @param  flash_offset    [IN] type #hi_u32��Offset address for writing data to the flash memory.
CNcomment:ָ��д��Flashƫ�Ƶ�ַ��CNend
* @param  size            [IN] type #hi_u32��Length of the data to be written (unit: byte).
CNcomment:��Ҫд��ĳ��ȣ���λ��byte����CNend
* @param  ram_data        [IN] type #hi_u8*��Cache address of the data to be written.
CNcomment:��Ҫд������ݵĻ����ַ��CNend
* @param  do_erase        [IN] type #hi_bool��HI_FALSE: Write data to the flash memory directly.
*                         HI_TRUE: Erase the sector space before write. The user data is written
*                         to the user operation space and the historical data is written back to other spaces.
CNcomment:��ʾ�Ƿ��Զ�����������д�롣HI_TRUE�����ӿ����Ȳ���д��HI_FALSE���û��Ѿ��������ӿڣ���ֱ��д�롣CNend
*
* @retval #HI_ERR_SUCCESS  Success.
* @retval #Other           Failure. For details, see hi_errno.h.
* @par ����:
*            @li hi_flashboot.h��FLASH driver APIs.CNcomment:�ýӿ��������ڵ�ͷ�ļ���CNend
* @see  None
* @since Hi3861_V100R001C00
*/
hi_u32 hi_flash_write(hi_u32 flash_addr, hi_u32 flash_write_size, const hi_u8 *p_flash_write_data, hi_bool do_erase);

/**
* @ingroup  iot_flash
* @brief  Reads the flash data to the specified cache. CNcomment:����Flash���ݵ�ָ����������CNend
*
* @par ����:
*           Reads the flash data to the specified cache. CNcomment:����Flash���ݵ�ָ����������CNend
*
* @attention None
* @param  flash_offset      [IN] type #hi_u32��Offset of the flash address.CNcomment:ָ����Flash��ַƫ�ơ�CNend
* @param  size              [IN] type #hi_u32��Read length (unit: byte).
CNcomment:ָ����ȡ�ĳ��ȣ���λ��byte����CNend
* @param  ram_data          [IN] type #hi_u8*��Destination cache address.CNcomment:Ŀ�Ļ����ַ��CNend
*
* @retval #HI_ERR_SUCCESS  Success.
* @retval #Other           Failure. For details, see hi_errno.h.
* @par ����:
*            @li hi_flashboot.h��FLASH driver APIs.CNcomment:�ýӿ��������ڵ�ͷ�ļ���CNend
* @see  None
* @since Hi3861_V100R001C00
*/
hi_u32 hi_flash_read(hi_u32 flash_addr, hi_u32 flash_read_size, hi_u8 *p_flash_read_data);

/** @defgroup iot_crc32 CRC32 APIs
* @ingroup iot_flashboot
*/
/**
* @ingroup  iot_crc32
* @brief  Generates a 32-bit CRC value.CNcomment:����32λCRCУ��ֵ��CNend
*
* @par ����:
*           Generates a 32-bit CRC value.CNcomment:����32λCRCУ��ֵ��CNend
*
* @attention None
* @param  crc               [IN] type #hi_u32��The CRC initial value.CNcomment:CRC��ʼֵ��CNend
* @param  p                 [IN] type #const hi_u8*��Pointer to the buffer to be verified.
CNcomment:��У��Bufferָ�롣CNend
* @param  len               [IN] type #hi_u32��Length of the buffer to be verified (unit: Byte).
CNcomment:��У��Buffer���ȣ���λ��byte����CNend
*
* @retval #HI_ERR_SUCCESS   Success
* @retval #Other            Failure. For details, see hi_boot_err.h.
*
* @par ����:
*            @li hi_flashboot.h��Describes CRC APIs.CNcomment:�ļ�����CRCУ��ӿڡ�CNend
* @see  None
* @since Hi3861_V100R001C00
*/
hi_u32  hi_crc32 (hi_u32 crc, const hi_u8 *p, hi_u32 len);

#endif

