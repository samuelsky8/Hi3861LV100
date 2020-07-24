/**
 * @file hi_nvm.h
 *
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2019. All rights reserved. \n
 * Description: hi_nvm.h. \n
 * Author: hisilicon \n
 * Create: 2019-08-27
 */

#ifndef __HI_NVM_H__
#define __HI_NVM_H__

#include <hi_types.h>
#include <hi_boot_rom.h>

#define hi_make_identifier(a, b, c, d)      hi_makeu32(hi_makeu16(a, b), hi_makeu16(c, d))
#define HNV_FILE_SIGNATURE               hi_make_identifier('H', 'N', 'V', '$')
#define FNV_FILE_SIGNATURE               hi_make_identifier('F', 'N', 'V', '#')

#define FACTORY_NV_SIZE   0x2000
#define FLASH_BLOCK_SIZE  0x1000
#define HNV_NCRC_SIZE  8                      /* ����crc�ĳ��� */
#define NV_TOTAL_MAX_NUM  255                 /* �����õ�nv������ */
#define HNV_FAULT_TOLERANT_TIMES  3           /* �ݴ���� */

#define HNV_MANAGE_FIXED_LEN  24              /* ��ֹ��reserve */

/* ������NV �ṹ����Ҫ��kernel�±�����ȫһ�£��̶������޸� */
typedef struct _hi_nvm_manage_s_ {
    hi_u32  magic;              /* nvͷħ���� */
    hi_u32  crc;                /* nv��������������crc32 ��ver��ֹ��flash_size��β */
    hi_u8   ver;                /* nv�������ṹ��汾�� */
    hi_u8   head_len;           /* nvͷ�ĳ��ȣ���magic��ֹ��reserve��β����4�ֽ������� */
    hi_u16  total_num;          /* nv�ܸ��� */
    hi_u32  seq;                /* дnv��ű�־(������Ȼ�������Լ�������) */
    hi_u32  ver_magic;          /* �汾ħ���֣���kernel�汾ħ����ƥ�� */
    hi_u32  flash_size;         /* NVռ�õ�FLASH��С����4096(4K)��65536(64K),��ʱδ�ã�������һ */
    hi_u8   keep_id_range[2];   /* ��������id��Χ��0:id�±߽� 1:id�ϱ߽� size 2 */
    hi_u8   reserve[2];         /* size 2 */
    hi_u8   nv_item_data[0];    /* ������ */
} hi_nv_manage;

typedef struct hi_nv_item_index_s_ {
    hi_u8 nv_id;
    hi_u8 nv_len;                /* nvʵ�ʳ��ȣ�����crc32ֵ��crc32�����Ŵ�� */
    hi_u16 nv_offset;            /* ��Ա�nv��ƫ�� */
} hi_nv_item_index;

typedef struct _hi_nv_ctrl_s_ {
    hi_u32 base_addr;
    hi_u32 block_size;
    hi_u32 total_block_size;
    hi_u32 current_addr;         /* �������� */
    hi_u32 seq;
    hi_u32 sem_handle;

    hi_u8 init_flag;
    hi_u8 reserve;
    hi_u16 total_num;         /* nv���� */
    hi_u32 ver_magic;
    hi_nv_item_index* index;
} hi_nv_ctrl;

typedef enum _hi_nv_type_e_ {
    HI_TYPE_NV = 0,
    HI_TYPE_FACTORY_NV,
    HI_TYPE_TEMP,
    HI_TYPE_NV_MAX,
} hi_nv_type;

hi_u32 hi_nv_flush_keep_ids(hi_u8* addr, hi_u32 len);
hi_u32 hi_nv_block_write(hi_u8* nv_file, hi_u32 len, hi_u32 flag);

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
*
* @retval #0            Success.
* @retval #Other        Failure. For details, see hi_errno.h.
* @par ����:
*           @li hi_flashboot.h��Describes NV APIs.CNcomment:�ļ���������NV��ؽӿڡ�CNend
* @see hi_factory_nv_write��
* @since Hi3861_V100R001C00
*/
hi_u32 hi_factory_nv_read(hi_u8 id, hi_pvoid pdata, hi_u8 len, hi_u32 flag);

/** @defgroup iot_crc32 CRC32 APIs
* @ingroup iot_flashboot
*/
/**
* @ingroup  iot_crc32
* @brief  Generates a 16-bit CRC value.CNcomment:����16λCRCУ��ֵ��CNend
*
* @par ����:
*           Generates a 16-bit CRC value.CNcomment:����16λCRCУ��ֵ��CNend
*
* @attention None
* @param  crc               [IN] type #hi_u16��The CRC initial value.CNcomment:CRC��ʼֵ��CNend
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

#endif   /* __HI_NVM_H__ */

