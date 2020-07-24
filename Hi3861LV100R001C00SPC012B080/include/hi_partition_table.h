/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: Partition table interfaces.
 * Author: hisilicon
 * Create: 2019-03-04
 */

/**
* @file hi_partition_table.h
*
* Copyright (c) Hisilicon Technologies Co., Ltd. 2019. All rights reserved.  \n
*
* Description: Partition table interfaces.
*/

/** @defgroup iot_flash_partiton FLASH Partition Management
 *  @ingroup system
 */
#ifndef __HI_PARTITION_TABLE_H__
#define __HI_PARTITION_TABLE_H__
#include <hi_types.h>

#define HI_FLASH_PARTITON_MAX 10
/**
 * @ingroup iot_flash_partiton
 *
 * Partition entry ID. CNcomment:������ID��CNend
 */
typedef enum {
    HI_FLASH_PARTITON_BOOT = 0,    /**< Boot partition ID.CNcomment:BOOT����ID.CNend */
    HI_FLASH_PARTITON_FACTORY_NV,  /**< Factory NV working partition ID.CNcomment:����NV����ID.CNend */
    HI_FLASH_PARTITON_NORMAL_NV,   /**< NORMAL NV partition ID.CNcomment:�ǹ���NV����ID.CNend */
    HI_FLASH_PARTITON_KERNEL_A,    /**< Kernel A running partition ID.CNcomment:�ں�A��ID.CNend */
    HI_FLASH_PARTITON_KERNEL_B,    /**< Kernel B runing partition ID.CNcomment:�ں�B��ID.CNend */
    HI_FLASH_PARTITON_HILINK,      /**< HILINK partition ID.CNcomment:HILINK����ID.CNend */
    HI_FLASH_PARTITON_FILE_SYSTEM, /**< File system partition ID.CNcomment:�ļ�ϵͳ��ID.CNend */
    HI_FLASH_PARTITON_CRASH_INFO,  /**< Crash log partition.CNcomment:�����洢��CNend */
    HI_FLASH_PARTITON_BOOT_BACK,   /**< Boot backup partition.CNcomment:����boot��CNend */
    HI_FLASH_PARTITON_RESERVE,     /**< Reserved 1 partition.CNcomment:������CNend */
} hi_flash_partition_table_id;

/**
 *  @ingroup iot_flash_partiton
 *
 *  Flash partition management. CNcomment:Flash�������CNend
 */
typedef struct {
    hi_u32  addr    :24;   /**< Flash partition address.The value is 16 MB.If the address is in reverse order,
                               the value is the end low address.CNcomment:Flash������ַ������Ϊ16MB��
                               ���Ϊ���򣬴��Ϊ�����ĵ͵�ֵַ CNend */
    hi_u32  id      :7;    /**< Flash partition ID.CNcomment:Flash��ID.CNend  */
    hi_u32  dir     :1;    /**< Flash area storage direction.0:regular.1: reversed.CNcomment:Flash����ŷ���
                               0��������������1������ĩ��ַ CNend */

    hi_u32  size    :24;   /**< Size of the parition(Unit:byte).CNcomment:Flash������С����λ��byte��CNend */
    hi_u32  reserve :8;    /**< Reserved. CNcomment:������CNend  */

    hi_u32  addition;      /**< Supplementary information about the flash partition, such as the address of the
                               Ram.CNcomment:Flash����������Ϣ����Ram��Ӧ��ַ�� CNend */
} hi_flash_partition_info;


/**
 *  @ingroup iot_flash_partiton
 *
 *  Flash partition table. CNcomment:Flash������CNend
 */
typedef struct {
    hi_flash_partition_info table[HI_FLASH_PARTITON_MAX];  /**< Flash partition entry information.CNcomment:
                                                               Flash������������ CNend */
} hi_flash_partition_table;

/**
* @ingroup  iot_flash_partiton
* @brief  Obtains the flash partition table. CNcomment:��ȡFlash������CNend
*
* @par ����:
*           Obtains the flash partition table. CNcomment:��ȡFlash������CNend
*
* @attention None
* @param None
*
* @retval #hi_flash_partition_table  Pointer to partition table information. CNcomment:������ָ�롣CNend
* @par ����:
*            @li hi_partition_table.h��Describes flash partition APIs.
CNomment:�ļ���������Flash������ؽӿڡ�CNend
* @see  None
* @since Hi3861_V100R001C00
*/
hi_flash_partition_table *hi_get_partition_table(hi_void);

/**
* @ingroup  iot_flash_partiton
* @brief  Initializes the flash partition table. CNcomment:Flash�������ʼ����CNend
*
* @par ����:
*           Initializes the flash partition table. CNcomment:Flash�������ʼ����CNend
*
* @attention None
* @param   None
*
* @retval #0      Success
* @retval #Other  Failure. For details, see hi_errno.h.
* @par ����:
*            @li hi_partition_table.h��Describes flash partition APIs.
CNomment:�ļ���������Flash������ؽӿڡ�CNend
* @see  None
* @since Hi3861_V100R001C00
*/
hi_u32 hi_flash_partition_init(hi_void);

/**
* @ingroup  iot_flash_partiton
* @brief  Get HiLink partition table'addr and size. CNcomment:��ȡHiLink������ַ�ʹ�С��CNend
*
* @par ����:
*           Get HiLink partition table'addr and size. CNcomment:��ȡHiLink������ַ�ʹ�С��CNend
*
* @attention Call after hi_flash_partition_init. CNcomment:��hi_flash_partition_init֮����á�CNend
* @param  addr    [OUT] type #hi_u32*, Address of HiLink partition.CNcomment:HiLink������ַ��CNend
* @param  size     [OUT] type #hi_u32*, Size of HiLink partitioin, in bytes.CNcomment:HiLink������С����λbyte��CNend
*
* @retval #0      Success
* @retval #Other  Failure. For details, see hi_errno.h.
* @par ����:
*            @li hi_partition_table.h��Describes flash partition APIs.
CNomment:�ļ���������Flash������ؽӿڡ�CNend
* @see  None
* @since Hi3861_V100R001C00
*/
hi_u32 hi_get_hilink_partition_table(hi_u32 *addr, hi_u32 *size);

/**
* @ingroup  iot_flash_partiton
* @brief  Get Crash info partition table'addr and size. CNcomment:��ȡ������Ϣ������ַ�ʹ�С��CNend
*
* @par ����:
*           Get Crash info partition table'addr and size. CNcomment:��ȡ������Ϣ������ַ�ʹ�С��CNend
*
* @attention Call after hi_flash_partition_init. CNcomment:��hi_flash_partition_init֮����á�CNend
* @param  addr    [OUT] type #hi_u32*, Address of Crash info partition.CNcomment:������Ϣ������ַ��CNend
* @param  size     [OUT] type #hi_u32*, Size of Crash info partitioin, in bytes.CNcomment:������Ϣ������С����λbyte��CNend
*
* @retval #0      Success
* @retval #Other  Failure. For details, see hi_errno.h.
* @par ����:
*            @li hi_partition_table.h��Describes flash partition APIs.
CNomment:�ļ���������Flash������ؽӿڡ�CNend
* @see  None
* @since Hi3861_V100R001C00
*/
hi_u32 hi_get_crash_partition_table(hi_u32 *addr, hi_u32 *size);

/**
* @ingroup  iot_flash_partiton
* @brief  Get File system partition table'addr and size. CNcomment:��ȡ�ļ�ϵͳ������ַ�ʹ�С��CNend
*
* @par ����:
*           Get File system partition table'addr and size. CNcomment:��ȡ�ļ�ϵͳ������ַ�ʹ�С��CNend
*
* @attention Call after hi_flash_partition_init. CNcomment:��hi_flash_partition_init֮����á�CNend
* @param  addr    [OUT] type #hi_u32*, Address of File system partition.CNcomment:�ļ�ϵͳ������ַ��CNend
* @param  size     [OUT] type #hi_u32*, Size of HiLink partitioin, in bytes.CNcomment:�ļ�ϵͳ������С����λbyte��CNend
*
* @retval #0      Success
* @retval #Other  Failure. For details, see hi_errno.h.
* @par ����:
*            @li hi_partition_table.h��Describes flash partition APIs.
CNomment:�ļ���������Flash������ؽӿڡ�CNend
* @see  None
* @since Hi3861_V100R001C00
*/
hi_u32 hi_get_fs_partition_table(hi_u32 *addr, hi_u32 *size);

/**
* @ingroup  iot_flash_partiton
* @brief  Get Normal NV partition table'addr and size. CNcomment:��ȡ�ǹ�����������ַ�ʹ�С��CNend
*
* @par ����:
*           Get Normal NV partition table'addr and size. CNcomment:��ȡ�ǹ�����������ַ�ʹ�С��CNend
*
* @attention Call after hi_flash_partition_init. CNcomment:��hi_flash_partition_init֮����á�CNend
* @param  addr    [OUT] type #hi_u32*, Address of Normal NV partition.CNcomment:�ǹ�����������ַ��CNend
* @param  size     [OUT] type #hi_u32*, Size of Normal NV partitioin, in bytes.CNcomment:�ǹ�����������С����λbyte��CNend
*
* @retval #0      Success
* @retval #Other  Failure. For details, see hi_errno.h.
* @par ����:
*            @li hi_partition_table.h��Describes flash partition APIs.
CNomment:�ļ���������Flash������ؽӿڡ�CNend
* @see  None
* @since Hi3861_V100R001C00
*/
hi_u32 hi_get_normal_nv_partition_table(hi_u32 *addr, hi_u32 *size);

#endif

