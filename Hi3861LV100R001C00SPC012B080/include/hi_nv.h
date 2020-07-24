/*
* Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2019. All rights reserved.
* Description: NV management.
* Author: HiSilicon
* Create: 2019-4-3
*/

/**
* @file hi_nv.h
*
* Copyright (c) Hisilicon Technologies Co., Ltd. 2018. All rights reserved. \n
*
* Description: NV items consist of the NV items in the factory partition and NV items in the normal partition.
*              The NV items in the normal partition are classified into NV items in the reserved partition and
*              NV items in the common partition. The values of NV items in the reserved partition won't change
*              after OTA upgrade. \n
CNcomment:NV��Ϊ������NV�ͷǹ�����NV���ǹ�����NV�ַ�Ϊ����������ͨ������������������NVֵ��CNend
*/

/** @defgroup iot_nv NV Management
 * @ingroup  system
 */
#ifndef __HI_NV_H__
#define __HI_NV_H__
#include <hi_types.h>

/**
* @ingroup  iot_nv
*
* Maximum length of an NV item (unit: byte). CNcomment:NV����󳤶ȣ���λ��byte����CNend
*/
#define HNV_ITEM_MAXLEN (256 - 4)
#define PRODUCT_CFG_NV_REG_NUM_MAX               20

#define HI_FNV_DEFAULT_ADDR         0x8000
#define HI_NV_DEFAULT_TOTAL_SIZE    0x2000
#define HI_NV_DEFAULT_BLOCK_SIZE    0x1000

/**
* @ingroup  iot_nv
*
* Maximum number of registered hi_nv_register_change_nofity_proc functions.
CNcomment:hi_nv_register_change_nofity_procע�ắ���������ֵ��CNend
*/
#define HI_NV_CHANGED_PROC_NUM  PRODUCT_CFG_NV_REG_NUM_MAX

/**
* @ingroup  iot_nv
* @brief Initialize Normal NV.CNcomment:�ǹ�����NV��ʼ����CNend
*
* @par ����:
*           Initialize Normal NV.CNcomment:�ǹ�����NV��ʼ����CNend
*
* @attention Parameters are obtained from the partition table and cannot be set randomly.
CNcomment:�����ӷ������л�ȡ����ֹ�������á�CNend
* @param  addr          [IN] type #hi_u32��Flash address of the normal NV partition, corresponding to the flash
*                            address of the member #HI_FLASH_PARTITON_NORMAL_NV in the partition table.
CNcomment:�ǹ�����NV��FLASH��ַ����Ӧ�������Ա#HI_FLASH_PARTITON_NORMAL_NV��FLASH��ַ��CNend
* @param  total_size    [IN] type #hi_u32��total size of normal NV.
CNcomment:�ǹ�����NV���ܴ�С��CNend
* @param  block_size    [IN] type #hi_u32��block size of normal NV.
CNcomment:�ǹ�����NV�Ŀ��С��CNend
*
* @retval #0            Success.
* @retval #Other        Failure. For details, see hi_errno.h.
* @par ����:
*           @li hi_nv.h��Describes NV APIs.CNcomment:�ļ���������NV��ؽӿڡ�CNend
* @see hi_get_partition_table | hi_nv_read | hi_nv_write��
* @since Hi3861_V100R001C00
*/
HI_EAPI hi_u32 hi_nv_init(hi_u32 addr, hi_u32 total_size, hi_u32 block_size);

/**
* @ingroup  iot_nv
* @brief Set the normal NV value.CNcomment:���÷ǹ�����NVֵ��CNend
*
* @par ����:
*           Set the normal NV value.CNcomment:���÷ǹ�����NVֵ��CNend
*
* @attention
*            @li Only a normal NV item can be operated.CNcomment:���ܲ����ǹ�����NV��CNend
*            @li This API is called only in a task and cannot be called in an interrupt.
CNcomment:��֧�������е��ã���֧���ж��е��á�CNend
* @param  id      [IN] type #hi_u8��NV item ID, ranging from #HI_NV_NORMAL_ID_START to #HI_NV_NORMAL_USR_ID_END.
CNcomment:NV��ID����Χ��#HI_NV_NORMAL_ID_START��#HI_NV_NORMAL_USR_ID_END��CNend
* @param  pdata   [IN] type #const hi_pvoid��NV item data.CNcomment:NV�����ݡ�CNend
* @param  len     [IN] type #hi_u8��Length of an NV item (unit: byte). The len must be equal to the Length of
the real NV item data.CNcomment:NV��ȣ���λ��byte����len�����NV���ʵ�ʳ�����ȡ�CNend
* @param  flag   [IN] type #hi_u32��Reserve.CNcomment:����������CNend
* @retval #0            Success.
* @retval #Other        Failure. For details, see hi_errno.h.
* @par ����:
*           @li hi_nv.h��Describes NV APIs.CNcomment:�ļ���������NV��ؽӿڡ�CNend
* @see hi_nv_read��
* @since Hi3861_V100R001C00
*/
HI_EAPI hi_u32 hi_nv_write(hi_u8 id, const hi_pvoid pdata, hi_u8 len, hi_u32 flag);

/**
* @ingroup  iot_nv
* @brief Read the normal NV value.CNcomment:��ȡ�ǹ�����NVֵ��CNend
*
* @par ����:
*           Read the normal NV value.CNcomment:��ȡ�ǹ�����NVֵ��CNend
*
* @attention
*            @li Only a normal NV item can be operated.CNcomment:���ܲ����ǹ�����NV��CNend
*            @li This API is called only in a task and cannot be called in an interrupt.
CNcomment:��֧�������е��ã���֧���ж��е��á�CNend
*
* @param  id      [IN] type #hi_u8��NV item ID, ranging from #HI_NV_NORMAL_ID_START to #HI_NV_NORMAL_USR_ID_END.
CNcomment:NV��ID����Χ��#HI_NV_NORMAL_ID_START��#HI_NV_NORMAL_USR_ID_END��CNend
* @param  pdata   [IN] type #const hi_pvoid��NV item data.CNcomment:NV�����ݡ�CNend
* @param  len     [IN] type #hi_u8��Length of an NV item (unit: byte).  The len must be equal to the Length of
the real NV item data.CNcomment:NV��ȣ���λ��byte����len�����NV���ʵ�ʳ�����ȡ�CNend
* @param  flag   [IN] type #hi_u32��Reserve.CNcomment:����������CNend
*
* @retval #0            Success.
* @retval #Other        Failure. For details, see hi_errno.h.
* @par ����:
*           @li hi_nv.h��Describes NV APIs.CNcomment:�ļ���������NV��ؽӿڡ�CNend
* @see hi_nv_write��
* @since Hi3861_V100R001C00
*/
HI_EAPI hi_u32 hi_nv_read(hi_u8 id, const hi_pvoid pdata, hi_u8 len, hi_u32 flag);

/**
* @ingroup  iot_nv
* @brief NV item change callback function.CNcomment:NV�����ص�������CNend
*
* @par ����:
*           NV item change callback function.CNcomment:NV�����ص�������CNend
*
* @attention This API can be called only after the SAL is initialized.
CNcomment:��SAL��ʼ��������ſ��Ե��øýӿڡ�CNend
*
* @param  id      [IN] type #hi_u8��NV item ID, ranging from #HI_NV_NORMAL_ID_START to #HI_NV_NORMAL_USR_ID_END.
CNcomment:NV��ID����Χ��#HI_NV_NORMAL_ID_START��#HI_NV_NORMAL_USR_ID_END��CNend
*
* @retval #0            Success.
* @retval #Other        Failure. For details, see hi_errno.h.
* @par ����:
*           @li hi_nv.h��Describes NV APIs.CNcomment:�ļ���������NV��ؽӿڡ�CNend
* @see None
* @since Hi3861_V100R001C00
*/
typedef hi_u32(*hi_nvm_changed_notify_f) (hi_u8 id);

/**
* @ingroup  iot_nv
* @brief Register the normal NV item change notification function.CNcomment:�ǹ�����NV����֪ͨ����ע�ᡣCNend
*
* @par ����:
*           Register the normal NV item change notification function.CNcomment:�ǹ�����NV����֪ͨ����ע�ᡣCNend
*
* @attention
*           Only the change notification function for normal NV items can be registered.
*           The maximum number of registered functions is #HI_NV_CHANGED_PROC_NUM. If the number of registered functions
*           exceeds the maximum, an error code is returned.
CNcomment:��֧�ַǹ���NV��ע����֪ͨ��������ע���������Ϊ#HI_NV_CHANGED_PROC_NUM���糬���᷵�ش����롣CNend
*
* @param  min_id [IN] type #hi_u8��Minimum value of an NV item ID.CNcomment:NV��ID��Сֵ��CNend
* @param  max_id [IN] type #hi_u8��Maximum value of an NV item ID.CNcomment:NV��ID���ֵ��CNend
* @param  func   [IN] type #hi_nvm_changed_notify_f��Handling function for NV item changes. That is, after an NV item
*                     is changed, the NV module automatically calls the registered API.
CNcomment:NV��ı�Ĵ�����, ��NV������NVģ����Զ����ø�ע��Ľӿڡ�CNend
*
* @retval #0            Success.
* @retval #Other        Failure. For details, see hi_errno.h.
* @par ����:
*           @li hi_nv.h��Describes NV APIs.CNcomment:�ļ���������NV��ؽӿڡ�CNend
* @see None
* @since Hi3861_V100R001C00
*/
HI_EAPI hi_u32 hi_nv_register_change_notify_proc(hi_u8 min_id, hi_u8 max_id, hi_nvm_changed_notify_f func);

/**
* @ingroup  iot_nv
* @brief Initialize factory NV.CNcomment:������NV��ʼ����CNend
*
* @par ����:
*          Initialize factory NV.CNcomment: ������NV��ʼ����CNend
*
* @attention The parameters cannot be set randomly and must match the product delivery plan.
CNcomment:���������������ã���Ҫ���Ʒ�����滮ƥ�䡣CNend
* @param  addr [IN] type #hi_u32��Start address of the NV factory partition in the flash. The address is planned by
*                   the factory and set by the macro #HI_FNV_DEFAULT_ADDR.
CNcomment:���ù�����NV FLASH�׵�ַ���ɳ����滮���궨��HI_FNV_DEFAULT_ADDR ͳһ���á�CNend
* @param  total_size    [IN] type #hi_u32��total size of factory NV.
CNcomment:������NV���ܴ�С��CNend
* @param  block_size    [IN] type #hi_u32��block size of factory NV.
CNcomment:������NV�Ŀ��С��CNend
* @retval #0            Success.
* @retval #Other        Failure. For details, see hi_errno.h.
* @par ����:
*           @li hi_nv.h��Describes NV APIs.CNcomment:�ļ���������NV��ؽӿڡ�CNend
* @see hi_factory_nv_write | hi_factory_nv_read��
* @since Hi3861_V100R001C00
*/
HI_EAPI hi_u32 hi_factory_nv_init(hi_u32 addr, hi_u32 total_size, hi_u32 block_size);

/**
* @ingroup  iot_nv
* @brief Set the NV value in the factory partition. CNcomment:���ù�����NVֵ��CNend
*
* @par ����:
*           Set the NV value in the factory partition.CNcomment:���ù�����NVֵ��CNend
*
* @attention None
* @param  id    [IN] type #hi_u8��NV item ID, ranging from #HI_NV_FACTORY_ID_START to #HI_NV_FACTORY_USR_ID_END.
CNcomment:NV��ID����Χ��#HI_NV_FACTORY_ID_START��#HI_NV_FACTORY_USR_ID_END��CNend
* @param  pdata [IN] type #hi_pvoid��NV item data.CNcomment:NV�����ݡ�CNend
* @param  len   [IN] type #hi_u8��Length of an NV item (unit: byte). The len must be equal to the Length of
the real NV item data.CNcomment:NV��ȣ���λ��byte����len�����NV���ʵ�ʳ�����ȡ�CNend
* @param  flag   [IN] type #hi_u32��Reserve.CNcomment:����������CNend
*
* @retval #0            Success.
* @retval #Other        Failure. For details, see hi_errno.h.
* @par ����:
*           @li hi_nv.h��Describes NV APIs.CNcomment:�ļ���������NV��ؽӿڡ�CNend
* @see hi_factory_nv_read��
* @since Hi3861_V100R001C00
*/
HI_EAPI hi_u32 hi_factory_nv_write(hi_u8 id, hi_pvoid pdata, hi_u8 len, hi_u32 flag);

/**
* @ingroup  iot_nv
* @brief Read the NV value in the factory partition.CNcomment:��ȡ������NVֵ��CNend
*
* @par ����:
*           Read the NV value in the factory partition.��ȡ������NVֵ��CNend
*
* @attention None
*
* @param  id      [IN] type #hi_u8��NV item ID, ranging from #HI_NV_NORMAL_ID_START to #HI_NV_NORMAL_USR_ID_END.
CNcomment:NV��ID����Χ��#HI_NV_NORMAL_ID_START��#HI_NV_NORMAL_USR_ID_END��CNend
* @param  pdata   [IN] type #hi_pvoid��NV item data.CNcomment:NV�����ݡ�CNend
* @param  len     [IN] type #hi_u8��Length of an NV item (unit: byte). The len must be equal to the Length of
the real NV item data.CNcomment:NV��ȣ���λ��byte����len�����NV���ʵ�ʳ�����ȡ�CNend
* @param  flag    [IN] type #hi_u32��Reserve.CNcomment:����������CNend
*
* @retval #0            Success.
* @retval #Other        Failure. For details, see hi_errno.h.
* @par ����:
*           @li hi_nv.h��Describes NV APIs.CNcomment:�ļ���������NV��ؽӿڡ�CNend
* @see hi_factory_nv_write��
* @since Hi3861_V100R001C00
*/
HI_EAPI hi_u32 hi_factory_nv_read(hi_u8 id, hi_pvoid pdata, hi_u8 len, hi_u32 flag);

#endif
