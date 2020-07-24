/**
* @file hi_men.h
*
* Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2019. All rights reserved.  \n
* Description: Memory management.   \n
* Author: Hisilicon   \n
* Create: 2019-12-18
*/

/**
 * @defgroup iot_mem  Memory
 * @ingroup osa
 */

#ifndef __HI_MEM_H__
#define __HI_MEM_H__
#include <hi_types_base.h>

/**
 * @ingroup iot_mem
 * Overall memory information.CNcomment:�����ڴ���Ϣ��CNend
 */
typedef struct {
    hi_u32 total;                /**< Total space of the memory pool (unit: byte).
                                    CNcomment:�ڴ���ܴ�С����λ��byte��CNend */
    hi_u32 used;                 /**< Used space of the memory pool (unit: byte).
                                    CNcomment:�ڴ���Ѿ�ʹ�ô�С����λ��byte��CNend */
    hi_u32 free;                 /**< Free space of the memory pool (unit: byte).
                                    CNcomment:�ڴ��ʣ��ռ䣨��λ��byte��CNend */
    hi_u32 free_node_num;        /**< Number of free nodes in the memory pool.
                                    CNcomment:�ڴ��ʣ��ռ�ڵ���� CNend */
    hi_u32 used_node_num;        /**< Number of used nodes in the memory pool.
                                    CNcomment:�ڴ���Ѿ�ʹ�õĽڵ���� CNend */
    hi_u32 max_free_node_size;   /**< Maximum size of the node in the free space of the memory pool (unit: byte).
                                    CNcomment:�ڴ��ʣ��ռ�ڵ������ڵ�Ĵ�С����λ��byte��CNend */
    hi_u32 malloc_fail_count;    /**< Number of memory application failures.CNcomment:�ڴ�����ʧ�ܼ��� CNend */
    hi_u32 peek_size;            /**< Peak memory usage of the memory pool.CNcomment:�ڴ��ʹ�÷�ֵCNend */
} hi_mdm_mem_info;

typedef struct {
    hi_u32 pool_addr;       /* �ڴ�ص�ַ */
    hi_u32 pool_size;       /* �ڴ�ش�С */
    hi_u32 fail_count;      /* �ڴ�����ʧ�ܼ��� */
    hi_u32 peek_size;       /* �ڴ��ʹ�÷�ֵ */
    hi_u32 cur_use_size;    /* �ڴ���Ѿ�ʹ�ô�С����λ��byte�� */
} hi_mem_pool_crash_info;

/**
* @ingroup  iot_mem
* @brief  Dynamically applies for memory.CNcomment:��̬�����ڴ档CNend
*
* @par ����:
*           Dynamically applies for memory.CNcomment:��̬�����ڴ档CNend
*
* @attention None
* @param  mod_id  [IN] type #hi_u32��ID of the called module.CNcomment:����ģ��ID��CNend
* @param  size    [IN] type #hi_u32��Requested memory size (unit: byte)
CNcomment:�����ڴ��С����λ��byte����CNend
*
* @retval #>0 Success
* @retval #HI_NULL   Failure. The memory is insufficient.
* @par ����:
*            @li hi_mem.h��Describes memory APIs.CNcomment:�ļ����������ڴ���ؽӿڡ�CNend
* @see  hi_free��
* @since Hi3861_V100R001C00
*/
hi_pvoid hi_malloc(hi_u32 mod_id, hi_u32 size);

/**
* @ingroup  iot_mem
* @brief  Releases the memory that is dynamically applied for.CNcomment:�ͷŶ�̬������ڴ档CNend
*
* @par ����:
*          Releases the memory that is dynamically applied for.CNcomment:�ͷŶ�̬������ڴ档CNend
*
* @attention None
* @param  mod_id  [IN] type #hi_u32��ID of the called module.CNcomment:����ģ��ID��CNend
* @param  addr    [IN] type #hi_pvoid��Start address of the requested memory. The validity of the address is ensured
*                 by the caller.CNcomment:�������ڴ���׵�ַ����ַ�Ϸ����ɵ����߱�֤��CNend
*
* @retval None
* @par ����:
*            @li hi_mem.h��Describes memory APIs.CNcomment:�ļ����������ڴ���ؽӿڡ�CNend
* @see  hi_malloc��
* @since Hi3861_V100R001C00
*/
hi_void hi_free(hi_u32 mod_id, const hi_pvoid addr);

/**
* @ingroup  iot_mem
* @brief  Obtains the memory information.CNcomment:��ȡ�ڴ���Ϣ��CNend
*
* @par ����:
*           Obtains the memory information.CNcomment:��ȡ�ڴ���Ϣ��CNend
*
* @attention None
* @param  mem_inf [OUT] type #hi_mdm_mem_info*��Overall memory information.CNcomment:�����ڴ���Ϣ��CNend
*
* @retval #0      Success.
* @retval #Other  Failure, for details, see hi_errno.h
* @par ����:
*            @li hi_mem.h��Describes memory APIs.CNcomment:�ļ����������ڴ���ؽӿڡ�CNend
* @see  None
* @since Hi3861_V100R001C00
*/
hi_u32 hi_mem_get_sys_info(HI_OUT hi_mdm_mem_info *mem_inf);

/**
* @ingroup  iot_mem
* @brief  Obtains memory information, used in a crash process.
CNcomment:��ȡ�ڴ���Ϣ������������ʹ�á�CNend
*
* @par ����:
*           Obtains memory information, used in a crash process. When the board is reset due to a memory exception,
*           if hi_mem_get_sys_info is used to obtain memory information, another exception may occur. In this case,
*           use hi_mem_get_sys_info_crash instead.CNcomment:��ȡ�ڴ���Ϣ������������ʹ�á����ڴ��쳣���µ��帴λʱ��
���ͨ��hi_mem_get_sys_info��ȡ�ڴ���Ϣ�����ٴβ����쳣����ʱӦ��ʹ��hi_mem_get_sys_info_crash��CNend
*
* @attention None
*
* @retval #hi_mem_pool_crash_info   Memory information.CNcomment:�ڴ���Ϣ��CNend
*
* @par ����:
*            @li hi_mem.h��Describes memory APIs.CNcomment:�ļ����������ڴ���ؽӿڡ�CNend
* @see  None
* @since Hi3861_V100R001C00
*/
HI_CONST hi_mem_pool_crash_info *hi_mem_get_sys_info_crash(hi_void);

#endif
