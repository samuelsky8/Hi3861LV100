/*
 * @file hi_cpu.h
 *
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2019. All rights reserved. \n
 * Description: CPU usage APIs. CNcomment:cpu��ؽӿڡ�CNend \n
 * Author: Hisilicon \n
 * Create: 2019-4-3
 */

/**
 * @defgroup iot_cpu CPU
 * @ingroup osa
 */

#ifndef __HI_CPU_H__
#define __HI_CPU_H__
#include <hi_types.h>
#include <los_base.h>

#define LOAD_SLEEP_TIME_DEFAULT   30

/**
 * @ingroup iot_cpu
 *
 * CPU usage information structure. CNcomment:cpuʹ�������Ϣ�ṹ CNend
 */
typedef struct {
    hi_u8 b_valid:1;    /**< Whether the information is valid. HI_TRUE: yes; HI_FALSE: no.
                           CNcomment:��ʾ������Ϣ�Ƿ�Ϊ��Ч��Ϣ��HI_TRUE:������Ϣ��Ч
                           HI_FALSE:������Ϣ��Ч CNend */
    hi_u8 b_task:1;     /**< Whether the message is a task or an interrupt. HI_TRUE: task; HI_FALSE: interrupt.
                           CNcomment:��ʾ������Ϣ��������жϣ�HI_TRUE:���� HI_FALSE:�ж� CNend */
    hi_u8 pad0:6;       /**< Reserved. CNcomment:���� CNend */
    hi_u8 id;           /**< Task ID/Interrupt number. CNcomment:��������Ϣ��ʾ����ʱΪ����ID,
                           ��������ϢΪ�ж���Ϣʱ��ʾ�жϺ� CNend */
    hi_u16 pad1;        /**< Reserved. CNcomment:���� CNend */
    hi_u32 permillage;  /**< CPU usage (per mil). CNcomment:cpuռ���ʣ�ǧ�ֱ� CNend */
    hi_u64 cpu_time;    /**< CPU usage time (unit: cputick), where, cputick x 160000000 = 1s.
                           CNcomment:cpuռ��ʱ��(��λ:cputick),160000000��cputick����1�� CNend */
} hi_cpup_item;


typedef enum {
    HI_CPU_CLK_80M,  /**< cpu clock:80M. CNcomment:CPU����Ƶ��:80M CNend */
    HI_CPU_CLK_120M, /**< cpu clock:120M. CNcomment:CPU����Ƶ��:120M CNend */
    HI_CPU_CLK_160M, /**< cpu clock:160M. CNcomment:CPU����Ƶ��:160M CNend */
    HI_CPU_CLK_MAX   /**< Maximum cpu clock, which cannot be used. CNcomment:CPU�����Ƶ�ʣ�
                         ����ʹ��CNend */
} hi_cpu_clk;

/**
* @ingroup  iot_cpu
* @brief  Obtains the CPU usage. CNcomment:��ȡCPUʹ�������CNend
*
* @par ����:
*         Obtains the CPU usage between the initialization of the CPU usage module is started or
*         the CPU usage statistics are reset to each task/interrupt.
CNcomment:��ȡcpuռ����ģ���ʼ����ʼ��cpuռ����ͳ����Ϣ���ÿ�ʼͳ�Ƶ���������(�ж�)
CPUռ�������CNend
*
* @attention
* @li A task/interrupt not scheduled after the CPU usage module is initialized or
*     the CPU usage statistics are reset is excluded.
CNcomment:cpuռ����ģ���ʼ����cpuռ����ͳ����Ϣ����֮��û�е��ȵ���������ж�
���ᱻͳ�ơ�CNend
*
* @param array_count [IN] type #hi_u32 Number of CPU usage records that can be stored
*                         in the space corresponding to cpup_items. CNcomment:��ʾp_cpup_items��Ӧ�Ŀռ����
�洢������cpuʹ�������Ϣ��CNend
* @param p_cpup_items [IN] type #hi_cpup_item* CPU usage information space, applied by the caller.
CNcomment:cpuʹ�������Ϣ�ռ䣬�ɵ��������롣CNend
*
* @retval #0   Success.
* @retval #Other    Failure. For details, see hi_errno.h.
* @par Dependency:
*            @li hi_cpu.h: Describes CPU usage APIs.
CNcomment:�ļ���������cpu��ؽӿڡ�CNend
* @see  None
* @since Hi3861_V100R001C00
*/
hi_u32 hi_cpup_get_usage(hi_u32 array_count, hi_cpup_item *p_cpup_items);

/**
* @ingroup  iot_cpu
* @brief  Resets CPU usage statistics. CNcomment:����cpuʹ�������Ϣ��CNend
*
* @param None
*
* @retval #None
* @par ����:
*         Resets CPU usage statistics. After the reset, the CPU usage statistics of all tasks and interrupts are
*         cleared. CNcomment:����cpuʹ�������Ϣ�����ú�����������жϵ�cpuռ������0��CNend
*
* @attention None
*
* @par Dependency:
*            @li hi_cpu.h: Describes CPU usage APIs.
CNcomment:�ļ���������cpu��ؽӿڡ�CNend
* @see None
* @since Hi3861_V100R001C00
*/
hi_void hi_cpup_reset_usage(hi_void);

/**
* @ingroup  iot_cpu
* @brief  Set CPU clock. CNcomment:����CPU�Ĺ���Ƶ�ʡ�CNend
*
* @par ����:
*         Set CPU clock, such as 80M/120M/160M.
*         CNcomment:����CPU�Ĺ���Ƶ�ʣ���80M/120M/160M��CNend
*
* @attention Default CPU clock is 160M, if change CPU clock, Shoud config it
both in System Startup and DeepSleep Wakeup stage.CNcomment:CPUĬ�Ϲ���Ƶ��Ϊ160M��
����ı�CPU�Ĺ���Ƶ�ʣ���Ҫ��ϵͳ��������˯���ѽ׶ξ��������á�CNend
* @param  clk        [IN] type #hi_cpu_clk��cpu clk. CNcomment:CPU����Ƶ�ʡ�CNend
*
* @retval #HI_ERR_SUCCESS  Success.
* @retval #HI_ERR_CPU_CLK_INVALID_PARAM  invalid clk. CNcomment:����Ƶ����Ч��CNend
*
* @par Dependency:
*            @li hi_cpu.h: Describes CPU usage APIs.
CNcomment:�ļ���������cpu��ؽӿڡ�CNend
* @see None
* @since Hi3861_V100R001C00
*/
hi_u32 hi_cpu_set_clk(hi_cpu_clk clk);

/**
* @ingroup  iot_cpu
* @brief  Get CPU clock. CNcomment:��ȡCPU�Ĺ���Ƶ�ʡ�CNend
*
* @par ����:
*         Get CPU clock, such as 80M/120M/160M.
*         CNcomment:��ȡCPU�Ĺ���Ƶ�ʣ���80M/120M/160M��CNend
*
* @attention None
* @param  None
*
* @retval #hi_cpu_clk  cpu clk.
*
* @par Dependency:
*            @li hi_cpu.h: Describes CPU usage APIs.
CNcomment:�ļ���������cpu��ؽӿڡ�CNend
* @see None
* @since Hi3861_V100R001C00
*/
hi_cpu_clk hi_cpu_get_clk(hi_void);

/**
* @ingroup  iot_cpu
* @brief  check cpu load percent and sleep. CNcomment:���idle����cpuռ���ʣ�
���С��������Ե�ǰ�������˯�ߡ�CNend
*
* @par ����:
*         check cpu load percent of idle task, if smaller than the threshold
(50%), Then sleep. CNcomment:���idle����cpuռ���ʣ����С������(50%)��Ե�ǰ����
����˯�ߡ�CNend
*
* @attention None
*
* @param  task_id  [IN] type #hi_u32��current task ID.
CNcomment:��ǰ�̶���д��ǰ����ID��CNend
* @param  ms       [IN] type #hi_u32*��sleep time:��ǰ����˯��ʱ�䡣CNend
*
* @retval None
* @par Dependency:
*            @li hi_cpu.h: Describes CPU usage APIs.
CNcomment:�ļ���������cpu��ؽӿڡ�CNend
* @see None
* @since Hi3861_V100R001C00
*/
hi_void hi_cpup_load_check_proc(hi_u32 task_id, hi_u32 ms);

/**
* @ingroup  iot_cpu
* @brief  Enable Dcache. CNcomment:ʹ��DCache��CNend
*
* @param None
*
* @retval #None
* @par ����:
*         Enable Dcache��system default Enable Dcache after startup.
CNcomment:ʹ��DCache��ϵͳ����Ĭ��ʹ�ܡ�CNend
*
* @attention None
*
* @par Dependency:
*            @li hi_cpu.h: Describes CPU usage APIs.
CNcomment:�ļ���������cpu��ؽӿڡ�CNend
* @see None
* @since Hi3861_V100R001C00
*/
hi_void hi_cache_enable(hi_void);

/**
* @ingroup  iot_cpu
* @brief  Disable Dcache. CNcomment:����DCache��CNend
*
* @param None
*
* @retval #None
* @par ����:
*         Disable Dcache. CNcomment:����DCache��CNend
*
* @attention:
*         flush cache before disable. CNcomment:����Dcacheǰ��ҪˢCache��CNend
*
* @par Dependency:
*            @li hi_cpu.h: Describes CPU usage APIs.
CNcomment:�ļ���������cpu��ؽӿڡ�CNend
* @see None
* @since Hi3861_V100R001C00
*/
hi_void hi_cache_disable(hi_void);

/**
* @ingroup  iot_cpu
* @brief  Flush Dcache. CNcomment:Flush DCache��CNend
*
* @param None
*
* @retval #None
* @par ����:
*         Flush Dcache, synchronize Dcache and memory.
CNcomment:ˢ��DCache��ά��DCache��memoryͬ����CNend
*
* @attention None
*
* @par Dependency:
*            @li hi_cpu.h: Describes CPU usage APIs.
CNcomment:�ļ���������cpu��ؽӿڡ�CNend
* @see None
* @since Hi3861_V100R001C00
*/
hi_void hi_cache_flush(hi_void);

#endif
