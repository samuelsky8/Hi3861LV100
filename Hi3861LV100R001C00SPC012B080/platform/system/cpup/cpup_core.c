/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: cpup_core.c.
 * Author: hisilicon
 * Create: 2019-08-27
 */

#include <hi_isr.h>
#include <hi_stdlib.h>
#include <los_hwi.h>
#include <los_task_pri.h>
#include <los_cpup_pri.h>
#include <hi_cpu.h>
#include <hi_mem.h>
#include <hi_sem.h>
#include <los_swtmr.h>
#include <hi_task.h>
#include "los_pmp.h"
#include "hi_sal.h"
#include "sal_reset.h"

static hi_bool g_cpup_timer_init = HI_FALSE;
static hi_u64* g_cpup_pre;
static hi_u64 g_idle_task_cpup;
static hi_u32 g_cpup_status;
static hi_u16 g_idle_handle;

#define GET_IDLE_INTERVAL 200
#define MIN_IDEL_RATE   50

hi_u64 cpup_get_idle(hi_void)
{
    return g_idle_task_cpup;
}

void cpup_calc_idle(hi_u32 size)
{
    hi_u32 task_id;
    hi_u64 total_cpup = 0;
    hi_s64 idle_cpup;
    if (g_cpup == HI_NULL) {
        return ;
    }
    idle_cpup = g_cpup[g_idleTaskID].allTime - g_cpup_pre[g_idleTaskID];
    for (task_id = 0; task_id < size; task_id++) {
        total_cpup += g_cpup[task_id].allTime - g_cpup_pre[task_id];
        g_cpup_pre[task_id] = g_cpup[task_id].allTime;
    }
    /* feed watchdog */
    watchdog_feed();
    /* flash protect sem signal per 2s */
    hi_sem_signal(g_flash_prot_sem);
    if (total_cpup == 0) {
        return;
    }
    g_idle_task_cpup = (LOS_CPUP_PRECISION * idle_cpup) / total_cpup;
    g_cpup_status = 0xFFFFFFFF;
}

hi_u32 hi_sal_timer_init(hi_void)
{
    hi_u32 ret;
    hi_u32 size;
    hi_u32 int_value;

    int_value = hi_int_lock();
    if (g_cpup_timer_init) {
        printf("idle cpup timer created\r\n");
        return HI_ERR_TIMER_FAILURE;
    }
    g_cpup_timer_init = TRUE;
    hi_int_restore(int_value);

#if (LOSCFG_BASE_CORE_CPUP_HWI == YES)
    size = (g_taskMaxNum + OS_HIMIDEER_LOCAL_IRQ_VECTOR_CNT) * sizeof(hi_u64);
#else
    size = g_taskMaxNum * sizeof(hi_u64);
#endif
    g_cpup_pre = hi_malloc(HI_MOD_ID_DRV, size);
    if (g_cpup_pre == NULL) {
        return HI_ERR_FAILURE;
    }
    // Ignore the return code when matching CSEC rule 6.6(3).
    (VOID)memset_s(g_cpup_pre, size, 0, size);

    ret = LOS_SwtmrCreate(GET_IDLE_INTERVAL, LOS_SWTMR_MODE_PERIOD, (SWTMR_PROC_FUNC)cpup_calc_idle,
                          &g_idle_handle, (size / sizeof(hi_u64)));
    if (ret != LOS_OK) {
        return HI_ERR_FAILURE;
    }
    ret = LOS_SwtmrStart(g_idle_handle);
    if (ret != LOS_OK) {
        return HI_ERR_FAILURE;
    }
    return HI_ERR_SUCCESS;
}

hi_u32 hi_sal_timer_suspend(hi_void)
{
    hi_watchdog_feed();
    hi_u32 ret = LOS_SwtmrStop(g_idle_handle);
    if (ret != LOS_OK) {
        return HI_ERR_FAILURE;
    }
    return HI_ERR_SUCCESS;
}

hi_u32 hi_sal_timer_resume(hi_void)
{
    hi_watchdog_feed();
    hi_u32 ret = LOS_SwtmrStart(g_idle_handle);
    if (ret != LOS_OK) {
        return HI_ERR_FAILURE;
    }
    return HI_ERR_SUCCESS;
}

hi_u32 hi_cpup_get_usage(hi_u32 array_count, hi_cpup_item* p_cpup_items)
{
    hi_u32 int_value;
    hi_u64 total_time = 0;
    hi_u32 i, j, tasknum_max;

    if (g_cpupInitFlg == 0) {
        return  HI_ERR_CPUP_NOT_INIT;
    }

    if (array_count == 0 || p_cpup_items == HI_NULL) {
        return HI_ERR_CPUP_INVALID_PARAM;
    }

    memset_s(p_cpup_items, array_count * sizeof(hi_cpup_item), 0, array_count * sizeof(hi_cpup_item));

    int_value = hi_int_lock();
    OsTskCycleEnd();
#if (LOSCFG_BASE_CORE_CPUP_HWI == YES)
    tasknum_max = g_taskMaxNum + OS_HIMIDEER_LOCAL_IRQ_VECTOR_CNT;
#else
    tasknum_max = g_taskMaxNum;
#endif
    for (i = 0, j = 0; i < tasknum_max; i++) {
        /* �Ѿ��ͷŵ������ʱ�䶪ʧ�ˣ��������ʱ����ܲ�׼ */
        if (g_cpup[i].allTime == 0) {
            continue;
        }

        total_time += g_cpup[i].allTime;

        if (j < array_count) {
            hi_cpup_item* p_item = &p_cpup_items[j];
            if (i < g_taskMaxNum) {
                p_item->b_task = HI_TRUE;
                p_item->id = i;
            } else {
                p_item->b_task = HI_FALSE;
                p_item->id = i - g_taskMaxNum + OS_HIMIDEER_SYS_VECTOR_CNT;
            }
            p_item->b_valid = HI_TRUE;
            p_item->cpu_time = g_cpup[i].allTime;
        }
        j++;
    }

    for (j = 0; j < array_count; j++) {
        hi_cpup_item* p_item = &p_cpup_items[j];
        if (p_item->b_valid && total_time != 0) {
            p_item->permillage = (hi_u32)((LOS_CPUP_PRECISION * p_item->cpu_time) / total_time);
        }
    }

    OsTskCycleStart();
    hi_int_restore(int_value);

    return HI_ERR_SUCCESS;
}

/*****************************************************************************
Function   : LOS_CpupReset
Description: reset data of CPU usage
Input      : None
Return     : None
*****************************************************************************/
hi_void hi_cpup_reset_usage(hi_void)
{
    hi_u32 max_num = g_taskMaxNum;

    if (g_cpup == HI_NULL) {
        return;
    }

    printf("reset cpup\r\n");
#if (LOSCFG_BASE_CORE_CPUP_HWI == YES)
            max_num += OS_HIMIDEER_LOCAL_IRQ_VECTOR_CNT;
#endif
    for (hi_u32 i = 0; i < max_num; i++) {
        g_cpup[i].startTime = OsGetCpuCycle();
        g_cpup[i].allTime = 0;
    }
}

hi_void hi_cpup_load_check_proc(hi_u32 task_id, hi_u32 ms)
{
    hi_u32 status = g_cpup_status & (1U << task_id);

    if (!status) {
        return;
    }
    if (cpup_get_idle() < MIN_IDEL_RATE) {
        g_cpup_status &= (~status);
        hi_sleep(ms);
    }
}

hi_void hi_cache_enable(hi_void)
{
    WRITE_CUSTOM_CSR_VAL(0x7C1, 0x1);
    Mb();
}

hi_void hi_cache_disable(hi_void)
{
    WRITE_CUSTOM_CSR_VAL(0x7C1, 0x0);
    Mb();
}

hi_void hi_cache_flush(hi_void)
{
    LOS_FlushDCacheByAll();
}

