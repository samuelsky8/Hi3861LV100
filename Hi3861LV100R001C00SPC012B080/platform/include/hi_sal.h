/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2012-2019. All rights reserved.
 * Description: sal head file.
 * Author: Hisilicon
 * Create: 2012-12-22
 */

/**
* @file hi_sal.h
*
* Copyright (c) Hisilicon Technologies Co., Ltd. 2019. All rights reserved.  \n
*
* Description: sal interfaces. \n
*/

#ifndef __HI_SAL_H__
#define __HI_SAL_H__
#include <hi_types.h>
#include <hi_ft_nv.h>
#include <hi_reset.h>
#include <watchdog.h>
#include <hi_sal_cfg.h>
#include <hi_time.h>
#include <hi_stdlib.h>

#ifdef __cplusplus
extern "C" {
#endif

#define WDG_TIMEOUT      13000
#define MS_PER_SEC       1000
#define MS_PER_MIN       (60 * 1000)

#define HI_WDT_FLAG_REG             GLB_CTL_GP_REG1_REG

#define HI_MONITOR_INTERVAL_MS      1000
#define HI_MONITOR_INTERVAL_SEC     (HI_MONITOR_INTERVAL_MS / 1000)

HI_EXTERN hi_u32 g_auto_rst_sys_timeout;
#define check_wd_timerout_enable()  (g_auto_rst_sys_timeout > 0)
HI_EXTERN hi_u32 g_cpu_clock;
HI_EXTERN hi_u32 g_flash_prot_sem;

hi_void watchdog_feed(hi_void);
hi_u32 hi_sal_timer_init(hi_void);
hi_u32 hi_sal_timer_suspend(hi_void);
hi_u32 hi_sal_timer_resume(hi_void);
hi_void hi_sal_init(hi_void);
hi_void hi_sal_wdg_clear(hi_void);

/**
* @ingroup  hct_reset_save
* @brief save crash messsage into flash. CNcomment:�洢crash��Ϣ��flash��CNend
*
* @par ����:
*           save crash messsage into flash. CNcomment:�洢crash��Ϣ��flash��CNend
*
* @attention �ޡ�
* @param  data          [IN] type #hi_pvoid ��Exception information pointer.CNcomment:�쳣��Ϣָ�롣CNend
* @param  str           [IN] type #hi_char * ��Exception description. CNcomment:�쳣������CNend
*
* @retval None.
* @par ����:
*           @li hi_crash.h���ļ����������쳣�洢�ӿڡ�
* @see hi_syserr_store_crash_info��
* @since Hi3861_V100R001C00
*/
hi_void hi_syserr_store_crash_info(hi_pvoid data);

#ifdef __cplusplus
}
#endif

#endif /* __HI_SAL_H__ */
