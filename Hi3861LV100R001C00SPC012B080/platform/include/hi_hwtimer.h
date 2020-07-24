/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2012-2019. All rights reserved.
 * Description: hi_hwtimer.h.
 * Author: Hisilicon
 * Create: 2012-12-22
 */

/**
* @file hi_hwtimer.h
*
* Copyright (c) Hisilicon Technologies Co., Ltd. 2019. All rights reserved.  \n
*
* Description: hwtimer interfaces. \n
*/

#ifndef __HI_HWTIMER_H__
#define __HI_HWTIMER_H__

#include <hi_types_base.h>


typedef enum {
    HI_RTC_CLK_32K = 32,
    HI_RTC_CLK_24M = 24,
    HI_RTC_CLK_40M = 40,
} hi_rtc_clk; /**< �͹�����˯�����£�24M/40Mʱ�Ӳ����� */

typedef void (*hi_hwtimer_callback)(hi_u32 data);

typedef void (*hi_hwrtc_callback)(hi_u32 data);

typedef void (*hwtimer_clken_callback)(hi_void);

/**
 * @ingroup hw_timer
 *
 * Timer mode control. CNcomment:��ʱ��ģʽ���ơ�CNend
 */
typedef enum {
    TIMER_MODE_FREE = 0,   /**< ����ģʽ */
    TIMER_MODE_CYCLE = 1,  /**< ����ģʽ */
} timer_mode;

/**
 * @ingroup hw_timer
 *
 * Timer interrupt mask control. CNcomment:��ʱ���ж�ģʽ���ơ�CNend
 */
typedef enum {
    TIMER_INT_UNMASK = 0,  /**< ������ */
    TIMER_INT_MASK = 1,    /**< ���� */
} timer_int_mask;

/**
 * @ingroup hw_timer
 *
 * hwtimer ID. CNcomment:Ӳ����ʱ��ID��CNend
 */
typedef enum {
    HI_TIMER_ID_0,
    HI_TIMER_ID_1,
    HI_TIMER_ID_2,
    HI_TIMER_ID_MAX, /* ��Чֵ */
} hi_timer_id;

/**
 * @ingroup hw_timer
 *
 * hwrtc ID. CNcomment:Ӳ��RTC ID��CNend
 */
typedef enum {
    HI_RTC_ID_0 = HI_TIMER_ID_MAX,
    HI_RTC_ID_1,
    HI_RTC_ID_2,
    HI_RTC_ID_3,
    HI_RTC_ID_MAX, /* ��Чֵ */
} hi_rtc_id;

/**
 * @ingroup hw_timer
 *
 * hwtimer working mode. CNcomment:Ӳ����ʱ������ģʽ��CNend
 */
typedef enum {
    HI_HWTIMER_MODE_ONCE,    /**< ����ģʽ */
    HI_HWTIMER_MODE_PERIOD,  /**< ����ģʽ */
    HI_HWTIMER_MODE_INVALID,
} hi_hwtimer_mode;

/**
 * @ingroup hw_timer
 *
 * hwrtc working mode. CNcomment:Ӳ��RTC����ģʽ��CNend
 */
typedef enum {
    HI_HWRTC_MODE_ONCE,    /**< ����ģʽ */
    HI_HWRTC_MODE_PERIOD,  /**< ����ģʽ */
    HI_HWRTC_MODE_INVALID,
} hi_hwrtc_mode;

/**
 * @ingroup hw_timer
 *
 * hwtimer handle structure. CNcomment:Ӳ����ʱ������ṹ��CNend
 */
typedef struct {
    hi_hwtimer_mode mode;       /**< ����ģʽ */
    hi_u32 expire;              /**< ��ʱʱ�䣨��λ��΢�룩�����ʱʱ��Ϊhi_u32(-1)/CLK������CLKΪ����ʱ��Ƶ�ʣ�
                                     ��������ʱ��Ϊ24Mhz����CLK=24�� */
    hi_u32 data;                /**< �ص��������� */
    hi_hwtimer_callback func;   /**< �ص����� */
    hi_timer_id timer_id;       /**< ��ʱ��ID */
} hi_hwtimer_ctl;

/**
 * @ingroup hw_timer
 *
 * hwrtc handle structure. CNcomment:Ӳ��RTC����ṹ��CNend
 */
typedef struct {
    hi_hwrtc_mode mode;         /**< ����ģʽ */
    hi_u32 expire;              /**< ��ʱʱ�䣬ʱ��Դ��Ϊ32K����λΪms����Ϊ24M��40M����λΪus�� */
    hi_u32 data;                /**< �ص��������� */
    hi_hwrtc_callback func;     /**< �ص����� */
    hi_rtc_id rtc_id;           /**< RTC ID */
} hi_hwrtc_ctl;


 /* ����������ʱ��Դѡ�񡢷�Ƶ�Ľӿ�����øýӿڣ������ּĴ���ֵ������ı���ֵһ�� */
hi_void hi_hwrtc_set_clk(hi_rtc_clk clk);

hi_u32 hi_hwtimer_init_new(hi_timer_id timer_id);
hi_u32 hi_hwtimer_start(const hi_hwtimer_ctl *timer);
hi_u32 hi_hwtimer_stop(hi_timer_id timer_id);
hi_u32 hi_hwtimer_destroy_new(hi_timer_id timer_id);
hi_u32 hi_hwtimer_get_cur_val(hi_timer_id timer_id, hi_u32 *val); /* ��ȡtimer��ǰֵ */
hi_u32 hi_hwtimer_get_load(hi_timer_id timer_id, hi_u32 *load);   /* ��ȡtimer��ֵ */

hi_u32 hi_hwrtc_start(const hi_hwrtc_ctl *rtc);
hi_u32 hi_hwrtc_init(hi_rtc_id timer_id);
hi_u32 hi_hwrtc_stop(hi_rtc_id rtc_id);
hi_u32 hi_hwrtc_destroy(hi_rtc_id rtc_id);
hi_u32 hi_hwrtc_get_cur_val(hi_rtc_id rtc_id, hi_u32 *val); /* ��ȡrtc��ǰֵ */
hi_u32 hi_hwrtc_get_load(hi_rtc_id rtc_id, hi_u32 *load);   /* ��ȡrtc��ֵ */

#endif
