/**
 * @file hi_lowpower.h
 *
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2019. All rights reserved. \n
 * Description: hi lowpower head \n
 * Author: hisilicon \n
 * Create: 2019-03-04
 */

/**
 * @defgroup iot_lp Power consumption management
 * @ingroup  system
 */

#ifndef __HI_LOWPOWER_H__
#define __HI_LOWPOWER_H__

#include <hi_types.h>
#include <hi_gpio.h>

/**
 * @ingroup iot_lp
 * UDP wakes up source enumeration.
 */
typedef enum {
    HI_UDS_GPIO3 = 1 << 0,  /**< ultra sleep wakeup source GPIO3.CNcomment:����˯����ԴGPIO3 CNend */
    HI_UDS_GPIO5 = 1 << 1,  /**< ultra sleep wakeup source GPIO5.CNcomment:����˯����ԴGPIO5 CNend */
    HI_UDS_GPIO7 = 1 << 2,  /**< ultra sleep wakeup source GPIO7.CNcomment:����˯����ԴGPIO7 CNend */
    HI_UDS_GPIO14 = 1 << 3, /**< ultra sleep wakeup source GPIO14.CNcomment:����˯����ԴGPIO14 CNend */
} hi_udsleep_src;

/**
 * @ingroup iot_lp
 * Sleep level enumeration.
 */
typedef enum {
    HI_NO_SLEEP,    /**< no sleep type.CNcomment:��˯ģʽ CNend */
    HI_LIGHT_SLEEP, /**< light sleep type.CNcomment:ǳ˯ģʽ CNend */
    HI_DEEP_SLEEP,  /**< deep sleep type.CNcomment:��˯ģʽ CNend */
} hi_lpc_type;

/**
 * @ingroup hct_lp
 *
 * ˯��ģ��ID ö�٣�ÿ��idռ��1��bit��������չʱҪע�����Ϊ(1 << 31)��
 */
typedef enum {
    HI_LPC_ID_DIAG  = 1 << 0, /**< diag uart Id.CNcomment:diagģ�� Id */
    HI_LPC_ID_SHELL = 1 << 1, /**< shell Id.CNcomment:shellģ�� Id CNend */
    HI_LPC_ID_RSV   = 1 << 15, /**< ֮ǰ��Ϊ�ڲ�Ԥ��id.CNcomment:�ڲ�Ԥ�� Id CNend */
    HI_LPC_ID_DEMO  = 1 << 16, /**< demo Id.CNcomment:�͹��Ĺ���id������֮��Ϊ�ͻ�Ԥ��Id CNend */
}hi_lpc_id;

/**
 * @ingroup iot_lp
 * Low power management structure.
 */
typedef struct {
    hi_u32  wakeup_times;                   /**< wakeup times.CNcomment:���Ѵ���ͳ�� CNend */
    hi_u32  sleep_threshold_refuse_times;  /**< sleep threshold refuse times.CNcomment:
                                                ��˯ʱ��С���趨���޴���ͳ�� CNend */
    hi_u32  sleep_check_refuse_times;       /**< sleep check refuse times.CNcomment:
                                                ��˯ͶƱ˯��ʧ�ܴ���ͳ�� CNend */
    hi_u32  sleep_times;                   /**< sleep times.CNcomment:��˯����ͳ�� CNend */
    hi_u32  sleep_threshold;               /**< sleep threshold, unit is ms, only when
                                                the system' Remaining idle time is bigger than the threshold,
                                                system can enter deep sleep state.CNcomment:��˯�����ޣ���λ
                                                Ϊms����ϵͳʣ�����ʱ����ڸ�����ʱ�����ɽ�����˯ CNend */
    hi_u32  dsleep_fail_times; /**< the times of power off fail during deepsleep.CNcomment:��˯�µ�ʧ�ܴ���ͳ�� CNend */
    hi_u8   type;                  /**< hi_lpc_type type, enable low power management.
                                         CNcomment:hi_lp_type���ͣ��͹������� CNend */
    hi_u8   evt_sts;                 /**< sleep event state.CNcomment:�����¼�״̬ CNend */
    hi_u8   int_sts;                 /**< sleep interrupt state.CNcomment:�����ж�״̬ CNend */
    hi_u8   last_time_vote_state;    /**< last time vote state, 0:no sleep, 1: light sleep, 2: deep sleep.
                                        CNcomment:���һ��˯��״̬��0:û����˯��1:ǳ˯��2:��˯�� CNend */
    hi_u32  timer_ticks; /**< the time ticks is about to expire, unit is 10 ms, if the value is 0xffffffff, there is
                                no timer that is about to expire.
                            CNcomment:��ʱ���������ڵ�ʱ�䣬��λΪ10ms�������0xffffffff����ʾû�м������ڵ�
                            ��ʱ�� CNend */
    hi_u32  timer_handle; /**< the callback function address of the timer that is about to expire. if the value is
                                0xffffffff, it means that there is no timer that is about to expire.
                            CNcomment:�������ڶ�ʱ���ص������ĵ�ַ�������0xffffffff,��ʾû�м������ڵĶ�ʱ�� CNend */
    hi_u32  timer_handle_arg; /**< the parameter of the timer callback function, if the value is 0xffffffff, it means
                                there is no timer to expire.CNcomment:��ʱ���ص������Ĳ����������0xffffffff,
                                ��ʾû�м������ڵĶ�ʱ�� CNend */
    hi_u32  task_ticks;  /**< the task ticks is about to expire, unit is 10 ms.CNcomment:���񼴽����ڵ�ʱ�䣬
                            ��λΪ10ms��CNend */
    hi_u32  task_id; /**< the task id that is about to expire.CNcomment:�������������ID��CNend */
    hi_u32  sleep_ticks; /**< last sleep time ticks, unit is 10 ms.CNcomment:���һ��˯�ߵ�tickʱ�䣬
                            ��λΪ10ms��CNend */
    hi_u32  veto_info;   /**< veto_info.CNcomment:ͶƱ���˯����Ϣ�����hi_lpc_id��CNend */
    hi_u16  dsleep_wk_gpio; /**< wakeup gpio for deep sleep.CNcomment:���ѵ�GPIO,��ֵ(1<<x)Ϊ1��ʾGPIOxʹ�ܡ�CNend */
    hi_u16  reserve;   /**< reserve.CNcomment:Ԥ����CNend */
} hi_lpc_info;

/**
 * @ingroup  iot_lp
 * @brief  Low power initialization.
 *
 * @par Description:
 *           Initializes power saving management. CNcomment:�͹��ĳ�ʼ��CNend
 *
 * @attention This is an initialization API and does not support multi-task calling or repeated calling.
 CNComment:��ʼ�������ǷǶ�����ȫ�ģ����Ҳ�֧���ظ����á�CNend
 * @param  None
 *
 * @retval #0                Success.
 * @retval #Other            Failure. For details, see hi_errno.h.
 * @par Dependency:
 *            @li hi_lowpower.h: Describes power saving management APIs.
 * @see  None
 * @since Hi3861_V100R001C00
 */
hi_u32 hi_lpc_init(hi_void);

/**
 * @ingroup  iot_lp
 * @brief  Set current lowpower type.
 *
 * @par Description:
 *           Set current lowpower sleep mode. CNcomment:���õ͹���ģʽCNend
 *
 * @param  sleep_mode  [IN] type #hi_lpc_type type.
 CNcomment:�͹���ģʽCNend
 *
 * @retval #HI_ERR_SUCCESS   Success.
 * @retval #Other    Failure. For details, see hi_errno.h.
 * @par Dependency:
 *            @li hi_lowpower.h: Describes power saving management APIs.
 * @see  None
 * @since Hi3861_V100R001C00
 */
hi_u32 hi_lpc_set_type(hi_lpc_type type);

/**
 * @ingroup  iot_lp
 * @brief  Get current lowpower type.
 *
 * @par Description:
 *           Get current lowpower type.CNcomment:��ȡ��ǰ�͹���ģʽ��CNend
 *
 * @param  None
 *
 * @retval #hi_lpc_type current lowpower type.
 * @par Dependency:
 *            @li hi_lowpower.h: Describes power saving management APIs.
 * @see  None
 * @since Hi3861_V100R001C00
 */
hi_lpc_type hi_lpc_get_type(hi_void);

/**
 * @ingroup  iot_lp
 * @brief  Register check callback fucntion.
 *
 * @par Description:
 *           Register check callback function.CNComment:ע�����Ƿ�����˯�߽ӿ�CNend
 *
 * @param  check_allowed [IN] type #hi_u32_void_callback
 *         If the return value is 0 means to disable sleep,others means enable.
 *         CNcomment:����ֵΪ0��ֹ˯�ߣ�����ֵΪ����.CNend
 *
 * @retval #hi_pvoid Hanlder.CNcomment:���CNend
 * @par Dependency:
 *            @li hi_lowpower.h: Describes power saving management APIs.
 * @see  hi_lowpower_unregister_vote
 * @since Hi3861_V100R001C00
 */
hi_pvoid hi_lpc_register_check_handler(hi_u32_void_callback check_allowed);

/**
 * @ingroup  iot_lp
 * @brief  Cancel registation of check callback fucntion.
 *
 * @par Description:
 *            Cancel registation of check callback fucntion.CNcomment:ȡ�����ӿ�ע��CNend
 *
 * @param  handle [IN] type #hi_pvoid Low power handler.CNcomment:�͹��ľ��CNend
 *
 * @retval #0   Success.
 * @retval #Other    Failure. For details, see hi_errno.h.
 * @par Dependency:
 *            @li hi_lowpower.h: Describes power saving management APIs.
 * @see  hi_lowpower_register_vote
 * @since Hi3861_V100R001C00
 */
hi_u32 hi_lpc_unregister_check_handler(hi_pvoid handle);

/**
 * @ingroup  iot_lp
 * @brief  Add low power sleep veto.
 *
 * @par Description:
 *           Add low power sleep veto. CNcomment:��ֹ����˯��ģʽCNend
 *
 * @param  id  [IN] type #hi_lpc_id module id.
 CNcomment:ģ��idCNend
 *
 * @retval #HI_ERR_SUCCESS   Success.
 * @retval #Other    Failure. For details, see hi_errno.h.
 * @par Dependency:
 *            @li hi_lowpower.h: Describes power saving management APIs.
 * @see  None
 * @since Hi3861_V100R001C00
 */
hi_u32 hi_lpc_add_veto(hi_lpc_id id);

/**
 * @ingroup  iot_lp
 * @brief  Remove low power sleep veto.
 *
 * @par Description:
 *           Set low power sleep mode. CNcomment:�����Ӧid�Ľ�ֹ����˯��ģʽ״̬CNend
 *
 * @param  sleep_mode  [IN] type #hi_lpc_id module id.
 CNcomment:ģ��idCNend
 *
 * @retval #HI_ERR_SUCCESS   Success.
 * @retval #Other    Failure. For details, see hi_errno.h.
 * @par Dependency:
 *            @li hi_lowpower.h: Describes power saving management APIs.
 * @see  None
 * @since Hi3861_V100R001C00
 */
hi_u32 hi_lpc_remove_veto(hi_lpc_id id);

/**
 * @ingroup  iot_lp
 * @brief  Statistics related to power saving.
 *
 * @par Description:
 *           Statistics related to power saving.CNcomment:�͹������ά��ͳ��CNend
 *
 * @param  None
 *
 * @retval hi_lp_stat Pointer to the status sturcture. CNcomment:ͳ����ָ��CNend
 * @par Dependency:
 *            @li hi_lowpower.h: Describes power saving management APIs.
 * @see  None
 * @since Hi3861_V100R001C00
 */
hi_lpc_info* hi_lpc_get_info(hi_void);

/**
 * @ingroup  iot_lp
 * @brief  enable ultra deep sleep wakeup source.
 *
 * @par Description:
 *            enable ultra deep sleep wakeup source to low power module.CNcomment:ʹ�ܵ͹��ĳ���˯����ԴCNend
 *
 * @param  src  [IN] type #hi_udsleep_src Type of ultra deep sleep wakeup source enumeration.
 CNcomment:����˯����ԴCNend
 *
 * @retval #0   Success.
 * @retval #Other    Failure. For details, see hi_errno.h.
 *
 * @par Dependency:
 *            @li hi_lowpower.h: Describes power saving management APIs.
 * @see  None
 * @since Hi3861_V100R001C00
 */
hi_u32 hi_lpc_enable_udsleep(hi_udsleep_src src);

/**
 * @ingroup  iot_lp
 * @brief  get ultra deep sleep wakeup source.
 *
 * @par Description:
 *            get the  wakeup source of ultra deep sleep.CNcomment:��ȡ�͹��ĳ���˯���ѵĴ���ԴCNend
 *
 * @param  wakeup_src  [IN] type #hi_udsleep_src Type of ultra deep sleep wakeup source enumeration.
 CNcomment:����˯����ԴCNend
 *
 * @retval #0   Success.
 * @retval #Other    Failure. For details, see hi_errno.h.
 *
 * @par Dependency:
 *            @li hi_lowpower.h: Describes power saving management APIs.
 * @see  None
 * @since Hi3861_V100R001C00
 */
hi_u32 hi_lpc_get_udsleep_wakeup_src(hi_u16 *src);

/**
 * @ingroup  iot_lp
 * @brief  Register hardware callback func of light_sleep or deep_sleep.
 *
 * @par Description:
 *         Register hardware callback func of light_sleep or deep_sleep.CNcomment:����˯�߽׶�Ӳ����ػص�����CNend
 *
 * @attention The save function is called after voting success and befor sleep, and the restore function is called
 * when waking up.
 CNComment:prepare������оƬʵ������ǰִ�У�resume������˯��ʱִ�С�CNend
 * @param  prepare     [IN] type #hi_u32_void_callback Callback func of sleep.CNcomment:˯��׼���׶λص�����CNend
 * @param  resume  [IN] type #hi_u32_void_callback Callback func of wake up.CNcomment:���ѽ׶λص�����CNend
 *
 * @retval #0   Success.
 * @retval #Other    Failure. For details, see hi_errno.h.
 *
 * @par Dependency:
 *            @li hi_lowpower.h: Describes power saving management APIs.
 * @see  None
 * @since Hi3861_V100R001C00
 */
hi_u32 hi_lpc_register_hw_handler(hi_u32_void_callback prepare, hi_u32_void_callback resume);

/**
 * @ingroup  iot_lp
 * @brief  Register software callback func of light_sleep or deep_sleep.
 *
 * @par Description:
 *         Register software callback func of light_sleep or deep_sleep.CNcomment:����˯�߽׶������ػص�����CNend
 *
 * @attention The save function is called before voting for sleep, and the restore function is called when waking up or
 * vote fail.
 CNComment:prepare������ϵͳ�ж��Ƿ������ǰִ�У�resume������˯��ʱ��ͶƱʧ�ܺ�ִ�С�CNend
 * @param  prepare     [IN] type #hi_u32_void_callback Callback func of sleep.CNcomment:˯��׼���׶λص�����CNend
 * @param  resume  [IN] type #hi_u32_void_callback Callback func of wake up.CNcomment:���ѽ׶λص�����CNend
 *
 * @retval #0   Success.
 * @retval #Other    Failure. For details, see hi_errno.h.
 *
 * @par Dependency:
 *            @li hi_lowpower.h: Describes power saving management APIs.
 * @see  None
 * @since Hi3861_V100R001C00
 */
hi_u32 hi_lpc_register_sw_handler(hi_u32_void_callback prepare, hi_u32_void_callback resume);

/**
 * @ingroup  iot_lp
 * @brief  Register callback func of peripheral init entry.
 *
 * @par Description:
 *            Register callback func of peripheral init entry.CNcomment:������˯����ʱ��ں�����һ�����������ʼ��CNend
 *
 * @param  func  [IN] type #hi_void_callback_f Callback func of wake up.CNcomment:���ѻص�����CNend
 *
 * @retval #0   Success.
 * @retval #Other    Failure. For details, see hi_errno.h.
 *
 * @par Dependency:
 *            @li hi_lowpower.h: Describes power saving management APIs.
 * @see  None
 * @since Hi3861_V100R001C00
 */
hi_u32 hi_lpc_register_wakeup_entry(hi_void_callback_f handler);

/**
 * @ingroup  iot_lp
 * @brief  Config deep sleep gpio wakeup IO.
 *
 * @par Description:
 *            Config deep sleep wakeup IO.CNcomment:��˯�߻���IO����CNend
 *
 * @param  id  [IN] type #hi_gpio_idx Wake up source IO.CNcomment:����IOCNend
 * @param  enable  [IN] type #hi_bool whether enable the source IO.CNcomment:����IOCNend
 *
 * @retval #0   Success.
 * @retval #Other    Failure. For details, see hi_errno.h.
 *
 * @par Dependency:
 *            @li hi_lowpower.h: Describes power saving management APIs.
 * @see  None
 * @since Hi3861_V100R001C00
 */
hi_u32 hi_lpc_config_dsleep_wakeup_io(hi_gpio_idx id, hi_bool enable);


#endif /*__HI_LOWPOWER_H__*/
