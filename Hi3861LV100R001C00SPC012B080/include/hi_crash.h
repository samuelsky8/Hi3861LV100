/**
* @file hi_crash.h
*
* Copyright (c) Hisilicon Technologies Co., Ltd. 2012-2019. All rights reserved.  \n
* Description: Dump crash log to flash. \n
* Author: Hisilicon \n
* Create: 2019-4-3
*/

/** @defgroup iot_crash_info    Crash Log Management
 * @ingroup system
 */

#ifndef __HI_CRASH_H__
#define __HI_CRASH_H__
#include <hi_types.h>
#include <hi_mdm_types.h>
#include <hi_os_stat.h>
#include <hi_mem.h>
#include <hi_isr.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
* @ingroup  iot_crash_info
*
* Version of the crash log module. CNcomment:�����洢ģ��汾�š�CNend
*/
#define HI_SYSERR_VERSION 1

/**
* @ingroup  iot_crash_info
*
* Power down flag. CNcomment:�µ��ʶ��CNend
*/
#define HI_SYSERR_POWER_DOWN    0x646F776E /* �µ��־ */

/**
* @ingroup  iot_crash_info
*
* No power down flag. CNcomment:δ�µ��ʶ��CNend
*/
#define HI_SYSERR_NO_POWER_DOWN 0xFFFFFFFF

/**
* @ingroup  iot_crash_info
*
* Length of the name string of an exception type. CNcomment:�쳣���͵������ַ����������ơ�CNend
*/
#define HI_SYSERR_EXC_TYPE_NAME_SIZE 8

/**
* @ingroup  iot_crash_info
*
* Length of the task name string of a logged exception.
CNcomment:�쳣�洢�����������ַ����������ơ�CNend
*/
#define HI_SYSERR_EXC_TASK_NAME_SIZE 8

/**
* @ingroup  iot_crash_info
*
* Depth of the scheduling track before an exception. CNcomment:�쳣ǰ���ȹ켣��ȡ�CNend
*/
#define HI_SYSERR_EXC_TRACE_DEPTH 10

/**
* @ingroup  iot_crash_info
*
* Exception stack information depth (unit: word). CNcomment:�쳣ջ��Ϣ���(wordΪ��λ)CNend
*/
#define HI_SYSERR_ESP_DATA_MAX_NUM 36

/**
* @ingroup  iot_crash_info
*
* Extended depth of the exception stack SP to the stack bottom (unit: word).
CNcomment:�쳣ջsp��ջ����չ���(wordΪ��λ)CNend
*/
#define HI_SYSERR_ESP_PRE_DATA_MAX_NUM 8

/**
* @ingroup  iot_crash_info
*
* Version of the running kernel when the exception occurs. CNcomment:�쳣ʱ��Ӧ�����а汾�İ汾��CNend
*/
#define HI_SYSERR_EXC_KERNEL_VER_LEN_MAX 60
#if !defined(PRODUCT_CFG_HSO)
#if (HI_SYSERR_EXC_KERNEL_VER_LEN_MAX < HI_BUILD_VER_PRODUCT_LEN_MAX)
#error "HI_SYSERR_EXC_KERNEL_VER_LEN_MAX != HI_BUILD_VER_PRODUCT_LEN_MAX"
#endif
#endif

/**
* @ingroup iot_crash_info
* Crash type eid.CNcomment:��������eid.CNend
*/
typedef enum {
    HI_SYSERR_EID_POWER_DOWN,           /**< Power Down or first Power on.CNcomment:�µ��������״��ϵ�.CNend */
    HI_SYSERR_EID_FAULT_IN_TASK,        /**< fault in task.CNcomment:����������.CNend */
    HI_SYSERR_EID_FAULT_IN_ISR,         /**< fault in isr.CNcomment:�ж�������.CNend */
    HI_SYSERR_EID_WATCHDOG_TSK,         /**< watchdog reset(in task).CNcomment:���Ź�����(������).CNend */
    HI_SYSERR_EID_WATCHDOG_ISR,         /**< watchdog reset(in isr).CNcomment:���Ź�����(�ж���).CNend */
    HI_SYSERR_EID_SYS_HARD_REBOOT,      /**< system hard reboot.CNcomment:ϵͳӲ��λ.CNend */
    HI_SYSERR_EID_SYS_SOFT_REBOOT,      /**< system soft reboot.CNcomment:ϵͳ��λ.CNend */
    HI_SYSERR_EID_RESERVE,
    HI_SYSERR_EID_MAX = 0xFF,
} hi_syserr_eid;

/* cpu registers */
typedef struct {
    hi_u32 mepc;
    hi_u32 ra;
    hi_u32 sp;
    hi_u32 gp;
    hi_u32 tp;
    hi_u32 t0;
    hi_u32 t1;
    hi_u32 t2;
    hi_u32 s0;
    hi_u32 s1;
    hi_u32 a0;
    hi_u32 a1;
    hi_u32 a2;
    hi_u32 a3;
    hi_u32 a4;
    hi_u32 a5;
    hi_u32 a6;
    hi_u32 a7;
    hi_u32 s2;
    hi_u32 s3;
    hi_u32 s4;
    hi_u32 s5;
    hi_u32 s6;
    hi_u32 s7;
    hi_u32 s8;
    hi_u32 s9;
    hi_u32 s10;
    hi_u32 s11;
    hi_u32 t3;
    hi_u32 t4;
    hi_u32 t5;
    hi_u32 t6;
} syserr_reg_info;

/**
* @ingroup iot_crash_info
* Task information.CNcomment:������Ϣ.CNend
*/
typedef struct {
    hi_char name[HI_SYSERR_EXC_TASK_NAME_SIZE];
    hi_u32 id;  /**< task id.CNcomment:����ID.CNend */
    hi_u32 status;  /**< task status.CNcomment:��������״̬.CNend */
    hi_u8 reserve[3];                       /* reserve's size 3 */
    hi_u8 stack_data_index; /**< extended stack information index from stack bottom.CNcomment:
                                ��ջ����չ��ջ��Ϣ����.CNend */
    hi_u16 stack_peak;      /**< stack peak.CNcomment:ջʹ�÷�ֵ.CNend */
    hi_u16 stack_size;      /**< stack size.CNcomment:����ջ��С.CNend */
    hi_u32 sp;              /**< stack point.CNcomment:ջָ��.CNend */
    hi_u32 stack[2];        /**< stack[2] is stack top and end address.CNcomment:ջ����ջ�׵�ַ.CNend */
    hi_u32 real_sp;         /**< real stack point.CNcomment:��ʵջָ��.CNend */
    hi_u32 stack_pre_data[HI_SYSERR_ESP_PRE_DATA_MAX_NUM]; /**< extended stack information from stack bottom.CNcomment:
                                                               ��ջ����չ��ջ��Ϣ�����ڻ���ջ�����ο�.CNend */
    hi_u32 stack_data[HI_SYSERR_ESP_DATA_MAX_NUM];         /**< stack data.CNcomment:ջ����.CNend */
    hi_u32 overflow_flag;                   /**< stack overflow flag.CNcomment:ջ�����ʶ.CNend */
} syserr_task_info;

/**
* @ingroup iot_crash_info
* OS information.CNcomment:����ϵͳ��Ϣ.CNend
*/
typedef struct {
    hi_os_resource_use_stat usage; /**< os resource used count.CNcomment:ϵͳ��Դʹ�ø���.CNend */
    syserr_task_info task;         /**< task information.CNcomment:������Ϣ.CNend */
    hi_mem_pool_crash_info mem;    /**< memory pool information.CNcomment:��̬�ڴ����Ϣ.CNend */
} syserr_os_info;

/**
* @ingroup iot_crash_info
* Basic information.CNcomment:������Ϣ.CNend
*/
typedef struct {
    hi_u16 log_ver;                /**< log version.CNcomment:Log�汾��.CNend */
    hi_u16 eid;                    /**< reset reason id.CNcomment:��λ����.CNend */
    hi_u32 rid;                    /**< exception id.CNcomment:�쳣����.CNend */
    hi_u32 now_tsec;               /**< current time relative start time.CNcomment:��ǰ�����������ʱ��.CNend */
    hi_u32 crash_tsec;             /**< crash time relative start time.CNcomment:�쳣ʱ��Ե�������ʱ��.CNend */
    hi_u32 boot_ver;
    hi_char kernel_ver[HI_SYSERR_EXC_KERNEL_VER_LEN_MAX]; /**< kernel version.CNcomment:�쳣ʱ���а汾�İ汾��.CNend */
    hi_char type_name[HI_SYSERR_EXC_TYPE_NAME_SIZE];      /**< reset reason name.CNcomment:������:��eid��Ӧ.CNend */
} syserr_basic_info;

/**
* @ingroup iot_crash_info
* Watchdog information.CNcomment:���Ź���Ϣ.CNend
*/
typedef struct {
    hi_u32 wdg_reset_pc;    /**< watchdog reset reserved PC.CNcomment:���Ź���λPC.CNend */
    hi_u32 time_ms : 31;    /**< watchdog timeout.CNcomment:���Ź���ʱʱ��.CNend */
    hi_u32 enable : 1;      /**< watchdog enable.CNcomment:���Ź�ʹ��״̬.CNend */
} syserr_wdg_info;

/**
* @ingroup iot_crash_info
* Flash protect information.CNcomment:Flash������Ϣ.CNend
*/
typedef struct {
    hi_u32 current_block : 13;  /**< flash protect current block.CNcomment:Flash������ǰblock.CNend */
    hi_u32 reserve : 18;
    hi_u32 enable : 1;          /**< flash protect enable.CNcomment:Flash����ʹ��״̬.CNend */
    hi_u32 status_reg;          /**< flash protect status.CNcomment:Flash����״̬�Ĵ���.CNend */
} syserr_fp_info;

/**
* @ingroup iot_crash_info
* Track item information.CNcomment:��������Ϣ.CNend
*/
typedef struct {
    hi_u16 type;      /**< track type.CNcomment:��������.CNend */
    hi_u16 id;        /**< track ID.CNcomment:������id.CNend */
    hi_u32 data;      /**< track userdata.CNcomment:�����û�����.CNend */
    hi_u32 entry;     /**< track Hook function Entry.CNcomment:���Ȼص����Ӻ���.CNend */
    hi_u32 timestamp; /**< The low 32 bit of the current time,us.CNcomment:����ʱ���.CNend */
} syserr_track_item;

/**
* @ingroup iot_crash_info
* Track information.CNcomment:���ȹ켣��Ϣ.CNend
*/
typedef struct {
    hi_u16 current_item;    /**< current track item.CNcomment:��ǰ������.CNend */
    hi_u16 item_cnt;        /**< track count of track information.CNcomment:�������¼����.CNend */
    syserr_track_item item[HI_SYSERR_EXC_TRACE_DEPTH];  /**< track item data.CNcomment:����������.CNend */
} syserr_track_info;

/**
* @ingroup iot_crash_info
* CPU csr registers information.CNcomment:CPU CSR�Ĵ�����Ϣ.CNend
*/
typedef struct {
    hi_u32 mstatus;     /**< CPU mstatus register value.CNcomment:CPU mstatus�Ĵ���ֵ.CNend */
    hi_u32 mtval;       /**< CPU mtval register value.CNcomment:CPU mtval�Ĵ���ֵ.CNend */
    hi_u32 mcause;      /**< CPU mcause register value.CNcomment:CPU mcause�Ĵ���ֵ.CNend */
    hi_u32 ccause;      /**< CPU ccause register value.CNcomment:CPU ccause�Ĵ���ֵ.CNend */
    hi_u16 cur_task_id; /**< current task id.CNcomment:��ǰ����ID.CNend */
} syserr_core_info;

/**
* @ingroup iot_crash_info
* Saved exception information.CNcomment:�쳣ʱ��Ӧ�洢��Ϣ��CNend
*/
typedef struct {
    hi_u32 sig_s;       /**< header flag of crash information.CNcomment:�쳣��Ϣǰ��ʶ.CNend */
    hi_u32 power_magic; /**< power down magic number.CNcomment:�µ�ħ����.CNend */
    hi_u32 power_down : 1; /**< power down flag.CNcomment:�µ��ʶ.CNend */
    hi_u32 crc_usable : 1; /**< CRC check enable of crash information.CNcomment:������ϢCRCУ��ʹ��.CNend */
    hi_u32 info_len : 14;  /**< crash information length.CNcomment:������Ϣ����.CNend */
    hi_u32 crc_val : 16;   /**< CRC16 calue of crash information.CNcomment:CRC16У��ֵ.CNend */

    syserr_basic_info basic_info; /**< basic data of crash information.CNcomment:����������Ϣ.CNend */
    syserr_os_info os_info;       /**< OS data of crash information.CNcomment:����OS��Ϣ.CNend */
    syserr_reg_info reg_info;     /**< CPU registers of crash information.CNcomment:����CPU�Ĵ�����Ϣ.CNend */
    syserr_wdg_info wdg_info;     /**< watchdog data of crash information.CNcomment:�������Ź�.CNend */
    syserr_fp_info protect_info;  /**< flash protect data of crash information.CNcomment:����Flash������Ϣ.CNend */
    syserr_track_info track_info; /**< track data of crash information.CNcomment:����������Ϣ.CNend */
    syserr_core_info core_info;   /**< CPU CSR registers of crash information.CNcomment:����CPU״̬�Ĵ�����Ϣ.CNend */
    hi_u32 sig_e;                 /**< end flag of crash information.CNcomment:�쳣��Ϣ���ʶ.CNend */
} hi_syserr_info;

typedef hi_void (*hi_syserr_exc_callback)(hi_void);

/**
* @ingroup  iot_crash_info
* @brief Initializes the exception information module. CNcomment:�쳣��Ϣģ���ʼ����CNend
*
* @par ����:
*           Initializes the exception information module. CNcomment:�쳣��Ϣģ���ʼ����CNend
*
* @attention s API can be called only once. Repeated initialization and multi-task calling are not supported.
CNcomment:����ʼ��һ�Σ�δ���Ƕ�γ�ʼ������������ó�����CNend
* @param  None
*
* @retval None
* @par ����:
*           @li hi_crash.h��Describes Crash log APIs. CNcomment:�ļ���������������ؽӿڡ�CNend
* @see None
* @since Hi3861_V100R001C00
*/
hi_void hi_syserr_init(hi_void);

/**
* @ingroup  iot_crash_info
* @brief Obtains the system exception information pointer (in the memory).
CNcomment:��ȡϵͳ�쳣��Ϣָ��(�ڴ���)��CNend
*
* @par ����:
*           Obtains the system exception information pointer (in the memory).
CNcomment:��ȡϵͳ�쳣��Ϣָ��(�ڴ���)��CNend
*
* @attention None
* @param  None
*
* @retval Pointer to the hi_syserr_info structure. CNcomment:hi_syserr_info�ṹ��ָ�롣CNend
* @par ����:
*           @li hi_crash.h��Describes Crash log APIs. CNcomment:�ļ���������������ؽӿڡ�CNend
* @see None
* @since Hi3861_V100R001C00
*/
hi_syserr_info *hi_syserr_ptr(hi_void);

/**
* @ingroup  iot_crash_info
* @brief Obtains the system exception information pointer (in the flash).
CNcomment:��ȡϵͳ�쳣��Ϣָ��(flash��)��CNend
*
* @par ����:
*           Obtains the system exception information pointer (in the flash).
CNcomment:��ȡϵͳ�쳣��Ϣָ��(flash��)��CNend
*
* @attention None
* @param  info          [IN] type #hi_syserr_info ��Pointer to the hi_syserr_info structure.
CNcomment:�쳣��Ϣ�������ŵ�ַ��CNend
*
* @retval #HI_ERR_SUCCESS  Success.
* @retval #Other values    Failure. For details, see hi_errno.h.
* @par ����:
*           @li hi_crash.h��Describes Crash log APIs. CNcomment:�ļ���������������ؽӿڡ�CNend
* @see None
* @since Hi3861_V100R001C00
*/
hi_u32 hi_syserr_get(hi_syserr_info *info);

/**
* @ingroup  iot_crash_info
* @brief Register exception handling callback. CNcomment:ע���쳣��������ص�������CNend
*
* @par ����:
*           Register exception handling callback. CNcomment:ע���쳣��������ص�������CNend
*
* @attention None
* @param  func          [IN] type #hi_syserr_exc_callback ��Callback function of exception happens
CNcoment:�쳣�ص�������CNend
*
* @retval None
* @par ����:
*           @li hi_crash.h��Describes Crash log APIs. CNcomment:�ļ���������������ؽӿڡ�CNend
* @see None
* @since Hi3861_V100R001C00
*/
hi_void hi_syserr_exc_register(hi_syserr_exc_callback func);

/**
* @ingroup  iot_crash_info
* @brief Retains the PC pointer when the watchdog reset. CNcomment:���Ź���λʱ��¼PCֵ��CNend
*
* @par ����:
*        Retains the PC pointer when the watchdog reset.
CNcomment:���Ź���λʱ��¼PCֵ���򿪴˹��ܺ��Ź���λ�и�λ����ȫ�ķ��գ������汾����عرա�CNend
*
* @attention None
* @param  enable          [IN] type #hi_bool ��Enable/Disable retains reset PC pointer function.
CNcoment:��/�رռ�¼��λPCֵ���ܡ�CNend
*
* @retval None
* @par ����:
*           @li hi_crash.h��Describes Crash log APIs. CNcomment:�ļ���������������ؽӿڡ�CNend
* @see None
* @since Hi3861_V100R001C00
*/
hi_void hi_syserr_watchdog_debug(hi_bool enable);


/**
* @ingroup  iot_crash_info
* @brief Retains the latest reboot reason. CNcomment:��ȡ���һ������ԭ��CNend
*
* @par ����:
*        Retains the latest reboot reason.
CNcomment:��ȡ���һ������ԭ��CNend
*
* @attention None
* @param  err_id         [IN] type #hi_u16 * , error id, see hi_syserr_eid.
CNcomment:����ԭ��ID��ȡֵ����μ�hi_syserr_eid��CNend
* @param  reboot_cause    [IN] type #hi_u32* ��reboot cause for soft reboot or hard reboot, see hi_sys_reboot_cause.
CNcomment:��ǰ����ԭ��ΪӲ��λ����λʱ�ľ���ԭ�򣬲μ�hi_sys_reboot_cause��CNend
*
* @retval None
* @par ����:
*           @li hi_crash.h��Describes Crash log APIs. CNcomment:�ļ���������������ؽӿڡ�CNend
* @see None
* @since Hi3861_V100R001C00
*/
hi_u32 hi_syserr_get_reboot_reason(hi_u16 *err_id, hi_u32 *reboot_cause);


#ifdef __cplusplus
}
#endif

#endif /* __HI_CRASH_H__ */
