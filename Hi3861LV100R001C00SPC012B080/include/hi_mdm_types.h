/**
* @file hi_mdm_types.h
*
* Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2019. All rights reserved. \n
* Description: Common types define. \n
* Author: Hisilicon \n
* Create: 2019-4-3
*/

#ifndef __HI_MDM_TYPES_H__
#define __HI_MDM_TYPES_H__
#ifndef __HI_TYPES_H__
#error "Please include hi_types.h before using hi_mdm_types.h"
#endif
HI_START_HEADER

#include <hi_types_base.h>

#define HI_ALL_F_32          0xFFFFFFFF

typedef struct {
    hi_u32 major_minor_version; /* ���汾��.�ΰ汾�� */
    hi_u32 revision_version;   /* �����汾�� */
    hi_u32 build_version;      /* �ڲ��汾�� */
} hi_ue_soft_version;

#define HI_BUILD_VER_DATE_LEN             10
#define HI_BUILD_VER_TIME_LEN             8
#define HI_BUILD_VER_PRODUCT_NAME_LEN_MAX 28
#define HI_BUILD_VER_PRODUCT_LEN_MAX      (HI_BUILD_VER_PRODUCT_NAME_LEN_MAX + HI_BUILD_VER_DATE_LEN +\
                                            HI_BUILD_VER_TIME_LEN + 6)
typedef struct {
    hi_u16 version_v;   /* �汾��: V���� */
    hi_u16 version_r;   /* �汾��: R���� */
    hi_u16 version_c;   /* �汾��: C���� */
    hi_u16 version_b;   /* �汾��: B���� */
    hi_u16 version_spc; /* �汾��: SPC���� */
    hi_u16 reserved[3]; /* ���� 3 */
} hi_ue_product_ver;

typedef struct {
    hi_char *product_version;      /* pszProductVer;  // "Hi3911 V100R001C00B00" */
    hi_char* build_date; /* pszDate;        // �� 2011-08-01 */
    hi_char* build_time; /* pszTime;        // �� 14:30:26 */
} hi_product_info;

/*
* @ingroup  iot_diag
* @brief Registers the callback function for DIAG channel status changes.
CNcomment:DIAGͨ��״̬����ص�������CNend
*
* @par ����:
*      Registers the callback function for DIAG channel status changes. That is, when the DIAG channel is
*      connected or disconnected, the function registered by this API is called back.
CNcomment:ע��DIAGͨ������ص�������������DIAGͨ�����ӻ�Ͽ�ʱ����ص����ӿ�ע��ĺ�������CNend
*
* @attention None��
* @param  port_num   [IN] type #hi_u16��port number.
CNcomment:�˿ںš�CNend
* @param  is_connected  [IN] type #hi_bool��connection status.
CNcomment:����״̬��CNend
*
* @retval #0      Success.
* @retval #Other  Failure. For details, see hi_errno.h.
* @par Dependency:
*           @li hi_diag.h: Describes DIAG APIs.
CNcomment:�ļ���������DIAG��ؽӿڡ�CNend
* @see  None
* @since Hi3861_V100R001C00
 */
typedef hi_u32 (*hi_diag_connect_f)(hi_u16 port_num, hi_bool is_connected);

/**
* @ingroup  iot_dms
*
* Strcture of Channel interface object.
CNcomment:ͨ���ӿ�ʵ���ṹ��CNend
*/
#define HI_DMS_FRM_INTER_INFO1_SIZE (sizeof(hi_u8) + sizeof(hi_u8)) /* mmt, vt */
#define HI_DMS_FRM_INTER_INFO2_SIZE 4                             /* ���ÿ����ֶγ��� */
#define HI_DMS_INTER_INFO_SIZE      (HI_DMS_FRM_INTER_INFO1_SIZE + HI_DMS_FRM_INTER_INFO2_SIZE)

typedef struct {
    hi_u16 data_size;                          /**< Length of data element(Unit: type).
                                                  CNcomment: ���ݴ�С����ucData��ռ�ռ��С����λ��byte��CNend */
    hi_u8 inside_info[HI_DMS_INTER_INFO_SIZE]; /**< For internal use. CNcomment:�ڲ�ʹ��CNend */
    hi_u8 data[0];                             /**< Data. CNcomment:����CNend */
} hi_dms_chl_tx_data;

#define HI_DMS_CHL_FRAME_HRD_SIZE (sizeof(hi_dms_chl_tx_data))

typedef struct {
    hi_u32 id;  /* Specify the message id. */
    hi_u32 src_mod_id;
    hi_u32 dest_mod_id;
    hi_u32 data_size;  /* the data size in bytes. */
    hi_pvoid data;     /* Pointer to the data buffer. */
} hi_diag_layer_msg;

/**
* @ingroup  iot_diag
* @brief Callback function for handling diagnosis commands.
CNcommond:HSO�����ص�������CNend
*
* @par ����:
*           Callback function for handling diagnosis commands, that is, the function body for executing commands.
CNcomment:HSO�����ص��������������ִ�к����塣CNend
*
* @attention
*           @li If the returned value is not HI_ERR_CONSUMED, the DIAG framework automatically forwards
*               the returned value to the host. CNcomment:�������ֵ��ΪHI_ERR_CONSUMED��
���ʾ��DIAG����Զ�ֱ�ӽ�����ֵ�ظ���HSO��CNend
*           @li If the return value is HI_ERR_CONSUMED, it indicates that the user sends a response (local connection)
*               to the host through the hi_diag_send_ack_packet API. The DIAG framework does not automatically
*               respond to the host. CNcomment:�������ֵΪHI_ERR_CONSUMED��
���ʾ�û�ͨ��hi_diag_send_ack_packet�ӿڸ�HSOӦ�𣨱������ӣ���DIAG��ܲ��Զ���HSOӦ��CNend
*           @li The return value of the API cannot be HI_ERR_NOT_FOUND.
CNcomment:��ע��ӿڵķ���ֵ����ΪHI_ERR_NOT_FOUND��CNend
* @param  cmd_id          [IN] type #hi_u16��Command ID CNcomment:����ID��CNend
* @param  cmd_param       [IN] type #hi_pvoid��Pointer to the use input command.
CNcomment:�û���������ָ�롣CNend
* @param  cmd_param_size  [IN] type #hi_u16��Length of the command input by the user (unit:byte).
CNcomment:�û���������ȣ���λ��byte����CNend
* @param  option          [IN] type #hi_u8��#HI_DIAG_CMD_INSTANCE_LOCAL and #HI_DIAG_CMD_INSTANCE_IREMOTE are supported.
CNcomment:֧��ʹ��#HI_DIAG_CMD_INSTANCE_LOCAL��#HI_DIAG_CMD_INSTANCE_IREMOTE��CNend.
*
* @retval #0              Success
* @retval #Other            Failure. For details, see hi_errno.h
* @par Dependency:
*           @li hi_diag.h: Describes DIAG APIs.
CNcomment: �ļ���������DIAG��ؽӿڡ�CNend
* @see  None.
* @since Hi3861_V100R001C00
*/
typedef hi_u32 (*hi_diag_cmd_f)(hi_u16 cmd_id, hi_pvoid cmd_param, hi_u16 cmd_param_size, hi_u8 option);
/**
* @ingroup  iot_diag
* Command registration structure. The same callback function can be used within the command ID range.
CNcommand:����ע��ṹ�壬֧�ֱ�ע����ID��Χ��ʹ��ͬһ���ص�������CNend.
*
* If a single command is used, the maximum and minimum IDs are the same.
CNcommand:����������������С��д��ͬID�š�CNend
*/
typedef struct {
    hi_u16 min_id;           /**< Minimum DIAG ID, [0, 65535]. CNcomment:��С��DIAG ID��ȡֵ��Χ[0, 65535]�� CNend */
    hi_u16 max_id;           /**< Maximum DIAG ID, [0, 65535]. CNcomment:����DIAG ID��ȡֵ��Χ[0, 65535]�� CNend */
    hi_diag_cmd_f input_cmd; /**< This Handler is used to process the HSO command.
                                CNcomment:����HSO�������ں�����CNend */
} hi_diag_cmd_reg_obj;

/**
 * @ingroup  iot_diag
 * Local instance  -->HSO  Interaction command between the host software and the local station.
 CNcomment:����ʵ��  -->HSO  ��ʾ��λ������ͱ���վ���Ľ������� CNend
 */
#define HI_DIAG_CMD_INSTANCE_DEFAULT ((hi_u8)0)

/**
 * @ingroup  iot_diag
 * Local instance  -->HSO  Interaction command between the host software and the local station.
 CNcomment: ����ʵ��  -->HSO  ��ʾ��λ������ͱ���վ���Ľ������� CNend
 */
#define HI_DIAG_CMD_INSTANCE_LOCAL   HI_DIAG_CMD_INSTANCE_DEFAULT /* Local CMD.CNcomment:�������� CNend */
#define HI_DIAG_CMD_INSTANCE_IREMOTE 1 /* Remote CMD.CNcomment:Զ������ CNend */

#if defined(HAVE_PCLINT_CHECK)
#define hi_check_default_id(id) (id) /* Ϊ�˷���ʹ�ã�����ĺ궨�岻��PCLINT��� */
#else
#define hi_check_default_id(id) (((id) == 0) ? __LINE__ : (id))
#endif
#define hi_diag_log_msg_mk_id_e(id) hi_makeu32(((((hi_u16)(hi_check_default_id(id))) << 2) + 0), \
    HI_DIAG_LOG_MSG_FILE_ID)
#define hi_diag_log_msg_mk_id_w(id) hi_makeu32(((((hi_u16)(hi_check_default_id(id))) << 2) + 1), \
    HI_DIAG_LOG_MSG_FILE_ID)
#define hi_diag_log_msg_mk_id_i(id) hi_makeu32(((((hi_u16)(hi_check_default_id(id))) << 2) + 2), \
    HI_DIAG_LOG_MSG_FILE_ID)

#define HI_ND_SYS_BOOT_CAUSE_NORMAL        0x0 /* �������� */
#define HI_ND_SYS_BOOT_CAUSE_EXP           0x1 /* �쳣���� */
#define HI_ND_SYS_BOOT_CAUSE_WD            0x2 /* ���Ź����� */
#define HI_ND_SYS_BOOT_CAUSE_UPG_VERIFY    0x3 /* ������֤���� */
#define HI_ND_SYS_BOOT_CAUSE_UPG_FAIL      0x4 /* ����ʧ������ */
#define HI_ND_SYS_BOOT_CAUSE_UPG_BACK_FAIL 0x5 /* ��������ʧ������ */

#define CHANLLENGE_SALT_SIZE 16
/******************************DIAG������־ ST***********************************************/
#define HI_DIAG_LOG_OPT_LOCAL_REQ           1 /**< Local command request from the host to DIAG.
                                                 CNcomment:������������ ��λ��->DIAG CNend */
#define HI_DIAG_LOG_OPT_LOCAL_IND           2 /**< local response from DIAG to the host.
                                                 CNcomment: ����Ӧ�� DIAG ->��λ�� CNend */
#define HI_DIAG_LOG_OPT_LOCAL_ACK           3 /**< Local ACK from DIAG to the host.
                                                 CNcomment: ����ACK DIAG ->��λ�� CNend */

/**
 * @ingroup  iot_diag
 * Describes the command type transferred to the app layer.
 CNcomment: �������ݸ�Ӧ�ò���������͡�CNend
 */
typedef struct {
    /**< Option configuration, which is used to set the command as a local command or a remote
       * command. The value is a HI_DIAG_LOG_OPT_XXX macro such as #HI_DIAG_LOG_OPT_LOCAL_REQ.
       CNcomment: ѡ�����ã��������ô�����Ϊ���������Զ���������Ϣ��
       ȡֵΪHI_DIAG_LOG_OPT_XXX �� CNend */
    hi_u32 opt;
} hi_diag_log_ctrl;

/**
* @ingroup  iot_diag
* @brief  Callback function for notifying DIAG operations.
CNcomment:DIAG����֪ͨ�ص�������CNend
*
* @par ����:
*          Carbon copies data to the app layer by using a callback function in
*          the case of data interaction between the host and the board.
CNcomment: �ú������ڵ�HSO�뵥�������ݽ�������ʱ��������ͨ���ص��������͸�Ӧ�ò㡣CNend
*
* @attention �ޡ�
* @param  cmd_id       [IN] type #hi_u32��Command ID. CNcomend:����ID��CNend
* @param  buffer       [IN] type #hi_pvoid��Data pointer transferred to the app layer.
CNcomment:���ݸ�Ӧ�ò������ָ�롣CNend
* @param  buffer_size  [IN] type #hi_u16��Length of the data transferred to the app layer (unit: byte)
CNcomment:���ݸ�Ӧ�ò�����ݳ��ȣ���λ��byte����CNend
* @param  log_ctrl     [IN] type #hi_diag_log_ctrl*��Command type sent to the app layer
CNcomment:���ݸ�Ӧ�ò���������͡�CNend
*
* @retval #0             Success
* @retval #Other         Failure. For details, see hi_errno.h.
* @par Dependency:
*           @li hi_diag.h��Describes DIAG APIs. CNcomment:�ļ���������DIAG��ؽӿڡ�CNend
* @see  None
* @since Hi3861_V100R001C00
 */
typedef hi_void (*hi_diag_cmd_notify_f)(hi_u16 cmd_id, hi_pvoid buffer, hi_u16 buffer_size,
                                        hi_diag_log_ctrl *log_ctrl);
HI_END_HEADER
#endif  /* __HI_MDM_TYPES_H__ */
