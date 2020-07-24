/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: app_mesh_task.h
 * Author: zhengbolu
 * Create: 2020-02-20
 */
#ifndef __AT_MESH_TASK_H__
#define __AT_MESH_TASK_H__

#ifdef LOSCFG_APP_MESH

#include "hi_io.h"
#include "hi_gpio.h"
#include "hi_wifi_mesh_api.h"
#include "hi_networking_api.h"
#include "hi_at.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif
/*****************************************************************************
  1 ����ͷ�ļ�����
*****************************************************************************/
/*****************************************************************************
  2 �궨��
*****************************************************************************/
/*****************************************************************************
  3 ö�ٶ���
*****************************************************************************/
/*****************************************************************************
  4 ȫ�ֱ�������
*****************************************************************************/
/*****************************************************************************
  5 ��Ϣͷ����
*****************************************************************************/
/*****************************************************************************
  6 ��Ϣ����
*****************************************************************************/
#define ID_MSG_MESH_DEMO_BASE 0x100
typedef enum {
    ID_MSG_MESH_DEMO_STA_SCAN = (ID_MSG_MESH_DEMO_BASE + 1),     /* ����staɨ�� */
    ID_MSG_MESH_DEMO_MESH_STA_SCAN,                     /* ����mesh staɨ�� */
    ID_MSG_MESH_DEMO_SCAN_DONE,                         /* ɨ�����֪ͨ */
    ID_MSG_MESH_DEMO_MESH_SCAN,                         /* ����MESHɨ�� */
    ID_MSG_MESH_DEMO_CONNECTED,                         /* sta������ap */
    ID_MSG_MESH_DEMO_DISCONNECTED,                      /* sta��apȥ���� */
    ID_MSG_MESH_DEMO_MESH_CONNECTED,                    /* Mesh������һ��Զ�˽ڵ� */
    ID_MSG_MESH_DEMO_MESH_DISCONNECTED,                 /* Meshһ��Զ�˽ڵ�ȥ���� */
    ID_MSG_MESH_DEMO_STA_CONNECTED,                     /* Mesh������һ��sta */
    ID_MSG_MESH_DEMO_STA_DISCONNECTED,                  /* һ��staȥ���� */
    ID_MSG_MESH_DEMO_MBR_TO_MR,                         /* MBR�˻���MR */
    ID_MSG_MESH_DEMO_DROP_TO_ROUTER,                    /* Mesh����ʧ���˻�������·���� */
    ID_MSG_MESH_ASSIGN_MBR_WAIT_TIMER                   /* ָ����MBR��ѡʧ�ܵȴ��´ξ�ѡ��ʱʱ�� */
}hi_mesh_msg_type;

typedef enum {
    HI_STA_SCAN,                                        /* ��ͨsta�����ɨ�� */
    HI_MESH_STA_DISCONNECT_SCAN,                        /* Mesh STA����״̬�����ɨ�� */
    HI_MESH_STA_CONNECTED_SCAN,                         /* Mesh STA����״̬�����ɨ�� */
    HI_MESH_STA_FAKE_SCAN,                              /* ������MSTA�����ɨ�� */
    HI_MESH_AP_SCAN,                                    /* Mesh AP�����ɨ�� */
    HI_ROUTER_MSTA_SCAN,                                /* ����·������MSTA�����ɨ�� */

    HI_MESH_SCAN_BUTT
}hi_mesh_demo_scan_type;

typedef enum {
    HI_MESH_UNKNOWN,              /* δ֪�ڵ��ɫ */
    HI_MESH_MBR,                  /* �ڵ��ɫ:MBR */
    HI_MESH_MR,                   /* �ڵ��ɫ:MR */
    HI_MESH_MSTA,                 /* �ڵ��ɫ:MSTA */

    HI_MESH_AUTO,                 /* δָ���ڵ��ɫ(MBR/MR��ѡ��) */

    HI_MESH_MBR_STA,              /* MBR��sta(δ����mesh ap) */
    HI_MESH_FAKE_MSTA,            /* ����MG֮ǰ��FAKE MSTA */
    HI_MESH_ROUTER_MSTA,          /* ������·������MSTA */
    HI_MESH_NODE_TYPE_BUTT
}hi_mesh_node_type;

typedef enum {
    HI_MESH_OPEN,                       /* OPEN���� */
    HI_MESH_AUTH,                       /* �������� */

    HI_MESH_AUTH_TYPE_BUTT
}hi_mesh_auth_type;

typedef enum {
    HI_MESH_STA_DISCONNECT,                       /* mesh sta��������ɨ�� */
    HI_MESH_STA_CONNECTED,                        /* mesh sta����״̬����ɨ�� */
    HI_MESH_ROUTER_MSTA_SCAN                      /* Router Msta�����ɨ�� */
}hi_mesh_scan_type;

/*****************************************************************************
  7 STRUCT����
*****************************************************************************/
typedef struct {
    hi_u8 conn_num;
    hi_u8 chl;
}mg_conn_info;
typedef struct {
    hi_wifi_conn_status conn_status;
    hi_u8 chnl;
    hi_u8 bssid[HI_WIFI_MAC_LEN];
    char ssid[HI_WIFI_MAX_SSID_LEN + 1];
}mesh_sta_conn_info;
typedef struct {
    hi_u8 conn_num;
    hi_u8 conn_sta_num;
    hi_u8 conn_mg_num;
    hi_u8 is_mbred;     /* �Ƿ�Ϊ��ѡMBR */
    hi_u8 mbr_miss_cnt; /* MBR��ʧͳ�� */
}mesh_gate_statistic_info;
/* Mesh�Զ������������ */
typedef struct {
    char ssid[HI_WIFI_MAX_SSID_LEN + 1];      /**< SSID */
    hi_mesh_auth_type auth;                   /**< ��֤���ͣ�ֻ֧��HI_MESH_OPEN,HI_MESH_AUTH���� */
    char key[HI_WIFI_AP_KEY_LEN + 1];         /**< ���� */
    hi_u8 chan;                               /* �ŵ� */
    hi_mesh_node_type usr_config_role;        /* �û����õ����� */
}mesh_auto_start_config;
/* Mesh�Զ�����Timer���� */
typedef struct {
    hi_u32 msta_scan_timer;                    /* Mesh STA����ɨ�趨ʱ�� */
    hi_u32 mg_scan_timer;                      /* MG����ɨ�趨ʱ�� */
    hi_u32 mbr_sta_scan_timer;                 /* MBR�ϵ�sta����ɨ�趨ʱ�� */
    hi_u32 mbr_timeout_timer;                  /* MBR�ĳ�ʱ��ʱ�� */
    hi_u32 mesh_drop_timer;                    /* MESH�Զ�����ģ��ĳ�ʱ��ʱ�� */
    hi_u8 mesh_drop_timer_is_work;             /* Mesh��ʱδ������ʱ���Ƿ��������� */
    hi_u8  mbr_timeout_timer_is_create;        /* MBR�ĳ�ʱ��ʱ���Ƿ�ע�� */
    hi_u32 mbr_assign_mbr_waiter_timer;       /* �û�ָ���ڵ��ɫΪMBR������ѡʧ�ܺ�ĵȴ�����ʱ�� */
    hi_u8  mbr_assign_mbr_waiter_timer_is_create; /* �û�ָ���ڵ��ɫΪMBR������ѡʧ�ܺ�ĵȴ���ʱ���Ƿ񴴽� */
}mesh_auto_start_timer;
typedef struct {
    mesh_auto_start_config mesh_config;     /* ·����/Mesh id */
    mesh_auto_start_timer mesh_timer;       /* Mesh Auto start��ʱ�� */
    hi_mesh_node_type mesh_current_role;
    mesh_gate_statistic_info mg_info;
    mesh_sta_conn_info sta_conn_info;
    hi_u8 conn_to_mbr;                      /* ��־�ڵ��Ƿ�ֱ�����ӵ�MBR */
    hi_u8 mg_need_rescan_mbr;               /* ��־�ڵ��Ƿ���Ҫ����ɨ�� */
    hi_u8 msta_need_change_bss;             /* ��־MSTA�ڵ��Ƿ���Ҫ�л�BSS */
    hi_u8 router_msta_conn_to_mesh;         /* ���router msta�Ƿ��ǹ�����Mesh�ڵ� */
    hi_char rpl_ifname[WIFI_IFNAME_MAX_SIZE + 1];
    hi_u8 ifname_len;
    hi_s32 rpl_ctx;
    hi_wifi_mesh_scan_result_info *mesh_list;
    hi_wifi_ap_info *ap_list;
}mesh_mgmt_info;

/*****************************************************************************
  8 UNION����
*****************************************************************************/
/*****************************************************************************
  9 OTHERS����
*****************************************************************************/
/*****************************************************************************
  10 ��������
*****************************************************************************/
hi_s32 hi_mbr_start(hi_void);
hi_u32 hi_mr_start(hi_void);
hi_void hi_msta_start(hi_void);
hi_void hi_mesh_start_fake_msta(hi_void);
hi_s32 hi_mesh_msta_stop(hi_void);
hi_s32 hi_mesh_mr_stop(hi_void);
hi_s32 hi_mesh_mbr_stop(hi_void);
hi_s32 hi_mesh_mbr_sta_stop(hi_void);
hi_u32 hi_mesh_get_mesh_demo_queue_id(hi_void);
hi_s32 hi_wifi_mesh_set_router_rssi_threshold(hi_s32 router_rssi);
hi_s32 hi_wifi_mesh_get_router_rssi_threshold(hi_void);
hi_s32 hi_mesh_set_mesh_autonetwork_bw_value(hi_wifi_bw bw);
hi_u8 hi_mesh_get_mesh_autonetwork_bw_value(hi_void);
hi_u32 mesh_demo_task_init(hi_void);
hi_u32 mesh_demo_task_exit(hi_void);
hi_u32 hi_mesh_join_network(mesh_auto_start_config mesh_auto_start);
hi_u32 hi_mesh_exit_network(hi_void);
hi_void notify_quit_task(hi_void);
hi_void mesh_demo_delete_queue(hi_void);
hi_void mesh_demo_clear_queue(hi_void);
hi_void hi_mesh_set_mesh_stop(hi_u8 value);
#endif

#ifdef __cplusplus
#if __cplusplus
    }
#endif
#endif

#endif /* end of app_mesh_task.h */
