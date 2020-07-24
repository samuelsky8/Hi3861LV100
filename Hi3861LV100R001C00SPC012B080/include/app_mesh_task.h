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
  1 其他头文件包含
*****************************************************************************/
/*****************************************************************************
  2 宏定义
*****************************************************************************/
/*****************************************************************************
  3 枚举定义
*****************************************************************************/
/*****************************************************************************
  4 全局变量声明
*****************************************************************************/
/*****************************************************************************
  5 消息头定义
*****************************************************************************/
/*****************************************************************************
  6 消息定义
*****************************************************************************/
#define ID_MSG_MESH_DEMO_BASE 0x100
typedef enum {
    ID_MSG_MESH_DEMO_STA_SCAN = (ID_MSG_MESH_DEMO_BASE + 1),     /* 触发sta扫描 */
    ID_MSG_MESH_DEMO_MESH_STA_SCAN,                     /* 触发mesh sta扫描 */
    ID_MSG_MESH_DEMO_SCAN_DONE,                         /* 扫描结束通知 */
    ID_MSG_MESH_DEMO_MESH_SCAN,                         /* 触发MESH扫描 */
    ID_MSG_MESH_DEMO_CONNECTED,                         /* sta关联上ap */
    ID_MSG_MESH_DEMO_DISCONNECTED,                      /* sta与ap去关联 */
    ID_MSG_MESH_DEMO_MESH_CONNECTED,                    /* Mesh关联上一个远端节点 */
    ID_MSG_MESH_DEMO_MESH_DISCONNECTED,                 /* Mesh一个远端节点去关联 */
    ID_MSG_MESH_DEMO_STA_CONNECTED,                     /* Mesh关联上一个sta */
    ID_MSG_MESH_DEMO_STA_DISCONNECTED,                  /* 一个sta去关联 */
    ID_MSG_MESH_DEMO_MBR_TO_MR,                         /* MBR退化成MR */
    ID_MSG_MESH_DEMO_DROP_TO_ROUTER,                    /* Mesh入网失败退化到关联路由器 */
    ID_MSG_MESH_ASSIGN_MBR_WAIT_TIMER                   /* 指定的MBR竞选失败等待下次竞选超时时间 */
}hi_mesh_msg_type;

typedef enum {
    HI_STA_SCAN,                                        /* 普通sta发起的扫描 */
    HI_MESH_STA_DISCONNECT_SCAN,                        /* Mesh STA断链状态发起的扫描 */
    HI_MESH_STA_CONNECTED_SCAN,                         /* Mesh STA关联状态发起的扫描 */
    HI_MESH_STA_FAKE_SCAN,                              /* 假启动MSTA发起的扫描 */
    HI_MESH_AP_SCAN,                                    /* Mesh AP发起的扫描 */
    HI_ROUTER_MSTA_SCAN,                                /* 关联路由器的MSTA发起的扫描 */

    HI_MESH_SCAN_BUTT
}hi_mesh_demo_scan_type;

typedef enum {
    HI_MESH_UNKNOWN,              /* 未知节点角色 */
    HI_MESH_MBR,                  /* 节点角色:MBR */
    HI_MESH_MR,                   /* 节点角色:MR */
    HI_MESH_MSTA,                 /* 节点角色:MSTA */

    HI_MESH_AUTO,                 /* 未指定节点角色(MBR/MR中选择) */

    HI_MESH_MBR_STA,              /* MBR的sta(未启动mesh ap) */
    HI_MESH_FAKE_MSTA,            /* 启动MG之前的FAKE MSTA */
    HI_MESH_ROUTER_MSTA,          /* 关联到路由器的MSTA */
    HI_MESH_NODE_TYPE_BUTT
}hi_mesh_node_type;

typedef enum {
    HI_MESH_OPEN,                       /* OPEN类型 */
    HI_MESH_AUTH,                       /* 加密类型 */

    HI_MESH_AUTH_TYPE_BUTT
}hi_mesh_auth_type;

typedef enum {
    HI_MESH_STA_DISCONNECT,                       /* mesh sta断链发起扫描 */
    HI_MESH_STA_CONNECTED,                        /* mesh sta关联状态发起扫描 */
    HI_MESH_ROUTER_MSTA_SCAN                      /* Router Msta发起的扫描 */
}hi_mesh_scan_type;

/*****************************************************************************
  7 STRUCT定义
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
    hi_u8 is_mbred;     /* 是否为备选MBR */
    hi_u8 mbr_miss_cnt; /* MBR丢失统计 */
}mesh_gate_statistic_info;
/* Mesh自动启动传入参数 */
typedef struct {
    char ssid[HI_WIFI_MAX_SSID_LEN + 1];      /**< SSID */
    hi_mesh_auth_type auth;                   /**< 认证类型，只支持HI_MESH_OPEN,HI_MESH_AUTH两种 */
    char key[HI_WIFI_AP_KEY_LEN + 1];         /**< 密码 */
    hi_u8 chan;                               /* 信道 */
    hi_mesh_node_type usr_config_role;        /* 用户设置的类型 */
}mesh_auto_start_config;
/* Mesh自动启动Timer集合 */
typedef struct {
    hi_u32 msta_scan_timer;                    /* Mesh STA定期扫描定时器 */
    hi_u32 mg_scan_timer;                      /* MG周期扫描定时器 */
    hi_u32 mbr_sta_scan_timer;                 /* MBR上的sta定期扫描定时器 */
    hi_u32 mbr_timeout_timer;                  /* MBR的超时定时器 */
    hi_u32 mesh_drop_timer;                    /* MESH自动组网模块的超时定时器 */
    hi_u8 mesh_drop_timer_is_work;             /* Mesh超时未入网定时器是否正在运行 */
    hi_u8  mbr_timeout_timer_is_create;        /* MBR的超时定时器是否注册 */
    hi_u32 mbr_assign_mbr_waiter_timer;       /* 用户指定节点角色为MBR，但竞选失败后的等待处理定时器 */
    hi_u8  mbr_assign_mbr_waiter_timer_is_create; /* 用户指定节点角色为MBR，但竞选失败后的等待定时器是否创建 */
}mesh_auto_start_timer;
typedef struct {
    mesh_auto_start_config mesh_config;     /* 路由器/Mesh id */
    mesh_auto_start_timer mesh_timer;       /* Mesh Auto start定时器 */
    hi_mesh_node_type mesh_current_role;
    mesh_gate_statistic_info mg_info;
    mesh_sta_conn_info sta_conn_info;
    hi_u8 conn_to_mbr;                      /* 标志节点是否直接连接到MBR */
    hi_u8 mg_need_rescan_mbr;               /* 标志节点是否需要重新扫描 */
    hi_u8 msta_need_change_bss;             /* 标志MSTA节点是否需要切换BSS */
    hi_u8 router_msta_conn_to_mesh;         /* 标记router msta是否是关联到Mesh节点 */
    hi_char rpl_ifname[WIFI_IFNAME_MAX_SIZE + 1];
    hi_u8 ifname_len;
    hi_s32 rpl_ctx;
    hi_wifi_mesh_scan_result_info *mesh_list;
    hi_wifi_ap_info *ap_list;
}mesh_mgmt_info;

/*****************************************************************************
  8 UNION定义
*****************************************************************************/
/*****************************************************************************
  9 OTHERS定义
*****************************************************************************/
/*****************************************************************************
  10 函数声明
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
