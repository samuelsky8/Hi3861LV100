/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: WAL layer external API interface implementation.
 * Author: Hisilicon
 * Create: 2019-11-11
 */

#include <hi_stdlib.h>
#include <hi_at.h>
#include "at.h"
#include "at_general.h"
#include <hi_time.h>
#include <hi_mem.h>
#include <hi_sal.h>
#include <hi_sal_nv.h>
#include <hi_nv.h>
#include <hi_cpu.h>
#include "lwip/netifapi.h"
#include "hi_config.h"
#include "lwip/api_shell.h"
#ifdef CONFIG_IPERF_SUPPORT
#include "iperf.h"
#endif
#include "sal_common.h"
#include <hi_os_stat.h>
#include <at_cmd.h>
#include <hi_wifi_api.h>
#include <hi_crash.h>
#ifdef CONFIG_SIGMA_SUPPORT
#include "hi_wifitest.h"
#endif
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "lwip/sockets.h"
#include <hi_mux.h>
#include <hi_task.h>
#include <hi_reset.h>
#include <hi_ver.h>
#include <hi_uart.h>
#include <cpup_diag_dfx.h>

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

#define HI_AT_VER_FULL_PRODUCT_NAME_MAX_SIZE 100


#ifdef CONFIG_IPERF_SUPPORT
HI_EXTERN UINT32 cmd_iperf(hi_s32 argc, const hi_char **argv);
#endif

#define IP_LINK_ID_MAX            8           /* 最多支持8个link,linkid 0-7 */
#define IP_TCP_SERVER_LISTEN_NUM  4           /* TCP 服务器能接收的最大客户端个数 */
#define IP_RESV_BUF_LEN           1024        /* IP收包buff */
#define IP_SEND_BUF_LEN           1024        /* IP发包buff，与AT_DATA_MAX_LEN 值要保持一致 */
#define IP_MUX_WAIT_TIME          HI_SYS_WAIT_FOREVER  /* 互斥锁时间 */
#define PRINT_SIZE_MAX            128
#define IP_UDP_LINK_MAX           4           /* 手动创建UDP link 最大个数 */

typedef struct {
    hi_s32 sfd;
    hi_u8 link_stats;
    hi_u8 link_res;       /* 标识当前连接是用户手动创建还是对端连接时自动创建 */
    hi_u8 ip_protocol;
    hi_u8 res;
} ip_conn_ctl_stru;

typedef struct {
    hi_s32 sfd;
    hi_u8 link_stats;
    hi_u8 res[3]; /* 3 4字节对齐补位 */
} ip_listen_socket_stru;

typedef enum {
    IP_NULL = 0,
    IP_TCP  = 1,
    IP_UDP  = 2,

    IP_PROTOCAL_BUTT
} ip_protocol ;
typedef hi_u8 ip_protocol_uint8;

typedef enum {
    IP_LINK_RES_INIT = 0, /* 初始值 */
    IP_LINK_MANUAL  = 1,  /* 手动创建link */
    IP_LINK_AUTO  = 2,   /* 自动创建link */

    IP_LINK_RES_BUTT
} ip_link_res ;
typedef hi_u8 ip_link_res_uint8;

typedef enum {
    IP_LINK_ID_IDLE = 0,      /* 空闲态 */
    IP_LINK_WAIT_RESV,        /* 等待接收数据 */
    IP_LINK_WAIT_CLOSE,       /* 执行异常触发关闭 */
    IP_LINK_USER_CLOSE,       /* 用户手动关闭 */
    IP_LINK_SERVER_LISTEN,    /* SERVER 监听态 */

    IP_LINK_STAUS_BUTT
} ip_link_stats ;
typedef hi_u8 ip_link_stats_uint8;

static ip_conn_ctl_stru g_ip_link_ctl[IP_LINK_ID_MAX];
static hi_s8 g_ip_task_exit;
static ip_listen_socket_stru g_listen_fd;
static hi_s32 g_ip_taskid = -1;
static hi_s8 g_link_id = -1;
static in_addr_t g_peer_ipaddr; /* 对端IP地址 */
static hi_u16 g_peer_port;      /* 对端端口 */
static hi_u32 g_ip_mux_id;      /* 多进程全局变量操作要加锁 */

hi_u32 at_exe_at_cmd(void)
{
    AT_RESPONSE_OK;
    return HI_ERR_SUCCESS;
}

hi_u32 at_task_show(void)
{
    TSK_INFO_S* ptask_info = HI_NULL;

    hi_u32 i = 0;

    ptask_info = (TSK_INFO_S*)hi_malloc(HI_MOD_ID_SAL_DFX, sizeof(TSK_INFO_S));
    if (ptask_info == HI_NULL) {
        hi_free(HI_MOD_ID_SAL_DFX, ptask_info);
        return HI_ERR_MALLOC_FAILUE;
    }

    hi_at_printf("task_info:\r\n");
    for (i = 0; i < g_taskMaxNum; i++) {
        memset_s(ptask_info, sizeof(TSK_INFO_S), 0, sizeof(TSK_INFO_S));
        hi_u32 ret = LOS_TaskInfoGet(i, ptask_info);
        if (ret == HI_ERR_SUCCESS) {
            hi_at_printf("%s,id=%d,status=%hd,pri=%hd,size=0x%x,cur_size=0x%x,peak_size=0x%x\r\n",
                         ptask_info->acName, ptask_info->uwTaskID, ptask_info->usTaskStatus, ptask_info->usTaskPrio,
                         ptask_info->uwStackSize, ptask_info->uwCurrUsed, ptask_info->uwPeakUsed);
        }
    }

    hi_free(HI_MOD_ID_SAL_DFX, ptask_info);
    return HI_ERR_SUCCESS;
}

hi_u32 at_query_sysinfo_cmd(hi_void)
{
    hi_os_resource_use_stat os_resource_stat = {0};
    hi_mdm_mem_info mem_inf = {0};

    (hi_void)hi_os_get_resource_status(&os_resource_stat);
    (hi_void)hi_mem_get_sys_info(&mem_inf);

    hi_at_printf("+SYSINFO:\r\n");
    hi_at_printf("mem:\r\n");
    hi_at_printf("total=%d,", mem_inf.total);
    hi_at_printf("used=%d,", mem_inf.used);
    hi_at_printf("free=%d,", mem_inf.free);
    hi_at_printf("peek_size=%d\r\n", mem_inf.peek_size);
    hi_at_printf("os_resource:\r\n");
    hi_at_printf("timer_usage=%d,", os_resource_stat.timer_usage);
    hi_at_printf("task_usage=%d,", os_resource_stat.task_usage);
    hi_at_printf("sem_usage=%d,", os_resource_stat.sem_usage);
    hi_at_printf("queue_usage=%d,", os_resource_stat.queue_usage);
    hi_at_printf("mux_usage=%d,", os_resource_stat.mux_usage);
    hi_at_printf("event_usage=%d\r\n", os_resource_stat.event_usage);

    hi_u32 ret = at_task_show();
    if (ret != HI_ERR_SUCCESS) {
        return ret;
    }
    hi_at_printf("cpup:\r\n");
    cmd_get_cpup(0, HI_NULL);
    sal_show_run_time();

    AT_RESPONSE_OK;

    return HI_ERR_SUCCESS;
}

hi_u32 at_query_ver_cmd(hi_void)
{
    hi_char soft_ver[HI_AT_VER_FULL_PRODUCT_NAME_MAX_SIZE];
    if (sprintf_s(soft_ver, HI_AT_VER_FULL_PRODUCT_NAME_MAX_SIZE, "+CSV:%s\r\n",
        hi_get_sdk_version()) == -1) {
        return HI_ERR_FAILURE;
    }

    hi_at_printf("%s", soft_ver);
    AT_RESPONSE_OK;

    return HI_ERR_SUCCESS;
}

hi_void at_exe_reset_cmd(hi_void)
{
    AT_RESPONSE_OK;
    hi_watchdog_disable();

    hi_udelay(3000); /* 延时3000us, 待AT_RESPONSE_OK打印结束 */
    hi_hard_reboot(HI_SYS_REBOOT_CAUSE_CMD);
}

hi_u32 at_setup_reset_cmd(hi_s32 argc, const hi_char *argv[])
{
    hi_u32 delay;
    if ((argc != 1) || (argv[0] == HI_NULL)) {
        return HI_ERR_FAILURE;
    }

    if (integer_check(argv[0]) != HI_ERR_SUCCESS) {
        return HI_ERR_FAILURE;
    }

    hi_watchdog_disable();
    delay = strtoul((const hi_char*)argv[0], NULL, 10); /* 0:命令1 10:10进制 */
    hi_at_printf("+RST:%u\r\n", delay);
    hi_udelay(delay);

    AT_RESPONSE_OK;
    hi_udelay(3000); /* 延时3000us, 待AT_RESPONSE_OK打印结束 */
    hi_hard_reboot(HI_SYS_REBOOT_CAUSE_CMD);

    return HI_ERR_SUCCESS;
}

hi_u32 at_exe_help_cmd(void)
{
    at_cmd_func_list *cmd_list = at_get_list();
    hi_u32 i = 0;
    hi_u32 cnt = 0;

    hi_at_printf("+HELP:\r\n");
    for (i = 0; i < AT_CMD_LIST_NUM; i++) {
        hi_u16 j = 0;

        for (j = 0; j < cmd_list->at_cmd_num[i]; j++) {
            at_cmd_func *cmd_func = (at_cmd_func *) ((cmd_list->at_cmd_list[i] + j));

            hi_at_printf("AT%-16s ", cmd_func->at_cmd_name);
            cnt++;
            if (cnt % 4 == 0) {  /* 每4个换行 */
                hi_at_printf("\r\n");
            }
        }
    }

    AT_ENTER;
    AT_RESPONSE_OK;
    return HI_ERR_SUCCESS;
}

/*****************************************************************************
 功能描述  :设置mac地址
*****************************************************************************/
hi_u32 cmd_set_macaddr(hi_s32 argc, const hi_char* argv[])
{
    hi_uchar mac_addr[6]; /* 6 mac len */

    if (argc != 1) {
        return HI_ERR_FAILURE;
    }
    if (at_param_null_check(argc, argv) == HI_ERR_FAILURE) {
        return HI_ERR_FAILURE;
    }

    if (argv[0][17] != '\0') { /* 17 mac string len */
        return HI_ERR_FAILURE;
    }

    hi_u32 ret = cmd_strtoaddr(argv[0], mac_addr, 6); /* 6 mac len */
    if (ret != HI_ERR_SUCCESS) {
        return HI_ERR_FAILURE;
    }

    if (hi_wifi_set_macaddr((hi_char*)mac_addr, 6) != 0) { /* 6 mac len */
        return HI_ERR_FAILURE;
    }
    hi_at_printf("OK\r\n");
    return HI_ERR_SUCCESS;
}

/*****************************************************************************
 功能描述  :设置mac地址
*****************************************************************************/
hi_u32 cmd_get_macaddr(hi_s32 argc, const hi_char* argv[])
{
    hi_uchar mac_addr[6] = {0}; /* 6 mac len */
    hi_unref_param(argc);
    hi_unref_param(argv);

    if (hi_wifi_get_macaddr((hi_char*)mac_addr, 6) != HI_ERR_SUCCESS) { /* 6 mac len */
        return HI_ERR_FAILURE;
    }
    hi_at_printf("+MAC:" AT_MACSTR "\r\n", at_mac2str(mac_addr));
    hi_at_printf("OK\r\n");

    return HI_ERR_SUCCESS;
}

#ifdef CONFIG_IPERF_SUPPORT
hi_u32 at_iperf(hi_s32 argc, const hi_char **argv)
{
    if (at_param_null_check(argc, argv) == HI_ERR_FAILURE) {
        return HI_ERR_FAILURE;
    }
    if (cmd_iperf(argc, argv) == 0) {
        return HI_ERR_SUCCESS;
    }

    return HI_ERR_FAILURE;
}
#endif

hi_u32 at_ping(hi_s32 argc, const hi_char **argv)
{
    if (at_param_null_check(argc, argv) == HI_ERR_FAILURE) {
            return HI_ERR_FAILURE;
    }
    if (osShellPing(argc, argv) == LOS_OK) {
        return HI_ERR_SUCCESS;
    }

    return HI_ERR_FAILURE;
}

hi_u32 at_ping6(hi_s32 argc, const hi_char **argv)
{
    if (at_param_null_check(argc, argv) == HI_ERR_FAILURE) {
        return HI_ERR_FAILURE;
    }
    if (osShellPing6(argc, argv) == LOS_OK) {
        return HI_ERR_SUCCESS;
    }

    return HI_ERR_FAILURE;
}

hi_u32 at_dns(hi_s32 argc, const hi_char **argv)
{
    if (at_param_null_check(argc, argv) == HI_ERR_FAILURE) {
            return HI_ERR_FAILURE;
    }
    if (osShellDns(argc, argv) == LOS_OK) {
        return HI_ERR_SUCCESS;
    }

    return HI_ERR_FAILURE;
}

hi_u32 at_show_dns(hi_s32 argc, hi_char **argv)
{
    hi_unref_param(argc);
    hi_unref_param(argv);
    if (osShellshowDns() == LOS_OK) {
        return HI_ERR_SUCCESS;
    }

    return HI_ERR_FAILURE;
}

hi_u32 at_netstat(hi_s32 argc, hi_char **argv)
{
    if (osShellNetstat(argc, argv) == LOS_OK) {
        return HI_ERR_SUCCESS;
    }

    return HI_ERR_FAILURE;
}

hi_u32 at_setup_dhcp(hi_s32 argc, const hi_char **argv)
{
    hi_s32 ret = 0;
    struct netif *netif_p = NULL;

    if (at_param_null_check(argc, argv) == HI_ERR_FAILURE) {
        return HI_ERR_FAILURE;
    }

    if (argc != 2) { /* at+dhcp cmd length equl 2 */
        return HI_ERR_FAILURE;
    }

    netif_p = netifapi_netif_find(argv[0]);
    if (netif_p == NULL) {
        return HI_ERR_FAILURE;
    }

    if (strcmp(argv[1], "1") == 0) {
        ret = netifapi_dhcp_start(netif_p);
    } else if (strcmp(argv[1], "0") == 0) {
        ret = netifapi_dhcp_stop(netif_p);
    } else if (strcmp(argv[1], "2") == 0) {
        dhcp_clients_info_show(netif_p);
        ret = LOS_OK;
    } else {
        return HI_ERR_FAILURE;
    }
    if (ret == LOS_OK) {
        hi_at_printf("OK\r\n");
    }

    return ret;
}

hi_u32 at_setup_dhcps(hi_s32 argc, const hi_char **argv)
{
    hi_s32 ret = 0;
    struct netif *netif_p = NULL;

    if (at_param_null_check(argc, argv) == HI_ERR_FAILURE) {
        return HI_ERR_FAILURE;
    }

    if (argc != 2) { /* at+dhcps cmd length equl 2 */
        return HI_ERR_FAILURE;
    }

    netif_p = netifapi_netif_find(argv[0]);
    if (netif_p == NULL) {
        return HI_ERR_FAILURE;
    }
    if (ip_addr_isany_val(netif_p->ip_addr)) {
        hi_at_printf("Please set ip address for dhcp server\r\n");
        return HI_ERR_FAILURE;
    }
    if (strcmp(argv[1], "1") == 0) {
        ret = netifapi_dhcps_start(netif_p, NULL, 0);
    } else if (strcmp(argv[1], "0") == 0) {
        ret = netifapi_dhcps_stop(netif_p);
    } else if (strcmp(argv[1], "2") == 0) {
        dhcps_info_show(netif_p);
        ret = LOS_OK;
    } else {
        return HI_ERR_FAILURE;
    }

    if (ret == LOS_OK) {
        hi_at_printf("OK\r\n");
    }

    return ret;
}

hi_u32 at_get_dump(hi_s32 argc, const hi_char **argv)
{
    hi_u32 ret;
    hi_unref_param(argc);
    hi_unref_param(argv);
    hi_syserr_info* info = hi_malloc(HI_MOD_ID_SAL_DFX, sizeof(hi_syserr_info));
    if (info == HI_NULL) {
        return HI_ERR_MALLOC_FAILUE;
    }

    ret = hi_syserr_get_at_printf(info);
    if (ret == HI_ERR_SYSERROR_NOT_FOUND) {
        hi_at_printf("No crash dump found!\n");
        hi_at_printf("OK\r\n");
        ret = HI_ERR_SUCCESS;
    } else if (ret == HI_ERR_SUCCESS) {
        hi_at_printf("OK\r\n");
        ret = HI_ERR_SUCCESS;
    }
    hi_free(HI_MOD_ID_SAL_DFX, info);

    return ret;
}

hi_u32 lwip_ifconfig_check(hi_s32 argc, const hi_char **argv)
{
    if ((argc == 0) || (argc == 1)) {
        return HI_ERR_SUCCESS;
    } else if (argc == 2) { /* 2个命令参数场景 */
        if ((strcmp("up", argv[1]) == 0) || (strcmp("down", argv[1]) == 0)) {
            return HI_ERR_SUCCESS;
        } else {
            return HI_ERR_FAILURE;
        }
    } else if (argc == 6) { /* 6个命令参数场景 */
        if ((strcmp("netmask", argv[2]) == 0) && (strcmp("gateway", argv[4]) == 0) && /* 2/4:配置netmask和gateway */
            (strcmp("inet", argv[1]) != 0) && (strcmp("inet6", argv[1]) != 0)) {
            return HI_ERR_SUCCESS;
        } else {
            return HI_ERR_FAILURE;
        }
    } else {
        return HI_ERR_FAILURE;
    }
}

hi_u32 at_lwip_ifconfig(hi_s32 argc, const hi_char **argv)
{
    ip4_addr_t loop_ipaddr, loop_netmask, loop_gw;
    if (at_param_null_check(argc, argv) == HI_ERR_FAILURE) {
        return HI_ERR_FAILURE;
    }

    hi_u32 ret = lwip_ifconfig_check(argc, argv);
    if (ret != HI_ERR_SUCCESS) {
        return HI_ERR_FAILURE;
    }

    if (argc == 2) { /* 2:参数个数 */
        struct netif *netif = netifapi_netif_find(argv[0]);
        if (netif == HI_NULL) {
            return HI_ERR_FAILURE;
        }

        if (strcmp(argv[1], "down") == 0) {
            (void)netifapi_netif_set_down(netif);
            (void)netifapi_netif_set_link_down(netif);
            (void)netifapi_netif_set_addr(netif, HI_NULL, HI_NULL, HI_NULL);
            for (hi_u8 index = 0; index < LWIP_IPV6_NUM_ADDRESSES; index++) {
                (void)netifapi_netif_rmv_ip6_address(netif, &netif->ip6_addr[index]);
            }
        } else if (strcmp(argv[1], "up") == 0) {
            (void)netifapi_netif_set_link_up(netif);
            if ((strcmp(argv[0], DEFAULT_IFNAME_AP) == 0) || (strcmp(argv[0], DEFAULT_IFNAME_MESH) == 0)) {
                (void)netifapi_netif_set_up(netif);
                (hi_void)netifapi_netif_add_ip6_linklocal_address(netif, HI_TRUE);
            } else if (strcmp(argv[0], DEFAULT_IFNAME_LOCALHOST) == 0) {
                IP4_ADDR(&loop_gw, 127, 0, 0, 1);       /* gateway 127.0.0.1 */
                IP4_ADDR(&loop_ipaddr, 127, 0, 0, 1);   /* ipaddr 127.0.0.1 */
                IP4_ADDR(&loop_netmask, 255, 0, 0, 0);  /* netmask 255.0.0.0 */
                (void)netifapi_netif_set_addr(netif, &loop_ipaddr, &loop_netmask, &loop_gw);
                (void)netifapi_netif_set_up(netif);
            }
        }
        hi_at_printf("OK\r\n");
        return HI_ERR_SUCCESS;
    } else {
        ret = lwip_ifconfig(argc, argv);
        if (ret == 0) {
            return HI_ERR_SUCCESS;
        } else if (ret == 3) { /* 3:up down 执行成功 */
            hi_at_printf("OK\r\n");
            return HI_ERR_SUCCESS;
        }
        return HI_ERR_FAILURE;
    }
}

#ifdef CONFIG_SIGMA_SUPPORT
hi_u32 at_sigma_start(hi_s32 argc, const hi_char **argv)
{
    hi_unref_param(argc);
    hi_unref_param(argv);

    if (hi_sigma_init() != HI_ERR_SUCCESS) {
        return HI_ERR_FAILURE;
    }

    hi_at_printf("OK\r\n");
    return HI_ERR_SUCCESS;
}
#endif

static hi_void ip_link_release(hi_u8 link_id)
{
    closesocket(g_ip_link_ctl[link_id].sfd);
    g_ip_link_ctl[link_id].sfd = -1;
    g_ip_link_ctl[link_id].link_stats = IP_LINK_ID_IDLE;
    g_ip_link_ctl[link_id].link_res = IP_LINK_RES_INIT;
    g_ip_link_ctl[link_id].ip_protocol = IP_NULL;
}

static hi_u32 ip_is_all_link_idle(hi_void)
{
    int i;
    hi_mux_pend(g_ip_mux_id, IP_MUX_WAIT_TIME);
    for (i = 0; i < IP_LINK_ID_MAX; i++) {
        if (g_ip_link_ctl[i].link_stats != IP_LINK_ID_IDLE) {
            hi_mux_post(g_ip_mux_id);
            return HI_ERR_FAILURE;
        }
    }
    hi_mux_post(g_ip_mux_id);
    return HI_ERR_SUCCESS;
}

static hi_void ip_monitor_link_close(hi_void)
{
    hi_u8 i;
    hi_mux_pend(g_ip_mux_id, IP_MUX_WAIT_TIME);
    for (i = 0; i < IP_LINK_ID_MAX; i++) {
        if (g_ip_link_ctl[i].link_stats == IP_LINK_WAIT_CLOSE) {
            hi_at_printf("link %d CLOSED\r\n", i);
            ip_link_release(i);
        } else if (g_ip_link_ctl[i].link_stats == IP_LINK_USER_CLOSE) {
            hi_at_printf("link %d CLOSED\r\n", i);
            ip_link_release(i);
            /* 用户手动关闭link需要打印OK作为命令返回 */
            hi_at_printf("OK\r\n");
        }
    }

    if (g_listen_fd.link_stats == IP_LINK_WAIT_CLOSE) {
        closesocket(g_listen_fd.sfd);
        g_listen_fd.sfd = -1;
        g_listen_fd.link_stats = IP_LINK_ID_IDLE;
    } else if (g_listen_fd.link_stats == IP_LINK_USER_CLOSE) {
        closesocket(g_listen_fd.sfd);
        g_listen_fd.sfd = -1;
        g_listen_fd.link_stats = IP_LINK_ID_IDLE;
        /* 用户手动关闭link需要打印OK作为命令返回 */
        hi_at_printf("OK\r\n");
    }
    hi_mux_post(g_ip_mux_id);
}

static hi_void ip_set_monitor_socket(fd_set *read_set, hi_s32 *sfd_max)
{
    hi_s32 sfd_max_inter = 0;
    hi_u8 i;
    hi_mux_pend(g_ip_mux_id, IP_MUX_WAIT_TIME);
    for (i = 0; i < IP_LINK_ID_MAX; i++) {
        if (g_ip_link_ctl[i].link_stats == IP_LINK_WAIT_RESV) {
            FD_SET(g_ip_link_ctl[i].sfd, read_set);
            if (g_ip_link_ctl[i].sfd > sfd_max_inter) {
                sfd_max_inter = g_ip_link_ctl[i].sfd;
            }
        }
    }
    if (g_listen_fd.link_stats == IP_LINK_SERVER_LISTEN) {
        FD_SET(g_listen_fd.sfd, read_set);
        if (g_listen_fd.sfd > sfd_max_inter) {
            sfd_max_inter = g_listen_fd.sfd;
        }
    }
    *sfd_max = sfd_max_inter;
    hi_mux_post(g_ip_mux_id);

    return;
}

static hi_u32 ip_ip_resv_show_msg(hi_u8 link_id)
{
    struct sockaddr_in cln_addr = {0};
    socklen_t cln_addr_len = (socklen_t)sizeof(cln_addr);
    hi_u32 print_len = 0;
    hi_s32 ret;

    hi_char *ip_buffer = (hi_char*)malloc(IP_RESV_BUF_LEN + 1);
    if (ip_buffer == HI_NULL) {
        printf("{ip_ip_resv_output:ip buffer malloc fail}\r\n");
        return HI_ERR_FAILURE;
    }

    /* 规则6.6: 禁止使用内存操作类危险函数 例外场景(3)从堆中分配内存后，赋予初值 */
    memset_s(ip_buffer, IP_RESV_BUF_LEN + 1, 0, IP_RESV_BUF_LEN + 1);
    errno = 0;
    ret = recvfrom(g_ip_link_ctl[link_id].sfd, ip_buffer, IP_RESV_BUF_LEN, 0,
        (struct sockaddr *)&cln_addr, (socklen_t *)&cln_addr_len);
    if (ret < 0) {
        hi_at_printf("link %d RESV FAIL\r\n", link_id);
        if ((errno != EINTR) && (errno != EAGAIN)) {
            g_ip_link_ctl[link_id].link_stats = IP_LINK_WAIT_CLOSE;
        }
        free(ip_buffer);
        return HI_ERR_FAILURE;
    } else if (ret == 0) {
        g_ip_link_ctl[link_id].link_stats = IP_LINK_WAIT_CLOSE;
        free(ip_buffer);
        return HI_ERR_FAILURE;
    }

    if (ret < PRINT_SIZE_MAX) {
        hi_at_printf("\r\n+IPD,%d,%d,%s,%d:%s", link_id, ret, inet_ntoa(cln_addr.sin_addr), htons(cln_addr.sin_port),
            ip_buffer);
    } else if ((ret >= PRINT_SIZE_MAX) && (ret <= IP_RESV_BUF_LEN)) {
        hi_at_printf("\r\n+IPD,%d,%d,%s,%d:", link_id, ret, inet_ntoa(cln_addr.sin_addr), htons(cln_addr.sin_port));
        do {
            char print_out_buff[PRINT_SIZE_MAX] = {0};
            if ((memset_s(print_out_buff, sizeof(print_out_buff), 0x0, sizeof(print_out_buff)) != EOK) ||
                (memcpy_s(print_out_buff, sizeof(print_out_buff) - 1, ip_buffer + print_len,
                    sizeof(print_out_buff)-1) != EOK)) {
                printf("{ip_ip_resv_output: print_out_buff memset_s/memcpy_s fail\r\n}");
            }
            hi_at_printf("%s", print_out_buff);

            ret -= sizeof(print_out_buff) - 1;
            print_len += sizeof(print_out_buff) - 1;
        } while (ret >= (PRINT_SIZE_MAX - 1));

        if (ret > 0) {
            hi_at_printf("%s", ip_buffer + print_len);
        }
    }
    free(ip_buffer);
    return HI_ERR_SUCCESS;
}

static hi_void ip_ip_resv_output(const fd_set *read_set)
{
    hi_u8 link_id;

    hi_mux_pend(g_ip_mux_id, IP_MUX_WAIT_TIME);
    for (link_id = 0; link_id < IP_LINK_ID_MAX; link_id++) {
        if ((g_ip_link_ctl[link_id].link_stats == IP_LINK_WAIT_RESV) && (FD_ISSET(g_ip_link_ctl[link_id].sfd,
            read_set))) {
            if (ip_ip_resv_show_msg(link_id) != HI_ERR_SUCCESS) {
                continue;
            }
        }
    }
    hi_mux_post(g_ip_mux_id);
    return;
}

static hi_void ip_tcp_accept(hi_void)
{
    struct sockaddr_in cln_addr = {0};
    socklen_t cln_addr_len = (socklen_t)sizeof(cln_addr);
    hi_s32 resv_fd;
    hi_s8 link_id = -1;
    hi_s8 i;
    hi_u32 opt = 1;

    hi_mux_pend(g_ip_mux_id, IP_MUX_WAIT_TIME);
    resv_fd = accept(g_listen_fd.sfd, (struct sockaddr *)&cln_addr, (socklen_t *)&cln_addr_len);
    if (resv_fd < 0) {
        printf("{accept failed, return is %d}\r\n", resv_fd);
        hi_mux_post(g_ip_mux_id);
        return;
    }

    /* 找到一个没有被使用的link id */
    for (i = 0; i < IP_LINK_ID_MAX; i++) {
        if (g_ip_link_ctl[i].link_stats == IP_LINK_ID_IDLE) {
            link_id = i;
            break;
        }
    }
    if ((i >= IP_LINK_ID_MAX) || (link_id == -1)) {
        hi_at_printf("no link id to use now\r\n");
        closesocket(resv_fd);
        return;
    }
    setsockopt(g_ip_link_ctl[link_id].sfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    /* 更新连接信息 */
    g_ip_link_ctl[link_id].sfd = resv_fd;
    g_ip_link_ctl[link_id].link_stats = IP_LINK_WAIT_RESV;
    g_ip_link_ctl[link_id].link_res = IP_LINK_AUTO;
    g_ip_link_ctl[link_id].ip_protocol = IP_TCP;
    hi_at_printf("%d,CONNECT\r\n", link_id);
    hi_mux_post(g_ip_mux_id);

    return;
}

static hi_void ip_monitor(hi_void)
{
    hi_s32 sfd_max;
    fd_set read_set;
    struct timeval time_val;
    hi_s32 ret = -1;
    int i;

    hi_mux_create(&g_ip_mux_id);
    g_ip_task_exit = 0;
    while (!g_ip_task_exit) {
        hi_cpup_load_check_proc(hi_task_get_current_id(), LOAD_SLEEP_TIME_DEFAULT);
        /* 当所有link 都处于空闲态并且没有监听socket，退出 ip_monitor */
        if ((ip_is_all_link_idle() == HI_ERR_SUCCESS) && (g_listen_fd.link_stats == IP_LINK_ID_IDLE)) {
            hi_mux_delete(g_ip_mux_id);
            g_ip_task_exit = 1;
            continue;
        }
        /* 监控需要close 的socket */
        ip_monitor_link_close();

        FD_ZERO(&read_set);
        sfd_max = 0;
        ip_set_monitor_socket(&read_set, &sfd_max);
        time_val.tv_sec = 0;
        time_val.tv_usec = 500000; /* 500000 超时时间500ms */
        ret = lwip_select(sfd_max + 1, &read_set, 0, 0, &time_val);
        if (ret < 0) {
            printf("{ip_monitor : socket select failure\r\n");
            goto failure;
        } else if (ret == 0) {
            continue;
        }
        /* ret > 0 说明被监控的socket有可读数据，可能是对端发数据或对端发起TCP client连接请求 */
        ip_ip_resv_output(&read_set);

        if ((g_listen_fd.link_stats == IP_LINK_SERVER_LISTEN) && (FD_ISSET(g_listen_fd.sfd, &read_set))) {
            ip_tcp_accept();
        }
    }
    g_ip_taskid = -1;
    return;

failure:
    for (i = 0; i < IP_LINK_ID_MAX; i++) {
        if (g_ip_link_ctl[i].link_stats != IP_LINK_ID_IDLE) {
            ip_link_release(i);
        }
    }
    if (g_listen_fd.link_stats != IP_LINK_ID_IDLE) {
        closesocket(g_listen_fd.sfd);
        g_listen_fd.sfd = -1;
        g_listen_fd.link_stats = IP_LINK_ID_IDLE;
    }
    g_ip_taskid = -1;
    printf("{ip_monitor : ip monitor exit}\r\n");
}

static hi_u32 ip_creat_ip_task(hi_void)
{
#if LWIP_LITEOS_TASK
    TSK_INIT_PARAM_S start_ip_task;
    if (g_ip_taskid > 0) {
        return HI_ERR_SUCCESS;
    }
    start_ip_task.pfnTaskEntry = (TSK_ENTRY_FUNC)ip_monitor;
    start_ip_task.uwStackSize  = LOSCFG_BASE_CORE_TSK_DEFAULT_STACK_SIZE;
    start_ip_task.pcName = "at_ip_monitor_task";
    start_ip_task.usTaskPrio = 28; /* 28 任务优先级 */
    start_ip_task.uwResved = LOS_TASK_STATUS_DETACHED;
    hi_u32 ret = LOS_TaskCreate((UINT32 *)(&g_ip_taskid), &start_ip_task);
    if (ret != HI_ERR_SUCCESS) {
        printf("{ip_creat_ip_task:task create failed 0x%08x.}\r\n", ret);
        return HI_ERR_FAILURE;
    }
#endif
    return HI_ERR_SUCCESS;
}

static void ip_set_tcp_link_info(hi_u8 link_id, hi_s32 sfd)
{
    hi_mux_pend(g_ip_mux_id, IP_MUX_WAIT_TIME);
    g_ip_link_ctl[link_id].sfd = sfd;
    g_ip_link_ctl[link_id].link_stats = IP_LINK_WAIT_RESV;
    g_ip_link_ctl[link_id].link_res = IP_LINK_MANUAL;
    g_ip_link_ctl[link_id].ip_protocol = IP_TCP;
    hi_mux_post(g_ip_mux_id);
}

static hi_u32 ip_start_tcp_client(hi_u8 link_id, const hi_char *peer_ipaddr, hi_u16 peer_port)
{
    hi_s32 ret;
    hi_u32 opt = 0;
    hi_s32 tos;
    struct sockaddr_in srv_addr = {0};

    if (link_id >= IP_LINK_ID_MAX) {
        return HI_ERR_FAILURE;
    }
    hi_mux_pend(g_ip_mux_id, IP_MUX_WAIT_TIME);
    if (g_ip_link_ctl[link_id].link_stats != IP_LINK_ID_IDLE) {
        hi_at_printf("invalid link\r\n");
        hi_mux_post(g_ip_mux_id);
        return HI_ERR_FAILURE;
    }
    hi_mux_post(g_ip_mux_id);

    hi_s32 sfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sfd == -1) {
        printf("{ip_start_tcp_client: socket fail}\r\n");
        return HI_ERR_FAILURE;
    }

    setsockopt(sfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    tos = 128; /* 128:TOS设定为128，对应tid = 4，WLAN_WME_AC_VI */
    ret = setsockopt(sfd, IPPROTO_IP, IP_TOS, &tos, sizeof(tos));
    if (ret) {
        printf("{ip_start_tcp_client: setsockopt TOPS fail, return is %d}\r\n", ret);
        closesocket(sfd);
        return HI_ERR_FAILURE;
    }
    srv_addr.sin_family = AF_INET;
    srv_addr.sin_addr.s_addr = inet_addr(peer_ipaddr);
    srv_addr.sin_port = htons (peer_port);
    ret = connect(sfd, (struct sockaddr *)&srv_addr, sizeof(srv_addr));
    if (ret != 0) {
        printf("{ip_start_tcp_client: connect fail, return is %d}\r\n", ret);
        closesocket(sfd);
        return HI_ERR_FAILURE;
    }

    ip_set_tcp_link_info(link_id, sfd);
    if (ip_creat_ip_task() != HI_ERR_SUCCESS) {
        printf("{ip_start_tcp_client: creat ip task fail}\r\n");
        hi_mux_pend(g_ip_mux_id, IP_MUX_WAIT_TIME);
        ip_link_release(link_id);
        hi_mux_post(g_ip_mux_id);
        return HI_ERR_FAILURE;
    }

    return HI_ERR_SUCCESS;
}

static hi_u32 ip_has_idle_udp_link(hi_void)
{
    hi_u8 udp_link_count = 0;
    hi_u8 link_id;

    hi_mux_pend(g_ip_mux_id, IP_MUX_WAIT_TIME);
    for (link_id = 0; link_id < IP_LINK_ID_MAX; link_id++) {
        if (g_ip_link_ctl[link_id].ip_protocol == IP_UDP) {
            udp_link_count++;
        }
    }
    hi_mux_post(g_ip_mux_id);
    if (udp_link_count >= IP_UDP_LINK_MAX) {
        return HI_ERR_FAILURE;
    }
    return HI_ERR_SUCCESS;
}

static hi_void ip_set_udp_link_info(hi_u8 link_id, hi_s32 sfd)
{
    hi_mux_pend(g_ip_mux_id, IP_MUX_WAIT_TIME);
    g_ip_link_ctl[link_id].sfd = sfd;
    g_ip_link_ctl[link_id].link_stats = IP_LINK_WAIT_RESV;
    g_ip_link_ctl[link_id].link_res = IP_LINK_MANUAL;
    g_ip_link_ctl[link_id].ip_protocol = IP_UDP;
    hi_mux_post(g_ip_mux_id);
}

static hi_u32 ip_start_udp(hi_u8 link_id, hi_u16 local_port)
{
    struct sockaddr_in srv_addr = {0};
    hi_s32 ret;
    hi_u32 opt = 0;
    hi_u32 tos;

    if ((link_id >= IP_LINK_ID_MAX) || (ip_has_idle_udp_link() != HI_ERR_SUCCESS)) {
        return HI_ERR_FAILURE;
    }
    hi_mux_pend(g_ip_mux_id, IP_MUX_WAIT_TIME);
    if (g_ip_link_ctl[link_id].link_stats != IP_LINK_ID_IDLE) {
        hi_at_printf("invalid link\r\n");
        hi_mux_post(g_ip_mux_id);
        return HI_ERR_FAILURE;
    }
    hi_mux_post(g_ip_mux_id);

    hi_s32 sfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sfd == -1) {
        printf("{ip_start_udp: socket fail}\r\n");
        return HI_ERR_FAILURE;
    }

    srv_addr.sin_family = AF_INET;
    srv_addr.sin_addr.s_addr = htonl(INADDR_ANY);  /* 监控本机所有的IP地址 */
    srv_addr.sin_port = htons(local_port);
    ret = bind(sfd, (struct sockaddr*)&srv_addr, sizeof(srv_addr));
    if (ret != 0) {
        printf("{ip_start_udp:bind failed, return is %d}\r\n", ret);
        closesocket(sfd);
        return HI_ERR_FAILURE;
    }
    setsockopt(sfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    tos = 128; /* 128:TOS设定为128，对应tid = 4，WLAN_WME_AC_VI */
    ret = setsockopt(sfd, IPPROTO_IP, IP_TOS, &tos, sizeof(tos));
    if (ret) {
        printf("{ip_start_udp: setsockopt TOPS fail, return is %d}\r\n", ret);
        closesocket(sfd);
        return HI_ERR_FAILURE;
    }

    ip_set_udp_link_info(link_id, sfd);
    if (ip_creat_ip_task() != HI_ERR_SUCCESS) {
        printf("{ip_start_tcp_client: creat ip task fail}\r\n");
        hi_mux_pend(g_ip_mux_id, IP_MUX_WAIT_TIME);
        ip_link_release(link_id);
        hi_mux_post(g_ip_mux_id);
        return HI_ERR_FAILURE;
    }

    return HI_ERR_SUCCESS;
}

static hi_u32 at_start_ip(hi_s32 argc, const hi_char **argv)
{
    hi_u8 link_id;
    hi_u16 peer_port;
    hi_u16 local_port;

    if (((argc != 3) && (argc != 4)) || (at_param_null_check(argc, argv) == HI_ERR_FAILURE)) { /* 3 4 参数个数校验 */
        return HI_ERR_FAILURE;
    }

    if (integer_check(argv[0]) == HI_ERR_FAILURE) {
        return HI_ERR_FAILURE;
    }
    link_id = (hi_u8)atoi(argv[0]);
    const hi_char *protocol = argv[1];

    if (strcmp(protocol, "tcp") == 0) {
        if ((argc != 4) || (integer_check(argv[3]) == HI_ERR_FAILURE)) { /* 4 3 参数校验 */
            return HI_ERR_FAILURE;
        }
        const hi_char *peer_ipaddr = argv[2];  /* 2 参数校验 */
        peer_port = (hi_u16)atoi(argv[3]); /* 3 参数校验 */
        if (ip_start_tcp_client(link_id, peer_ipaddr, peer_port) != HI_ERR_SUCCESS) {
            return HI_ERR_FAILURE;
        }
    } else if (strcmp(protocol, "udp") == 0) {
        if ((argc != 3) || (integer_check(argv[2]) == HI_ERR_FAILURE)) { /* 3 2 参数校验 */
            return HI_ERR_FAILURE;
        }
        local_port = (hi_u16)atoi(argv[2]); /* 2 参数校验 */
        if (ip_start_udp(link_id, local_port) != HI_ERR_SUCCESS) {
            return HI_ERR_FAILURE;
        }
    } else {
        return HI_ERR_FAILURE;
    }
    hi_at_printf("OK\r\n");
    return HI_ERR_SUCCESS;
}

static hi_void ip_tcp_send(hi_u8 link_id, const hi_char *send_msg)
{
    hi_s32 ret;
    hi_u32 send_len;
    send_len = strlen(send_msg);
    hi_mux_pend(g_ip_mux_id, IP_MUX_WAIT_TIME);
    ret = send(g_ip_link_ctl[link_id].sfd, send_msg, send_len, 0);
    hi_mux_post(g_ip_mux_id);
    if (ret <= 0) {
        hi_at_printf("ERROR\r\n");
        return;
    }
    hi_at_printf("SEND %d bytes\r\nOK\r\n", ret);
    return;
}

static hi_void ip_udp_send(hi_u8 link_id, in_addr_t peer_ipaddr, hi_u16 peer_port, const hi_char *send_msg)
{
    hi_s32 ret;
    struct sockaddr_in cln_addr = {0};
    hi_u32 send_len;
    send_len = strlen(send_msg);
    cln_addr.sin_family = AF_INET;
    cln_addr.sin_addr.s_addr = peer_ipaddr;
    cln_addr.sin_port = htons(peer_port);
    hi_mux_pend(g_ip_mux_id, IP_MUX_WAIT_TIME);
    ret = sendto(g_ip_link_ctl[link_id].sfd, send_msg, send_len, 0,
        (struct sockaddr *)&cln_addr, (socklen_t)sizeof(cln_addr));
    hi_mux_post(g_ip_mux_id);
    if (ret <= 0) {
        hi_at_printf("ERROR\r\n");
        return;
    }
    hi_at_printf("SEND %d bytes\r\nOK\r\n", ret);
    return;
}

static hi_u32 at_ip_send(hi_s32 argc, const hi_char **argv)
{
    if ((at_param_null_check(argc, argv) == HI_ERR_FAILURE) || ((argc != 2) && (argc != 4)) || /* 2 4 参数校验 */
        ((integer_check(argv[0]) == HI_ERR_FAILURE) || (integer_check(argv[1]) == HI_ERR_FAILURE))) {
        return HI_ERR_FAILURE;
    }

    g_link_id = (hi_u16)atoi(argv[0]);
    if ((g_link_id < 0) || (g_link_id >= IP_LINK_ID_MAX)) {
        hi_at_printf("invalid link\r\n");
        return HI_ERR_FAILURE;
    }

    hi_mux_pend(g_ip_mux_id, IP_MUX_WAIT_TIME);
    if (g_ip_link_ctl[g_link_id].link_stats == IP_LINK_ID_IDLE) {
        hi_at_printf("invalid link\r\n");
        hi_mux_post(g_ip_mux_id);
        return HI_ERR_FAILURE;
    }
    hi_mux_post(g_ip_mux_id);

    if ((atoi(argv[1]) <= 0) || (atoi(argv[1]) > IP_SEND_BUF_LEN)) {
        return HI_ERR_FAILURE;
    }

    g_at_ctrl.send_len = (hi_u16)atoi(argv[1]);

    hi_mux_pend(g_ip_mux_id, IP_MUX_WAIT_TIME);
    if (g_ip_link_ctl[g_link_id].ip_protocol == IP_TCP) {
        if (argc != 2) { /* 2 参数校验 */
            hi_at_printf("invalid link\r\n");
            hi_mux_post(g_ip_mux_id);
            return HI_ERR_FAILURE;
        }
    } else if (g_ip_link_ctl[g_link_id].ip_protocol == IP_UDP) {
        if (argc != 4) { /* 4 参数校验 */
            hi_at_printf("invalid link\r\n");
            hi_mux_post(g_ip_mux_id);
            return HI_ERR_FAILURE;
        }
        g_peer_ipaddr = inet_addr(argv[2]);  /* 2 参数校验 */
        if (integer_check(argv[3]) == HI_ERR_FAILURE) { /* 3 参数校验 */
            hi_mux_post(g_ip_mux_id);
            return HI_ERR_FAILURE;
        }
        g_peer_port = (hi_u16)atoi(argv[3]); /* 3 参数校验 */
    } else {
        hi_mux_post(g_ip_mux_id);
        return HI_ERR_FAILURE;
    }
    hi_mux_post(g_ip_mux_id);

    g_at_ctrl.at_state = AT_DATA_RECVING;
    hi_at_printf(">");
    return HI_ERR_RECVING;
}

hi_void at_send_serial_data(hi_char *serial_data)
{
    hi_char *send_msg = serial_data;
    hi_mux_pend(g_ip_mux_id, IP_MUX_WAIT_TIME);
    if (g_ip_link_ctl[g_link_id].ip_protocol == IP_TCP) {
        ip_tcp_send(g_link_id, send_msg);
    } else if (g_ip_link_ctl[g_link_id].ip_protocol == IP_UDP) {
        ip_udp_send(g_link_id, g_peer_ipaddr, g_peer_port, send_msg);
        g_peer_ipaddr = 0;
        g_peer_port = 0;
    }
    g_link_id = -1;
    hi_mux_post(g_ip_mux_id);
    return;
}


static hi_u32 at_set_uart_func_nv(hi_s32 argc, const hi_char *argv[])
{
    hi_u32 ret;
    hi_nv_uart_port_alloc nv;

    if (argc != 3) { /* "+SETUART"命令固定3个命令参数 */
        return HI_ERR_FAILURE;
    }

    ret = hi_nv_read(HI_NV_SYS_UART_PORT_ID, &nv, sizeof(hi_nv_uart_port_alloc), 0);
    if (ret != HI_ERR_SUCCESS) {
        hi_at_printf("read nv fail\r\n");
        return HI_ERR_FAILURE;
    }

    if (argv[0] != HI_NULL) { /* 0:uart_port_at */
        if (integer_check(argv[0]) != HI_ERR_SUCCESS) {
            return HI_ERR_FAILURE;
        }
        nv.uart_port_at = strtoul((const char*)argv[0], NULL, 10); /* param 0; 10:hexadecimal */
    }

    if (argv[1] != HI_NULL) { /* 1:uart_port_debug */
        if (integer_check(argv[1]) != HI_ERR_SUCCESS) {
            return HI_ERR_FAILURE;
        }
        nv.uart_port_debug = strtoul((const char*)argv[1], NULL, 10); /* param 1; 10:hexadecimal */
    }

    if (argv[2] != HI_NULL) { /* 2:uart_port_sigma */
        if (integer_check(argv[2]) != HI_ERR_SUCCESS) {
            return HI_ERR_FAILURE;
        }
        nv.uart_port_sigma = strtoul((const char*)argv[2], NULL, 10); /* param 2; 10:hexadecimal */
    }

    if (nv.uart_port_at > HI_UART_IDX_2 ||
        nv.uart_port_debug > HI_UART_IDX_2 ||
        nv.uart_port_sigma > HI_UART_IDX_2) {
        return HI_ERR_FAILURE;
    }

    if (nv.uart_port_at == nv.uart_port_debug ||
        nv.uart_port_at == nv.uart_port_sigma ||
        nv.uart_port_debug == nv.uart_port_sigma) {
        hi_at_printf("reuse of a uart port %d:%d:%d\r\n", nv.uart_port_at, nv.uart_port_debug, nv.uart_port_sigma);
        return HI_ERR_FAILURE;
    }

    ret = hi_nv_write(HI_NV_SYS_UART_PORT_ID, &nv, sizeof(hi_nv_uart_port_alloc), 0);
    if (ret != 0) {
        hi_at_printf("write nv fail\r\n");
        return HI_ERR_FAILURE;
    }
    hi_at_printf("OK\r\n");
    return HI_ERR_SUCCESS;
}

static hi_u32 ip_close_link(hi_s32 link_id)
{
    if (link_id >= IP_LINK_ID_MAX) {
        hi_at_printf("invalid link\r\n");
        return HI_ERR_FAILURE;
    }

    hi_mux_pend(g_ip_mux_id, IP_MUX_WAIT_TIME);
    if (g_ip_link_ctl[link_id].link_stats == IP_LINK_ID_IDLE) {
        hi_at_printf("invalid link\r\n");
        hi_mux_post(g_ip_mux_id);
        return HI_ERR_FAILURE;
    }

    g_ip_link_ctl[link_id].link_stats = IP_LINK_USER_CLOSE;
    hi_mux_post(g_ip_mux_id);
    return HI_ERR_SUCCESS;
}

static hi_u32 at_ip_close_link(hi_s32 argc, const hi_char **argv)
{
    hi_s32 link_id;
    if ((argc != 1) || (integer_check(argv[0]) == HI_ERR_FAILURE)) {
        return HI_ERR_FAILURE;
    }

    link_id = atoi(argv[0]);
    if (ip_close_link(link_id) != HI_ERR_SUCCESS) {
        return HI_ERR_FAILURE;
    }
    return HI_ERR_SUCCESS;
}

static hi_u32 ip_tcp_server_close(hi_void)
{
    int i;
    hi_mux_pend(g_ip_mux_id, IP_MUX_WAIT_TIME);
    if (g_listen_fd.link_stats == IP_LINK_ID_IDLE) {
        hi_at_printf("no server\r\n");
        hi_mux_post(g_ip_mux_id);
        return HI_ERR_FAILURE;
    }

    g_listen_fd.link_stats = IP_LINK_USER_CLOSE;

    /* 服务器关闭时，与之相连接的所有link都要关闭 */
    for (i = 0; i < IP_LINK_ID_MAX; i++) {
        if (g_ip_link_ctl[i].link_res == IP_LINK_AUTO) {
            g_ip_link_ctl[i].link_stats = IP_LINK_WAIT_CLOSE;
        }
    }
    hi_mux_post(g_ip_mux_id);
    return HI_ERR_SUCCESS;
}

static hi_u32 ip_tcp_server_start(hi_u16 local_port)
{
    struct sockaddr_in srv_addr = {0};
    hi_s32 ret;
    hi_u32 opt = 1;

    if (g_listen_fd.link_stats == IP_LINK_SERVER_LISTEN) {
        hi_at_printf("server is running\r\n");
        return HI_ERR_FAILURE;
    }

    g_listen_fd.sfd = socket(AF_INET, SOCK_STREAM, 0);
    if (g_listen_fd.sfd == -1) {
        printf("{ip_tcp_server_start: creat socket failed}\r\n");
        return HI_ERR_FAILURE;
    }

    setsockopt(g_listen_fd.sfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    srv_addr.sin_family = AF_INET;
    srv_addr.sin_addr.s_addr = htonl(INADDR_ANY);  /* 监控本机所有的IP地址 */
    srv_addr.sin_port = htons(local_port);
    ret = bind(g_listen_fd.sfd, (struct sockaddr *)&srv_addr, sizeof(srv_addr));
    if (ret != 0) {
        printf("{ip_tcp_server_start:bind failed, return is %d}\r\n", ret);

        closesocket(g_listen_fd.sfd);
        g_listen_fd.sfd = -1;
        g_listen_fd.link_stats = IP_LINK_ID_IDLE;
        return HI_ERR_FAILURE;
    }

    ret = listen(g_listen_fd.sfd, IP_TCP_SERVER_LISTEN_NUM);
    if (ret != 0) {
        printf("{ip_tcp_server_start:listen failed, return is %d\n}", ret);

        closesocket(g_listen_fd.sfd);
        g_listen_fd.sfd = -1;
        g_listen_fd.link_stats = IP_LINK_ID_IDLE;
        return HI_ERR_FAILURE;
    }

    if (ip_creat_ip_task() != HI_ERR_SUCCESS) {
        printf("{ip_tcp_server_start:ip_creat_ip_task fail}\r\n");

        closesocket(g_listen_fd.sfd);
        g_listen_fd.sfd = -1;
        g_listen_fd.link_stats = IP_LINK_ID_IDLE;
        return HI_ERR_FAILURE;
    }

    g_listen_fd.link_stats = IP_LINK_SERVER_LISTEN;

    return HI_ERR_SUCCESS;
}

static hi_u32 at_ip_tcp_server(hi_s32 argc, const hi_char **argv)
{
    hi_u16 local_port;
    hi_s32 server_ctl;

    if (at_param_null_check(argc, argv) == HI_ERR_FAILURE) {
        return HI_ERR_FAILURE;
    }
    if ((argc != 1) && (argc != 2)) { /* 1 2 参数校验 */
        return HI_ERR_FAILURE;
    }
    if (integer_check(argv[0]) == HI_ERR_FAILURE) {
        return HI_ERR_FAILURE;
    }

    server_ctl = atoi(argv[0]);
    if (server_ctl == 1) {
        if ((argv[1] == HI_NULL) || (integer_check(argv[1]) == HI_ERR_FAILURE)) {
            return HI_ERR_FAILURE;
        }
        local_port = (hi_u16)atoi(argv[1]);
        if (ip_tcp_server_start(local_port) != HI_ERR_SUCCESS) {
            return HI_ERR_FAILURE;
        }
    } else if (server_ctl == 0) {
        if (argc != 1) {
            return HI_ERR_FAILURE;
        }
        if (ip_tcp_server_close() != HI_ERR_SUCCESS) {
            return HI_ERR_FAILURE;
        }
        return HI_ERR_SUCCESS;
    } else {
        return HI_ERR_FAILURE;
    }
    hi_at_printf("OK\r\n");

    return HI_ERR_SUCCESS;
}

hi_u32 at_query_xtal_compesation(hi_void)
{
    hi_u32 ret;
    hi_s16 high_temp_threshold = 0;;
    hi_s16 low_temp_threshold = 0;
    hi_s16 pll_compesation = 0;

    ret = get_rf_cmu_pll_param(&high_temp_threshold, &low_temp_threshold, &pll_compesation);
    if (ret != HI_ERR_SUCCESS) {
        return ret;
    }

    hi_at_printf("+XTALCOM:%d,%d,%d\r\n", high_temp_threshold, low_temp_threshold, pll_compesation);
    AT_RESPONSE_OK;

    return HI_ERR_SUCCESS;
}

const at_cmd_func g_at_general_func_tbl[] = {
    {"", 0, HI_NULL, HI_NULL, HI_NULL, (at_call_back_func)at_exe_at_cmd},
    {"+HELP", 5, HI_NULL, HI_NULL, HI_NULL, (at_call_back_func)at_exe_help_cmd},
    {"+SYSINFO", 8, HI_NULL, HI_NULL, HI_NULL, (at_call_back_func)at_query_sysinfo_cmd},
    {"+RST", 4, HI_NULL, HI_NULL, (at_call_back_func)at_setup_reset_cmd, (at_call_back_func)at_exe_reset_cmd},
    {"+DHCP", 5, HI_NULL, HI_NULL, (at_call_back_func)at_setup_dhcp, HI_NULL},
    {"+DHCPS", 6, HI_NULL, HI_NULL, (at_call_back_func)at_setup_dhcps, HI_NULL},
    {"+MAC", 4, HI_NULL, (at_call_back_func)cmd_get_macaddr, (at_call_back_func)cmd_set_macaddr, HI_NULL},
    {"+NETSTAT", 8, HI_NULL, HI_NULL, HI_NULL, (at_call_back_func)at_netstat},
#ifdef CONFIG_IPERF_SUPPORT
    {"+IPERF", 6, HI_NULL, HI_NULL, (at_call_back_func)at_iperf, HI_NULL},
#endif
    {"+PING", 5, HI_NULL, HI_NULL, (at_call_back_func)at_ping, HI_NULL},
    {"+PING6", 6, HI_NULL, HI_NULL, (at_call_back_func)at_ping6, HI_NULL},
#if LWIP_DNS
    {"+DNS", 4, HI_NULL, (at_call_back_func)at_show_dns, (at_call_back_func)at_dns, HI_NULL},
#endif
    /* {"+ARP", 4, HI_NULL, HI_NULL, HI_NULL, lwip_arp}, */
#if LWIP_IPV4 && LWIP_IGMP
#ifdef LWIP_DEBUG_OPEN
    {"+IGMP", 5, HI_NULL, HI_NULL, (at_call_back_func)at_osShellIgmp, HI_NULL},
#endif
#endif
    /* {"+CPU", 4, HI_NULL, HI_NULL, (at_call_back_func)at_cmd_get_cpup, HI_NULL}, */
#ifdef _PRE_WLAN_FEATURE_CSI
    /* {"+CSI", 4, HI_NULL, HI_NULL, (at_call_back_func)at_cmd_csi_set_switch, HI_NULL}, */
    /* {"+CSICONFIG", 10, HI_NULL, HI_NULL, (at_call_back_func)at_cmd_csi_set_config, HI_NULL}, */
#endif
#ifdef CONFIG_SIGMA_SUPPORT
    {"+SIGMA", 6, HI_NULL, HI_NULL, HI_NULL, (at_call_back_func)at_sigma_start},
#endif
    {"+DUMP", 5, HI_NULL, HI_NULL, HI_NULL, (at_call_back_func)at_get_dump},
    {"+IPSTART", 8, HI_NULL, HI_NULL, (at_call_back_func)at_start_ip, HI_NULL},
    {"+IPLISTEN", 9, HI_NULL, HI_NULL, (at_call_back_func)at_ip_tcp_server, HI_NULL},
    {"+IPSEND", 7, HI_NULL, HI_NULL, (at_call_back_func)at_ip_send, HI_NULL},
    {"+IPCLOSE", 8, HI_NULL, HI_NULL, (at_call_back_func)at_ip_close_link, HI_NULL},
    {"+XTALCOM", 8, HI_NULL, (at_call_back_func)at_query_xtal_compesation, HI_NULL, HI_NULL},
#ifdef LWIP_DEBUG_OPEN
    {"+MLD6", 5, HI_NULL, HI_NULL, (at_call_back_func)os_shell_mld6, HI_NULL},
    {"+RTED", 5, HI_NULL, HI_NULL, HI_NULL, (at_call_back_func)osRteDebug},
    {"+MCAST6", 7, HI_NULL, HI_NULL, (at_call_back_func)os_shell_mcast6, HI_NULL},
    {"+RPL", 4, HI_NULL, HI_NULL, (at_call_back_func)osShellRpl, HI_NULL},
#endif
};

#define AT_GENERAL_FUNC_NUM (sizeof(g_at_general_func_tbl) / sizeof(g_at_general_func_tbl[0]))

void hi_at_general_cmd_register(void)
{
    hi_at_register_cmd(g_at_general_func_tbl, AT_GENERAL_FUNC_NUM);
}

const at_cmd_func g_at_general_factory_test_func_tbl[] = {
    {"+CSV", 4, HI_NULL, HI_NULL, HI_NULL, (at_call_back_func)at_query_ver_cmd},
    {"+SETUART", 8, HI_NULL, HI_NULL, (at_call_back_func)at_set_uart_func_nv, HI_NULL},
    {"+IFCFG", 6, HI_NULL, HI_NULL, (at_call_back_func)at_lwip_ifconfig, (at_call_back_func)at_lwip_ifconfig},
};
#define AT_GENERAL_FACTORY_TEST_FUNC_NUM (sizeof(g_at_general_factory_test_func_tbl) / sizeof(g_at_general_factory_test_func_tbl[0]))

void hi_at_general_factory_test_cmd_register(void)
{
    hi_at_register_cmd(g_at_general_factory_test_func_tbl, AT_GENERAL_FACTORY_TEST_FUNC_NUM);
}

#ifdef __cplusplus
#if __cplusplus
    }
#endif
#endif
