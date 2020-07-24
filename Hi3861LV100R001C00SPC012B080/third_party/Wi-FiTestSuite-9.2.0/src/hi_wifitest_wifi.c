/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: sigma WiFi function
 * Create: 2019-04-25
 */

/*****************************************************************************
头文件包含
*****************************************************************************/
#include "los_typedef.h"
#include "shell.h"
#include "los_event.h"
#include "los_task.h"
#include "stdio.h"
#include "string.h"
#include "lwip/netif.h"
#include "hi_os_stat.h"
#include "hi_mem.h"
#include "hi_task.h"
#include "hi_sem.h"
#include "hi_config.h"
#include "los_task.h"
#include "lwip/api_shell.h"
#include "hi_types.h"
#include "hi_mdm_types.h"
#include <hi3861_platform_base.h>
#include "lwip/netifapi.h"
#include "wfa_debug.h"
#include "wfa_types.h"
#include "wfa_tg.h"
#include "wfa_cmds.h"
#include "wfa_rsp.h"
#include "hi_wifitest_wifi.h"
#include "hi_wifi_api.h"
#include "lwip/icmp.h"
#include "lwip/sockets.h"
#include "lwip/dns.h"
#include "lwip/inet_chksum.h"
#include "hi_time.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

/*****************************************************************************
宏定义
*****************************************************************************/
#define MAC_SEP_COLON_TAG    ":"
#define MAC_STRING_LEN       17
#define HISI_SUCC            0

#define IPV4_TYPE            1
#define IPV6_TYPE            2
/*****************************************************************************
全局变量定义
*****************************************************************************/
#define SCAN_AP_LIMIT            64

/* g_wpa_assoc_params: 缓存STA认证参数 */
hi_wifi_assoc_request g_wpa_assoc_params = {"", HI_WIFI_SECURITY_SAE, "", "", 0};
char g_sigma_ipaddr_str[SIGMA_IPADDR_GET_LEN] = {0};
char g_sigma_dns_str[SIGMA_DNS_GET_LEN] = {0};
char g_sigma_dhcp_stat[SIGMA_DHCP_STAT] = {0};
int g_sigma_traffic_ping_pkt[2] = {0};
caStaSetIpConfig_t g_ipconfig_param = {0};
extern unsigned int g_wait_sta_associate_sem;
extern unsigned int g_wait_ping_stop_sem;
hi_bool g_is_sigma_stop_ping_flag = 0;
static int g_ping_taskid = -1;
static int g_ping_kill = 0;

/*****************************************************************************
函 数 名  : sigma_start_hapd
功能描述  : 通过文件系统启动hostapd
*****************************************************************************/
int sigma_start_hapd(char* ifname, int* length)
{
    hi_wifi_protocol_mode phy_mode = HI_WIFI_PHY_MODE_11BGN;
    ip4_addr_t        st_gw;
    ip4_addr_t        st_ipaddr;
    ip4_addr_t        st_netmask;
    struct netif     *lwip_netif = NULL;
    hi_wifi_softap_config ap_defa_start = {"abc11n", "123456789", 6, 0, HI_WIFI_SECURITY_WPA2PSK, HI_WIFI_PAIRWISE_AES};

    IP4_ADDR(&st_gw, 192, 168, 43, 1);
    IP4_ADDR(&st_ipaddr, 192, 168, 43, 1);
    IP4_ADDR(&st_netmask, 255, 255, 255, 0);

    hi_wifi_softap_set_protocol_mode(phy_mode);
    if (hi_wifi_softap_start(&ap_defa_start, ifname, length) != WFA_SUCCESS) {
        DPRINT_INFO(WFA_OUT, "wfaApResetDefault memset_s error\n");
        return WFA_FAILURE;
    }

    lwip_netif = netifapi_netif_find("ap0");
    if (lwip_netif == NULL) {
        DPRINT_ERR(WFA_ERR,  "cmd_start_hapd::Null param of netdev\n");
        return WFA_FAILURE;
    }

    if (netifapi_netif_set_addr(lwip_netif, &st_ipaddr, &st_netmask, &st_gw) != WFA_SUCCESS) {
        DPRINT_INFO(WFA_OUT, "wfaApResetDefault netifapi_netif_set_addr error\n");
        return WFA_FAILURE;
    }

    if (netifapi_dhcps_start(lwip_netif, NULL, 0) != WFA_SUCCESS) {
        DPRINT_INFO(WFA_OUT, "wfaApResetDefault memset_s error\n");
        return WFA_FAILURE;
    }
    return WFA_SUCCESS;
}
/*****************************************************************************
 函 数 名  : strtoaddr
 功能描述  : 字符串转MAC地址
 输入参数  : pc_param: MAC地址字符串, 格式 xx:xx:xx:xx:xx:xx
 输出参数  : puc_mac_addr: 转换成16进制后的MAC地址
 返 回 值  : unsigned int
*****************************************************************************/
unsigned int check_mac_elem(const char elem)
{
    if (elem >= '0' && elem <= '9') {
        return HI_ERR_SUCCESS;
    } else if (elem >= 'A' && elem <= 'F') {
        return HI_ERR_SUCCESS;
    } else if (elem >= 'a' && elem <= 'f') {
        return HI_ERR_SUCCESS;
    } else if (elem == ':') {
        return HI_ERR_SUCCESS;
    }

    return HI_ERR_FAILURE;
}

unsigned int str_to_addr(char *pc_param, unsigned char *puc_mac_addr)
{
    unsigned int ui_cnt;
    char *pc_tmp1 = pc_param;
    char *pc_tmp2;
    char *pc_tmp3 = NULL;

    for (ui_cnt = 0; ui_cnt < MAC_STRING_LEN; ui_cnt++) {
        if (check_mac_elem(pc_param[ui_cnt]) != HI_ERR_SUCCESS) {
            return HI_ERR_FAILURE;
        }
    }

    for (ui_cnt = 0; ui_cnt < (ETH_ALEN - 1); ui_cnt++) {
        pc_tmp2 = (char *)strsep(&pc_tmp1, MAC_SEP_COLON_TAG);
        if (pc_tmp2 == NULL) {
            return HI_ERR_SIGMA_INVALID_PARAMETER;
        }
        puc_mac_addr[ui_cnt] = (unsigned char)strtoul(pc_tmp2, &pc_tmp3, 16);
    }

    if (pc_tmp1 == NULL) {
        return HI_ERR_SIGMA_INVALID_PARAMETER;
    }
    puc_mac_addr[ui_cnt] = (unsigned char)strtoul(pc_tmp1, &pc_tmp3, 16);
    return HI_ERR_SUCCESS;
}

/*****************************************************************************
 功能描述  :设置mac地址
*****************************************************************************/
int sigma_set_macaddr(char *mac_addr_str)
{
    char mac_addr[ETH_ALEN];

    if (mac_addr_str == NULL) {
        return WFA_FAILURE;
    }
    hi_u32 ret = str_to_addr(mac_addr_str, (unsigned char *)mac_addr);
    if (ret != HI_ERR_SUCCESS) {
        printf("Mac set failed!");
        return WFA_FAILURE;
    }
    mac_addr[0] &= 0xFE;

    if (hi_wifi_set_macaddr(mac_addr, ETH_ALEN) != WFA_OK) {
        printf("Mac set failed!");
        return WFA_FAILURE;
    }
    printf("Mac set succ!");

    return WFA_SUCCESS;
}

unsigned int connect_get_time(void)
{
    unsigned int ul_time;
    struct timeval tv;

    gettimeofday(&tv, NULL);
    ul_time = tv.tv_usec / 1000 + tv.tv_sec * 1000;
    return ul_time;
}

/*****************************************************************************
 功能描述  : 启动wpa_supplicant
*****************************************************************************/
int sigma_wpa_start(char *hw_mode)
{
    char ifname[IFNAME_MAX_SIZE + 1] = {0};
    int len = 0;
    hi_wifi_protocol_mode phy_mode = HI_WIFI_PHY_MODE_11BGN;

    if (strncmp(hw_mode, "11n", 3) == 0) {
        phy_mode = HI_WIFI_PHY_MODE_11BGN;
    } else if (strncmp(hw_mode, "11g", 3) == 0) {
        phy_mode = HI_WIFI_PHY_MODE_11BG;
    } else if (strncmp(hw_mode, "11b", 3) == 0) {
        phy_mode = HI_WIFI_PHY_MODE_11B;
    } else {
        phy_mode = HI_WIFI_PHY_MODE_BUTT;
    }
    hi_wifi_sta_set_protocol_mode(phy_mode);
    int ret = hi_wifi_sta_start(ifname, &len);
    if (ret != WFA_OK) {
        printf("cmd_wpa_start fail.");
        return WFA_FAILURE;
    }
    printf("cmd_wpa_start creat new netdev : %s.", ifname);

    return WFA_SUCCESS;
}

/*****************************************************************************
 功能描述  : 停止wpa_supplicant
*****************************************************************************/
void sigma_wpa_stop(void)
{
    int ret = hi_wifi_sta_stop();
    if (ret != WFA_OK) {
        DPRINT_ERR(WFA_ERR, "cmd_wpa_stop fail.");
        return;
    }
}

/*****************************************************************************
 功能描述  : 发起关联
*****************************************************************************/
int sigma_wpa_connect(char *ifname)
{
    if (ifname == NULL || strlen(ifname) > WFA_IF_NAME_LEN) {
        return WFA_ERROR;
    }

    int ret = hi_wifi_sta_connect(&g_wpa_assoc_params);
    if (ret != WFA_OK) {
        DPRINT_ERR(WFA_ERR, "STA assocate AP fail!\n");
        return WFA_FAILURE;
    }

    return WFA_SUCCESS;
}

/*****************************************************************************
 功能描述  : 发起去关联
*****************************************************************************/
void sigma_wpa_disconnect(void)
{
    hi_wifi_sta_disconnect();
}

/*****************************************************************************
 功能描述  : 获取ip地址
*****************************************************************************/
int sigma_get_ipaddr(char ipaddr_str[], int ipaddr_len, char mask_str[], int mask_len)
{
    struct netif *lwip_netif = NULL;

    lwip_netif = netifapi_netif_find("wlan0");
    if (lwip_netif == NULL) {
        DPRINT_INFO(WFA_OUT, "sigma_get_ipaddr :: lwip_netif is null\n");
        return WFA_FAILED;
    }

    if (memcpy_s(ipaddr_str, ipaddr_len, ip4addr_ntoa(&(lwip_netif->ip_addr.u_addr.ip4)),
        strlen(ip4addr_ntoa(&(lwip_netif->ip_addr.u_addr.ip4)))) != EOK) {
        DPRINT_INFO(WFA_OUT, "sigma_get_ipaddr :: memcpy_s is fail\n");
        return WFA_FAILED;
    }
    if (memcpy_s(mask_str, mask_len, ip4addr_ntoa(&(lwip_netif->netmask.u_addr.ip4)),
        strlen(ip4addr_ntoa(&(lwip_netif->netmask.u_addr.ip4)))) != EOK) {
        DPRINT_INFO(WFA_OUT, "sigma_get_ipaddr :: memcpy_s is fail\n");
        return WFA_FAILED;
    }

    return WFA_SUCCESS;
}

/*****************************************************************************
 功能描述  : 获取dns地址
*****************************************************************************/
int sigma_get_dns(char dns_pri[], int pri_len, char dns_sec[], int sec_len)
{
    ip_addr_t dnsserver;
    ip_addr_t dnsserver1;
    int ret;

    ret = lwip_dns_getserver(0, &dnsserver); /* primary-dns */
    ret |= lwip_dns_getserver(1, &dnsserver1); /* secondary-dns */
    if (ret != WFA_SUCCESS) {
        DPRINT_ERR(WFA_ERR, "sigma_get_dns lwip_dns_getserver fail!\n");
        return WFA_FAILED;
    }

    if (memcpy_s(dns_pri, pri_len, ip4addr_ntoa(&dnsserver.u_addr.ip4),
        strlen(ip4addr_ntoa(&dnsserver.u_addr.ip4))) != EOK) {
        DPRINT_INFO(WFA_OUT, "sigma_get_dns : str[0] memcpy_s is fail\n");
        return WFA_FAILED;
    }
    if (memcpy_s(dns_sec, sec_len, ip4addr_ntoa(&dnsserver1.u_addr.ip4),
        strlen(ip4addr_ntoa(&dnsserver1.u_addr.ip4))) != EOK) {
        DPRINT_INFO(WFA_OUT, "sigma_get_dns :: str[1] memcpy_s is fail\n");
        return WFA_FAILED;
    }

    return WFA_SUCCESS;
}

/*****************************************************************************
 功能描述  : 获取mac地址
*****************************************************************************/
int sigma_get_macaddr(char macaddr_str[], int str_len)
{
    struct netif *lwip_netif = NULL;

    lwip_netif = netifapi_netif_find("wlan0");
    if (lwip_netif == NULL) {
        DPRINT_INFO(WFA_OUT, "sigma_get_ipaddr :: lwip_netif is null\n");
        return WFA_FAILED;
    }

    if (memcpy_s(macaddr_str, str_len, lwip_netif->hwaddr, WFA_MAC_ADDR_STR_LEN) != EOK) {
        DPRINT_INFO(WFA_OUT, "sigma_get_ipaddr :: memcpy_s is null\n");
        return WFA_FAILED;
    }

    return WFA_OK;
}

/*****************************************************************************
 功能描述  : 起dhcp
*****************************************************************************/
int sigma_start_dhcp(char *ifname)
{
    struct netif *netif_start_dhcp = NULL;

    if (ifname == NULL) {
        return WFA_FAILURE;
    }

    netif_start_dhcp = netifapi_netif_find(ifname);
    if (netif_start_dhcp == NULL) {
        DPRINT_ERR(WFA_ERR, "sigma_start_dhcp netif_p is null!\n");
        return WFA_FAILURE;
    }

    unsigned int ret = netifapi_dhcp_start(netif_start_dhcp);
    if (ret != WFA_SUCCESS) {
        DPRINT_ERR(WFA_ERR, "sigma_start_dhcp netifapi_dhcp_start fail! ret  = %d\n", ret);
        return WFA_FAILURE;
    }

    return WFA_SUCCESS;
}

/*****************************************************************************
 功能描述  : 设置ip地址
*****************************************************************************/
void ipaddr_strtok(char* ipaddr, unsigned int* ipaddr_arr)
{
    unsigned int i = 0;
    char* str = NULL;
    char* str_ptr = ipaddr;
    while (str_ptr != NULL) {
        str = strtok_r(NULL, ".", &str_ptr);
        ipaddr_arr[i] = atoi(str);
        i++;
    }
}

int sigma_sta_set_ip_pram_ckeck(void)
{
    if (g_ipconfig_param.intf[0] == '\0') {
        DPRINT_ERR(WFA_ERR, "Invalid ip_param value!\n");
        return WFA_FAILURE;
    }
    if (strlen(g_ipconfig_param.intf) > WFA_IF_NAME_LEN) {
        DPRINT_ERR(WFA_ERR, "Invalid interface name!\n");
        return WFA_FAILURE;
    }
    if (g_ipconfig_param.type == IPV6_TYPE) {
    } else {
        if (strlen(g_ipconfig_param.ipaddr) > WFA_IP_ADDR_STR_LEN) {
            DPRINT_ERR(WFA_ERR, "Invalid ip length!\n");
            return WFA_FAILURE;
        }
    }
    if (strlen(g_ipconfig_param.mask) > WFA_IP_ADDR_STR_LEN) {
        DPRINT_ERR(WFA_ERR, "Invalid mask ip length!\n");
        return WFA_FAILURE;
    }
    if (strlen(g_ipconfig_param.defGateway) > WFA_IP_ADDR_STR_LEN) {
        DPRINT_ERR(WFA_ERR, "Invalid Gateway ip length!\n");
        return WFA_FAILURE;
    }
    if (strlen(g_ipconfig_param.pri_dns) > WFA_IP_ADDR_STR_LEN) {
        DPRINT_ERR(WFA_ERR, "Invalid primary dns length!\n");
        return WFA_FAILURE;
    }
    if (strlen(g_ipconfig_param.sec_dns) > WFA_IP_ADDR_STR_LEN) {
        DPRINT_ERR(WFA_ERR, "Invalid second dns length!\n");
        return WFA_FAILURE;
    }

    return WFA_SUCCESS;
}

int sigma_sta_set_ip(void)
{
    ip4_addr_t st_gw, st_ipaddr, st_netmask;
    ip_addr_t st_pri_dns, st_sec_dns;
    unsigned int ipaddr_arr[4]   = {0}; /* 4个元素 */
    unsigned int netmask_arr[4]  = {0}; /* 4个元素 */
    unsigned int gw_arr[4]       = {0}; /* 4个元素 */

    if (sigma_sta_set_ip_pram_ckeck() != WFA_SUCCESS) {
        DPRINT_ERR(WFA_ERR, "sigma_sta_set_ip_pram_ckeck fail!\n");
        return WFA_FAILURE;
    }

    if (g_ipconfig_param.ipaddr[0] != '\0') {
        ipaddr_strtok(g_ipconfig_param.ipaddr, ipaddr_arr);
        IP4_ADDR(&st_ipaddr, ipaddr_arr[0], ipaddr_arr[1], ipaddr_arr[2], ipaddr_arr[3]);  /* ipaddr 第1/2/3/4位 */
    } else {
        IP4_ADDR(&st_ipaddr, 0, 0, 0, 0);
    }
    if (g_ipconfig_param.mask[0] != '\0') {
        ipaddr_strtok(g_ipconfig_param.mask, netmask_arr);
        IP4_ADDR(&st_netmask, netmask_arr[0], netmask_arr[1], netmask_arr[2], netmask_arr[3]); /* netmask 第1/2/3/4位 */
    } else {
        IP4_ADDR(&st_netmask, 0, 0, 0, 0);
    }
    if (g_ipconfig_param.defGateway[0] != '\0') {
        ipaddr_strtok(g_ipconfig_param.defGateway, ipaddr_arr);
        IP4_ADDR(&st_gw, gw_arr[0], gw_arr[1], gw_arr[2], gw_arr[3]);      /* gw 第1/2/3/4位 */
    } else {
        IP4_ADDR(&st_gw, 0, 0, 0, 0);
    }

    struct netif* netif_p = netifapi_netif_find(g_ipconfig_param.intf);
    if (netif_p == NULL) {
        return WFA_FAILURE;
    }

    if (netifapi_netif_set_addr(netif_p, &st_ipaddr, &st_netmask, &st_gw) != WFA_SUCCESS) {
        return WFA_FAILURE;
    }

    if (g_ipconfig_param.pri_dns[0] != '\0') {
        if ((ip4addr_aton(g_ipconfig_param.pri_dns, &st_pri_dns.u_addr.ip4) != 1) ||
            (lwip_dns_setserver(0, &st_pri_dns) != WFA_SUCCESS)) {
            return WFA_FAILURE;
        }
    }

    if (g_ipconfig_param.sec_dns[0] != '\0') {
        if ((ip4addr_aton(g_ipconfig_param.pri_dns, &st_sec_dns.u_addr.ip4) != 1) ||
            (lwip_dns_setserver(1, &st_sec_dns) != WFA_SUCCESS)) {
            return WFA_FAILURE;
        }
    }

    return WFA_SUCCESS;
}

/*****************************************************************************
 功能描述  : 判断sta是否已经连接
*****************************************************************************/
int sigma_is_sta_connected(char *ifname)
{
    int ret;
    hi_wifi_status wifi_status;

    if (ifname == NULL || strlen(ifname) > WFA_IF_NAME_LEN) {
        return WFA_ERROR;
    }

    /* 安全编程规则6.6例外（2）结构体赋予初值 */
    memset(&wifi_status, 0, sizeof(hi_wifi_status));

    ret = hi_wifi_sta_get_connect_info(&wifi_status);
    if (ret != HISI_OK) {
        DPRINT_ERR(WFA_ERR, "Get connection information failed.\n");
        return WFA_ERROR;
    }

    if (wifi_status.status == HI_WIFI_CONNECTED) {
        return WFA_SUCCESS;
    }

    return WFA_ERROR;
}

/*****************************************************************************
 功能描述  : 获取bssid
*****************************************************************************/
int sigma_get_bssid(unsigned char str[], int str_len, char *ifname)
{
    int ret;
    hi_wifi_status wifi_status;

    if (ifname == NULL || strlen(ifname) > WFA_IF_NAME_LEN) {
        return WFA_ERROR;
    }

    /* 安全编程规则6.6例外（2）结构体赋予初值 */
    memset(&wifi_status, 0, sizeof(hi_wifi_status));

    ret = hi_wifi_sta_get_connect_info(&wifi_status);
    if (ret != HISI_OK) {
        DPRINT_ERR(WFA_ERR, "Get connection information failed.\n");
        return WFA_ERROR;
    }

    if (wifi_status.status == HI_WIFI_CONNECTED) {
        if (memcpy_s(str, str_len, wifi_status.bssid, WFA_MAC_ADDR_STR_LEN) != EOK) {
            DPRINT_INFO(WFA_OUT, "sigma_get_ipaddr :: memcpy_s is null\n");
            return WFA_FAILED;
        }
    } else {
        if (memset_s(str, str_len, 0, WFA_MAC_ADDR_STR_LEN) != EOK) {
            DPRINT_INFO(WFA_OUT, "sigma_get_ipaddr :: memset_s is null\n");
            return WFA_FAILED;
        }
    }

    return WFA_SUCCESS;
}
/*****************************************************************************
 功能描述  : 发送ping命令
*****************************************************************************/
int sigma_send_ping(tgPingStart_t *ping_param, int ping_interval, int total_packets)
{
    int i;
    char *cmd[PING_PARAM_MAX_NUM];
    for (i = 0; i < PING_PARAM_MAX_NUM; i++) {
        cmd[i] = malloc(WFA_IP_ADDR_STR_LEN);
        memset_s(cmd[i], WFA_IP_ADDR_STR_LEN, 0, WFA_IP_ADDR_STR_LEN);
    }

    DPRINT_INFO(WFA_OUT, "ping IPv4\n");
    i = 0;
    sprintf(cmd[i++], "%s", "-w");                   /* 指定超时间隔，单位为毫秒 */
    sprintf(cmd[i++], "%d", ping_interval);          /* ping packets inter */
    sprintf(cmd[i++], "%s", "-l");                   /* 发送包含由 length 指定的数据量的数据包 */
    sprintf(cmd[i++], "%d", ping_param->frameSize);  /* frame Size in bytes */

    if (total_packets == 0) {                        /* number of seconds to ping. 0 = continuous. */
        sprintf(cmd[i++], "%s", "-t");               /* ping forerver */
    } else {
        sprintf(cmd[i++], "%s", "-n");               /* 发送指定的数据包数 */
        sprintf(cmd[i++], "%d", total_packets);      /* send total packets: frameRate * duration */

    }
    sprintf(cmd[i++], "%s", ping_param->dipaddr);    /* IP address to send the pings */
    if (sigma_shell_ping(i, cmd) != WFA_SUCCESS) {
        DPRINT_INFO(WFA_OUT, "sigma_send_ping :: sigma_shell_ping is fail\n");
        return WFA_FAILED;
    }

    for (i = 0; i < PING_PARAM_MAX_NUM; i++) {
        free(cmd[i]);
    }
    return WFA_SUCCESS;
}

void sigma_stop_ping(dutCmdResponse_t *stop_ping_resp)
{
    char *cmd[] = {"-k"};  /* stop the current ping task */

    g_is_sigma_stop_ping_flag = 1;
    unsigned int ret = sigma_shell_ping(1, cmd);
    if (ret == WFA_SUCCESS) {
        hi_sem_wait(g_wait_ping_stop_sem, HI_SYS_WAIT_FOREVER);
    }

    stop_ping_resp->cmdru.pingStp.sendCnt = g_sigma_traffic_ping_pkt[0];
    stop_ping_resp->cmdru.pingStp.repliedCnt = g_sigma_traffic_ping_pkt[1];
}

static void sigma_ping_cmd(unsigned int p0, unsigned int p1, unsigned int p2, unsigned int p3)
{
    unsigned int destip = p0;
    unsigned int count = p1;
    unsigned int interval = p2;
    unsigned int data_len = p3;
    int ret;

    ret = sigma_ping_func(destip, count, interval, data_len);
    if (ret < 0) {
        printf("Ping cmd failed due some errors\n");
    }

    g_ping_taskid = -1;
}

int sigma_ping_func(unsigned int destip, unsigned int cnt, unsigned int interval, unsigned int data_len)
{
    struct sockaddr_in to;
    struct pbuf *pbuf_resp = NULL;
    struct icmp_echo_hdr *iecho = NULL;
    struct icmp_echo_hdr *iecho_resp = NULL;
    struct ip_hdr *iphdr_resp = NULL;
    char *data_buf = NULL;
    unsigned int timeout_flag = false;
    struct timeval time_val;
    fd_set read_set;
    unsigned int iecho_len, forever, intrvl, i;
    unsigned int succ_cnt = 0;
    unsigned int failed_cnt = 0;
    unsigned long long start_us, end_us, timout_end_us;
    int timout_ms, rtt, sfd;
    int ret = 0;
    short ip_hlen;

    iecho_len = sizeof(struct icmp_echo_hdr) + data_len;
    sfd = lwip_socket(PF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (sfd < 0) {
        perror("Ping socket create fail\n");
        return -1;
    }
    pbuf_resp = pbuf_alloc(PBUF_RAW, IP_HLEN + sizeof(struct icmp_echo_hdr), PBUF_RAM);
    if (pbuf_resp == NULL) {
        printf("Ping: pbuf_resp malloc failed\n");
        ret = -1;
        goto failure;
    }
    iecho = (struct icmp_echo_hdr *)mem_malloc(iecho_len);
    if (iecho == NULL) {
        printf("Ping: echo request malloc failed\n");
        ret = -1;
        goto failure;
    }

    to.sin_family = AF_INET;
    to.sin_addr.s_addr = destip; /* already in network order */
    to.sin_port = 0;

    if (data_len > 8) { /* 8: data_len */
        (void)memset_s(iecho, sizeof(struct icmp_echo_hdr) + 8, 0, sizeof(struct icmp_echo_hdr) + 8); /* 8: data_len */
        data_buf = (char *)iecho + sizeof(struct icmp_echo_hdr) + 8; /* 8: data_len */
        for (i = 0; i < data_len - 8; i++) { /* 8: data_len */
            *(data_buf + i) = i + 0x10;
        }
    } else {
        (void)memset_s(iecho, sizeof(struct icmp_echo_hdr) + data_len, 0, sizeof(struct icmp_echo_hdr) + data_len);
    }
    iecho->id = htons((u16_t)LOS_CurTaskIDGet());
    ICMPH_TYPE_SET(iecho, (u8_t)ICMP_ECHO);
    forever = (cnt ? 0 : 1);
    i = 0;
    while (!g_ping_kill && (forever || (i < cnt))) {
        iecho->seqno = htons((u16_t)i);
        iecho->chksum = 0;
        iecho->chksum = inet_chksum((void *)iecho, iecho_len);
        ret = sendto(sfd, iecho, iecho_len, 0, (struct sockaddr *)&to, (socklen_t)sizeof(to));
        if (ret < 0) {
            perror("Ping: sending ICMP echo request failed\n");
            g_sigma_traffic_ping_pkt[1] = 0; /* ping不通的时候需要将接收返回的个数变量清0 */
            goto failure;
        }

        /* capture the start ms to calculate RTT */
        start_us = hi_get_us();
        do {
            timeout_flag = false;
            /* Wait in select for ICMP response msg */
            FD_ZERO(&read_set);
            FD_SET(sfd, &read_set);
            time_val.tv_sec = LWIP_SHELL_CMD_PING_TIMEOUT / 1000; /* 1000 转换为S */
            time_val.tv_usec = 0;
            ret = lwip_select(sfd + 1, &read_set, 0, 0, &time_val);
            if (ret < 0) {
                printf("ping : poll/select failure\n");
                goto failure;
            } else if (ret == 0) {
                timeout_flag = true; /* first type timeout event */
                break;
            }
            /* construct timeout event if poll lose efficacy when other host ping us */
            ret = recv(sfd, pbuf_resp->payload, pbuf_resp->len, MSG_DONTWAIT);
            if (ret < 0) {
                perror("Ping: recv echo reply failed\n");
                goto failure;
            }

            iphdr_resp = pbuf_resp->payload; /* Accessing ip header and icmp header */
            ip_hlen = (IPH_HL(iphdr_resp) << 2); /* 2: 左移两位 */
            if (pbuf_header(pbuf_resp, -ip_hlen)) {
                /* this failure will never happen, but failure handle is written just to be in safe side */
                printf("Ping : memory management failure\n");
                goto failure;
            }
            iecho_resp = (struct icmp_echo_hdr *)pbuf_resp->payload;
            if (pbuf_header(pbuf_resp, ip_hlen)) { /* Reverting back pbuf to its original state */
                /* this failure will never happen, but failure handle is written just to be in safe side */
                printf("ping : memory management failure\n");
                goto failure;
            }

            if ((iphdr_resp->src.addr != to.sin_addr.s_addr) ||
                ((ICMPH_TYPE(iecho_resp) == ICMP_ECHO) && (iphdr_resp->src.addr == to.sin_addr.s_addr))) {
                /* second type timeout event */
                timout_end_us = hi_get_us();
                timout_ms = (s32_t)((timout_end_us / US_PER_MSECOND - start_us / US_PER_MSECOND));
                if (timout_ms < 0) {
                    timout_ms = (s32_t)(timout_end_us / US_PER_MSECOND + (0xFFFFFFFF - start_us / US_PER_MSECOND));
                }
                timout_ms = LWIP_SHELL_CMD_PING_TIMEOUT - timout_ms;
            } else {
                timout_ms = 0;
                break;
            }
        } while (timout_ms >= 0);

        if ((timout_ms < 0) || (timeout_flag == true)) { /* all timeout events are true timeout */
            failed_cnt++;
            i++;
            printf("\nPing: destination unreachable ...");
            continue;
        }

        end_us = hi_get_us(); /* capture the end ms to calculate round trip time */
        rtt = (s32_t)(end_us / US_PER_MSECOND - start_us / US_PER_MSECOND);
        if (rtt < 0) {
            rtt = (s32_t)(end_us / US_PER_MSECOND + (0xFFFFFFFF - start_us / US_PER_MSECOND));
        }
        if (iphdr_resp->src.addr == to.sin_addr.s_addr) {
            switch (ICMPH_TYPE(iecho_resp)) {
                case 0: /* 判断case 为0的分支 */
                    printf("\n[%u]Reply from %s: ", i, inet_ntoa(to.sin_addr));
                    if (rtt < 1) {
                        printf("time<1 ms ");
                    } else {
                        printf("time=%i ms ", rtt);
                    }
                    printf("TTL=%u", iphdr_resp->_ttl);

                    intrvl = interval; /* delay 1s for every successful ping */
                    do {
                        if (intrvl < 1000) { /* 1000 小于1000 */
                            sys_msleep(intrvl);
                            break;
                        }
                        intrvl -= 1000;    /* 1000 减1000 */
                        sys_msleep(1000);  /* 1000 延时1S */
                        if (g_ping_kill == 1) {
                            break;
                        }
                    }
                    while (intrvl > 0);
                    succ_cnt++;
                    break;
                default :
                    printf("\nPing: unknow error ...");
                    break;
            }
            i++;
        }
    }
    printf("\n--- %s ping statistics ---\n", inet_ntoa(to.sin_addr));
    printf("%u packets transmitted, %u received, %u loss\n", i, succ_cnt, failed_cnt);
    g_sigma_traffic_ping_pkt[0] = i;
    g_sigma_traffic_ping_pkt[1] = succ_cnt;
    if (g_ping_kill == 1) {
        if (g_is_sigma_stop_ping_flag == 1) {
            printf("\nstop ping by sigma cmd...\n");
            g_is_sigma_stop_ping_flag = 0;
            hi_sem_signal(g_wait_ping_stop_sem);
        }
    }

failure:
    g_ping_kill = 0;
    (void)lwip_close(sfd);
    if (pbuf_resp != NULL) {
        (void)pbuf_free(pbuf_resp);
    }
    if (iecho != NULL) {
        mem_free(iecho);
    }
    return ret;
}

unsigned int sigma_shell_ping(int argc, char **argv)
{
    int ret;
    unsigned int i = 0;
    unsigned int count = 0;
    unsigned int interval = 1000; /* 默认设为1000 */
    unsigned int data_len = 48;   /* 默认设为48 */
    ip4_addr_t dst_ipaddr;
    struct in_addr ip_addr;
    TSK_INIT_PARAM_S stPingTask;

    if ((argc < 1) || (argv == NULL)) {
        printf("Ping: require dest ipaddr at least \n");
        return LOS_NOK;
    }

    while (argc > 0) {  /* could add more param support */
        if (strcmp("-n", argv[i]) == 0 && (argc > 1)) {
            ret = atoi(argv[i + 1]);
            if (ret <= 0) {
                printf("Ping count should be greater than 0 \n");
                return LOS_NOK;
            }
            count = ret;
            i += 2;         /* 2: 参数计数加2 */
            argc -= 2;      /* 2: 参数减2 */
        } else if (strcmp("-t", argv[i]) == 0) {
            count = 0;      /* ping forerver */
            i++;
            argc--;
        } else if (strcmp("-w", argv[i]) == 0 && (argc > 1)) {
            ret = atoi(argv[i + 1]);
            if (ret <= 0) {
                printf("Ping interval should be greater than 0 \n");
                return LOS_NOK;
            }
            interval = ret;
            i += 2;       /* 2: 参数计数加2 */
            argc -= 2;    /* 2: 参数减2 */
        } else if (strcmp("-l", argv[i]) == 0 && (argc > 1)) {
            ret = atoi(argv[i + 1]);
            if (ret < 0 || ret > (int)(LWIP_MAX_UDP_RAW_SEND_SIZE - sizeof(struct icmp_echo_hdr))) {
                return LOS_NOK;
            }
            data_len = ret;
            i += 2;      /* 2: 参数计数加2 */
            argc -= 2;   /* 2: 参数减2 */
        } else if (strcmp("-k", argv[i]) == 0) {
            if (g_ping_taskid > 0) {
                g_ping_kill = 1; /* stop the current ping task */
                printf("+PING:\r\nOK\r\n");
                return LOS_OK;
            } else {
                return LOS_NOK;
            }
        } else {
            if (argc == 1) {
                break;
            } else {
                printf("Invalid Ping param\n");
                return LOS_NOK;
            }
        }
    }

    if (inet_aton(argv[i], &ip_addr) != 1) {
        printf("inet_aton failed\n");
        return LOS_NOK;
    }

    dst_ipaddr.addr = ip_addr.s_addr;
    if (dst_ipaddr.addr == IPADDR_NONE || dst_ipaddr.addr == IPADDR_ANY) {
        printf("Invalid dest ipaddr: %s\n", argv[i]);
        return LOS_NOK;
    }
    /* start one task if ping forever or ping count greater than 60 */
    if (count == 0 || count > LWIP_SHELL_CMD_PING_RETRY_TIMES) {
        if (g_ping_taskid > 0) {
            printf("Ping task already running and only support one now\n");
            return LOS_NOK;
        }
        stPingTask.pfnTaskEntry = (TSK_ENTRY_FUNC)sigma_ping_cmd;
        stPingTask.uwStackSize  = LOSCFG_BASE_CORE_TSK_DEFAULT_STACK_SIZE;
        stPingTask.pcName = "ping_task";
        stPingTask.usTaskPrio = 8; /* 8 higher than shell */
        stPingTask.uwResved = LOS_TASK_STATUS_DETACHED;
        stPingTask.auwArgs[0] = dst_ipaddr.addr; /* network order */
        stPingTask.auwArgs[1] = count;      /* 1 counter */
        stPingTask.auwArgs[2] = interval;   /* 2 interval */
        stPingTask.auwArgs[3] = data_len;   /* 3 data_len */
        ret = LOS_TaskCreate((UINT32 *)(&g_ping_taskid), &stPingTask);
        if (ret != LOS_OK) {
            printf("ping_task create failed 0x%08x.\n", ret);
            count = LWIP_SHELL_CMD_PING_RETRY_TIMES;
        }else {
            return LOS_OK;
        }
    }
    /* two cases: 1, ping cout less  than LWIP_SHELL_CMD_PING_RETRY_TIMES; 2, ping task create failed; */
    if (sigma_ping_func(dst_ipaddr.addr, count, interval, data_len) < 0) {
        return LOS_NOK;
    }

    return LOS_OK;
}

#ifdef __cplusplus
#if __cplusplus
    }
#endif
#endif

