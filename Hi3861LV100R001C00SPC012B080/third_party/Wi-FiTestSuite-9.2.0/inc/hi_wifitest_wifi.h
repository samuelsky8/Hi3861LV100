/*
 *Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2019. All rights reserved.
 *Description: sigma WiFi function
 *Create: 2019-04-25
 */

#ifndef __HI_WIFITEST_WIFI__
#define __HI_WIFITEST_WIFI__

#include "hi_wifi_api.h"

#define SIGMA_IPADDR_GET_LEN  16
#define SIGMA_DNS_GET_LEN     32
#define SIGMA_MAC_GET_LEN     1024
#define SIGMA_DHCP_STAT       256
#define ETH_ALEN              6
#define IFNAME_MAX_SIZE       16
#define STATUS_BUF_LEN_LIMIT  512
#define PING_PARAM_MAX_NUM    7

int sigma_start_hapd(char* ifname, int* length);
int sigma_set_macaddr(char *mac_addr_str);
int sigma_wpa_start(char *hw_mode);
void sigma_wpa_stop(void);
int sigma_wpa_connect(char *ifname);
void sigma_wpa_disconnect(void);
int sigma_get_ipaddr(char ipaddr_str[], int ipaddr_len, char mask_str[], int mask_len);
int sigma_get_dns(char dns_pri[], int pri_len, char dns_sec[], int sec_len);
int sigma_get_macaddr(char macaddr_str[], int str_len);
int sigma_start_dhcp(char *ifname);
int sigma_sta_set_ip(void);
int sigma_is_sta_connected(char *ifname);
int sigma_get_bssid(unsigned char str[], int str_len, char *ifname);
int sigma_send_ping(tgPingStart_t *ping_param, int ping_interval, int total_packets);
void sigma_stop_ping(dutCmdResponse_t *stop_ping_resp);
unsigned int sigma_shell_ping(int argc, char **argv);
int sigma_ping_func(unsigned int destip, unsigned int cnt, unsigned int interval, unsigned int data_len);
unsigned int str_to_addr(char *pc_param, unsigned char *puc_mac_addr);

#endif

