/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2013-2015. All rights reserved.
 * Description: declare shell cmds APIs
 * Author: none
 * Create: 2013
 */

#ifndef LWIP_API_SHELL_H
#define LWIP_API_SHELL_H

#include "lwip/opt.h"
#include "lwip/netif.h"
#if defined (__cplusplus) && __cplusplus
extern "C" {
#endif

struct ping_ctx {
  char              *dst_ip;
  u8_t               icmp_type;
  u8_t               icmp_code;
  u8_t               ttl;
  s32_t              rtt;
  s32_t              count;
  s32_t              len;
};

typedef void (*icmp_code_hander)(u8_t code, void *arg);

#ifdef CUSTOM_AT_COMMAND
typedef enum netstat_trans_type {
  TCP_IP6,
  TCP,
  UDP_IP6,
  UDP,
  RAW,
  PKT_RAW,
} netstat_trans_type;
#endif

u32_t lwip_ifconfig(int argc, const char **argv);
u32_t lwip_get_ipv4(char *localIp, unsigned char ipLen, unsigned char *ifname);
u32_t lwip_get_mac_addr(unsigned char *macAddr, unsigned int len, unsigned char *ifname);

u32_t lwip_ifstats(int argc, char **argv);
u32_t lwip_arp(int argc, char **argv);
u32_t at_lwip_arp(int argc, char **argv);
u32_t osShellNetIfUp(int argc, char **argv);
u32_t osShellNetIfDown(int argc, char **argv);
u32_t osShellPing(int argc, const char **argv);
u32_t osShellPingDfx(struct ping_ctx *ping_content);
#if LWIP_IPV6
u32_t osShellPing6(int argc, const char **argv);
#endif

#if LWIP_RPL || LWIP_RIPPLE
u32_t osShellRpl(int argc, char **argv);
u32_t osRteDebug(int argc, char **argv);
#endif

u32_t osShellTftp(int argc, char **argv);
#if LWIP_SNTP
u32_t osShellNtpdate(int argc, char **argv);
#endif
#if LWIP_DNS
#ifdef CUSTOM_AT_COMMAND
u32_t osShellshowDns(void);
#endif
u32_t osShellDns(int argc, const char **argv);
#endif /* LWIP_DNS */
#if LWIP_IPV4 && LWIP_IGMP
u32_t osShellIgmp(int argc, char **argv);
u32_t at_osShellIgmp(int argc, char **argv);
#endif /* LWIP_IPV4 && LWIP_IGMP */
#if (LWIP_IPV6 && (LWIP_IPV6_MLD || LWIP_IPV6_MLD_QUERIER))
u32_t os_shell_mld6(int argc, char **argv);
#endif /* (LWIP_IPV6 && (LWIP_IPV6_MLD || LWIP_IPV6_MLD_QUERIER)) */
#if LWIP_DHCP
u32_t osShellDhcp(int argc, const char **argv);
void dhcp_clients_info_show(struct netif *netif_p);
#if LWIP_DHCPS
u32_t osShellDhcps(int argc, const char **argv);
void dhcps_info_show(struct netif *netif);
#endif /* LWIP_DHCPS */
#endif /* LWIP_DHCP */
u32_t osShellNetstat(int argc, char **argv);

void netstat_internal(void *ctx);

u32_t os_shell_mcast6(int argc, char **argv);
#if LWIP_RIPPLE
u32_t os_shell_l2test(int argc, char **argv);
#endif /* LWIP_RIPPLE */

u32_t os_shell_netif(int argc, char **argv);

#if defined (__cplusplus) && __cplusplus
}
#endif

#endif

