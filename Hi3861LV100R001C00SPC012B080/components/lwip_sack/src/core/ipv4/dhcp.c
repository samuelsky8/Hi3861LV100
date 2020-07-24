/**
 * @file
 * Dynamic Host Configuration Protocol client
 *
 * @defgroup dhcp4 DHCPv4
 * @ingroup ip4
 * DHCP (IPv4) related functions
 * This is a DHCP client for the lwIP TCP/IP stack. It aims to conform
 * with RFC 2131 and RFC 2132.
 *
 * @todo:
 * - Support for interfaces other than Ethernet (SLIP, PPP, ...)
 *
 * Options:
 * @ref DHCP_COARSE_TIMER_SECS (recommended 60 which is a minute)
 * @ref DHCP_FINE_TIMER_MSECS (recommended 500 which equals TCP coarse timer)
 *
 * dhcp_start() starts a DHCP client instance which
 * configures the interface by obtaining an IP address lease and maintaining it.
 *
 * Use dhcp_release() to end the lease and use dhcp_stop()
 * to remove the DHCP client.
 *
 * @see netifapi_dhcp4
 */

/*
 * Copyright (c) 2001-2004 Leon Woestenberg <leon.woestenberg@gmx.net>
 * Copyright (c) 2001-2004 Axon Digital Design B.V., The Netherlands.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT
 * SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT
 * OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
 * IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY
 * OF SUCH DAMAGE.
 *
 * This file is part of the lwIP TCP/IP stack.
 * The Swedish Institute of Computer Science and Adam Dunkels
 * are specifically granted permission to redistribute this
 * source code.
 *
 * Author: Leon Woestenberg <leon.woestenberg@gmx.net>
 *
 */

#include "lwip/opt.h"

#if LWIP_IPV4 && LWIP_DHCP /* don't build if not configured for use in lwipopts.h */

#include "lwip/stats.h"
#include "lwip/mem.h"
#include "lwip/udp.h"
#include "lwip/ip_addr.h"
#include "lwip/netif.h"
#include "lwip/def.h"
#include "lwip/dhcp.h"
#include "lwip/autoip.h"
#include "lwip/dns.h"
#include "lwip/etharp.h"
#include "lwip/prot/dhcp.h"
#if LWIP_NAT64
#include "lwip/nat64_v4_dhcpc.h"
#include "lwip/nat64_addr.h"
#include "lwip/nat64.h"
#endif

#if LWIP_RPL || LWIP_RIPPLE
#include "lwip/lwip_rpl.h"
#endif

#if LWIP_DHCP_COAP_RELAY
#include "dhcp_coap.h"
#endif

#include <string.h>

/** DHCP_CREATE_RAND_XID: if this is set to 1, the xid is created using
 * LWIP_RAND() (this overrides DHCP_GLOBAL_XID)
 */
#ifndef DHCP_CREATE_RAND_XID
#define DHCP_CREATE_RAND_XID        1
#endif

/** Default for DHCP_GLOBAL_XID is 0xABCD0000
 * This can be changed by defining DHCP_GLOBAL_XID and DHCP_GLOBAL_XID_HEADER, e.g.
 *  \#define DHCP_GLOBAL_XID_HEADER "stdlib.h"
 *  \#define DHCP_GLOBAL_XID rand()
 */
#ifdef DHCP_GLOBAL_XID_HEADER
#include DHCP_GLOBAL_XID_HEADER /* include optional starting XID generation prototypes */
#endif

/** Holds the decoded option values, only valid while in dhcp_recv.
    @todo: move this into struct dhcp? */
u32_t dhcp_rx_options_val[DHCP_OPTION_IDX_MAX];
/** Holds a flag which option was received and is contained in dhcp_rx_options_val,
    only valid while in dhcp_recv.
    @todo: move this into struct dhcp? */
u8_t  dhcp_rx_options_given[DHCP_OPTION_IDX_MAX];

static u8_t dhcp_discover_request_options[] = {
  DHCP_OPTION_SUBNET_MASK,
  DHCP_OPTION_ROUTER,
  DHCP_OPTION_BROADCAST
#if LWIP_DHCP_PROVIDE_DNS_SERVERS
  , DHCP_OPTION_DNS_SERVER
#endif /* LWIP_DHCP_PROVIDE_DNS_SERVERS */
#if LWIP_DHCP_GET_NTP_SRV
  , DHCP_OPTION_NTP
#endif /* LWIP_DHCP_GET_NTP_SRV */
};

#ifdef DHCP_GLOBAL_XID
static u32_t xid;
static u8_t xid_initialised;
#endif /* DHCP_GLOBAL_XID */

#if LWIP_DHCP_VENDOR_CLASS_IDENTIFIER
LWIP_STATIC struct vci_info g_vci_info = {{0}, 0, {0}};
#endif /* LWIP_DHCP_VENDOR_CLASS_IDENTIFIER */

#define dhcp_option_given(dhcp, idx)          (dhcp_rx_options_given[idx] != 0)
#define dhcp_got_option(dhcp, idx)            (dhcp_rx_options_given[idx] = 1)
#define dhcp_clear_option(dhcp, idx)          (dhcp_rx_options_given[idx] = 0)
#define dhcp_clear_all_options(dhcp)          ((void)memset(dhcp_rx_options_given, 0, sizeof(dhcp_rx_options_given)))
#define dhcp_get_option_value(dhcp, idx)      (dhcp_rx_options_val[idx])
#define dhcp_set_option_value(dhcp, idx, val) (dhcp_rx_options_val[idx] = (val))

struct udp_pcb *dhcp_pcb;
static u8_t dhcp_pcb_refcount;

static err_t dhcp_release_client(struct netif *netif, struct dhcp_client *dhcp);
static err_t dhcp_renew_client(struct netif *netif, struct dhcp_client *dhcp);
static void dhcp_stop_client(struct netif *netif, struct dhcp_client *dhcp);

#if LWIP_DHCP_SUBSTITUTE
static void dhcp_substitute_clients_restart(struct netif *netif, struct dhcp_client *dhcp);
static s32_t dhcp_addr_clients_check(struct dhcp *netif_dhcp, const ip4_addr_t *ipaddr);
#endif /* LWIP_DHCP_SUBSTITUTE */

/* DHCP client state machine functions */
static err_t dhcp_discover(struct netif *netif, struct dhcp_client *dhcp);
static err_t dhcp_select(struct netif *netif, struct dhcp_client *dhcp);
static void dhcp_bind(struct netif *netif, struct dhcp_client *dhcp);
#if DHCP_DOES_ARP_CHECK
static err_t dhcp_decline(struct netif *netif, struct dhcp_client *dhcp);
#endif /* DHCP_DOES_ARP_CHECK */
static err_t dhcp_rebind(struct netif *netif, struct dhcp_client *dhcp);
static err_t dhcp_reboot(struct netif *netif);
static void dhcp_set_state(struct dhcp_client *dhcp, u8_t new_state);

/* receive, unfold, parse and free incoming messages */
static void dhcp_recv(void *arg, struct udp_pcb *pcb, struct pbuf *p, const ip_addr_t *addr, u16_t port);

/* set the DHCP timers */
static void dhcp_timeout(struct netif *netif, struct dhcp_client *dhcp);
static void dhcp_t1_timeout(struct netif *netif, struct dhcp_client *dhcp);
static void dhcp_t2_timeout(struct netif *netif, struct dhcp_client *dhcp);

/* build outgoing messages */
/* create a DHCP message, fill in common headers */
static err_t dhcp_create_msg(struct netif *netif, struct dhcp_client *dhcp, u8_t message_type);
/* free a DHCP request */
static void dhcp_delete_msg(struct dhcp_client *dhcp);
/* add a DHCP option (type, then length in bytes) */
static void dhcp_option(struct dhcp_client *dhcp, u8_t option_type, u8_t option_len);
/* add option values */
static void dhcp_option_byte(struct dhcp_client *dhcp, u8_t value);
static void dhcp_option_short(struct dhcp_client *dhcp, u16_t value);
static void dhcp_option_long(struct dhcp_client *dhcp, u32_t value);
#if LWIP_NETIF_HOSTNAME
static void dhcp_option_hostname(struct dhcp_client *dhcp, struct netif *netif);
#endif /* LWIP_NETIF_HOSTNAME */

#if LWIP_DHCP_VENDOR_CLASS_IDENTIFIER
LWIP_STATIC void dhcp_option_vci(struct dhcp_client *dhcp, struct netif *netif);
#endif /* LWIP_DHCP_VENDOR_CLASS_IDENTIFIER */

/* always add the DHCP options trailer to end and pad */
static void dhcp_option_trailer(struct dhcp_client *dhcp);

/* Ensure DHCP PCB is allocated and bound */
static err_t
dhcp_inc_pcb_refcount(struct netif *netif)
{
  if (dhcp_pcb_refcount == 0) {
    LWIP_ASSERT("dhcp_inc_pcb_refcount(): memory leak", dhcp_pcb == NULL);

    /* allocate UDP PCB */
    dhcp_pcb = udp_new();
    if (dhcp_pcb == NULL) {
      return ERR_MEM;
    }

#if LWIP_SO_PRIORITY
    dhcp_pcb->priority = LWIP_PKT_PRIORITY_DHCP;
#endif /* LWIP_SO_PRIORITY */

    ip_set_option(dhcp_pcb, SOF_BROADCAST);

#if LWIP_SO_BINDTODEVICE
    /* bind dhcp udp_pcb to specific netif, this could make dhcp client start on multiple netif */
    dhcp_pcb->ifindex = netif->ifindex;
#else
    (void)netif;
#endif

    /* set up local and remote port for the pcb -> listen on all interfaces on all src/dest IPs */
    (void)udp_bind(dhcp_pcb, IP4_ADDR_ANY, DHCP_CLIENT_PORT);
    (void)udp_connect(dhcp_pcb, IP4_ADDR_ANY, DHCP_SERVER_PORT);
    udp_recv(dhcp_pcb, dhcp_recv, NULL);
  }

  dhcp_pcb_refcount++;

  return ERR_OK;
}

/* Free DHCP PCB if the last netif stops using it */
static void
dhcp_dec_pcb_refcount(void)
{
  LWIP_ASSERT("dhcp_pcb_refcount(): refcount error", (dhcp_pcb_refcount > 0));
  dhcp_pcb_refcount--;

  if (dhcp_pcb_refcount == 0) {
    udp_remove(dhcp_pcb);
    dhcp_pcb = NULL;
  }
}

static void
dhcp_ip_to_mask(ip4_addr_t *server_ip_addr, ip4_addr_t *sn_mask)
{
  u8_t first_octet = ip4_addr1(server_ip_addr);
  if (first_octet <= IPV4_ADDRESS_PREFIX_CLASS_A) {
    ip4_addr_set_u32(sn_mask, PP_HTONL(0xff000000UL));
  } else if (first_octet >= IPV4_ADDRESS_PREFIX_CLASS_C) {
    ip4_addr_set_u32(sn_mask, PP_HTONL(0xffffff00UL));
  } else {
    ip4_addr_set_u32(sn_mask, PP_HTONL(0xffff0000UL));
  }

  return;
}

static err_t
dhcp_mac_to_idx(struct netif *netif, const u8_t *hwaddr,
                u8_t hwaddr_len, dhcp_num_t *mac_idx)
{
  if ((netif->hwaddr_len == hwaddr_len) && (memcmp(netif->hwaddr, hwaddr, hwaddr_len) == 0)) {
    *mac_idx = LWIP_DHCP_NATIVE_IDX;
    return ERR_OK;
  }

#if LWIP_DHCP_SUBSTITUTE && LWIP_NAT64
  return nat64_entry_mac_to_idx(hwaddr, hwaddr_len, mac_idx);
#else
  return ERR_VAL;
#endif /* LWIP_DHCP_SUBSTITUTE && LWIP_NAT64 */
}

err_t
dhcp_idx_to_mac(struct netif *netif, dhcp_num_t mac_idx,
                u8_t *hwaddr, u8_t *hwaddr_len)
{
  if ((hwaddr == NULL) || (hwaddr_len == NULL)) {
    return ERR_VAL;
  }
  if (mac_idx == LWIP_DHCP_NATIVE_IDX) {
    if (memcpy_s(hwaddr, NETIF_MAX_HWADDR_LEN, netif->hwaddr, NETIF_MAX_HWADDR_LEN) != EOK) {
      LWIP_DEBUGF(DHCP_DEBUG | LWIP_DBG_TRACE | LWIP_DBG_LEVEL_WARNING, ("dhcp_idx_to_mac:memcpy failed\n"));
      return ERR_MEM;
    }
    *hwaddr_len = netif->hwaddr_len;
    return ERR_OK;
  }

#if LWIP_DHCP_SUBSTITUTE && LWIP_NAT64
  u8_t hw_len = NETIF_MAX_HWADDR_LEN;
  if (nat64_entry_idx_to_mac(mac_idx, hwaddr, &hw_len) == ERR_OK) {
    *hwaddr_len = hw_len;
    return ERR_OK;
  }
#endif /* LWIP_DHCP_SUBSTITUTE && LWIP_NAT64 */
  LWIP_DEBUGF(DHCP_DEBUG | LWIP_DBG_TRACE | LWIP_DBG_LEVEL_WARNING, ("dhcp_idx_to_mac:not find in nat64\n"));
  return ERR_VAL;
}

static err_t
dhcp_client_find_by_mac_idx(struct dhcp_client *dhcp, dhcp_num_t mac_idx, dhcp_num_t *cli_idx)
{
  int i;

  for (i = 0; i < DHCP_CLIENT_NUM; i++) {
    if ((dhcp->states)[i].idx == mac_idx) {
      *cli_idx = (dhcp_num_t)i;
      return ERR_OK;
    }
  }

  return ERR_VAL;
}

static err_t
dhcp_client_state_new(struct dhcp_client *dhcp, dhcp_num_t mac_idx, dhcp_num_t *cli_idx)
{
  int i;

  if (dhcp->cli_cnt == DHCP_CLIENT_NUM) {
    LWIP_DEBUGF(DHCP_DEBUG | LWIP_DBG_TRACE, ("dhcp_client_state_new:max cnt\n"));
    return ERR_VAL;
  }

  for (i = 1; i < DHCP_CLIENT_NUM; i++) {
    if ((dhcp->states)[i].idx == 0) {
      *cli_idx = (dhcp_num_t)i;
      (dhcp->states)[i].idx = mac_idx;
      return ERR_OK;
    }
  }

  return ERR_VAL;
}

static void
dhcp_clients_count_update(struct dhcp_client *dhcp)
{
  int i;
  dhcp_num_t cnt = 0;

  for (i = 0; i < DHCP_CLIENT_NUM; i++) {
    if ((dhcp->states)[i].hwaddr_len != 0) {
      cnt++;
    }
  }

  dhcp->cli_cnt = cnt;
  return;
}

/**
 * Back-off the DHCP client (because of a received NAK response).
 *
 * Back-off the DHCP client because of a received NAK. Receiving a
 * NAK means the client asked for something non-sensible, for
 * example when it tries to renew a lease obtained on another network.
 *
 * We clear any existing set IP address and restart DHCP negotiation
 * afresh (as per RFC2131 3.2.3).
 *
 * @param netif the netif under DHCP control
 */
static void
dhcp_handle_nak(struct netif *netif, struct dhcp_client *dhcp)
{
  LWIP_DEBUGF(DHCP_DEBUG | LWIP_DBG_TRACE, ("dhcp_handle_nak(netif=%p) %c%c%"U16_F"\n",
                                            (void *)netif, netif->name[0], netif->name[1], (u16_t)netif->num));
  /* Change to a defined state - set this before assigning the address
     to ensure the callback can use dhcp_supplied_address() */
  dhcp_set_state(dhcp, DHCP_STATE_BACKING_OFF);
  /* remove IP address from interface (must no longer be used, as per RFC2131) */
  if (dhcp->cli_idx == LWIP_DHCP_NATIVE_IDX) {
    (void)netif_set_addr(netif, IP4_ADDR_ANY4, IP4_ADDR_ANY4, IP4_ADDR_ANY4);
  }
  /* We can immediately restart discovery */
  (void)dhcp_discover(netif, dhcp);
}

#if DHCP_DOES_ARP_CHECK
/**
 * Checks if the offered IP address is already in use.
 *
 * It does so by sending an ARP request for the offered address and
 * entering CHECKING state. If no ARP reply is received within a small
 * interval, the address is assumed to be free for use by us.
 *
 * @param netif the netif under DHCP control
 */
static void
dhcp_check(struct netif *netif, struct dhcp_client *dhcp)
{
  err_t result;
  u16_t msecs;
  struct dhcp_state *dhcp_state = &((dhcp->states)[dhcp->cli_idx]);
  ip4_addr_t cli_ip;
  LWIP_DEBUGF(DHCP_DEBUG | LWIP_DBG_TRACE, ("dhcp_check(netif=%p) %c%c\n", (void *)netif, (s16_t)netif->name[0],
                                            (s16_t)netif->name[1]));
  dhcp_set_state(dhcp, DHCP_STATE_CHECKING);
  DHCP_HOST_TO_IP(cli_ip.addr, ip_2_ip4(&dhcp->server_ip_addr)->addr, dhcp->offered_sn_mask.addr,
                  dhcp_state->offered_ip_addr);
  /* create an ARP query for the offered IP address, expecting that no host
     responds, as the IP address should not be in use. */
  result = etharp_query(netif, &cli_ip, NULL);
  if (result != ERR_OK) {
    LWIP_DEBUGF(DHCP_DEBUG | LWIP_DBG_TRACE | LWIP_DBG_LEVEL_WARNING, ("dhcp_check: could not perform ARP query\n"));
  }
  if (dhcp_state->tries < 255) {
    dhcp_state->tries++;
  }
  msecs = 500;
  dhcp_state->request_timeout = (u16_t)((msecs + DHCP_FINE_TIMER_MSECS - 1) / DHCP_FINE_TIMER_MSECS);
  LWIP_DEBUGF(DHCP_DEBUG | LWIP_DBG_TRACE | LWIP_DBG_STATE, ("dhcp_check(): set request timeout %"U16_F" msecs\n",
                                                             msecs));
}
#endif /* DHCP_DOES_ARP_CHECK */

/**
 * Remember the configuration offered by a DHCP server.
 *
 * @param netif the netif under DHCP control
 */
static void
dhcp_handle_offer(struct netif *netif, struct dhcp_client *dhcp)
{
  struct dhcp_state *dhcp_state = &((dhcp->states)[dhcp->cli_idx]);
  ip4_addr_t cli_ip;
  LWIP_DEBUGF(DHCP_DEBUG | LWIP_DBG_TRACE, ("dhcp_handle_offer(netif=%p) %c%c%"U16_F"\n",
                                            (void *)netif, netif->name[0], netif->name[1], (u16_t)netif->num));
  /* obtain the server address */
  if (dhcp_option_given(dhcp, DHCP_OPTION_IDX_SERVER_ID)) {
    dhcp_state->request_timeout = 0; /* stop timer , Stop timeout only if offer is accepted */
    ip_addr_set_ip4_u32(&dhcp->server_ip_addr, lwip_htonl(dhcp_get_option_value(dhcp, DHCP_OPTION_IDX_SERVER_ID)));
    LWIP_DEBUGF(DHCP_DEBUG | LWIP_DBG_STATE, ("dhcp_handle_offer(): server 0x%08"X32_F"\n",
                                              ip4_addr_get_u32(ip_2_ip4(&dhcp->server_ip_addr))));
    if (dhcp_option_given(dhcp, DHCP_OPTION_IDX_SUBNET_MASK)) {
      ip4_addr_set_u32(&dhcp->offered_sn_mask, lwip_htonl(dhcp_get_option_value(dhcp, DHCP_OPTION_IDX_SUBNET_MASK)));
    } else {
      dhcp_ip_to_mask(ip_2_ip4(&dhcp->server_ip_addr), &dhcp->offered_sn_mask);
    }
    /* remember offered address */
    ip4_addr_copy(cli_ip, dhcp->msg_in->yiaddr);
    LWIP_DEBUGF(DHCP_DEBUG | LWIP_DBG_STATE, ("dhcp_handle_offer(): offer for 0x%08"X32_F"\n",
                                              ip4_addr_get_u32(&cli_ip)));
    DHCP_IP_TO_HOST(dhcp_state->offered_ip_addr, cli_ip.addr, dhcp->offered_sn_mask.addr);
#if LWIP_DHCP_REQUEST_UNICAST
    ip4_addr_copy(dhcp->relay_ip, dhcp->msg_in->giaddr);
#endif
    (void)dhcp_select(netif, dhcp);
  } else {
    LWIP_DEBUGF(DHCP_DEBUG | LWIP_DBG_TRACE | LWIP_DBG_LEVEL_SERIOUS,
                ("dhcp_handle_offer(netif=%p) did not get server ID!\n", (void *)netif));
  }
}

/**
 * Select a DHCP server offer out of all offers.
 *
 * Simply select the first offer received.
 *
 * @param netif the netif under DHCP control
 * @return lwIP specific error (see error.h)
 */
static err_t
dhcp_select(struct netif *netif, struct dhcp_client *dhcp)
{
  err_t result;
  u16_t msecs;
  u8_t i;
  ip4_addr_t cli_ip;
  struct dhcp_state *dhcp_state = &((dhcp->states)[dhcp->cli_idx]);
#if LWIP_DHCP_REQUEST_UNICAST
  ip_addr_t unicast_ip_addr;
#endif

  LWIP_DEBUGF(DHCP_DEBUG | LWIP_DBG_TRACE, ("dhcp_select(netif=%p) %c%c%"U16_F"\n", (void *)netif, netif->name[0],
                                            netif->name[1], (u16_t)netif->num));
  dhcp_set_state(dhcp, DHCP_STATE_REQUESTING);

  /* create and initialize the DHCP message header */
  result = dhcp_create_msg(netif, dhcp, DHCP_REQUEST);
  if (result == ERR_OK) {
    dhcp_option(dhcp, DHCP_OPTION_MAX_MSG_SIZE, DHCP_OPTION_MAX_MSG_SIZE_LEN);
    dhcp_option_short(dhcp, DHCP_MAX_MSG_LEN(netif));

    /* MUST request the offered IP address */
    dhcp_option(dhcp, DHCP_OPTION_REQUESTED_IP, 4);
    DHCP_HOST_TO_IP(cli_ip.addr, ip_2_ip4(&dhcp->server_ip_addr)->addr, dhcp->offered_sn_mask.addr,
                    dhcp_state->offered_ip_addr);
    dhcp_option_long(dhcp, lwip_ntohl(cli_ip.addr));

    dhcp_option(dhcp, DHCP_OPTION_SERVER_ID, 4);
    dhcp_option_long(dhcp, lwip_ntohl(ip4_addr_get_u32(ip_2_ip4(&dhcp->server_ip_addr))));

    dhcp_option(dhcp, DHCP_OPTION_CLIENT_ID, 1 + dhcp_state->hwaddr_len);
    dhcp_option_byte(dhcp, dhcp->msg_out->htype);
    for (i = 0; i < dhcp_state->hwaddr_len; i++) {
      dhcp_option_byte(dhcp, dhcp->hwaddr[i]);
    }

    dhcp_option(dhcp, DHCP_OPTION_PARAMETER_REQUEST_LIST, LWIP_ARRAYSIZE(dhcp_discover_request_options));
    for (i = 0; i < LWIP_ARRAYSIZE(dhcp_discover_request_options); i++) {
      dhcp_option_byte(dhcp, dhcp_discover_request_options[i]);
    }

#if LWIP_NETIF_HOSTNAME
    dhcp_option_hostname(dhcp, netif);
#endif /* LWIP_NETIF_HOSTNAME */

#if LWIP_DHCP_VENDOR_CLASS_IDENTIFIER
    dhcp_option_vci(dhcp, netif);
#endif /* LWIP_DHCP_VENDOR_CLASS_IDENTIFIER */

    dhcp_option_trailer(dhcp);
    /* shrink the pbuf to the actual content length */
    pbuf_realloc(dhcp->p_out, (u16_t)((sizeof(struct dhcp_msg) - DHCP_OPTIONS_LEN) + dhcp->options_out_len));

#if LWIP_DHCP_REQUEST_UNICAST
    if (dhcp->relay_ip.addr != 0) {
      ip_addr_set_ip4_u32_val(&unicast_ip_addr, (u32_t)(dhcp->relay_ip.addr));
      LWIP_DEBUGF(DHCP_DEBUG | LWIP_DBG_TRACE | LWIP_DBG_STATE, ("dhcp_select: UNICAST relay\n"));
    } else {
      ip_addr_set_ip4_u32(&unicast_ip_addr, ip4_addr_get_u32(ip_2_ip4(&dhcp->server_ip_addr)));
      LWIP_DEBUGF(DHCP_DEBUG | LWIP_DBG_TRACE | LWIP_DBG_STATE, ("dhcp_select: UNICAST serv\n"));
    }
    (void)udp_sendto_if_src(dhcp_pcb, dhcp->p_out, &unicast_ip_addr, DHCP_SERVER_PORT, netif, IP4_ADDR_ANY);
#else
    /* send broadcast to any DHCP server */
    (void)udp_sendto_if_src(dhcp_pcb, dhcp->p_out, IP_ADDR_BROADCAST, DHCP_SERVER_PORT, netif, IP4_ADDR_ANY);
#endif
    dhcp_delete_msg(dhcp);
    LWIP_DEBUGF(DHCP_DEBUG | LWIP_DBG_TRACE | LWIP_DBG_STATE, ("dhcp_select: REQUESTING\n"));
  } else {
    LWIP_DEBUGF(DHCP_DEBUG | LWIP_DBG_TRACE | LWIP_DBG_LEVEL_WARNING,
                ("dhcp_select: could not allocate DHCP request\n"));
  }
  if (dhcp_state->tries < 255) {
    dhcp_state->tries++;
  }
  msecs = (u16_t)((dhcp_state->tries < 6 ? 1UL << dhcp_state->tries : 60) * 1000);
  dhcp_state->request_timeout = (u16_t)((msecs + DHCP_FINE_TIMER_MSECS - 1) / DHCP_FINE_TIMER_MSECS);
  LWIP_DEBUGF(DHCP_DEBUG | LWIP_DBG_STATE, ("dhcp_select(): set request timeout %"U16_F" msecs\n", msecs));
  return result;
}

static void
dhcp_client_coarse_tmr(struct netif *netif, struct dhcp_client *dhcp)
{
  struct dhcp_state *dhcp_state = &((dhcp->states)[dhcp->cli_idx]);

  if ((dhcp_state->state == DHCP_STATE_OFF)) {
    return;
  }

  /* compare lease time to expire timeout */
  if ((dhcp->t0_timeout != 0) && (++dhcp_state->lease_used >= dhcp->t0_timeout)) {
    LWIP_DEBUGF(DHCP_DEBUG | LWIP_DBG_TRACE | LWIP_DBG_STATE, ("dhcp_coarse_tmr(): t0 timeout\n"));
    /* this clients' lease time has expired */
    if (dhcp->cli_idx == LWIP_DHCP_NATIVE_IDX) {
      (void)dhcp_release(netif);
    } else {
      (void)dhcp_release_client(netif, dhcp);
    }
    (void)dhcp_discover(netif, dhcp);
    /* timer is active (non zero), and triggers (zeroes) now? */
  } else if ((dhcp->t2_timeout != 0) && (dhcp_state->lease_used >= dhcp->t2_timeout)) {
    if ((dhcp_state->re_time == 0) || (dhcp_state->re_time-- != 1)) {
      return;
    }
    LWIP_DEBUGF(DHCP_DEBUG | LWIP_DBG_TRACE | LWIP_DBG_STATE, ("dhcp_coarse_tmr(): t2 timeout\n"));
    /* this clients' rebind timeout triggered */
    dhcp_t2_timeout(netif, dhcp);
    /* timer is active (non zero), and triggers (zeroes) now */
  } else if ((dhcp->t1_timeout != 0) && (dhcp_state->re_time != 0) && (dhcp_state->re_time-- == 1)) {
    LWIP_DEBUGF(DHCP_DEBUG | LWIP_DBG_TRACE | LWIP_DBG_STATE, ("dhcp_coarse_tmr(): t1 timeout\n"));
    /* this clients' renewal timeout triggered */
    dhcp_t1_timeout(netif, dhcp);
  }

  return;
}

static void
dhcp_netif_coarse_tmr(struct netif *netif, struct dhcp *netif_dhcp)
{
  struct dhcp_state *dhcp_state = NULL;
  int i;
  u8_t hwaddr_len;

  for (i = 0; i < DHCP_CLIENT_NUM; i++) {
    netif_dhcp->client.cli_idx = (dhcp_num_t)i;
    dhcp_state = &((netif_dhcp->client.states)[i]);
    if ((i != LWIP_DHCP_NATIVE_IDX) && (dhcp_state->idx == 0)) {
      continue;
    }
    if (dhcp_idx_to_mac(netif, dhcp_state->idx, netif_dhcp->client.hwaddr, &hwaddr_len) != ERR_OK) {
      LWIP_DEBUGF(DHCP_DEBUG | LWIP_DBG_TRACE | LWIP_DBG_LEVEL_WARNING,
                  ("dhcp_netif_coarse_tmr:idx %u to mac failed\n", dhcp_state->idx));
      continue;
    }
    dhcp_state->hwaddr_len = hwaddr_len;
    dhcp_client_coarse_tmr(netif, &(netif_dhcp->client));
  }

  return;
}

/**
 * The DHCP timer that checks for lease renewal/rebind timeouts.
 * Must be called once a minute (see @ref DHCP_COARSE_TIMER_SECS).
 */
void
dhcp_coarse_tmr(void)
{
  struct netif *netif = netif_list;
  LWIP_DEBUGF(DHCP_DEBUG | LWIP_DBG_TRACE, ("dhcp_coarse_tmr()\n"));
  /* iterate through all network interfaces */
  while (netif != NULL) {
    /* only act on DHCP configured interfaces */
    struct dhcp *netif_dhcp = netif_dhcp_data(netif);
    if (netif_dhcp != NULL) {
      dhcp_netif_coarse_tmr(netif, netif_dhcp);
    }
    /* proceed to next netif */
    netif = netif->next;
  }
}

#if LWIP_LOWPOWER
#include "lwip/lowpower.h"

static u32_t
dhcp_netif_coarse_tmr_tick(struct dhcp *netif_dhcp)
{
  struct dhcp_state *dhcp_state = NULL;
  struct dhcp_client *client = NULL;
  s32_t i;
  u32_t tick = 0;
  u32_t val;
  u16_t lease_used;

  for (i = 0; i < DHCP_CLIENT_NUM; i++) {
    dhcp_state = &((netif_dhcp->client.states)[i]);
    if ((i != LWIP_DHCP_NATIVE_IDX) && (dhcp_state->idx == 0)) {
      continue;
    }
    if ((dhcp_state->state == DHCP_STATE_OFF)) {
      continue;
    }

    client = &(netif_dhcp->client);
    lease_used = dhcp_state->lease_used;
    if (client->t0_timeout > 0) {
      if (client->t0_timeout > lease_used) {
        val = client->t0_timeout - lease_used;
        SET_TMR_TICK(tick, val);
      } else {
        SET_TMR_TICK(tick, 1);
      }
    }

    if (client->t2_timeout > 0) {
      if (client->t2_timeout > lease_used) {
        val = (client->t2_timeout - lease_used);
        SET_TMR_TICK(tick, val);
      } else if (dhcp_state->re_time > 0) {
        val = dhcp_state->re_time;
        SET_TMR_TICK(tick, val);
      } else {
        SET_TMR_TICK(tick, 1);
      }
    }

    if (dhcp_state->re_time > 0) {
      val = dhcp_state->re_time;
      SET_TMR_TICK(tick, val);
    }
  }

  return tick;
}

u32_t
dhcp_coarse_tmr_tick(void)
{
  struct netif *netif = netif_list;
  u32_t tick = 0;
  u32_t val;

  while (netif != NULL) {
    /* only act on DHCP configured interfaces */
    struct dhcp *netif_dhcp = netif_dhcp_data(netif);
    if (netif_dhcp == NULL) {
      /* proceed to next netif */
      netif = netif->next;
      continue;
    }
    val = dhcp_netif_coarse_tmr_tick(netif_dhcp);
    SET_TMR_TICK(tick, val);
    /* proceed to next netif */
    netif = netif->next;
  }

  LOWPOER_DEBUG(("%s tmr tick: %u\n", __func__, tick));
  return tick;
}

u32_t
dhcp_fine_tmr_tick(void)
{
  struct netif *netif = netif_list;
  struct dhcp_state *dhcp_state = NULL;
  int i;
  u32_t tick = 0;
  u32_t val;

  /* loop through netif's */
  while (netif != NULL) {
    struct dhcp *netif_dhcp = netif_dhcp_data(netif);
    if (netif_dhcp == NULL) {
      netif = netif->next;
      continue;
    }

    for (i = 0; i < DHCP_CLIENT_NUM; i++) {
      dhcp_state = &((netif_dhcp->client.states)[i]);
      if ((i != LWIP_DHCP_NATIVE_IDX) && (dhcp_state->idx == 0)) {
        continue;
      }
      if (dhcp_state->request_timeout >= 1) {
        val = dhcp_state->request_timeout;
        SET_TMR_TICK(tick, val);
      }
    }
    /* proceed to next network interface */
    netif = netif->next;
  }
  LOWPOER_DEBUG(("%s tmr tick: %d\n", __func__, tick));
  return tick;
}
#endif

static void
dhcp_client_fine_tmr(struct netif *netif, struct dhcp_client *dhcp)
{
  struct dhcp_state *dhcp_state = &((dhcp->states)[dhcp->cli_idx]);
  /* timer is active (non zero), and is about to trigger now */
  if (dhcp_state->request_timeout > 1) {
    dhcp_state->request_timeout--;
  } else if (dhcp_state->request_timeout == 1) {
    dhcp_state->request_timeout--;
    LWIP_DEBUGF(DHCP_DEBUG | LWIP_DBG_TRACE | LWIP_DBG_STATE, ("dhcp_fine_tmr(): request timeout\n"));
    /* this client's request timeout triggered */
    dhcp_timeout(netif, dhcp);
  }

  return;
}

static void
dhcp_netif_fine_tmr(struct netif *netif, struct dhcp *netif_dhcp)
{
  struct dhcp_state *dhcp_state = NULL;
  int i;
  u8_t hwaddr_len;

  for (i = 0; i < DHCP_CLIENT_NUM; i++) {
    netif_dhcp->client.cli_idx = (dhcp_num_t)i;
    dhcp_state = &((netif_dhcp->client.states)[i]);
    if ((i != LWIP_DHCP_NATIVE_IDX) && (dhcp_state->idx == 0)) {
      continue;
    }
    if (dhcp_idx_to_mac(netif, dhcp_state->idx, netif_dhcp->client.hwaddr, &hwaddr_len) != ERR_OK) {
      LWIP_DEBUGF(DHCP_DEBUG | LWIP_DBG_TRACE | LWIP_DBG_LEVEL_WARNING,
                  ("dhcp_netif_fine_tmr:idx %u to mac failed\n", dhcp_state->idx));
      continue;
    }
    dhcp_state->hwaddr_len = hwaddr_len;
    dhcp_client_fine_tmr(netif, &(netif_dhcp->client));
  }

  return;
}

/**
 * DHCP transaction timeout handling (this function must be called every 500ms,
 * see @ref DHCP_FINE_TIMER_MSECS).
 *
 * A DHCP server is expected to respond within a short period of time.
 * This timer checks whether an outstanding DHCP request is timed out.
 */
void
dhcp_fine_tmr(void)
{
  struct netif *netif = netif_list;
  /* loop through netif's */
  while (netif != NULL) {
    struct dhcp *netif_dhcp = netif_dhcp_data(netif);
    /* only act on DHCP configured interfaces */
    if (netif_dhcp != NULL) {
      dhcp_netif_fine_tmr(netif, netif_dhcp);
    }
    /* proceed to next network interface */
    netif = netif->next;
  }
}

/**
 * A DHCP negotiation transaction, or ARP request, has timed out.
 *
 * The timer that was started with the DHCP or ARP request has
 * timed out, indicating no response was received in time.
 *
 * @param netif the netif under DHCP control
 */
static void
dhcp_timeout(struct netif *netif, struct dhcp_client *dhcp)
{
  struct dhcp_state *dhcp_state = &((dhcp->states)[dhcp->cli_idx]);

  LWIP_DEBUGF(DHCP_DEBUG | LWIP_DBG_TRACE, ("dhcp_timeout()\n"));
  /* back-off period has passed, or server selection timed out */
  if ((dhcp_state->state == DHCP_STATE_BACKING_OFF) || (dhcp_state->state == DHCP_STATE_SELECTING)) {
    LWIP_DEBUGF(DHCP_DEBUG | LWIP_DBG_TRACE, ("dhcp_timeout(): restarting discovery\n"));
    (void)dhcp_discover(netif, dhcp);
    /* receiving the requested lease timed out */
  } else if (dhcp_state->state == DHCP_STATE_REQUESTING) {
    LWIP_DEBUGF(DHCP_DEBUG | LWIP_DBG_TRACE | LWIP_DBG_STATE, ("dhcp_timeout(): REQUESTING, DHCP request timed out\n"));
    if (dhcp_state->tries <= 5) {
      (void)dhcp_select(netif, dhcp);
    } else {
      LWIP_DEBUGF(DHCP_DEBUG | LWIP_DBG_TRACE | LWIP_DBG_STATE, ("dhcp_timeout(): REQUESTING,releasing,restarting\n"));
      if (dhcp->cli_idx == LWIP_DHCP_NATIVE_IDX) {
        (void)dhcp_release(netif);
      } else {
        (void)dhcp_release_client(netif, dhcp);
      }
      (void)dhcp_discover(netif, dhcp);
    }
#if DHCP_DOES_ARP_CHECK
    /* received no ARP reply for the offered address (which is good) */
  } else if (dhcp_state->state == DHCP_STATE_CHECKING) {
    LWIP_DEBUGF(DHCP_DEBUG | LWIP_DBG_TRACE | LWIP_DBG_STATE, ("dhcp_timeout(): CHECKING, ARP request timed out\n"));
    if (dhcp_state->tries <= 1) {
      dhcp_check(netif, dhcp);
      /* no ARP replies on the offered address,
         looks like the IP address is indeed free */
    } else {
      /* bind the interface to the offered address */
      dhcp_bind(netif, dhcp);
    }
#endif /* DHCP_DOES_ARP_CHECK */
  } else if (dhcp_state->state == DHCP_STATE_REBOOTING) {
    if (dhcp_state->tries < REBOOT_TRIES) {
      (void)dhcp_reboot(netif);
    } else {
      (void)dhcp_discover(netif, dhcp);
    }
  } else if (dhcp_state->state == DHCP_STATE_RENEWING) {
    /* 5: send dhcp request package six times to renew its lease */
    if (dhcp_state->tries <= 5) {
      (void)dhcp_renew_client(netif, dhcp);
    }
  } else if (dhcp_state->state == DHCP_STATE_REBINDING) {
    /* 5: send dhcp request package six times to Rebind with a DHCP server for an existing DHCP lease. */
    if (dhcp_state->tries <= 5) {
      (void)dhcp_rebind(netif, dhcp);
    }
  }
}

/**
 * The renewal period has timed out.
 *
 * @param netif the netif under DHCP control
 */
static void
dhcp_t1_timeout(struct netif *netif, struct dhcp_client *dhcp)
{
  struct dhcp_state *dhcp_state = &((dhcp->states)[dhcp->cli_idx]);

  LWIP_DEBUGF(DHCP_DEBUG | LWIP_DBG_STATE, ("dhcp_t1_timeout()\n"));
  if ((dhcp_state->state == DHCP_STATE_REQUESTING) || (dhcp_state->state == DHCP_STATE_BOUND) ||
      (dhcp_state->state == DHCP_STATE_RENEWING)) {
    /* just retry to renew - note that the rebind timer (t2) will
     * eventually time-out if renew tries fail. */
    LWIP_DEBUGF(DHCP_DEBUG | LWIP_DBG_TRACE | LWIP_DBG_STATE,
                ("dhcp_t1_timeout(): must renew\n"));
    /* This slightly different to RFC2131: DHCPREQUEST will be sent from state
       DHCP_STATE_RENEWING, not DHCP_STATE_BOUND */
    (void)dhcp_renew_client(netif, dhcp);
    /* Calculate next timeout */
    if (((dhcp->t2_timeout - dhcp_state->lease_used) / 2) >=
        ((60 + DHCP_COARSE_TIMER_SECS / 2) / DHCP_COARSE_TIMER_SECS)) {
      dhcp_state->re_time = (u16_t)((dhcp->t2_timeout - dhcp_state->lease_used) / 2);
    } else {
      dhcp_state->re_time = (u16_t)(dhcp->t2_timeout - dhcp_state->lease_used);
    }
  }
}

/**
 * The rebind period has timed out.
 *
 * @param netif the netif under DHCP control
 */
static void
dhcp_t2_timeout(struct netif *netif, struct dhcp_client *dhcp)
{
  struct dhcp_state *dhcp_state = &((dhcp->states)[dhcp->cli_idx]);

  LWIP_DEBUGF(DHCP_DEBUG | LWIP_DBG_TRACE | LWIP_DBG_STATE, ("dhcp_t2_timeout()\n"));
  if ((dhcp_state->state == DHCP_STATE_REQUESTING) || (dhcp_state->state == DHCP_STATE_BOUND) ||
      (dhcp_state->state == DHCP_STATE_RENEWING) || (dhcp_state->state == DHCP_STATE_REBINDING)) {
    /* just retry to rebind */
    LWIP_DEBUGF(DHCP_DEBUG | LWIP_DBG_TRACE | LWIP_DBG_STATE,
                ("dhcp_t2_timeout(): must rebind\n"));
    /* This slightly different to RFC2131: DHCPREQUEST will be sent from state
       DHCP_STATE_REBINDING, not DHCP_STATE_BOUND */
    (void)dhcp_rebind(netif, dhcp);
    /* Calculate next timeout */
    if (((dhcp->t0_timeout - dhcp_state->lease_used) / 2) >=
        ((60 + DHCP_COARSE_TIMER_SECS / 2) / DHCP_COARSE_TIMER_SECS)) {
      dhcp_state->re_time = (u16_t)((dhcp->t0_timeout - dhcp_state->lease_used) / 2);
    }
  }
}

/**
 * Handle a DHCP ACK packet
 *
 * @param netif the netif under DHCP control
 */
static void
dhcp_handle_ack(struct netif *netif, struct dhcp_client *dhcp)
{
#if LWIP_DHCP_BOOTP_FILE
  struct dhcp *netif_dhcp = netif_dhcp_data(netif);
#else
  (void)netif;
#endif /* LWIP_DHCP_BOOTP_FILE */
  ip4_addr_t cli_ip;
  struct dhcp_state *dhcp_state = &((dhcp->states)[dhcp->cli_idx]);

#if LWIP_DHCP_PROVIDE_DNS_SERVERS || LWIP_DHCP_GET_NTP_SRV
  u8_t n;
#endif /* LWIP_DHCP_PROVIDE_DNS_SERVERS || LWIP_DHCP_GET_NTP_SRV */
#if LWIP_DHCP_GET_NTP_SRV
  ip4_addr_t ntp_server_addrs[LWIP_DHCP_MAX_NTP_SERVERS];
#endif

  /* clear options we might not get from the ACK */
  ip4_addr_set_zero(&dhcp->offered_sn_mask);
  ip4_addr_set_zero(&dhcp->offered_gw_addr);
#if LWIP_DHCP_BOOTP_FILE
  if (dhcp->cli_idx == LWIP_DHCP_NATIVE_IDX) {
    ip4_addr_set_zero(&netif_dhcp->offered_si_addr);
  }
#endif /* LWIP_DHCP_BOOTP_FILE */

  /* lease time given? */
  if (dhcp_option_given(dhcp, DHCP_OPTION_IDX_LEASE_TIME)) {
    /* remember offered lease time */
    dhcp->offered_t0_lease = dhcp_get_option_value(dhcp, DHCP_OPTION_IDX_LEASE_TIME);
  }
  /* renewal period given? */
  if (dhcp_option_given(dhcp, DHCP_OPTION_IDX_T1)) {
    /* remember given renewal period */
    dhcp->offered_t1_renew = dhcp_get_option_value(dhcp, DHCP_OPTION_IDX_T1);
  } else {
    /* calculate safe periods for renewal */
    dhcp->offered_t1_renew = dhcp->offered_t0_lease / 2;
  }

  /* renewal period given? */
  if (dhcp_option_given(dhcp, DHCP_OPTION_IDX_T2)) {
    /* remember given rebind period */
    dhcp->offered_t2_rebind = dhcp_get_option_value(dhcp, DHCP_OPTION_IDX_T2);
  } else {
    /* calculate safe periods for rebinding (offered_t0_lease * 0.875 -> 87.5%) */
    dhcp->offered_t2_rebind = (dhcp->offered_t0_lease * 7U) / 8U;
  }

#if LWIP_DHCP_BOOTP_FILE
  /* copy boot server address,
     boot file name copied in dhcp_parse_reply if not overloaded */
  if (dhcp->cli_idx == LWIP_DHCP_NATIVE_IDX) {
    ip4_addr_copy(netif_dhcp->offered_si_addr, dhcp->msg_in->siaddr);
  }
#endif /* LWIP_DHCP_BOOTP_FILE */

  /* subnet mask given? */
  if (dhcp_option_given(dhcp, DHCP_OPTION_IDX_SUBNET_MASK)) {
    /* remember given subnet mask */
    ip4_addr_set_u32(&dhcp->offered_sn_mask, lwip_htonl(dhcp_get_option_value(dhcp, DHCP_OPTION_IDX_SUBNET_MASK)));
    dhcp->subnet_mask_given = lwIP_TRUE;
  } else {
    dhcp_ip_to_mask(ip_2_ip4(&dhcp->server_ip_addr), &dhcp->offered_sn_mask);
    dhcp->subnet_mask_given = lwIP_FALSE;
  }

  /* (y)our internet address */
  ip4_addr_copy(cli_ip, dhcp->msg_in->yiaddr);
  DHCP_IP_TO_HOST(dhcp_state->offered_ip_addr, cli_ip.addr, dhcp->offered_sn_mask.addr);

  /* gateway router */
  if (dhcp_option_given(dhcp, DHCP_OPTION_IDX_ROUTER)) {
    ip4_addr_set_u32(&dhcp->offered_gw_addr, lwip_htonl(dhcp_get_option_value(dhcp, DHCP_OPTION_IDX_ROUTER)));
  }

#if LWIP_DHCP_GET_NTP_SRV
  /* NTP servers */
  if (dhcp->cli_idx == LWIP_DHCP_NATIVE_IDX) {
    for (n = 0; (n < LWIP_DHCP_MAX_NTP_SERVERS) && dhcp_option_given(dhcp, DHCP_OPTION_IDX_NTP_SERVER + n); n++) {
      ip4_addr_set_u32(&ntp_server_addrs[n], lwip_htonl(dhcp_get_option_value(dhcp, DHCP_OPTION_IDX_NTP_SERVER + n)));
    }
    dhcp_set_ntp_servers(n, ntp_server_addrs);
  }
#endif /* LWIP_DHCP_GET_NTP_SRV */

#if LWIP_DNS
#if LWIP_DHCP_PROVIDE_DNS_SERVERS
  /* DNS servers */
  if (dhcp->cli_idx == LWIP_DHCP_NATIVE_IDX) {
    for (n = 0; (n < LWIP_DHCP_PROVIDE_DNS_SERVERS) && dhcp_option_given(dhcp, DHCP_OPTION_IDX_DNS_SERVER + n); n++) {
      ip_addr_t dns_addr;
      ip_addr_set_ip4_u32_val(&dns_addr, lwip_htonl(dhcp_get_option_value(dhcp, DHCP_OPTION_IDX_DNS_SERVER + n)));
      dns_setserver(n, &dns_addr);
    }
  }
#endif /* LWIP_DHCP_PROVIDE_DNS_SERVERS */
#endif
}

#if LWIP_API_RICH
/**
 * @ingroup dhcp4
 * Set a statically allocated struct dhcp to work with.
 * Using this prevents dhcp_start to allocate it using mem_malloc.
 *
 * @param netif the netif for which to set the struct dhcp
 * @param dhcp (uninitialised) dhcp struct allocated by the application
 */
void
dhcp_set_struct(struct netif *netif, struct dhcp *dhcp)
{
  LWIP_ERROR("netif != NULL", (netif != NULL), return);
  LWIP_ERROR("dhcp != NULL", (dhcp != NULL), return);

  /* clear data structure */
  (void)memset_s(dhcp, sizeof(struct dhcp), 0, sizeof(struct dhcp));
  netif_set_client_data(netif, LWIP_NETIF_CLIENT_DATA_INDEX_DHCP, dhcp);
}

void
dhcp_remove_struct(struct netif *netif)
{
  LWIP_ERROR("netif != NULL", (netif != NULL), return);

  netif_set_client_data(netif, LWIP_NETIF_CLIENT_DATA_INDEX_DHCP, NULL);
  return;
}
#endif /* LWIP_API_RICH */

/**
 * @ingroup dhcp4
 * Removes a struct dhcp from a netif.
 *
 * ATTENTION: Only use this when not using dhcp_set_struct() to allocate the
 *            struct dhcp since the memory is passed back to the heap.
 *
 * @param netif the netif from which to remove the struct dhcp
 */
void
dhcp_cleanup(struct netif *netif)
{
  struct dhcp *netif_dhcp = NULL;
#if LWIP_DHCP_SUBSTITUTE
  int i;
  struct dhcp_client *dhcp = NULL;
  struct dhcp_state *dhcp_state = NULL;
#endif /* LWIP_DHCP_SUBSTITUTE */

  LWIP_ERROR("netif != NULL", (netif != NULL), return);

  netif_dhcp = netif_dhcp_data(netif);
  if (netif_dhcp == NULL) {
    return;
  }
  if (netif_dhcp->pcb_allocated != 0) {
    dhcp_stop(netif);
  }
#if LWIP_DHCP_SUBSTITUTE
  dhcp = &(netif_dhcp->client);
  for (i = 1; i < DHCP_CLIENT_NUM; i++) {
    dhcp_state = &((dhcp->states)[i]);
    if (dhcp_state->idx == 0) {
      continue;
    }
    dhcp_substitute_stop(netif, dhcp_state->idx);
  }
#endif /* LWIP_DHCP_SUBSTITUTE */

  mem_free(netif_dhcp_data(netif));
  netif_set_client_data(netif, LWIP_NETIF_CLIENT_DATA_INDEX_DHCP, NULL);
}

#if LWIP_API_RICH
/**
 * Check DHCP negotiation is done for a network interface.
 *
 * @param netif The lwIP network interface
 * @return
 * - ERR_OK - if DHCP is bound
 * - ERR_MEM - if DHCP bound is still progressing
 */
err_t
dhcp_is_bound(struct netif *netif)
{
  struct dhcp *netif_dhcp = NULL;

  LWIP_ERROR("netif != NULL", (netif != NULL), return ERR_ARG);

  netif_dhcp =  netif_dhcp_data(netif);
  LWIP_ERROR("netif->dhcp != NULL", (netif_dhcp != NULL), return ERR_ARG);

  if ((netif_dhcp->client.states)[LWIP_DHCP_NATIVE_IDX].state == DHCP_STATE_BOUND) {
    return ERR_OK;
  } else {
    return ERR_INPROGRESS;
  }
}
#endif /* LWIP_API_RICH */

static void
dhcp_native_reset(struct dhcp *netif_dhcp)
{
  netif_dhcp->pcb_allocated = 0;
#if LWIP_DHCP_AUTOIP_COOP
  netif_dhcp->autoip_coop_state = DHCP_AUTOIP_COOP_STATE_OFF;
#endif /* LWIP_DHCP_AUTOIP_COOP */
#if LWIP_DHCP_BOOTP_FILE
  (void)memset_s(&(netif_dhcp->offered_si_addr), sizeof(netif_dhcp->offered_si_addr),
                 0x0, sizeof(netif_dhcp->offered_si_addr));
  (void)memset_s(netif_dhcp->boot_file_name, sizeof(netif_dhcp->boot_file_name),
                 0x0, sizeof(netif_dhcp->boot_file_name));
#endif /* LWIP_DHCP_BOOTP_FILE */

  return;
}

static struct dhcp *
dhcp_netif_dhcp_new(void)
{
  struct dhcp *netif_dhcp = NULL;

  LWIP_DEBUGF(DHCP_DEBUG | LWIP_DBG_TRACE, ("dhcp_netif_dhcp_new(): starting new DHCP client\n"));
  netif_dhcp = (struct dhcp *)mem_malloc(sizeof(struct dhcp));
  if (netif_dhcp == NULL) {
    LWIP_DEBUGF(DHCP_DEBUG | LWIP_DBG_TRACE, ("dhcp_netif_dhcp_new(): could not allocate dhcp\n"));
    return NULL;
  }

  (void)memset_s(netif_dhcp, sizeof(struct dhcp), 0x0, sizeof(struct dhcp));

  return netif_dhcp;
}

static err_t
dhcp_start_client_native(struct netif *netif)
{
  struct dhcp *netif_dhcp = NULL;
  struct dhcp_client *dhcp = NULL;

  netif_dhcp = netif_dhcp_data(netif);
  dhcp = &(netif_dhcp->client);
  (void)dhcp;
  LWIP_DEBUGF(DHCP_DEBUG | LWIP_DBG_TRACE | LWIP_DBG_STATE,
              ("dhcp_start_client_native(): restarting DHCP configuration\n"));
  LWIP_ASSERT("pbuf p_out wasn't freed", dhcp->p_out == NULL);
  LWIP_ASSERT("reply wasn't freed", dhcp->msg_in == NULL );

  if (netif_dhcp->pcb_allocated != 0) {
    dhcp_dec_pcb_refcount(); /* free DHCP PCB if not needed any more */
  }
  /* dhcp is cleared below, no need to reset flag */
  /* clear data structure */
  dhcp_native_reset(netif_dhcp);

  LWIP_DEBUGF(DHCP_DEBUG | LWIP_DBG_TRACE, ("dhcp_start_client_native(): starting DHCP configuration\n"));

  if (dhcp_inc_pcb_refcount(netif) != ERR_OK) { /* ensure DHCP PCB is allocated */
    dhcp_stop(netif);
    return ERR_MEM;
  }
  netif_dhcp->pcb_allocated = 1;

  return ERR_OK;
}

static err_t
dhcp_start_client(struct netif *netif, dhcp_num_t mac_idx)
{
  struct dhcp *netif_dhcp = NULL;
  struct dhcp_client *dhcp = NULL;
  struct dhcp_state *dhcp_state = NULL;
  u8_t hwaddr_len;
  err_t result;
#if LWIP_DHCP_SUBSTITUTE
  u8_t is_new = lwIP_FALSE;
#endif /* LWIP_DHCP_SUBSTITUTE */

  /* check MTU of the netif */
  if (netif->mtu < DHCP_MAX_MSG_LEN_MIN_REQUIRED) {
    LWIP_DEBUGF(DHCP_DEBUG | LWIP_DBG_TRACE,
                ("dhcp_start_client(): Cannot use this netif with DHCP: MTU is too small\n"));
    return ERR_MEM;
  }

  netif_dhcp = netif_dhcp_data(netif);
  /* no DHCP client attached yet? */
  if (netif_dhcp == NULL) {
    netif_dhcp = dhcp_netif_dhcp_new();
    if (netif_dhcp == NULL) {
      return ERR_MEM;
    }
    /* store this dhcp client in the netif */
    netif_set_client_data(netif, LWIP_NETIF_CLIENT_DATA_INDEX_DHCP, netif_dhcp);
    LWIP_DEBUGF(DHCP_DEBUG | LWIP_DBG_TRACE, ("dhcp_start_client(): allocated dhcp"));
    /* already has DHCP client attached */
  }
  dhcp = &(netif_dhcp->client);
  if (dhcp_client_find_by_mac_idx(dhcp, mac_idx, &(dhcp->cli_idx)) != ERR_OK) {
    LWIP_DEBUGF(DHCP_DEBUG | LWIP_DBG_TRACE, ("dhcp_start_client(): client state not find for %u\n", mac_idx));
    if (dhcp_client_state_new(dhcp, mac_idx, &(dhcp->cli_idx)) != ERR_OK) {
      LWIP_DEBUGF(DHCP_DEBUG | LWIP_DBG_TRACE, ("dhcp_start_client(): no client state for %u\n", mac_idx));
      return ERR_MEM;
    } else {
#if LWIP_DHCP_SUBSTITUTE
      LWIP_DEBUGF(DHCP_DEBUG | LWIP_DBG_TRACE, ("dhcp_start_client(): new client state for %u\n", mac_idx));
      is_new = lwIP_TRUE;
#endif /* LWIP_DHCP_SUBSTITUTE */
    }
  }
  dhcp_state = &((dhcp->states)[dhcp->cli_idx]);
  if (dhcp_idx_to_mac(netif, dhcp_state->idx, dhcp->hwaddr, &hwaddr_len) != ERR_OK) {
    LWIP_DEBUGF(DHCP_DEBUG | LWIP_DBG_TRACE, ("dhcp_start_client(): no client state for %u\n", mac_idx));
    return ERR_MEM;
  }
  dhcp_state->hwaddr_len = hwaddr_len;

  if (mac_idx == LWIP_DHCP_NATIVE_IDX) {
    result = dhcp_start_client_native(netif);
    if (result != ERR_OK) {
      (void)memset_s(dhcp_state, sizeof(struct dhcp_state), 0, sizeof(struct dhcp_state));
      return result;
    }
  }
#if LWIP_DHCP_SUBSTITUTE
  else {
    if ((is_new == lwIP_TRUE) && (dhcp_inc_pcb_refcount(netif) != ERR_OK)) {
      (void)memset_s(dhcp_state, sizeof(struct dhcp_state), 0, sizeof(struct dhcp_state));
      return ERR_MEM;
    }
  }
#endif /* LWIP_DHCP_SUBSTITUTE */

#if LWIP_DHCP_CHECK_LINK_UP
  if (!netif_is_link_up(netif)) {
    /* set state INIT and wait for dhcp_network_changed() to call dhcp_discover() */
    dhcp_set_state(dhcp, DHCP_STATE_INIT);
    return ERR_OK;
  }
#endif /* LWIP_DHCP_CHECK_LINK_UP */

  /* (re)start the DHCP negotiation */
  result = dhcp_discover(netif, dhcp);
  if (result != ERR_OK) {
    /* free resources allocated above */
    if (mac_idx == LWIP_DHCP_NATIVE_IDX) {
      dhcp_stop(netif);
    } else {
      dhcp_stop_client(netif, dhcp);
    }
    return ERR_MEM;
  }

  return ERR_OK;
}

/**
 * @ingroup dhcp4
 * Start DHCP negotiation for a network interface.
 *
 * If no DHCP client instance was attached to this interface,
 * a new client is created first. If a DHCP client instance
 * was already present, it restarts negotiation.
 *
 * @param netif The lwIP network interface
 * @return lwIP error code
 * - ERR_OK - No error
 * - ERR_MEM - Out of memory
 */
err_t
dhcp_start(struct netif *netif)
{
  err_t result;

  LWIP_ERROR("netif != NULL", (netif != NULL), return ERR_ARG);
  LWIP_ERROR("netif is not up, old style port?", netif_is_up(netif), return ERR_ARG);

  netif_set_ipaddr(netif, IP4_ADDR_ANY4);
  netif_set_gw(netif, IP4_ADDR_ANY4);
  netif_set_netmask(netif, IP4_ADDR_ANY4);

  LWIP_DEBUGF(DHCP_DEBUG | LWIP_DBG_TRACE | LWIP_DBG_STATE, ("dhcp_start(netif=%p) %c%c%"U16_F"\n", (void *)netif,
                                                             netif->name[0], netif->name[1], (u16_t)netif->num));

  /* 
   * Remove the flag that says this netif is handled by DHCP,
   * it is set when we succeeded starting.
   */
  netif->flags = (netif->flags & (~NETIF_FLAG_DHCP));

  result = dhcp_start_client(netif, LWIP_DHCP_NATIVE_IDX);
  if (result != ERR_OK) {
    return result;
  }

  dhcp_clients_count_update(&(netif_dhcp_data(netif)->client));
  /* Set the flag that says this netif is handled by DHCP. */
  netif->flags |= NETIF_FLAG_DHCP;
  return ERR_OK;
}

/**
 * @ingroup dhcp4
 * Inform a DHCP server of our manual configuration.
 *
 * This informs DHCP servers of our fixed IP address configuration
 * by sending an INFORM message. It does not involve DHCP address
 * configuration, it is just here to be nice to the network.
 *
 * @param netif The lwIP network interface
 */
void
dhcp_inform(struct netif *netif)
{
  struct dhcp_client *dhcp = NULL;
  u8_t is_malloc = lwIP_FALSE;
  u16_t malloc_size;
  err_t result;
  u32_t i;
  u8_t hwaddr_len;
  struct dhcp_state *dhcp_state = NULL;
  struct dhcp *netif_dhcp = NULL;

  LWIP_ERROR("netif != NULL", (netif != NULL), return);

  if (dhcp_inc_pcb_refcount(netif) != ERR_OK) { /* ensure DHCP PCB is allocated */
    return;
  }
  netif_dhcp = netif_dhcp_data(netif);
  if (netif_dhcp != NULL) {
    dhcp = &(netif_dhcp->client);
  } else {
    malloc_size = (u16_t)(sizeof(struct dhcp_client) - (DHCP_CLIENT_NUM - 1) * sizeof(struct dhcp_state));
    dhcp = (struct dhcp_client *)mem_malloc(malloc_size);
    if (dhcp == NULL) {
      LWIP_DEBUGF(DHCP_DEBUG | LWIP_DBG_TRACE | LWIP_DBG_LEVEL_SERIOUS, ("dhcp_inform: malloc failed\n"));
      return;
    }
    (void)memset_s(dhcp, malloc_size, 0, malloc_size);
    is_malloc = lwIP_TRUE;
  }

  dhcp->cli_idx = LWIP_DHCP_NATIVE_IDX;
  dhcp_state = &(dhcp->states[LWIP_DHCP_NATIVE_IDX]);
  dhcp_set_state(dhcp, DHCP_STATE_INFORMING);
  if (dhcp_idx_to_mac(netif, LWIP_DHCP_NATIVE_IDX, dhcp->hwaddr, &hwaddr_len) != ERR_OK) {
    dhcp_dec_pcb_refcount();
    if (is_malloc == lwIP_TRUE) {
      mem_free(dhcp);
    }
    return;
  }
  dhcp_state->hwaddr_len = hwaddr_len;

  /* create and initialize the DHCP message header */
  result = dhcp_create_msg(netif, dhcp, DHCP_INFORM);
  if (result == ERR_OK) {
    dhcp_option(dhcp, DHCP_OPTION_CLIENT_ID, 1 + netif->hwaddr_len);
    dhcp_option_byte(dhcp, dhcp->msg_out->htype);
    for (i = 0; i < dhcp_state->hwaddr_len; i++) {
      dhcp_option_byte(dhcp, dhcp->hwaddr[i]);
    }

    dhcp_option(dhcp, DHCP_OPTION_MAX_MSG_SIZE, DHCP_OPTION_MAX_MSG_SIZE_LEN);
    dhcp_option_short(dhcp, DHCP_MAX_MSG_LEN(netif));

#if LWIP_DHCP_VENDOR_CLASS_IDENTIFIER
    dhcp_option_vci(dhcp, netif);
#endif /* LWIP_DHCP_VENDOR_CLASS_IDENTIFIER */

    dhcp_option_trailer(dhcp);

    pbuf_realloc(dhcp->p_out, (u16_t)((sizeof(struct dhcp_msg) - DHCP_OPTIONS_LEN) + dhcp->options_out_len));

    LWIP_DEBUGF(DHCP_DEBUG | LWIP_DBG_TRACE | LWIP_DBG_STATE, ("dhcp_inform: INFORMING\n"));

    (void)udp_sendto_if(dhcp_pcb, dhcp->p_out, IP_ADDR_BROADCAST, DHCP_SERVER_PORT, netif);

    dhcp_delete_msg(dhcp);
  } else {
    LWIP_DEBUGF(DHCP_DEBUG | LWIP_DBG_TRACE | LWIP_DBG_LEVEL_SERIOUS,
                ("dhcp_inform: could not allocate DHCP request\n"));
  }

  dhcp_dec_pcb_refcount(); /* delete DHCP PCB if not needed any more */
  if (is_malloc == lwIP_TRUE) {
    mem_free(dhcp);
  }
}

/** Handle a possible change in the network configuration.
 *
 * This enters the REBOOTING state to verify that the currently bound
 * address is still valid.
 */
static void
dhcp_network_changed_client(struct netif *netif, struct dhcp_client *dhcp)
{
#if LWIP_DHCP_AUTOIP_COOP
  struct dhcp *netif_dhcp = netif_dhcp_data(netif);
#endif /* LWIP_DHCP_AUTOIP_COOP */
  struct dhcp_state *dhcp_state = &((dhcp->states)[dhcp->cli_idx]);

  switch (dhcp_state->state) {
    case DHCP_STATE_REBINDING:
    case DHCP_STATE_RENEWING:
    case DHCP_STATE_BOUND:
    case DHCP_STATE_REBOOTING:
      dhcp_state->tries = 0;
      (void)dhcp_reboot(netif);
      break;
    case DHCP_STATE_OFF:
      /* stay off */
      break;
    default:
      /* INIT/REQUESTING/CHECKING/BACKING_OFF restart with new 'rid' because the
         state changes, SELECTING: continue with current 'rid' as we stay in the
         same state */
#if LWIP_DHCP_AUTOIP_COOP
      if ((dhcp->cli_idx == LWIP_DHCP_NATIVE_IDX) &&
          (netif_dhcp->autoip_coop_state == DHCP_AUTOIP_COOP_STATE_ON)) {
        (void)autoip_stop(netif);
        netif_dhcp->autoip_coop_state = DHCP_AUTOIP_COOP_STATE_OFF;
      }
#endif /* LWIP_DHCP_AUTOIP_COOP */
      /* ensure we start with short timeouts, even if already discovering */
      dhcp_state->tries = 0;
      (void)dhcp_discover(netif, dhcp);
      break;
  }
}

void
dhcp_network_changed(struct netif *netif)
{
  struct dhcp *netif_dhcp = netif_dhcp_data(netif);
  struct dhcp_client *dhcp = NULL;
  struct dhcp_state *dhcp_state = NULL;
  int i;
  u8_t hwaddr_len;
  LWIP_DEBUGF(DHCP_DEBUG | LWIP_DBG_TRACE | LWIP_DBG_STATE, ("dhcp_network_changed()\n"));
  if (netif_dhcp == NULL) {
    return;
  }

  dhcp = &(netif_dhcp->client);

  for (i = 0; i < DHCP_CLIENT_NUM; i++) {
    dhcp->cli_idx = (dhcp_num_t)i;
    dhcp_state = &((dhcp->states)[i]);
    if ((i != LWIP_DHCP_NATIVE_IDX) && (dhcp_state->idx == 0)) {
      continue;
    }
    if (dhcp_idx_to_mac(netif, dhcp_state->idx, dhcp->hwaddr, &hwaddr_len) != ERR_OK) {
      LWIP_DEBUGF(DHCP_DEBUG | LWIP_DBG_TRACE | LWIP_DBG_LEVEL_WARNING,
                  ("dhcp_network_changed:idx %u to mac failed\n", dhcp_state->idx));
      continue;
    }
    dhcp_state->hwaddr_len = hwaddr_len;
    dhcp_network_changed_client(netif, dhcp);
  }
}

#if DHCP_DOES_ARP_CHECK
/**
 * Match an ARP reply with the offered IP address:
 * check whether the offered IP address is not in use using ARP
 *
 * @param netif the network interface on which the reply was received
 * @param addr The IP address we received a reply from
 */
void
dhcp_arp_reply(struct netif *netif, const ip4_addr_t *addr)
{
  struct dhcp *netif_dhcp = NULL;
  struct dhcp_client *dhcp = NULL;
  struct dhcp_state *dhcp_state = NULL;
  ip4_addr_t cli_ip;
  u8_t hwaddr_len;
  int i;

  LWIP_ERROR("netif != NULL", (netif != NULL), return);
  LWIP_ERROR("addr != NULL", (addr != NULL), return);
  netif_dhcp = netif_dhcp_data(netif);
  LWIP_DEBUGF(DHCP_DEBUG | LWIP_DBG_TRACE, ("dhcp_arp_reply()\n"));
  /* is a DHCP client doing an ARP check? */
  if (netif_dhcp == NULL) {
    return;
  }

  dhcp = &(netif_dhcp->client);
  for (i = 0; i < DHCP_CLIENT_NUM; i++) {
    dhcp->cli_idx = (dhcp_num_t)i;
    dhcp_state = &((dhcp->states)[i]);
    if ((i != LWIP_DHCP_NATIVE_IDX) && (dhcp_state->idx == 0)) {
      continue;
    }
    if ((dhcp_state->state == DHCP_STATE_CHECKING)) {
      LWIP_DEBUGF(DHCP_DEBUG | LWIP_DBG_TRACE | LWIP_DBG_STATE,
                  ("dhcp_arp_reply(): CHECKING, arp reply for 0x%08"X32_F"\n",
                   ip4_addr_get_u32(addr)));
      /* did a host respond with the address we
         were offered by the DHCP server? */
      DHCP_HOST_TO_IP(cli_ip.addr, ip_2_ip4(&dhcp->server_ip_addr)->addr, dhcp->offered_sn_mask.addr,
                      dhcp_state->offered_ip_addr);
      if (!ip4_addr_cmp(addr, &cli_ip)) {
        continue;
      }
      /* we will not accept the offered address */
      LWIP_DEBUGF(DHCP_DEBUG | LWIP_DBG_TRACE | LWIP_DBG_STATE | LWIP_DBG_LEVEL_WARNING,
                  ("dhcp_arp_reply(): arp reply matched with offered address, declining\n"));
      if (dhcp_idx_to_mac(netif, dhcp_state->idx, dhcp->hwaddr, &hwaddr_len) != ERR_OK) {
        LWIP_DEBUGF(DHCP_DEBUG | LWIP_DBG_TRACE | LWIP_DBG_LEVEL_WARNING,
                    ("dhcp_arp_reply:idx %u to mac failed\n", dhcp_state->idx));
        return;
      }
      dhcp_state->hwaddr_len = hwaddr_len;
      (void)dhcp_decline(netif, dhcp);
      return;
    }
  }

  return;
}

/**
 * Decline an offered lease.
 *
 * Tell the DHCP server we do not accept the offered address.
 * One reason to decline the lease is when we find out the address
 * is already in use by another host (through ARP).
 *
 * @param netif the netif under DHCP control
 */
static err_t
dhcp_decline(struct netif *netif, struct dhcp_client *dhcp)
{
  err_t result;
  u16_t msecs;
  u32_t i;
  ip4_addr_t cli_ip;
  struct dhcp_state *dhcp_state = &((dhcp->states)[dhcp->cli_idx]);

  LWIP_DEBUGF(DHCP_DEBUG | LWIP_DBG_TRACE, ("dhcp_decline()\n"));
  dhcp_set_state(dhcp, DHCP_STATE_BACKING_OFF);
  /* create and initialize the DHCP message header */
  result = dhcp_create_msg(netif, dhcp, DHCP_DECLINE);
  if (result == ERR_OK) {
    dhcp_option(dhcp, DHCP_OPTION_CLIENT_ID, 1 + dhcp_state->hwaddr_len);
    dhcp_option_byte(dhcp, dhcp->msg_out->htype);
    for (i = 0; i < dhcp_state->hwaddr_len; i++) {
      dhcp_option_byte(dhcp, dhcp->hwaddr[i]);
    }

    dhcp_option(dhcp, DHCP_OPTION_REQUESTED_IP, 4);
    DHCP_HOST_TO_IP(cli_ip.addr, ip_2_ip4(&dhcp->server_ip_addr)->addr, dhcp->offered_sn_mask.addr,
                    dhcp_state->offered_ip_addr);
    dhcp_option_long(dhcp, lwip_ntohl(ip4_addr_get_u32(&cli_ip)));

    dhcp_option_trailer(dhcp);
    /* resize pbuf to reflect true size of options */
    pbuf_realloc(dhcp->p_out, (u16_t)((sizeof(struct dhcp_msg) - DHCP_OPTIONS_LEN) + dhcp->options_out_len));

    /* per section 4.4.4, broadcast DECLINE messages */
    (void)udp_sendto_if_src(dhcp_pcb, dhcp->p_out, IP_ADDR_BROADCAST, DHCP_SERVER_PORT, netif, IP4_ADDR_ANY);
    dhcp_delete_msg(dhcp);
    LWIP_DEBUGF(DHCP_DEBUG | LWIP_DBG_TRACE | LWIP_DBG_STATE, ("dhcp_decline: BACKING OFF\n"));
  } else {
    LWIP_DEBUGF(DHCP_DEBUG | LWIP_DBG_TRACE | LWIP_DBG_LEVEL_SERIOUS,
                ("dhcp_decline: could not allocate DHCP request\n"));
  }
  if (dhcp_state->tries < 255) {
    dhcp_state->tries++;
  }
  msecs = 10 * 1000;
  dhcp_state->request_timeout = (u16_t)((msecs + DHCP_FINE_TIMER_MSECS - 1) / DHCP_FINE_TIMER_MSECS);
  LWIP_DEBUGF(DHCP_DEBUG | LWIP_DBG_TRACE, ("dhcp_decline(): set request timeout %"U16_F" msecs\n", msecs));
  return result;
}
#endif /* DHCP_DOES_ARP_CHECK */


/**
 * Start the DHCP process, discover a DHCP server.
 *
 * @param netif the netif under DHCP control
 */
static err_t
dhcp_discover(struct netif *netif, struct dhcp_client *dhcp)
{
#if LWIP_DHCP_AUTOIP_COOP
  struct dhcp *netif_dhcp = netif_dhcp_data(netif);
#endif
  struct dhcp_state *dhcp_state = &((dhcp->states)[dhcp->cli_idx]);
  err_t result = ERR_OK;
  u16_t msecs;
  u8_t i;
  LWIP_DEBUGF(DHCP_DEBUG | LWIP_DBG_TRACE, ("dhcp_discover()\n"));
  dhcp_state->offered_ip_addr = 0;
  dhcp_set_state(dhcp, DHCP_STATE_SELECTING);
  /* create and initialize the DHCP message header */
  result = dhcp_create_msg(netif, dhcp, DHCP_DISCOVER);
  if (result == ERR_OK) {
    LWIP_DEBUGF(DHCP_DEBUG | LWIP_DBG_TRACE, ("dhcp_discover: making request\n"));

    dhcp_option(dhcp, DHCP_OPTION_CLIENT_ID, 1 + dhcp_state->hwaddr_len);
    dhcp_option_byte(dhcp, dhcp->msg_out->htype);
    for (i = 0; i < dhcp_state->hwaddr_len; i++) {
      dhcp_option_byte(dhcp, dhcp->hwaddr[i]);
    }

    dhcp_option(dhcp, DHCP_OPTION_MAX_MSG_SIZE, DHCP_OPTION_MAX_MSG_SIZE_LEN);
    dhcp_option_short(dhcp, DHCP_MAX_MSG_LEN(netif));

    dhcp_option(dhcp, DHCP_OPTION_PARAMETER_REQUEST_LIST, LWIP_ARRAYSIZE(dhcp_discover_request_options));
    for (i = 0; i < LWIP_ARRAYSIZE(dhcp_discover_request_options); i++) {
      dhcp_option_byte(dhcp, dhcp_discover_request_options[i]);
    }
#if LWIP_NETIF_HOSTNAME
    dhcp_option_hostname(dhcp, netif);
#endif /* LWIP_NETIF_HOSTNAME */

#if LWIP_DHCP_VENDOR_CLASS_IDENTIFIER
    dhcp_option_vci(dhcp, netif);
#endif /* LWIP_DHCP_VENDOR_CLASS_IDENTIFIER */

    dhcp_option_trailer(dhcp);

    LWIP_DEBUGF(DHCP_DEBUG | LWIP_DBG_TRACE, ("dhcp_discover: realloc()ing\n"));
    pbuf_realloc(dhcp->p_out, (u16_t)((sizeof(struct dhcp_msg) - DHCP_OPTIONS_LEN) + dhcp->options_out_len));

    LWIP_DEBUGF(DHCP_DEBUG | LWIP_DBG_TRACE, ("dhcp_discover: sendto(DISCOVER,IP_ADDR_BROADCAST,DHCP_SERVER_PORT)\n"));
    (void)udp_sendto_if_src(dhcp_pcb, dhcp->p_out, IP_ADDR_BROADCAST, DHCP_SERVER_PORT, netif, IP4_ADDR_ANY);
    LWIP_DEBUGF(DHCP_DEBUG | LWIP_DBG_TRACE, ("dhcp_discover: deleting()ing\n"));
    dhcp_delete_msg(dhcp);
    LWIP_DEBUGF(DHCP_DEBUG | LWIP_DBG_TRACE | LWIP_DBG_STATE, ("dhcp_discover: SELECTING\n"));
  } else {
    LWIP_DEBUGF(DHCP_DEBUG | LWIP_DBG_TRACE | LWIP_DBG_LEVEL_SERIOUS,
                ("dhcp_discover: could not allocate DHCP request\n"));
  }
  if (dhcp_state->tries < 255) {
    dhcp_state->tries++;
  }
#if LWIP_DHCP_AUTOIP_COOP
  if ((dhcp->cli_idx == LWIP_DHCP_NATIVE_IDX) && (dhcp_state->tries >= LWIP_DHCP_AUTOIP_COOP_TRIES) &&
      (netif_dhcp->autoip_coop_state == DHCP_AUTOIP_COOP_STATE_OFF)) {
    netif_dhcp->autoip_coop_state = DHCP_AUTOIP_COOP_STATE_ON;
    autoip_start(netif);
  }
#endif /* LWIP_DHCP_AUTOIP_COOP */
  msecs = (u16_t)((dhcp_state->tries < 6 ? (1UL << dhcp_state->tries) : 60) * DHCP_DISCOVER_RETRANSMIT_INTERVAL);
  dhcp_state->request_timeout = (u16_t)((msecs + DHCP_FINE_TIMER_MSECS - 1) / DHCP_FINE_TIMER_MSECS);
  LWIP_DEBUGF(DHCP_DEBUG | LWIP_DBG_TRACE | LWIP_DBG_STATE, ("dhcp_discover(): set request timeout %"U16_F" msecs\n",
                                                             msecs));
  return result;
}


/**
 * Bind the interface to the offered IP address.
 *
 * @param netif network interface to bind to the offered address
 */
static void
dhcp_bind(struct netif *netif, struct dhcp_client *dhcp)
{
  u32_t timeout;
  struct dhcp *netif_dhcp = NULL;
  ip4_addr_t sn_mask, gw_addr;
  u8_t is_native = lwIP_FALSE;
  ip4_addr_t cli_ip;
  struct dhcp_state *dhcp_state = NULL;
  LWIP_ERROR("dhcp_bind: netif != NULL", (netif != NULL), return);
  netif_dhcp = netif_dhcp_data(netif);
  LWIP_ERROR("dhcp_bind: netif_dhcp != NULL", (netif_dhcp != NULL), return);
  LWIP_DEBUGF(DHCP_DEBUG | LWIP_DBG_TRACE, ("dhcp_bind(netif=%p) %c%c%"U16_F"\n", (void *)netif, netif->name[0],
                                            netif->name[1], (u16_t)netif->num));

  if (dhcp->cli_idx == LWIP_DHCP_NATIVE_IDX) {
    is_native = lwIP_TRUE;
  }

  dhcp_state = &((dhcp->states)[dhcp->cli_idx]);

  /* reset time used of lease */
  dhcp_state->lease_used = 0;

  if (dhcp->offered_t0_lease != 0xffffffffUL) {
    /* set renewal period timer */
    LWIP_DEBUGF(DHCP_DEBUG | LWIP_DBG_TRACE, ("dhcp_bind(): t0 renewal timer %"U32_F" secs\n", dhcp->offered_t0_lease));
    timeout = (dhcp->offered_t0_lease + DHCP_COARSE_TIMER_SECS / 2) / DHCP_COARSE_TIMER_SECS;
    if (timeout > 0xffff) {
      timeout = 0xffff;
    }
    dhcp->t0_timeout = (u16_t)timeout;
    if (dhcp->t0_timeout == 0) {
      dhcp->t0_timeout = 1;
    }
    LWIP_DEBUGF(DHCP_DEBUG | LWIP_DBG_TRACE | LWIP_DBG_STATE, ("dhcp_bind(): set request timeout %"U32_F" msecs\n",
                                                               dhcp->offered_t0_lease * 1000));
  }

  /* temporary DHCP lease? */
  if (dhcp->offered_t1_renew != 0xffffffffUL) {
    /* set renewal period timer */
    LWIP_DEBUGF(DHCP_DEBUG | LWIP_DBG_TRACE, ("dhcp_bind(): t1 renewal timer %"U32_F" secs\n", dhcp->offered_t1_renew));
    timeout = (dhcp->offered_t1_renew + DHCP_COARSE_TIMER_SECS / 2) / DHCP_COARSE_TIMER_SECS;
    if (timeout > 0xffff) {
      timeout = 0xffff;
    }
    dhcp->t1_timeout = (u16_t)timeout;
    if (dhcp->t1_timeout == 0) {
      dhcp->t1_timeout = 1;
    }
    LWIP_DEBUGF(DHCP_DEBUG | LWIP_DBG_TRACE | LWIP_DBG_STATE, ("dhcp_bind(): set request timeout %"U32_F" msecs\n",
                                                               dhcp->offered_t1_renew * 1000));
    dhcp_state->re_time = dhcp->t1_timeout;
  }
  /* set renewal period timer */
  if (dhcp->offered_t2_rebind != 0xffffffffUL) {
    LWIP_DEBUGF(DHCP_DEBUG | LWIP_DBG_TRACE, ("dhcp_bind(): t2 rebind timer %"U32_F" secs\n", dhcp->offered_t2_rebind));
    timeout = (dhcp->offered_t2_rebind + DHCP_COARSE_TIMER_SECS / 2) / DHCP_COARSE_TIMER_SECS;
    if (timeout > 0xffff) {
      timeout = 0xffff;
    }
    dhcp->t2_timeout = (u16_t)timeout;
    if (dhcp->t2_timeout == 0) {
      dhcp->t2_timeout = 1;
    }
    LWIP_DEBUGF(DHCP_DEBUG | LWIP_DBG_TRACE | LWIP_DBG_STATE, ("dhcp_bind(): set request timeout %"U32_F" msecs\n",
                                                               dhcp->offered_t2_rebind * 1000));
  }

  /* If we have sub 1 minute lease, t2 and t1 will kick in at the same time. */
  if ((dhcp->t1_timeout >= dhcp->t2_timeout) && (dhcp->t2_timeout > 0)) {
    dhcp->t1_timeout = 0;
    dhcp_state->re_time = dhcp->t2_timeout;
  }

  if (dhcp->subnet_mask_given == lwIP_TRUE) {
    /* copy offered network mask */
    ip4_addr_copy(sn_mask, dhcp->offered_sn_mask);
  } else {
    /* subnet mask not given, choose a safe subnet mask given the network class */
    dhcp_ip_to_mask(ip_2_ip4(&dhcp->server_ip_addr), &sn_mask);
    ip4_addr_copy(dhcp->offered_sn_mask, sn_mask);
  }

  DHCP_HOST_TO_IP(cli_ip.addr, ip_2_ip4(&dhcp->server_ip_addr)->addr, dhcp->offered_sn_mask.addr,
                  dhcp_state->offered_ip_addr);

  ip4_addr_copy(gw_addr, dhcp->offered_gw_addr);
  /* gateway address not given? */
  if (ip4_addr_isany_val(gw_addr)) {
    /* copy network address */
    ip4_addr_get_network(&gw_addr, &cli_ip, &sn_mask);
    /* use first host address on network as gateway */
    ip4_addr_set_u32(&gw_addr, ip4_addr_get_u32(&gw_addr) | PP_HTONL(0x00000001UL));
  }

#if LWIP_DHCP_AUTOIP_COOP
  if ((is_native == lwIP_TRUE) && (dhcp->autoip_coop_state == DHCP_AUTOIP_COOP_STATE_ON)) {
    autoip_stop(netif);
    dhcp->autoip_coop_state = DHCP_AUTOIP_COOP_STATE_OFF;
  }
#endif /* LWIP_DHCP_AUTOIP_COOP */

  LWIP_DEBUGF(DHCP_DEBUG | LWIP_DBG_STATE, ("dhcp_bind(): IP: 0x%08"X32_F" SN: 0x%08"X32_F" GW: 0x%08"X32_F"\n",
                                            ip4_addr_get_u32(&cli_ip),
                                            ip4_addr_get_u32(&sn_mask),
                                            ip4_addr_get_u32(&gw_addr)));
  /* netif is now bound to DHCP leased address - set this before assigning the address
     to ensure the callback can use dhcp_supplied_address() */
  dhcp_set_state(dhcp, DHCP_STATE_BOUND);

  if (is_native == lwIP_TRUE) {
    (void)netif_set_addr(netif, &cli_ip, &sn_mask, &gw_addr);
    /* interface is used by routing now that an address is set */
#if (LWIP_RPL || LWIP_RIPPLE) && LWIP_DHCP_COAP_RELAY
    if (lwip_rpl_is_br()) {
#if (LWIP_LITEOS_COMPAT == 0)
      start_mbr_dhcp_relay_fake_client(dhcp->server_ip_addr);
#endif
    }
#endif
  }
#if LWIP_NAT64
  else {
#if LWIP_RPL && LWIP_DHCP_COAP_RELAY
    coap_address_t local_addr;
    linklayer_addr_t mac;
    /* 2: store for offered ip addr and offered_sn_mask */
    char data[1 + (2 * sizeof(ip4_addr_t))];
    data[0] = COAP_MSG_DATA_MG_ADDR;
    local_addr.port = DHCP_COAP_CLIENT_PORT;
    local_addr.addr.type = IPADDR_TYPE_V6;
    (void)memcpy_s(mac.addr, sizeof(mac.addr), dhcp->hwaddr, sizeof(mac.addr));
    mac.addrlen = sizeof(mac.addr) > dhcp_state->hwaddr_len ? dhcp_state->hwaddr_len : sizeof(mac.addr);
    nat64_addr_mac_to6(&mac, &local_addr.addr.u_addr.ip6);
    (void)memcpy_s(&data[1], sizeof(ip4_addr_t), &dhcp->offered_ip_addr, sizeof(ip4_addr_t));
    (void)memcpy_s(&data[1 + sizeof(ip4_addr_t)], sizeof(ip4_addr_t), &dhcp->offered_sn_mask, sizeof(ip4_addr_t));
    coap_client_get(&local_addr, sizeof(data), (u8_t *)data);
#endif
    nat64_dhcp_ip4_event(dhcp->hwaddr, dhcp_state->hwaddr_len, &cli_ip, NAT64_DHCP_EVENT_OFFER);
  }
#endif
}

static err_t
dhcp_renew_client(struct netif *netif, struct dhcp_client *dhcp)
{
  err_t result;
  u16_t msecs;
  u8_t i;
  struct dhcp_state *dhcp_state = &((dhcp->states)[dhcp->cli_idx]);

  dhcp_set_state(dhcp, DHCP_STATE_RENEWING);

  /* create and initialize the DHCP message header */
  result = dhcp_create_msg(netif, dhcp, DHCP_REQUEST);
  if (result == ERR_OK) {
    dhcp_option(dhcp, DHCP_OPTION_MAX_MSG_SIZE, DHCP_OPTION_MAX_MSG_SIZE_LEN);
    dhcp_option_short(dhcp, DHCP_MAX_MSG_LEN(netif));

    dhcp_option(dhcp, DHCP_OPTION_PARAMETER_REQUEST_LIST, LWIP_ARRAYSIZE(dhcp_discover_request_options));
    for (i = 0; i < LWIP_ARRAYSIZE(dhcp_discover_request_options); i++) {
      dhcp_option_byte(dhcp, dhcp_discover_request_options[i]);
    }

    dhcp_option(dhcp, DHCP_OPTION_CLIENT_ID, 1 + dhcp_state->hwaddr_len);
    dhcp_option_byte(dhcp, dhcp->msg_out->htype);
    for (i = 0; i < dhcp_state->hwaddr_len; i++) {
      dhcp_option_byte(dhcp, dhcp->hwaddr[i]);
    }

#if LWIP_NETIF_HOSTNAME
    dhcp_option_hostname(dhcp, netif);
#endif /* LWIP_NETIF_HOSTNAME */

#if LWIP_DHCP_VENDOR_CLASS_IDENTIFIER
    dhcp_option_vci(dhcp, netif);
#endif /* LWIP_DHCP_VENDOR_CLASS_IDENTIFIER */

    /* append DHCP message trailer */
    dhcp_option_trailer(dhcp);

    pbuf_realloc(dhcp->p_out, (u16_t)((sizeof(struct dhcp_msg) - DHCP_OPTIONS_LEN) + dhcp->options_out_len));

    (void)udp_sendto_if(dhcp_pcb, dhcp->p_out, &dhcp->server_ip_addr, DHCP_SERVER_PORT, netif);
    dhcp_delete_msg(dhcp);

    LWIP_DEBUGF(DHCP_DEBUG | LWIP_DBG_TRACE | LWIP_DBG_STATE, ("dhcp_renew_client: RENEWING\n"));
  } else {
    LWIP_DEBUGF(DHCP_DEBUG | LWIP_DBG_TRACE | LWIP_DBG_LEVEL_SERIOUS,
                ("dhcp_renew_client: could not allocate DHCP request\n"));
  }
  if (dhcp_state->tries < 255) {
    dhcp_state->tries++;
  }
  /* back-off on retries, but to a maximum of 20 seconds */
  msecs = (u16_t)(dhcp_state->tries < 10 ? dhcp_state->tries * 2000 : 20 * 1000);
  dhcp_state->request_timeout = (u16_t)((msecs + DHCP_FINE_TIMER_MSECS - 1) / DHCP_FINE_TIMER_MSECS);
  LWIP_DEBUGF(DHCP_DEBUG | LWIP_DBG_TRACE | LWIP_DBG_STATE,
              ("dhcp_renew_client(): set request timeout %"U16_F" msecs\n", msecs));

  return result;
}

/*
 * @ingroup dhcp4
 * Renew an existing DHCP lease at the involved DHCP server.
 *
 * @param netif network interface which must renew its lease
 */
err_t
dhcp_renew(struct netif *netif)
{
  struct dhcp *netif_dhcp = NULL;
  struct dhcp_state *dhcp_state = NULL;
  u8_t hwaddr_len;

  LWIP_DEBUGF(DHCP_DEBUG | LWIP_DBG_TRACE, ("dhcp_renew()\n"));
  LWIP_ERROR("netif != NULL", (netif != NULL), return ERR_ARG);

  netif_dhcp = netif_dhcp_data(netif);
  LWIP_ERROR("netif != NULL", (netif_dhcp != NULL), return ERR_VAL);
  netif_dhcp->client.cli_idx = LWIP_DHCP_NATIVE_IDX;
  dhcp_state = &((netif_dhcp->client.states)[LWIP_DHCP_NATIVE_IDX]);

  if (dhcp_idx_to_mac(netif, LWIP_DHCP_NATIVE_IDX, netif_dhcp->client.hwaddr, &hwaddr_len) != ERR_OK) {
    LWIP_DEBUGF(DHCP_DEBUG | LWIP_DBG_TRACE, ("dhcp_renew():get mac failed\n"));
    return ERR_VAL;
  }
  dhcp_state->hwaddr_len = hwaddr_len;

  return dhcp_renew_client(netif, &(netif_dhcp->client));
}

/*
 * Rebind with a DHCP server for an existing DHCP lease.
 *
 * @param netif network interface which must rebind with a DHCP server
 */
static err_t
dhcp_rebind(struct netif *netif, struct dhcp_client *dhcp)
{
  err_t result;
  u16_t msecs;
  u8_t i;
  struct dhcp_state *dhcp_state = &((dhcp->states)[dhcp->cli_idx]);
  LWIP_DEBUGF(DHCP_DEBUG | LWIP_DBG_TRACE | LWIP_DBG_STATE, ("dhcp_rebind()\n"));
  dhcp_set_state(dhcp, DHCP_STATE_REBINDING);

  /* create and initialize the DHCP message header */
  result = dhcp_create_msg(netif, dhcp, DHCP_REQUEST);
  if (result == ERR_OK) {
    dhcp_option(dhcp, DHCP_OPTION_MAX_MSG_SIZE, DHCP_OPTION_MAX_MSG_SIZE_LEN);
    dhcp_option_short(dhcp, DHCP_MAX_MSG_LEN(netif));

    dhcp_option(dhcp, DHCP_OPTION_PARAMETER_REQUEST_LIST, LWIP_ARRAYSIZE(dhcp_discover_request_options));
    for (i = 0; i < LWIP_ARRAYSIZE(dhcp_discover_request_options); i++) {
      dhcp_option_byte(dhcp, dhcp_discover_request_options[i]);
    }

    dhcp_option(dhcp, DHCP_OPTION_CLIENT_ID, 1 + dhcp_state->hwaddr_len);
    dhcp_option_byte(dhcp, dhcp->msg_out->htype);
    for (i = 0; i < dhcp_state->hwaddr_len; i++) {
      dhcp_option_byte(dhcp, dhcp->hwaddr[i]);
    }

#if LWIP_NETIF_HOSTNAME
    dhcp_option_hostname(dhcp, netif);
#endif /* LWIP_NETIF_HOSTNAME */

#if LWIP_DHCP_VENDOR_CLASS_IDENTIFIER
    dhcp_option_vci(dhcp, netif);
#endif /* LWIP_DHCP_VENDOR_CLASS_IDENTIFIER */

    dhcp_option_trailer(dhcp);

    pbuf_realloc(dhcp->p_out, (u16_t)((sizeof(struct dhcp_msg) - DHCP_OPTIONS_LEN) + dhcp->options_out_len));

    /* broadcast to server */
    (void)udp_sendto_if(dhcp_pcb, dhcp->p_out, IP_ADDR_BROADCAST, DHCP_SERVER_PORT, netif);
    dhcp_delete_msg(dhcp);
    LWIP_DEBUGF(DHCP_DEBUG | LWIP_DBG_TRACE | LWIP_DBG_STATE, ("dhcp_rebind: REBINDING\n"));
  } else {
    LWIP_DEBUGF(DHCP_DEBUG | LWIP_DBG_TRACE | LWIP_DBG_LEVEL_SERIOUS, ("dhcp_rebind: can not allocate DHCP request\n"));
  }
  if (dhcp_state->tries < 255) {
    dhcp_state->tries++;
  }
  msecs = (u16_t)(dhcp_state->tries < 10 ? dhcp_state->tries * 1000 : 10 * 1000);
  dhcp_state->request_timeout = (u16_t)((msecs + DHCP_FINE_TIMER_MSECS - 1) / DHCP_FINE_TIMER_MSECS);
  LWIP_DEBUGF(DHCP_DEBUG | LWIP_DBG_TRACE | LWIP_DBG_STATE, ("dhcp_rebind(): set request timeout %"U16_F" msecs\n",
                                                             msecs));
  return result;
}

/**
 * Enter REBOOTING state to verify an existing lease
 *
 * @param netif network interface which must reboot
 */
static err_t
dhcp_reboot(struct netif *netif)
{
  struct dhcp_client *dhcp = &(netif_dhcp_data(netif)->client);
  struct dhcp_state *dhcp_state = &((dhcp->states)[dhcp->cli_idx]);
  err_t result;
  u16_t msecs;
  u8_t i;
  ip4_addr_t cli_ip;

  LWIP_DEBUGF(DHCP_DEBUG | LWIP_DBG_TRACE | LWIP_DBG_STATE, ("dhcp_reboot()\n"));
  dhcp_set_state(dhcp, DHCP_STATE_REBOOTING);

  /* create and initialize the DHCP message header */
  result = dhcp_create_msg(netif, dhcp, DHCP_REQUEST);
  if (result == ERR_OK) {
    dhcp_option(dhcp, DHCP_OPTION_MAX_MSG_SIZE, DHCP_OPTION_MAX_MSG_SIZE_LEN);
    dhcp_option_short(dhcp, DHCP_MAX_MSG_LEN_MIN_REQUIRED);

    DHCP_HOST_TO_IP(cli_ip.addr, ip_2_ip4(&dhcp->server_ip_addr)->addr, dhcp->offered_sn_mask.addr,
                    dhcp_state->offered_ip_addr);
    dhcp_option(dhcp, DHCP_OPTION_REQUESTED_IP, 4);
    dhcp_option_long(dhcp, lwip_ntohl(ip4_addr_get_u32(&cli_ip)));

    dhcp_option(dhcp, DHCP_OPTION_PARAMETER_REQUEST_LIST, LWIP_ARRAYSIZE(dhcp_discover_request_options));
    for (i = 0; i < LWIP_ARRAYSIZE(dhcp_discover_request_options); i++) {
      dhcp_option_byte(dhcp, dhcp_discover_request_options[i]);
    }

    dhcp_option(dhcp, DHCP_OPTION_CLIENT_ID, 1 + dhcp_state->hwaddr_len);
    dhcp_option_byte(dhcp, dhcp->msg_out->htype);
    for (i = 0; i < dhcp_state->hwaddr_len; i++) {
      dhcp_option_byte(dhcp, dhcp->hwaddr[i]);
    }

#if LWIP_DHCP_VENDOR_CLASS_IDENTIFIER
    dhcp_option_vci(dhcp, netif);
#endif /* LWIP_DHCP_VENDOR_CLASS_IDENTIFIER */

    dhcp_option_trailer(dhcp);

    pbuf_realloc(dhcp->p_out, (u16_t)((sizeof(struct dhcp_msg) - DHCP_OPTIONS_LEN) + dhcp->options_out_len));

    /* broadcast to server */
    (void)udp_sendto_if(dhcp_pcb, dhcp->p_out, IP_ADDR_BROADCAST, DHCP_SERVER_PORT, netif);
    dhcp_delete_msg(dhcp);
    LWIP_DEBUGF(DHCP_DEBUG | LWIP_DBG_TRACE | LWIP_DBG_STATE, ("dhcp_reboot: REBOOTING\n"));
  } else {
    LWIP_DEBUGF(DHCP_DEBUG | LWIP_DBG_TRACE | LWIP_DBG_LEVEL_SERIOUS, ("dhcp_reboot: can not allocate DHCP request\n"));
  }
  if (dhcp_state->tries < 255) {
    dhcp_state->tries++;
  }
  msecs = (u16_t)(dhcp_state->tries < 10 ? dhcp_state->tries * 1000 : 10 * 1000);
  dhcp_state->request_timeout = (u16_t)((msecs + DHCP_FINE_TIMER_MSECS - 1) / DHCP_FINE_TIMER_MSECS);
  LWIP_DEBUGF(DHCP_DEBUG | LWIP_DBG_TRACE | LWIP_DBG_STATE, ("dhcp_reboot(): set request timeout %"U16_F" msecs\n",
                                                             msecs));

  return result;
}

/**
 * @ingroup dhcp4
 * Release a DHCP lease (usually called before @ref dhcp_stop).
 *
 * @param netif network interface which must release its lease
 */
static err_t
dhcp_release_client(struct netif *netif, struct dhcp_client *dhcp)
{
  err_t result;
  ip_addr_t server_ip_addr;
  u32_t i;
  struct dhcp_state *dhcp_state = &((dhcp->states)[dhcp->cli_idx]);

  ip_addr_copy(server_ip_addr, dhcp->server_ip_addr);

  dhcp_state->lease_used = 0;

  if (dhcp->cli_cnt == 1) {
    dhcp->offered_t0_lease = dhcp->offered_t1_renew = dhcp->offered_t2_rebind = 0;
    dhcp->t0_timeout = 0;
    dhcp->t1_timeout = 0;
    dhcp->t2_timeout = 0;
  }

  if (!((dhcp_state->state == DHCP_STATE_BOUND) ||
        (dhcp_state->state == DHCP_STATE_RENEWING) ||
        (dhcp_state->state == DHCP_STATE_REBINDING))) {
    /* clean old DHCP offer */
    if (dhcp->cli_cnt == 1) {
      ip_addr_set_zero_ip4(&dhcp->server_ip_addr);
      ip4_addr_set_zero(&dhcp->offered_sn_mask);
      ip4_addr_set_zero(&dhcp->offered_gw_addr);
    }
    dhcp_state->offered_ip_addr = 0;
    /* don't issue release message when address is not dhcp-assigned */
    return ERR_OK;
  }

  /* create and initialize the DHCP message header */
  result = dhcp_create_msg(netif, dhcp, DHCP_RELEASE);
  if (result == ERR_OK) {
    dhcp_option(dhcp, DHCP_OPTION_SERVER_ID, 4);
    dhcp_option_long(dhcp, lwip_ntohl(ip4_addr_get_u32(ip_2_ip4(&server_ip_addr))));

    dhcp_option(dhcp, DHCP_OPTION_CLIENT_ID, 1 + dhcp_state->hwaddr_len);
    dhcp_option_byte(dhcp, dhcp->msg_out->htype);
    for (i = 0; i < dhcp_state->hwaddr_len; i++) {
      dhcp_option_byte(dhcp, dhcp->hwaddr[i]);
    }

    dhcp_option_trailer(dhcp);

    pbuf_realloc(dhcp->p_out, (u16_t)((sizeof(struct dhcp_msg) - DHCP_OPTIONS_LEN) + dhcp->options_out_len));

    (void)udp_sendto_if(dhcp_pcb, dhcp->p_out, &server_ip_addr, DHCP_SERVER_PORT, netif);
    dhcp_delete_msg(dhcp);
    LWIP_DEBUGF(DHCP_DEBUG | LWIP_DBG_TRACE | LWIP_DBG_STATE, ("dhcp_release: RELEASED, DHCP_STATE_OFF\n"));
  } else {
    /* sending release failed, but that's not a problem since the correct behaviour of dhcp does not rely on release */
    LWIP_DEBUGF(DHCP_DEBUG | LWIP_DBG_TRACE | LWIP_DBG_LEVEL_SERIOUS, ("dhcp_release: can't allocate DHCP request\n"));
  }
  /* idle DHCP client */
  dhcp_set_state(dhcp, DHCP_STATE_OFF);
  /* clean old DHCP offer */
  if (dhcp->cli_cnt == 1) {
    ip_addr_set_zero_ip4(&dhcp->server_ip_addr);
    ip4_addr_set_zero(&dhcp->offered_sn_mask);
    ip4_addr_set_zero(&dhcp->offered_gw_addr);
  }
  dhcp_state->offered_ip_addr = 0;

  return result;
}

/*
 * @ingroup dhcp4
 * Release a DHCP lease (usually called before @ref dhcp_stop).
 *
 * @param netif network interface which must release its lease
 */
err_t
dhcp_release(struct netif *netif)
{
  err_t result;
  struct dhcp *netif_dhcp = NULL;
  struct dhcp_state *dhcp_state = NULL;
  u8_t hwaddr_len;

  LWIP_DEBUGF(DHCP_DEBUG | LWIP_DBG_TRACE, ("dhcp_release()\n"));
  LWIP_ERROR("netif != NULL", (netif != NULL), return ERR_ARG);

  netif_dhcp = netif_dhcp_data(netif);
  if (netif_dhcp == NULL) {
    return ERR_ARG;
  }

  netif_dhcp->client.cli_idx = LWIP_DHCP_NATIVE_IDX;
  dhcp_state = &((netif_dhcp->client.states)[LWIP_DHCP_NATIVE_IDX]);
  if (dhcp_state->state == DHCP_STATE_OFF) {
    return ERR_ARG;
  }

  if (dhcp_idx_to_mac(netif, LWIP_DHCP_NATIVE_IDX, netif_dhcp->client.hwaddr, &hwaddr_len) != ERR_OK) {
    LWIP_DEBUGF(DHCP_DEBUG | LWIP_DBG_TRACE, ("dhcp_release():get mac failed\n"));
    return ERR_VAL;
  }
  dhcp_state->hwaddr_len = hwaddr_len;

#if LWIP_DHCP_BOOTP_FILE
  ip4_addr_set_zero(&netif_dhcp->offered_si_addr);
#endif /* LWIP_DHCP_BOOTP_FILE */

  result = dhcp_release_client(netif, &(netif_dhcp->client));

  /* remove IP address from interface (prevents routing from selecting this interface) */
  (void)netif_set_addr(netif, IP4_ADDR_ANY4, IP4_ADDR_ANY4, IP4_ADDR_ANY4);

  return result;
}

static void
dhcp_stop_client(struct netif *netif, struct dhcp_client *dhcp)
{
  struct dhcp *netif_dhcp = NULL;
  struct dhcp_state *dhcp_state = &((dhcp->states)[dhcp->cli_idx]);

  netif_dhcp = netif_dhcp_data(netif);

  LWIP_ASSERT("reply wasn't freed", dhcp->msg_in == NULL);
  if (dhcp->cli_idx == LWIP_DHCP_NATIVE_IDX) {
    (void)dhcp_release(netif);
    if (netif_dhcp->pcb_allocated != 0) {
      dhcp_dec_pcb_refcount(); /* free DHCP PCB if not needed any more */
      netif_dhcp->pcb_allocated = 0;
    }
  } else {
#if LWIP_DHCP_SUBSTITUTE
    (void)dhcp_release_client(netif, dhcp);
    dhcp_dec_pcb_refcount();
#endif /* LWIP_DHCP_SUBSTITUTE */
  }
  dhcp_set_state(dhcp, DHCP_STATE_OFF);
  (void)memset_s(dhcp_state, sizeof(struct dhcp_state), 0, sizeof(struct dhcp_state));
  dhcp_clients_count_update(dhcp);
}

/**
 * @ingroup dhcp4
 * Remove the DHCP client from the interface.
 *
 * @param netif The network interface to stop DHCP on
 */
void
dhcp_stop(struct netif *netif)
{
  struct dhcp *netif_dhcp = NULL;
  struct dhcp_state *dhcp_state = NULL;
  u8_t hwaddr_len;
  LWIP_ERROR("dhcp_stop: netif != NULL", (netif != NULL), return);
  netif_dhcp = netif_dhcp_data(netif);

  netif->flags = netif->flags & (~NETIF_FLAG_DHCP);

  LWIP_DEBUGF(DHCP_DEBUG | LWIP_DBG_TRACE, ("dhcp_stop()\n"));
  /* netif is DHCP configured? */
  if (netif_dhcp != NULL) {
#if LWIP_DHCP_AUTOIP_COOP
    if (netif_dhcp->autoip_coop_state == DHCP_AUTOIP_COOP_STATE_ON) {
      autoip_stop(netif);
      netif_dhcp->autoip_coop_state = DHCP_AUTOIP_COOP_STATE_OFF;
    }
#endif /* LWIP_DHCP_AUTOIP_COOP */

    netif_dhcp->client.cli_idx = LWIP_DHCP_NATIVE_IDX;
    dhcp_state = &((netif_dhcp->client.states)[LWIP_DHCP_NATIVE_IDX]);

    if (dhcp_idx_to_mac(netif, LWIP_DHCP_NATIVE_IDX, netif_dhcp->client.hwaddr, &hwaddr_len) != ERR_OK) {
      LWIP_DEBUGF(DHCP_DEBUG | LWIP_DBG_TRACE, ("dhcp_stop():get mac failed\n"));
      return;
    }
    dhcp_state->hwaddr_len = hwaddr_len;

    dhcp_stop_client(netif, &(netif_dhcp->client));
  }
}

/*
 * Set the DHCP state of a DHCP client.
 *
 * If the state changed, reset the number of tries.
 */
static void
dhcp_set_state(struct dhcp_client *dhcp, u8_t new_state)
{
  struct dhcp_state *dhcp_state = &((dhcp->states)[dhcp->cli_idx]);
  if (new_state != dhcp_state->state) {
    dhcp_state->state = new_state;
    dhcp_state->tries = 0;
    dhcp_state->request_timeout = 0;
  }
}

/*
 * Concatenate an option type and length field to the outgoing
 * DHCP message.
 *
 */
static void
dhcp_option(struct dhcp_client *dhcp, u8_t option_type, u8_t option_len)
{
  LWIP_ASSERT("dhcp_option: dhcp->options_out_len + 2 + option_len <= DHCP_OPTIONS_LEN",
              dhcp->options_out_len + 2U + option_len <= DHCP_OPTIONS_LEN);
  dhcp->msg_out->options[dhcp->options_out_len++] = option_type;
  dhcp->msg_out->options[dhcp->options_out_len++] = option_len;
}
/*
 * Concatenate a single byte to the outgoing DHCP message.
 *
 */
static void
dhcp_option_byte(struct dhcp_client *dhcp, u8_t value)
{
  LWIP_ASSERT("dhcp_option_byte: dhcp->options_out_len < DHCP_OPTIONS_LEN", dhcp->options_out_len < DHCP_OPTIONS_LEN);
  dhcp->msg_out->options[dhcp->options_out_len++] = value;
}

static void
dhcp_option_short(struct dhcp_client *dhcp, u16_t value)
{
  LWIP_ASSERT("dhcp_option_short: dhcp->options_out_len + 2 <= DHCP_OPTIONS_LEN",
              dhcp->options_out_len + 2U <= DHCP_OPTIONS_LEN);
  dhcp->msg_out->options[dhcp->options_out_len++] = (u8_t)((value & 0xff00U) >> 8);
  dhcp->msg_out->options[dhcp->options_out_len++] = (u8_t) (value & 0x00ffU);
}

static void
dhcp_option_long(struct dhcp_client *dhcp, u32_t value)
{
  LWIP_ASSERT("dhcp_option_long: dhcp->options_out_len + 4 <= DHCP_OPTIONS_LEN",
              dhcp->options_out_len + 4U <= DHCP_OPTIONS_LEN);
  dhcp->msg_out->options[dhcp->options_out_len++] = (u8_t)((value & 0xff000000UL) >> 24);
  dhcp->msg_out->options[dhcp->options_out_len++] = (u8_t)((value & 0x00ff0000UL) >> 16);
  dhcp->msg_out->options[dhcp->options_out_len++] = (u8_t)((value & 0x0000ff00UL) >> 8);
  dhcp->msg_out->options[dhcp->options_out_len++] = (u8_t)((value & 0x000000ffUL));
}

#if LWIP_NETIF_HOSTNAME
static void
dhcp_option_hostname(struct dhcp_client *dhcp, struct netif *netif)
{
  const char *p = NULL;
  char dhcp_hostname[NETIF_HOSTNAME_MAX_LEN];
  size_t namelen = strlen(netif->hostname);
  if (namelen > 0) {
    p = netif->hostname;
  }

  if (p == NULL) {
    if (snprintf_s(dhcp_hostname, NETIF_HOSTNAME_MAX_LEN,
                   NETIF_HOSTNAME_MAX_LEN - 1, "%02x%02x%02x%02x%02x%02x",
                   netif->hwaddr[0], netif->hwaddr[1], netif->hwaddr[2],
                   netif->hwaddr[3], netif->hwaddr[4], netif->hwaddr[5]) <= EOK) {
      return;
    }
    dhcp_hostname[NETIF_HOSTNAME_MAX_LEN - 1] = '\0';
    p = dhcp_hostname;
  }

  namelen = strlen(p);
  /*
   * 3 : Validate length against available bytes (need 2 bytes for OPTION_HOSTNAME
   * and 1 byte for trailer)
   */
  LWIP_ASSERT("DHCP: hostname is too long!", namelen + 3 + dhcp->options_out_len <= DHCP_OPTIONS_LEN);
  dhcp_option(dhcp, DHCP_OPTION_HOSTNAME, (u8_t)namelen);
  while (namelen--) {
    dhcp_option_byte(dhcp, (u8_t)(*p++));
  }
}
#endif /* LWIP_NETIF_HOSTNAME */

#if LWIP_DHCP_VENDOR_CLASS_IDENTIFIER
LWIP_STATIC void
dhcp_option_vci(struct dhcp_client *dhcp, struct netif *netif)
{
  const char *p = NULL;
  u8_t len;
  size_t vci_len;
  size_t available;

  LWIP_UNUSED_ARG(netif);

  vci_len = g_vci_info.vci_len;
  if (vci_len > 0) {
    p = g_vci_info.vci;
  } else {
    return;
  }

  /* Shrink len to available bytes (need 2 bytes for DHCP_OPTION_VCI
     and 1 byte for trailer) */
  available = DHCP_OPTIONS_LEN - dhcp->options_out_len - 3;
  LWIP_ASSERT("DHCP: vci is too long!", vci_len <= available);
  len = (u8_t)LWIP_MIN(vci_len, available);
  dhcp_option(dhcp, DHCP_OPTION_VCI, len);
  while (len--) {
    dhcp_option_byte(dhcp, (u8_t)(*p++));
  }
}

err_t
dhcp_set_vci(char *vci, u8_t vci_len)
{
  if (memcpy_s(g_vci_info.vci, DHCP_VCI_MAX_LEN, vci, vci_len) == EOK) {
    g_vci_info.vci_len = vci_len;
    return ERR_OK;
  } else {
    return ERR_VAL;
  }
}

#if LWIP_DHCP_GET_VENDOR_CLASS_IDENTIFIER
err_t
dhcp_get_vci(char *vci, u8_t *vci_len)
{
  if (g_vci_info.vci_len == 0) {
    *vci_len = 0;
    return ERR_VAL;
  } else {
    if (memcpy_s(vci, *vci_len, g_vci_info.vci, g_vci_info.vci_len) == EOK) {
      *vci_len = g_vci_info.vci_len;
      return ERR_OK;
    } else {
      *vci_len = 0;
      return ERR_VAL;
    }
  }
}
#endif /* LWIP_DHCP_GET_VENDOR_CLASS_IDENTIFIER */
#endif /* LWIP_DHCP_VENDOR_CLASS_IDENTIFIER */

/**
 * Extract the DHCP message and the DHCP options.
 *
 * Extract the DHCP message and the DHCP options, each into a contiguous
 * piece of memory. As a DHCP message is variable sized by its options,
 * and also allows overriding some fields for options, the easy approach
 * is to first unfold the options into a contiguous piece of memory, and
 * use that further on.
 *
 */
static err_t
dhcp_parse_reply(struct dhcp *netif_dhcp, struct dhcp_client *dhcp, struct pbuf *p)
{
  u8_t *options = NULL;
  u16_t offset;
  u16_t offset_max;
  u16_t options_idx;
  u16_t options_idx_max;
  struct pbuf *q = NULL;
  int parse_file_as_options = 0;
  int parse_sname_as_options = 0;
  u16_t options_offset;

  (void)netif_dhcp;

  /* clear received options */
  dhcp_clear_all_options(dhcp);
  /* check that beginning of dhcp_msg (up to and including chaddr) is in first pbuf */
  if (p->len < DHCP_SNAME_OFS) {
    return ERR_BUF;
  }
  dhcp->msg_in = (struct dhcp_msg *)p->payload;
#if LWIP_DHCP_BOOTP_FILE
  /* clear boot file name */
  if (dhcp->cli_idx == LWIP_DHCP_NATIVE_IDX) {
    netif_dhcp->boot_file_name[0] = 0;
  }
#endif /* LWIP_DHCP_BOOTP_FILE */

  /* parse options */
  /* start with options field */
  options_idx = DHCP_OPTIONS_OFS;
  /* parse options to the end of the received packet */
  options_idx_max = p->tot_len;
again:
  q = p;
  options_offset = options_idx;
  while ((q != NULL) && (options_idx >= q->len)) {
    options_idx = (u16_t)(options_idx - q->len);
    options_idx_max = (u16_t)(options_idx_max - q->len);;
    q = q->next;
  }
  if (q == NULL) {
    return ERR_BUF;
  }
  offset = options_idx;
  offset_max = options_idx_max;
  options = (u8_t *)q->payload;
  /* at least 1 byte to read and no end marker, then at least 3 bytes to read? */
  while ((q != NULL) && (offset < offset_max) && (options[offset] != DHCP_OPTION_END)) {
    u8_t op = options[offset];
    u8_t len;
    u8_t decode_len = 0;
    int decode_idx = 0;
    u16_t val_offset = (u16_t)(offset + 2);
    /* len byte might be in the next pbuf */
    if ((offset + 1) < q->len) {
      len = options[offset + 1];
    } else {
      len = (u8_t)(q->next != NULL ? ((u8_t *)q->next->payload)[0] : 0);
    }

    decode_len = len;
    switch (op) {
      /* case(DHCP_OPTION_END): handled above */
      case (DHCP_OPTION_PAD):
        /* special option: no len encoded */
        decode_len = len = 0;
        /* will be increased below */
        offset--;
        break;
      case (DHCP_OPTION_SUBNET_MASK):
        LWIP_ERROR("len == 4", len == 4, return ERR_VAL);
        decode_idx = DHCP_OPTION_IDX_SUBNET_MASK;
        break;
      case (DHCP_OPTION_ROUTER):
        decode_len = 4; /* only copy the first given router */
        LWIP_ERROR("len >= decode_len", len >= decode_len, return ERR_VAL);
        decode_idx = DHCP_OPTION_IDX_ROUTER;
        break;
#if LWIP_DHCP_PROVIDE_DNS_SERVERS
      case (DHCP_OPTION_DNS_SERVER):
        /* special case: there might be more than one server */
        LWIP_ERROR("len %% 4 == 0", len % 4 == 0, return ERR_VAL);
        /* limit number of DNS servers */
#if DNS_MAX_SERVERS > 64
#error "Max number of servers can not be greater than 64"
#endif
        decode_len = (u8_t)LWIP_MIN(len, 4 * DNS_MAX_SERVERS);
        LWIP_ERROR("len >= decode_len", len >= decode_len, return ERR_VAL);
        decode_idx = DHCP_OPTION_IDX_DNS_SERVER;
        break;
#endif /* LWIP_DHCP_PROVIDE_DNS_SERVERS */
      case (DHCP_OPTION_LEASE_TIME):
        LWIP_ERROR("len == 4", len == 4, return ERR_VAL);
        decode_idx = DHCP_OPTION_IDX_LEASE_TIME;
        break;
#if LWIP_DHCP_GET_NTP_SRV
      case (DHCP_OPTION_NTP):
        /* special case: there might be more than one server */
        LWIP_ERROR("len %% 4 == 0", len % 4 == 0, return ERR_VAL);
        /* limit number of NTP servers */
        decode_len = LWIP_MIN(len, 4 * LWIP_DHCP_MAX_NTP_SERVERS);
        LWIP_ERROR("len >= decode_len", len >= decode_len, return ERR_VAL);
        decode_idx = DHCP_OPTION_IDX_NTP_SERVER;
        break;
#endif /* LWIP_DHCP_GET_NTP_SRV */
      case (DHCP_OPTION_OVERLOAD):
        LWIP_ERROR("len == 1", len == 1, return ERR_VAL);
        /* decode overload only in options, not in file/sname: invalid packet */
        LWIP_ERROR("overload in file/sname", options_offset == DHCP_OPTIONS_OFS, return ERR_VAL);
        decode_idx = DHCP_OPTION_IDX_OVERLOAD;
        break;
      case (DHCP_OPTION_MESSAGE_TYPE):
        LWIP_ERROR("len == 1", len == 1, return ERR_VAL);
        decode_idx = DHCP_OPTION_IDX_MSG_TYPE;
        break;
      case (DHCP_OPTION_SERVER_ID):
        LWIP_ERROR("len == 4", len == 4, return ERR_VAL);
        decode_idx = DHCP_OPTION_IDX_SERVER_ID;
        break;
      case (DHCP_OPTION_T1):
        LWIP_ERROR("len == 4", len == 4, return ERR_VAL);
        decode_idx = DHCP_OPTION_IDX_T1;
        break;
      case (DHCP_OPTION_T2):
        LWIP_ERROR("len == 4", len == 4, return ERR_VAL);
        decode_idx = DHCP_OPTION_IDX_T2;
        break;
      default:
        decode_len = 0;
        LWIP_DEBUGF(DHCP_DEBUG, ("skipping option %"U16_F" in options\n", (u16_t)op));
        break;
    }
    offset = (u16_t)(offset + len + 2);
    if (decode_len > 0) {
      u32_t value = 0;
      u16_t copy_len;
decode_next:
      LWIP_ERROR("check decode_idx", (decode_idx >= 0) && (decode_idx < DHCP_OPTION_IDX_MAX), return ERR_VAL);
      if (!dhcp_option_given(dhcp, decode_idx)) {
        copy_len = (u16_t)LWIP_MIN(decode_len, 4);
        if (pbuf_copy_partial(q, &value, copy_len, val_offset) != copy_len) {
          return ERR_BUF;
        }
        if (decode_len > 4) {
          /* decode more than one u32_t */
          LWIP_ERROR("decode_len %% 4 == 0", decode_len % 4 == 0, return ERR_VAL);
          dhcp_got_option(dhcp, decode_idx);
          dhcp_set_option_value(dhcp, decode_idx, lwip_htonl(value));
          decode_len = (u8_t)(decode_len - 4);
          val_offset = (u16_t)(val_offset + 4);
          decode_idx++;
          goto decode_next;
        } else if (decode_len == 4) {
          value = lwip_ntohl(value);
        } else {
          LWIP_ERROR("invalid decode_len", decode_len == 1, return ERR_VAL);
          value = ((u8_t *)&value)[0];
        }
        dhcp_got_option(dhcp, decode_idx);
        dhcp_set_option_value(dhcp, decode_idx, value);
      }
    }
    if (offset >= q->len) {
      offset = (u16_t)(offset - q->len);
      offset_max = (u16_t)(offset_max - q->len);
      if ((offset < offset_max) && offset_max) {
        q = q->next;
        LWIP_ERROR("next pbuf was null", q != NULL, return ERR_VAL);
        options = (u8_t *)q->payload;
      } else {
        /* We've run out of bytes, probably no end marker. Don't proceed. */
        break;
      }
    }
  }
  /* is this an overloaded message? */
  if (dhcp_option_given(dhcp, DHCP_OPTION_IDX_OVERLOAD)) {
    u32_t overload = dhcp_get_option_value(dhcp, DHCP_OPTION_IDX_OVERLOAD);
    dhcp_clear_option(dhcp, DHCP_OPTION_IDX_OVERLOAD);
    if (overload == DHCP_OVERLOAD_FILE) {
      parse_file_as_options = 1;
      LWIP_DEBUGF(DHCP_DEBUG | LWIP_DBG_TRACE, ("overloaded file field\n"));
    } else if (overload == DHCP_OVERLOAD_SNAME) {
      parse_sname_as_options = 1;
      LWIP_DEBUGF(DHCP_DEBUG | LWIP_DBG_TRACE, ("overloaded sname field\n"));
    } else if (overload == DHCP_OVERLOAD_SNAME_FILE) {
      parse_sname_as_options = 1;
      parse_file_as_options = 1;
      LWIP_DEBUGF(DHCP_DEBUG | LWIP_DBG_TRACE, ("overloaded sname and file field\n"));
    } else {
      LWIP_DEBUGF(DHCP_DEBUG | LWIP_DBG_TRACE, ("invalid overload option: %d\n", (int)overload));
    }
#if LWIP_DHCP_BOOTP_FILE
    if ((dhcp->cli_idx == LWIP_DHCP_NATIVE_IDX) && (parse_file_as_options == 0)) {
      /* only do this for ACK messages */
      if (dhcp_option_given(dhcp, DHCP_OPTION_IDX_MSG_TYPE) &&
          (dhcp_get_option_value(dhcp, DHCP_OPTION_IDX_MSG_TYPE) == DHCP_ACK))
        /* copy bootp file name, don't care for sname (server hostname) */
        if (pbuf_copy_partial(p, netif_dhcp->boot_file_name, DHCP_FILE_LEN - 1, DHCP_FILE_OFS) != (DHCP_FILE_LEN - 1)) {
          return ERR_BUF;
        }
      /* make sure the string is really NULL-terminated */
      netif_dhcp->boot_file_name[DHCP_FILE_LEN - 1] = 0;
    }
#endif /* LWIP_DHCP_BOOTP_FILE */
  }
  if (parse_file_as_options) {
    /* if both are overloaded, parse file first and then sname (RFC 2131 ch. 4.1) */
    parse_file_as_options = 0;
    options_idx = DHCP_FILE_OFS;
    options_idx_max = DHCP_FILE_OFS + DHCP_FILE_LEN;
    goto again;
  } else if (parse_sname_as_options) {
    parse_sname_as_options = 0;
    options_idx = DHCP_SNAME_OFS;
    options_idx_max = DHCP_SNAME_OFS + DHCP_SNAME_LEN;
    goto again;
  }
  return ERR_OK;
}

/*
 * If an incoming DHCP message is in response to us, then trigger the state machine
 */
static void
dhcp_recv(void *arg, struct udp_pcb *pcb, struct pbuf *p, const ip_addr_t *addr, u16_t port)
{
  struct netif *netif = ip_current_input_netif();
  struct dhcp *netif_dhcp = netif_dhcp_data(netif);
  struct dhcp_client *dhcp = NULL;
  struct dhcp_msg *reply_msg = (struct dhcp_msg *)p->payload;
  u8_t msg_type;
  dhcp_num_t mac_idx;
  struct dhcp_state *dhcp_state = NULL;
  u8_t hwaddr_len;
  u32_t xid;
#if LWIP_DHCP_SUBSTITUTE
  ip_addr_t server_id;
#endif /* LWIP_DHCP_SUBSTITUTE */

  LWIP_UNUSED_ARG(arg);

  /* Caught DHCP message from netif that does not have DHCP enabled? -> not interested */
  if ((netif_dhcp == NULL) || (dhcp_pcb_refcount == 0)) {
    goto free_pbuf_and_return;
  }

  LWIP_ASSERT("invalid server address type", IP_IS_V4(addr));

  LWIP_DEBUGF(DHCP_DEBUG | LWIP_DBG_TRACE,
              ("dhcp_recv(pbuf = %p) from DHCP server %"U16_F".%"U16_F".%"U16_F".%"U16_F" port %"U16_F"\n", (void *)p,
               ip4_addr1_16(ip_2_ip4(addr)), ip4_addr2_16(ip_2_ip4(addr)),
               ip4_addr3_16(ip_2_ip4(addr)), ip4_addr4_16(ip_2_ip4(addr)),
               port));
  LWIP_DEBUGF(DHCP_DEBUG | LWIP_DBG_TRACE, ("pbuf->len = %"U16_F"\n", p->len));
  LWIP_DEBUGF(DHCP_DEBUG | LWIP_DBG_TRACE, ("pbuf->tot_len = %"U16_F"\n", p->tot_len));
  /* prevent warnings about unused arguments */
  LWIP_UNUSED_ARG(pcb);
  LWIP_UNUSED_ARG(addr);
  LWIP_UNUSED_ARG(port);

  if (p->len < DHCP_MIN_REPLY_LEN) {
    LWIP_DEBUGF(DHCP_DEBUG | LWIP_DBG_TRACE | LWIP_DBG_LEVEL_WARNING, ("DHCP reply message or pbuf too short\n"));
    goto free_pbuf_and_return;
  }

  if (reply_msg->op != DHCP_BOOTREPLY) {
    LWIP_DEBUGF(DHCP_DEBUG | LWIP_DBG_TRACE | LWIP_DBG_LEVEL_WARNING, ("not a DHCP reply message, but type %"U16_F"\n",
                                                                       (u16_t)reply_msg->op));
    goto free_pbuf_and_return;
  }
  dhcp = &(netif_dhcp->client);

  if (dhcp_mac_to_idx(netif, reply_msg->chaddr, reply_msg->hlen, &mac_idx) != ERR_OK) {
    LWIP_DEBUGF(DHCP_DEBUG | LWIP_DBG_TRACE, ("dhcp_recv(): mac idx failed\n"));
    goto free_pbuf_and_return;
  }
  if (dhcp_client_find_by_mac_idx(dhcp, mac_idx, &(dhcp->cli_idx)) != ERR_OK) {
    LWIP_DEBUGF(DHCP_DEBUG | LWIP_DBG_TRACE, ("dhcp_recv(): no client\n"));
    goto free_pbuf_and_return;
  }
  dhcp_state = &((dhcp->states)[dhcp->cli_idx]);
  if (dhcp_idx_to_mac(netif, dhcp_state->idx, dhcp->hwaddr, &hwaddr_len) != ERR_OK) {
    LWIP_DEBUGF(DHCP_DEBUG | LWIP_DBG_TRACE, ("dhcp_recv(): get mac failed\n"));
    goto free_pbuf_and_return;
  }
  dhcp_state->hwaddr_len = hwaddr_len;

  LWIP_ASSERT("reply wasn't freed", dhcp->msg_in == NULL);

  /* match transaction ID against what we expected */
  DHCP_XID(xid, dhcp->hwaddr, dhcp_state->hwaddr_len, dhcp_state->xid);
  if (lwip_ntohl(reply_msg->xid) != xid) {
    LWIP_DEBUGF(DHCP_DEBUG | LWIP_DBG_TRACE | LWIP_DBG_LEVEL_WARNING,
                ("transaction id mismatch reply_msg->xid(%"X32_F")!=dhcp->xid(%"X32_F")\n",
                 (u32_t)lwip_ntohl(reply_msg->xid), xid));
    goto free_pbuf_and_return;
  }
  /* option fields could be unfold? */
  if (dhcp_parse_reply(netif_dhcp, dhcp, p) != ERR_OK) {
    LWIP_DEBUGF(DHCP_DEBUG | LWIP_DBG_TRACE | LWIP_DBG_LEVEL_SERIOUS,
                ("problem unfolding DHCP message - too short on memory?\n"));
    goto free_pbuf_and_return;
  }

#if LWIP_DHCP_SUBSTITUTE
  /* to check if the server changed */
  if (dhcp_option_given(dhcp, DHCP_OPTION_IDX_SERVER_ID)) {
    ip_addr_set_ip4_u32(&server_id, lwip_htonl(dhcp_get_option_value(dhcp, DHCP_OPTION_IDX_SERVER_ID)));
    if (!(ip4_addr_isany_val(dhcp->server_ip_addr.u_addr.ip4)) &&
        !(ip4_addr_cmp(ip_2_ip4(&server_id), ip_2_ip4(&(dhcp->server_ip_addr))))) {
      LWIP_DEBUGF(DHCP_DEBUG | LWIP_DBG_TRACE,
                  ("%u diff serv_id %s\n", dhcp->cli_idx, ip4addr_ntoa(ip_2_ip4(&server_id))));
      if (dhcp->cli_idx != LWIP_DHCP_NATIVE_IDX) {
        goto free_pbuf_and_return;
      }
      dhcp_substitute_clients_restart(netif, dhcp);
      dhcp->cli_idx = LWIP_DHCP_NATIVE_IDX;
      if (dhcp_idx_to_mac(netif, dhcp_state->idx, dhcp->hwaddr, &hwaddr_len) != ERR_OK) {
        LWIP_DEBUGF(DHCP_DEBUG | LWIP_DBG_TRACE, ("dhcp_recv(): get mac failed\n"));
        goto free_pbuf_and_return;
      }
      dhcp_state->hwaddr_len = hwaddr_len;
    }
  } else {
    LWIP_DEBUGF(DHCP_DEBUG | LWIP_DBG_TRACE | LWIP_DBG_LEVEL_SERIOUS,
                ("dhcp_recv(netif=%p) did not get server ID!\n", (void *)netif));
    goto free_pbuf_and_return;
  }
#endif /* LWIP_DHCP_SUBSTITUTE */

  LWIP_DEBUGF(DHCP_DEBUG | LWIP_DBG_TRACE, ("searching DHCP_OPTION_MESSAGE_TYPE\n"));
  /* obtain pointer to DHCP message type */
  if (!dhcp_option_given(dhcp, DHCP_OPTION_IDX_MSG_TYPE)) {
    LWIP_DEBUGF(DHCP_DEBUG | LWIP_DBG_TRACE | LWIP_DBG_LEVEL_WARNING, ("DHCP_OPTION_MESSAGE_TYPE option not found\n"));
    goto free_pbuf_and_return;
  }

  /* read DHCP message type */
  msg_type = (u8_t)dhcp_get_option_value(dhcp, DHCP_OPTION_IDX_MSG_TYPE);
  /* message type is DHCP ACK? */
  if (msg_type == DHCP_ACK) {
    LWIP_DEBUGF(DHCP_DEBUG | LWIP_DBG_TRACE, ("DHCP_ACK received\n"));
    /* in requesting state? */
    if (dhcp_state->state == DHCP_STATE_REQUESTING) {
      dhcp_handle_ack(netif, dhcp);
#if LWIP_DHCP_SUBSTITUTE
      ip4_addr_t cli_ip;
      DHCP_HOST_TO_IP(cli_ip.addr, ip_2_ip4(&dhcp->server_ip_addr)->addr, dhcp->offered_sn_mask.addr,
                      (dhcp->states)[dhcp->cli_idx].offered_ip_addr);
      if (dhcp_addr_clients_check(netif_dhcp, &cli_ip) == lwIP_TRUE) {
        LWIP_DEBUGF(DHCP_DEBUG | LWIP_DBG_TRACE | LWIP_DBG_LEVEL_WARNING, ("addr been used by substitute client\n"));
        goto free_pbuf_and_return;
      }
#endif /* LWIP_DHCP_SUBSTITUTE */
#if DHCP_DOES_ARP_CHECK
      if ((netif->flags & NETIF_FLAG_ETHARP) != 0) {
        /* check if the acknowledged lease address is already in use */
        dhcp_check(netif, dhcp);
      } else {
        /* bind interface to the acknowledged lease address */
        dhcp_bind(netif, dhcp);
      }
#else
      /* bind interface to the acknowledged lease address */
      dhcp_bind(netif, dhcp);
#endif
    }
    /* already bound to the given lease address? */
    else if ((dhcp_state->state == DHCP_STATE_REBOOTING) || (dhcp_state->state == DHCP_STATE_REBINDING) ||
             (dhcp_state->state == DHCP_STATE_RENEWING)) {
      dhcp_handle_ack(netif, dhcp);
      dhcp_bind(netif, dhcp);
    }
  }
  /* received a DHCP_NAK in appropriate state? */
  else if ((msg_type == DHCP_NAK) &&
           ((dhcp_state->state == DHCP_STATE_REBOOTING) || (dhcp_state->state == DHCP_STATE_REQUESTING) ||
            (dhcp_state->state == DHCP_STATE_REBINDING) || (dhcp_state->state == DHCP_STATE_RENEWING))) {
    LWIP_DEBUGF(DHCP_DEBUG | LWIP_DBG_TRACE, ("DHCP_NAK received\n"));
    dhcp_handle_nak(netif, dhcp);
  }
  /* received a DHCP_OFFER in DHCP_STATE_SELECTING state? */
  else if ((msg_type == DHCP_OFFER) && (dhcp_state->state == DHCP_STATE_SELECTING)) {
    LWIP_DEBUGF(DHCP_DEBUG | LWIP_DBG_TRACE, ("DHCP_OFFER received in DHCP_STATE_SELECTING state\n"));
    /* remember offered lease */
    dhcp_handle_offer(netif, dhcp);
  }

free_pbuf_and_return:
  if (dhcp != NULL) {
    dhcp->msg_in = NULL;
  }
  (void)pbuf_free(p);
}

/**
 * Create a DHCP request, fill in common headers
 *
 * @param netif the netif under DHCP control
 * @param dhcp dhcp control struct
 * @param message_type message type of the request
 */
static err_t
dhcp_create_msg(struct netif *netif, struct dhcp_client *dhcp, u8_t message_type)
{
  u16_t i;
  ip4_addr_t cli_ip;
  struct dhcp_state *dhcp_state = &((dhcp->states)[dhcp->cli_idx]);

#ifndef DHCP_GLOBAL_XID
  /** default global transaction identifier starting value (easy to match
   *  with a packet analyser). We simply increment for each new request.
   *  Predefine DHCP_GLOBAL_XID to a better value or a function call to generate one
   *  at runtime, any supporting function prototypes can be defined in DHCP_GLOBAL_XID_HEADER */
#if DHCP_CREATE_RAND_XID && defined(LWIP_RAND)
  static u32_t xid;
#else /* DHCP_CREATE_RAND_XID && defined(LWIP_RAND) */
  static u32_t xid = 0xABCD0000;
#endif /* DHCP_CREATE_RAND_XID && defined(LWIP_RAND) */
#else
  if (!xid_initialised) {
    xid = DHCP_GLOBAL_XID;
    xid_initialised = !xid_initialised;
  }
#endif
  LWIP_ERROR("dhcp_create_msg: netif != NULL", (netif != NULL), return ERR_ARG);
  LWIP_ERROR("dhcp_create_msg: dhcp != NULL", (dhcp != NULL), return ERR_VAL);
  LWIP_ASSERT("dhcp_create_msg: dhcp->p_out == NULL", dhcp->p_out == NULL);
  LWIP_ASSERT("dhcp_create_msg: dhcp->msg_out == NULL", dhcp->msg_out == NULL);
  dhcp->p_out = pbuf_alloc(PBUF_TRANSPORT, sizeof(struct dhcp_msg), PBUF_RAM);
  if (dhcp->p_out == NULL) {
    LWIP_DEBUGF(DHCP_DEBUG | LWIP_DBG_TRACE | LWIP_DBG_LEVEL_SERIOUS,
                ("dhcp_create_msg(): could not allocate pbuf\n"));
    return ERR_MEM;
  }
  LWIP_ASSERT("dhcp_create_msg: check that first pbuf can hold struct dhcp_msg",
              (dhcp->p_out->len >= sizeof(struct dhcp_msg)));

#if DRIVER_STATUS_CHECK
  dhcp->p_out->flags |= PBUF_FLAG_DHCP_BUF;
#endif

  /* DHCP_REQUEST should reuse 'xid' from DHCPOFFER */
  if ((message_type != DHCP_REQUEST) || (dhcp_state->state == DHCP_STATE_REBOOTING)) {
    /* reuse transaction identifier in retransmissions */
    if (dhcp_state->tries == 0) {
#if DHCP_CREATE_RAND_XID && defined(LWIP_RAND)
      xid = (u32_t)LWIP_RAND();
#else /* DHCP_CREATE_RAND_XID && defined(LWIP_RAND) */
      xid++;
#endif /* DHCP_CREATE_RAND_XID && defined(LWIP_RAND) */
    }
    dhcp_state->xid = (u8_t)xid;
  }
  LWIP_DEBUGF(DHCP_DEBUG | LWIP_DBG_TRACE,
              ("transaction id xid(%"X32_F")\n", xid));

  dhcp->msg_out = (struct dhcp_msg *)dhcp->p_out->payload;

  dhcp->msg_out->op = DHCP_BOOTREQUEST;

#if LWIP_ALWAYS_SEND_HWTYPE_AS_ETHER_IN_DHCP
  dhcp->msg_out->htype = DHCP_HTYPE_ETH;
#else
  dhcp->msg_out->htype = (u8_t)(netif->link_layer_type & 0xFF);
#endif
  dhcp->msg_out->hlen = dhcp_state->hwaddr_len;
  dhcp->msg_out->hops = 0;
  DHCP_XID(dhcp->msg_out->xid, dhcp->hwaddr, dhcp_state->hwaddr_len, dhcp_state->xid);
  dhcp->msg_out->xid = lwip_htonl(dhcp->msg_out->xid);
  dhcp->msg_out->secs = 0;
  /* we don't need the broadcast flag since we can receive unicast traffic
     before being fully configured! */
  dhcp->msg_out->flags = 0;
#if LWIP_DHCP_SUBSTITUTE
  if (dhcp->cli_idx != LWIP_DHCP_NATIVE_IDX) {
    dhcp->msg_out->flags |= lwip_htons(DHCP_BROADCAST_FLAG);
  }
#endif /* LWIP_DHCP_SUBSTITUTE */
  ip4_addr_set_zero(&dhcp->msg_out->ciaddr);
  /* set ciaddr to dhcp->offered_ip_addr based on message_type and state */
  if ((message_type == DHCP_INFORM) || ((message_type == DHCP_DECLINE) &&
                                        ((dhcp_state->state == DHCP_STATE_BOUND) ||
                                         (dhcp_state->state == DHCP_STATE_RENEWING) ||
                                         (dhcp_state->state == DHCP_STATE_REBINDING))) ||
      (message_type == DHCP_RELEASE) ||
      ((message_type == DHCP_REQUEST) && /* DHCP_STATE_BOUND not used for sending! */
       ((dhcp_state->state == DHCP_STATE_RENEWING) ||
        dhcp_state->state == DHCP_STATE_REBINDING))) {
    DHCP_HOST_TO_IP(cli_ip.addr, ip_2_ip4(&dhcp->server_ip_addr)->addr, dhcp->offered_sn_mask.addr,
                    dhcp_state->offered_ip_addr);
    ip4_addr_copy(dhcp->msg_out->ciaddr, cli_ip);
  }
  ip4_addr_set_zero(&dhcp->msg_out->yiaddr);
  ip4_addr_set_zero(&dhcp->msg_out->siaddr);
  ip4_addr_set_zero(&dhcp->msg_out->giaddr);
  for (i = 0; i < DHCP_CHADDR_LEN; i++) {
    /* copy client hardware address, pad with zeroes */
    dhcp->msg_out->chaddr[i] = (u8_t)((i < dhcp_state->hwaddr_len &&
                                       i < NETIF_MAX_HWADDR_LEN) ? dhcp->hwaddr[i] : 0); /* pad byte */
  }
  for (i = 0; i < DHCP_SNAME_LEN; i++) {
    dhcp->msg_out->sname[i] = 0;
  }
  for (i = 0; i < DHCP_FILE_LEN; i++) {
    dhcp->msg_out->file[i] = 0;
  }
  dhcp->msg_out->cookie = PP_HTONL(DHCP_MAGIC_COOKIE);
  dhcp->options_out_len = 0;
  /* fill options field with an incrementing array (for debugging purposes) */
  for (i = 0; i < DHCP_OPTIONS_LEN; i++) {
    dhcp->msg_out->options[i] = (u8_t)i; /* for debugging only, no matter if truncated */
  }
  /* Add option MESSAGE_TYPE */
  dhcp_option(dhcp, DHCP_OPTION_MESSAGE_TYPE, DHCP_OPTION_MESSAGE_TYPE_LEN);
  dhcp_option_byte(dhcp, message_type);
  return ERR_OK;
}

/**
 * Free previously allocated memory used to send a DHCP request.
 *
 * @param dhcp the dhcp struct to free the request from
 */
static void
dhcp_delete_msg(struct dhcp_client *dhcp)
{
  LWIP_ERROR("dhcp_delete_msg: dhcp != NULL", (dhcp != NULL), return);
  LWIP_ASSERT("dhcp_delete_msg: dhcp->p_out != NULL", dhcp->p_out != NULL);
  LWIP_ASSERT("dhcp_delete_msg: dhcp->msg_out != NULL", dhcp->msg_out != NULL);
  if (dhcp->p_out != NULL) {
    (void)pbuf_free(dhcp->p_out);
  }
  dhcp->p_out = NULL;
  dhcp->msg_out = NULL;
}

/**
 * Add a DHCP message trailer
 *
 * Adds the END option to the DHCP message, and if
 * necessary, up to three padding bytes.
 *
 * @param dhcp DHCP state structure
 */
static void
dhcp_option_trailer(struct dhcp_client *dhcp)
{
  LWIP_ERROR("dhcp_option_trailer: dhcp != NULL", (dhcp != NULL), return);
  LWIP_ASSERT("dhcp_option_trailer: dhcp->msg_out != NULL\n", dhcp->msg_out != NULL);
  LWIP_ASSERT("dhcp_option_trailer: dhcp->options_out_len < DHCP_OPTIONS_LEN\n",
              dhcp->options_out_len < DHCP_OPTIONS_LEN);
  dhcp->msg_out->options[dhcp->options_out_len++] = DHCP_OPTION_END;
  /* packet is too small, or not 4 byte aligned? */
  while (((dhcp->options_out_len < DHCP_MIN_OPTIONS_LEN) || (dhcp->options_out_len & 3)) &&
         (dhcp->options_out_len < DHCP_OPTIONS_LEN)) {
    /* add a fill/padding byte */
    dhcp->msg_out->options[dhcp->options_out_len++] = 0;
  }
}

#if LWIP_API_RICH
/** check if DHCP supplied netif->ip_addr
 *
 * @param netif the netif to check
 * @return 1 if DHCP supplied netif->ip_addr (states BOUND or RENEWING),
 *         0 otherwise
 */
u8_t
dhcp_supplied_address(const struct netif *netif)
{
  struct dhcp *netif_dhcp = NULL;
  struct dhcp_state *dhcp_state = NULL;
  if (netif != NULL) {
    netif_dhcp = netif_dhcp_data(netif);
    if (netif_dhcp == NULL) {
      return 0;
    }
    dhcp_state = &((netif_dhcp->client.states)[LWIP_DHCP_NATIVE_IDX]);
    return (u8_t)((dhcp_state->state == DHCP_STATE_BOUND) ||
                  (dhcp_state->state == DHCP_STATE_RENEWING) ||
                  (dhcp_state->state == DHCP_STATE_REBINDING));
  }
  return 0;
}
#endif /* LWIP_API_RICH */

#if LWIP_DHCP_SUBSTITUTE
static void
dhcp_substitute_clients_restart(struct netif *netif, struct dhcp_client *dhcp)
{
  int i;
  u8_t hwaddr_len;
  struct dhcp_state *dhcp_state = NULL;

  for (i = 1; i < DHCP_CLIENT_NUM; i++) {
    dhcp_state = &((dhcp->states)[i]);
    if ((dhcp_state->idx == 0)) {
      continue;
    }
    dhcp->cli_idx = (dhcp_num_t)i;
    if (dhcp_idx_to_mac(netif, dhcp_state->idx, dhcp->hwaddr, &hwaddr_len) != ERR_OK) {
      LWIP_DEBUGF(DHCP_DEBUG | LWIP_DBG_TRACE,
                  ("dhcp_substitute_clients_restart(): %u get mac failed\n", dhcp_state->idx));
      continue;
    }
    dhcp_state->hwaddr_len = hwaddr_len;
    (void)dhcp_release_client(netif, dhcp);
    (void)dhcp_discover(netif, dhcp);
  }

  return;
}

static s32_t
dhcp_addr_clients_check(struct dhcp *netif_dhcp, const ip4_addr_t *ipaddr)
{
  struct dhcp_client *dhcp = NULL;
  dhcp_num_t offered_ip_addr;
  struct dhcp_state *dhcp_state = NULL;
  int i;

  dhcp = &(netif_dhcp->client);

  DHCP_IP_TO_HOST(offered_ip_addr, ipaddr->addr, dhcp->offered_sn_mask.addr);
  for (i = 1; i < DHCP_CLIENT_NUM; i++) {
    dhcp_state = &((dhcp->states)[i]);
    if ((dhcp_state->idx == 0)) {
      continue;
    }
    if ((dhcp_state->state != DHCP_STATE_BOUND) && (dhcp_state->state != DHCP_STATE_RENEWING) &&
        (dhcp_state->state != DHCP_STATE_REBINDING)) {
      continue;
    }
    if (dhcp_state->offered_ip_addr == offered_ip_addr) {
      LWIP_DEBUGF(DHCP_DEBUG | LWIP_DBG_TRACE, ("dhcp_addr_clients_check(): %s used by substitute\n",
                                                ip4addr_ntoa(ipaddr)));
      return lwIP_TRUE;
    }
  }

  return lwIP_FALSE;
}

err_t
dhcp_substitute_start(struct netif *netif, dhcp_num_t mac_idx)
{
  err_t err;
  LWIP_ERROR("netif != NULL", (netif != NULL), return ERR_ARG);
  LWIP_ERROR("netif is not up, old style port?", netif_is_up(netif), return ERR_ARG);
  LWIP_ERROR("mac_idx != LWIP_DHCP_NATIVE_IDX", (mac_idx != LWIP_DHCP_NATIVE_IDX), return ERR_ARG);
  LWIP_DEBUGF(DHCP_DEBUG | LWIP_DBG_TRACE, ("dhcp_substitute_start:%u\n", mac_idx));

  err = dhcp_start_client(netif, mac_idx);
  if (err == ERR_OK) {
    dhcp_clients_count_update(&(netif_dhcp_data(netif)->client));
  }
  return err;
}

void
dhcp_substitute_stop(struct netif *netif, dhcp_num_t mac_idx)
{
  struct dhcp_client *dhcp = NULL;
  struct dhcp *netif_dhcp = NULL;
  struct dhcp_state *dhcp_state = NULL;
  u8_t hwaddr_len;

  LWIP_ERROR("netif != NULL", (netif != NULL), return);
  LWIP_ERROR("netif is not up, old style port?", netif_is_up(netif), return);
  LWIP_ERROR("mac_idx != LWIP_DHCP_NATIVE_IDX", (mac_idx != LWIP_DHCP_NATIVE_IDX), return);
  LWIP_DEBUGF(DHCP_DEBUG | LWIP_DBG_TRACE, ("dhcp_substitute_stop:%u\n", mac_idx));

  netif_dhcp = netif_dhcp_data(netif);
  if (netif_dhcp == NULL) {
    return;
  }

  dhcp = &(netif_dhcp->client);
  if (dhcp_client_find_by_mac_idx(dhcp, mac_idx, &(dhcp->cli_idx)) != ERR_OK) {
    LWIP_DEBUGF(DHCP_DEBUG | LWIP_DBG_TRACE, ("dhcp_substitute_stop(): client state not find for %u\n", mac_idx));
    return;
  }

  dhcp_state = &((dhcp->states)[dhcp->cli_idx]);
  if (dhcp_idx_to_mac(netif, dhcp_state->idx, dhcp->hwaddr, &hwaddr_len) != ERR_OK) {
    LWIP_DEBUGF(DHCP_DEBUG | LWIP_DBG_TRACE, ("dhcp_substitute_stop(): no client state for %u\n", mac_idx));
    return;
  }
  dhcp_state->hwaddr_len = hwaddr_len;

  dhcp_stop_client(netif, dhcp);

  return;
}

err_t
dhcp_substitute_idx_to_ip(struct netif *netif, dhcp_num_t idx, ip4_addr_t *ip)
{
  struct dhcp_client *dhcp = NULL;
  struct dhcp *netif_dhcp = NULL;
  struct dhcp_state *dhcp_state = NULL;
  int i;

  LWIP_ERROR("dhcp_substitute_idx_to_ip:netif != NULL", (netif != NULL), return ERR_ARG);
  LWIP_ERROR("dhcp_substitute_idx_to_ip:ip != NULL", (ip != NULL), return ERR_ARG);

  netif_dhcp = netif_dhcp_data(netif);
  if (netif_dhcp == NULL) {
    return ERR_VAL;
  }
  dhcp = &(netif_dhcp->client);

  for (i = 0; i < DHCP_CLIENT_NUM; i++) {
    dhcp_state = &((dhcp->states)[i]);
    if ((dhcp_state->idx != idx)) {
      continue;
    }
    if ((dhcp_state->state != DHCP_STATE_BOUND) && (dhcp_state->state != DHCP_STATE_RENEWING) &&
        (dhcp_state->state != DHCP_STATE_REBINDING)) {
      return ERR_INPROGRESS;
    }
    DHCP_HOST_TO_IP(ip->addr, ip_2_ip4(&dhcp->server_ip_addr)->addr, dhcp->offered_sn_mask.addr,
                    dhcp_state->offered_ip_addr);
    return ERR_OK;
  }

  return ERR_VAL;
}
#endif /* LWIP_DHCP_SUBSTITUTE */
#endif /* LWIP_IPV4 && LWIP_DHCP */
