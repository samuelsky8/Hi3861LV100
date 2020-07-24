/**
 * @file
 * Implementation of raw protocol PCBs for low-level handling of
 * different types of protocols besides (or overriding) those
 * already available in lwIP.\n
 * See also @ref raw_raw
 *
 * @defgroup raw_raw RAW
 * @ingroup callbackstyle_api
 * Implementation of raw protocol PCBs for low-level handling of
 * different types of protocols besides (or overriding) those
 * already available in lwIP.\n
 * @see @ref raw_api
 */

/*
 * Copyright (c) 2001-2004 Swedish Institute of Computer Science.
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
 *
 * Author: Adam Dunkels <adam@sics.se>
 *
 */

#include "lwip/opt.h"

#if LWIP_RAW /* don't build if not configured for use in lwipopts.h */

#include "lwip/def.h"
#include "lwip/memp.h"
#include "lwip/ip_addr.h"
#include "lwip/netif.h"
#include "lwip/raw.h"
#include "lwip/stats.h"
#include "lwip/ip6.h"
#include "lwip/ip6_addr.h"
#include "lwip/inet_chksum.h"

#ifdef LWIP_IPV6
#include "lwip/icmp6.h"
#include "lwip/prot/udp.h"
#include "lwip/prot/tcp.h"
#include "lwip/api.h"
#endif

#include <string.h>

#if PF_PKT_SUPPORT
const struct eth_hdr *g_lwip_current_eth_hdr;
const struct netif *g_lwip_current_netif;
#endif

/** The list of RAW PCBs */
struct raw_pcb *raw_pcbs;
#if PF_PKT_SUPPORT
struct raw_pcb *pkt_raw_pcbs;
struct raw_pcb *all_pkt_raw_pcbs;
#endif

static u8_t
raw_input_match(struct raw_pcb *pcb, u8_t broadcast)
{
  LWIP_UNUSED_ARG(broadcast); /* in IPv6 only case */

#if LWIP_IPV4 && LWIP_IPV6
  /* Dual-stack: PCBs listening to any IP type also listen to any IP address */
  if (IP_IS_ANY_TYPE_VAL(pcb->local_ip)) {
#if IP_SOF_BROADCAST_RECV
    if ((broadcast != 0) && !ip_get_option(pcb, SOF_BROADCAST)) {
      return 0;
    }
#endif /* IP_SOF_BROADCAST_RECV */
    return 1;
  }
#endif /* LWIP_IPV4 && LWIP_IPV6 */

  /* Only need to check PCB if incoming IP version matches PCB IP version */
  if (IP_ADDR_PCB_VERSION_MATCH_EXACT(pcb, ip_current_dest_addr())) {
#if LWIP_IPV4
    /* Special case: IPv4 broadcast: receive all broadcasts
     * Note: broadcast variable can only be 1 if it is an IPv4 broadcast */
    if (broadcast != 0
#if IP_SOF_BROADCAST_RECV
        && (ip_get_option(pcb, SOF_BROADCAST))
#endif /* IP_SOF_BROADCAST_RECV */
       ) {
      if (ip4_addr_isany(ip_2_ip4(&pcb->local_ip))) {
        return 1;
      }
    } else
#endif /* LWIP_IPV4 */
      /* Handle IPv4 and IPv6: catch all or exact match */
      if (ip_addr_isany(&pcb->local_ip) ||
          ip_addr_cmp(&pcb->local_ip, ip_current_dest_addr())) {
        return 1;
      }
  }

  return 0;
}

#if LWIP_IPV6
#if LWIP_SOCK_OPT_ICMP6_FILTER
static u32_t
icmpv6_filter_check(struct pbuf *p, struct raw_pcb *pcb, s16_t proto, u16_t *typep)
{
  u8_t type;
  struct icmpv6_hdr *icmp6_tmphdr = NULL;
  /*
   * extract the icmp6 header type and check if it is present in icmp6_filter
   * filter structure.Use the ICMP6_FILTER_WILLBLOCK macros to check
   * if this icmpv6 message need to be blocked/filtered at application.
   * The current Macros are slightly reversed to rfc2292 macros. Macros are in compliance
   * with the litos linux header files.
   */
  if (proto == IPPROTO_ICMPV6) {
    u32_t *data = &pcb->icmp6_filter.icmp6_filt[0];
    icmp6_tmphdr = (struct icmpv6_hdr *)(p->payload);
    type = icmp6_tmphdr->type;
    *typep = type;
    return (u32_t) ((data[(type) >> ICMP6_FILTER_VAL]) & (1U << ((type) & ICMP6_FILTER_INTVAL)));
  }

  return 0;
}
#endif

static u32_t
lwip_ipv6checksum_validate(struct pbuf *p, struct raw_pcb *pcb, s16_t proto)
{
  u32_t ret = 0;

  if (proto == IP6_NEXTH_ICMP6) {
    /* checksum will be from 3rd byte. so */
    if (p->len < sizeof(struct icmpv6_hdr)) {
      /* drop short packets and dont give to application */
      LWIP_DEBUGF(RAW_DEBUG, ("icmp6_input: length mismatch failed .\n"));
      return 1;
    }

    /* if ret value is 0 it mean checksum is Ok. */
    ret = ip6_chksum_pseudo(p, pcb->raw_proto,  p->tot_len, ip6_current_src_addr(), ip6_current_dest_addr());
  } else {
    if (pcb->chksum_reqd == 0) {
      /* returning 0 , as the checksum validation is not enabled so need to give to app layer */
      return 0;
    }

    if ((proto == IP6_NEXTH_UDP) && (p->len < UDP_HLEN)) {
      /*
       * In this case it will be given to recv callback
       * in raw_input() if length is not proper
       * drop short packets
       */
      LWIP_DEBUGF(RAW_DEBUG,
                  ("udp_input: short UDP datagram (%"U16_F" bytes) discarded\n", p->tot_len));
      return 1;
    } else if ((proto == IP6_NEXTH_TCP) && (p->len < TCP_HLEN)) {
      /* drop short packets */
      LWIP_DEBUGF(RAW_DEBUG, ("tcp_input: short packet (%"U16_F" bytes) discarded\n", p->tot_len));
      return 1;
    }

    /* if ret value is 0 it mean checksum is Ok. */
    ret = ip6_chksum_pseudo(p, (u8_t)proto, p->tot_len,
                            ip6_current_src_addr(),
                            ip6_current_dest_addr());
  }
  return ret;
}

u32_t
is_icmpv6_ping_response(struct pbuf *p, s16_t proto)
{
  struct icmpv6_hdr *icmp6_tmphdr = NULL;

  if (proto == IPPROTO_ICMPV6) {
    /* extract the icmp6 header type and get type */
    icmp6_tmphdr = (struct icmpv6_hdr *)(p->payload);
    return (icmp6_tmphdr->type == ICMP6_TYPE_EREP);
  }
  return 0;
}

#endif

/**
 * Determine if in incoming IP packet is covered by a RAW PCB
 * and if so, pass it to a user-provided receive callback function.
 *
 * Given an incoming IP datagram (as a chain of pbufs) this function
 * finds a corresponding RAW PCB and calls the corresponding receive
 * callback function.
 *
 * @param p pbuf to be demultiplexed to a RAW PCB.
 * @param inp network interface on which the datagram was received.
 * @return - 1 if the packet has been processed by a RAW PCB receive
 *           callback function.
 * @return - 0 if packet is not been processed.
 *
 */
u8_t
raw_input(struct pbuf *p, struct netif *inp)
{
  struct raw_pcb *pcb = NULL;
  s16_t proto = 0;
  u8_t eaten = 0;

  u8_t broadcast = (u8_t)(ip_addr_isbroadcast(ip_current_dest_addr(), ip_current_netif()));

  LWIP_UNUSED_ARG(inp);

#if LWIP_IPV6
#if LWIP_IPV4
  if (IP_HDR_GET_VERSION(p->payload) == 6)
#endif /* LWIP_IPV4 */
  {
    struct ip6_hdr *ip6hdr = (struct ip6_hdr *)p->payload;
    proto = IP6H_NEXTH(ip6hdr);
  }
#if LWIP_IPV4
  else
#endif /* LWIP_IPV4 */
#endif /* LWIP_IPV6 */
#if LWIP_IPV4
  {
    proto = IPH_PROTO((struct ip_hdr *)p->payload);
  }
#endif /* LWIP_IPV4 */

  pcb = raw_pcbs;
  /* loop through all raw pcbs */
  /* this allows multiple pcbs to match against the packet by design */
  while (pcb != NULL) {
    if ((pcb->raw_proto == proto) &&
#if LWIP_SO_BINDTODEVICE
        ((pcb->ifindex == 0) || (pcb->ifindex == inp->ifindex)) &&
#endif
        raw_input_match(pcb, broadcast)) {
      /* receive callback function available? */
      if (pcb->recv != NULL) {
#if LWIP_IPV4 && LWIP_IPV6
        struct netconn *conn = NULL;
        conn = (struct netconn *) pcb->recv_arg;
        if (NETCONNTYPE_ISIPV6(NETCONN_TYPE(conn)) && IP_IS_V4_VAL(*ip_current_src_addr())) {
          pcb = pcb->next;
          continue;
        }
#endif
        /* the receive callback function did not eat the packet? */
        if (pcb->recv(pcb->recv_arg, pcb, p, ip_current_src_addr())) {
          eaten = 1;
        }
      }
      /* no receive callback function was set for this raw PCB */
    }

    pcb = pcb->next;
  }
  return eaten;
}

#ifdef LWIP_IPV6
/*
 * Determine if in incoming IP packet is covered by a RAW PCB
 * and if so, pass it to a user-provided receive callback function.
 *
 * Given an incoming IP datagram (as a chain of pbufs) this function
 * finds a corresponding RAW PCB and calls the corresponding receive
 * callback function.
 *
 * @param p pbuf to be demultiplexed to a RAW PCB.
 * @param inp network interface on which the datagram was received.
 * @return - 1 if the packet has been processed by a RAW PCB receive
 *           callback function.
 * @return - 0 if packet is not been processed.
 *
 */
u8_t
raw_input6(struct pbuf *p, s16_t proto, s8_t *isCheckSumInvalid, struct netif *inp)
{
  struct raw_pcb *pcb = NULL;
#if LWIP_SOCK_OPT_ICMP6_FILTER
  u16_t type = 0;
#endif
  u8_t eaten = 0;
  u32_t ret;
  if ((p == NULL) || (isCheckSumInvalid == NULL) || (inp == NULL)) {
    return eaten;
  }
  u8_t broadcast = (u8_t)(ip_addr_isbroadcast(ip_current_dest_addr(), ip_current_netif()));
  *isCheckSumInvalid = 0;
  for (pcb = raw_pcbs; pcb != NULL; pcb = pcb->next) {
    if ((pcb->raw_proto == proto) &&
        raw_input_match(pcb, broadcast)) {
      if (pcb->recv != NULL) {
#if LWIP_MAC_SECURITY
        /*
         * If the raw socket pcb will accept only secure packets
         * then we will drop the packet reeived without mac layer encryption
         */
        if ((inp->flags & NETIF_FLAG_MAC_SECURITY_SUPPORT) &&
            ((pcb->macsec_reqd != 0) && !is_icmpv6_ping_response(p, IPPROTO_ICMPV6)) &&
            !(p->flags & PBUF_FLAG_WITH_ENCRYPTION)) {
          LWIP_DEBUGF(RAW_DEBUG, ("Drop the packet as its not secure\n"));
          return eaten;
        }
#else
        (void)inp;
#endif
        ret = lwip_ipv6checksum_validate(p, pcb, proto);
        if (ret) {
          LWIP_DEBUGF(RAW_DEBUG, ("checksum validation failed for proto = %"U16_F"\n", proto));
          *isCheckSumInvalid = 1;
          continue;
        }
#if LWIP_SOCK_OPT_ICMP6_FILTER
        type = 0;
        ret = icmpv6_filter_check(p, pcb, proto, &type);
        if (ret != 0) {
          LWIP_DEBUGF(RAW_DEBUG, ("packet filtered of icmp6 type = %"U16_F"\n", type));
          continue;
        }
#endif
        /* the receive callback function did not eat the packet? */
        if (pcb->recv(pcb->recv_arg, pcb, p, ip_current_src_addr())) {
          eaten = 1;
        }
      }
    }
  }
  return eaten;
}

#endif

#if PF_PKT_SUPPORT
/*
 * Determine if in incoming IP packet is covered by a RAW PCB
 * and if so, pass it to a user-provided receive callback function.
 *
 * Given an incoming IP datagram (as a chain of pbufs) this function
 * finds a corresponding RAW PCB and calls the corresponding receive
 * callback function.
 *
 * @param p pbuf to be demultiplexed to a RAW PCB.
 * @param inp network interface on which the datagram was received.
  * @param from the pbuf is from which NETCONN_PKT_RAW type raw_pcb,
 *           otherwise it should be NULL.
 * @return- void
 *
 */
void
raw_pkt_input(struct pbuf *p, struct netif *inp, struct raw_pcb *from)
{
  struct raw_pcb *pcb = NULL;
  struct eth_hdr *ethhdr = NULL;
  u16_t proto;

  LWIP_UNUSED_ARG(inp);

  ethhdr = (struct eth_hdr *)p->payload;
  proto = ethhdr->type;

  g_lwip_current_eth_hdr = ethhdr;
  g_lwip_current_netif = inp;

  pcb = pkt_raw_pcbs;
  /* loop through all raw pcbs until the packet is eaten by one */
  /* this allows multiple pcbs to match against the packet by design */
  while (pcb != NULL) {
    if (((pcb->proto.eth_proto == htons(ETHTYPE_ALL)) ||
        ((p != NULL) && (p->flags & PBUF_FLAG_OUTGOING == 0) && (pcb->proto.eth_proto == proto))) &&
        ((pcb->netifindex == 0) || (pcb->netifindex == inp->ifindex)) && (pcb != from)) {
      /* receive callback function available? */
      if (pcb->recv != NULL) {
        /* the receive callback function did not eat the packet? */
        if (pcb->recv(pcb->recv_arg, pcb, p, NULL) != 0) {
          LWIP_DEBUGF(RAW_DEBUG, ("raw_pkt_input: packets recved failed \n"));
        }
      }
      /* no receive callback function was set for this raw PCB */
    }

    pcb = pcb->next;
  }

  g_lwip_current_eth_hdr = NULL;
  return;
}
#endif


/**
 * @ingroup raw_raw
 * Bind a RAW PCB.
 *
 * @param pcb RAW PCB to be bound with a local address ipaddr.
 * @param ipaddr local IP address to bind with. Use IP4_ADDR_ANY to
 * bind to all local interfaces.
 *
 * @return lwIP error code.
 * - ERR_OK. Successful. No error occurred.
 * - ERR_USE. The specified IP address is already bound to by
 * another RAW PCB.
 *
 * @see raw_disconnect()
 */
err_t
raw_bind(struct raw_pcb *pcb, const ip_addr_t *ipaddr)
{
  if ((pcb == NULL) || (ipaddr == NULL)) {
    return ERR_VAL;
  }

  ip_addr_set_ipaddr(&pcb->local_ip, ipaddr);

  if (netif_ipaddr_isbrdcast(ipaddr) || ip_addr_ismulticast(ipaddr)) {
    ip_set_option(pcb, SOF_BINDNONUNICAST);
  } else {
    ip_reset_option(pcb, SOF_BINDNONUNICAST);
  }

  pcb->flags |= RAW_FLAGS_HOST_ADDR_SET;
  return ERR_OK;
}

#if PF_PKT_SUPPORT
/*
 * Bind a RAW PCB for Packet family.
 *
 * @param pcb RAW PCB to be bound with a local address ipaddr.
 * @param ifindex Interface Index to bind with. Use IP_ADDR_ANY to
 * bind to all local interfaces.
 *
 * @return lwIP error code.
 * - ERR_OK. Successful. No error occured.
 *
 * @see raw_disconnect()
 */
err_t
raw_pkt_bind(struct raw_pcb *pcb, u8_t ifindex, u16_t proto)
{
  struct netif *loc_netif = NULL;

  if (ifindex != 0) {
    for (loc_netif = netif_list; loc_netif != NULL; loc_netif = loc_netif->next) {
      if (ifindex == loc_netif->ifindex) {
        break;
      }
    }

    /* Return if no matching netifs to bind */
    if (loc_netif == NULL) {
      LWIP_DEBUGF(RAW_DEBUG, ("raw_pkt_bind: No matching netif found for ifindex(%u)\n", ifindex));
      return ERR_NODEV;
    }
  } else {
    return ERR_NODEV;
  }

#if DRIVER_STATUS_CHECK
  if (!netif_is_up(loc_netif) || !netif_is_ready(loc_netif)) {
#else
  if (!netif_is_up(loc_netif)) {
#endif
    LWIP_DEBUGF(RAW_DEBUG, ("raw_pkt_bind: bind failed as netif (index %u) was down\n", ifindex));
    return ERR_NETDOWN;
  }

  pcb->netifindex = ifindex;
  pcb->proto.eth_proto = proto;

  return ERR_OK;
}
#endif

/**
 * @ingroup raw_raw
 * Connect an RAW PCB. This function is required by upper layers
 * of lwip. Using the raw api you could use raw_sendto() instead
 *
 * This will associate the RAW PCB with the remote address.
 *
 * @param pcb RAW PCB to be connected with remote address ipaddr and port.
 * @param ipaddr remote IP address to connect with.
 *
 * @return lwIP error code
 *
 * @see raw_disconnect() and raw_sendto()
 */
err_t
raw_connect(struct raw_pcb *pcb, const ip_addr_t *ipaddr)
{
  struct netif *netif = NULL;

  if ((pcb == NULL) || (ipaddr == NULL)) {
    return ERR_VAL;
  }

  netif = ip_route_pcb(ipaddr, (struct ip_pcb *)pcb);
  if (netif == NULL) {
    return ERR_NETUNREACH;
  }

  if (!ip_get_option(pcb, SOF_BROADCAST) && ip_addr_isbroadcast(ipaddr, netif)) {
    return ERR_ACCESS;
  }

  ip_addr_set_ipaddr(&pcb->remote_ip, ipaddr);
  pcb->flags |= RAW_FLAGS_PEER_ADDR_SET;
  return ERR_OK;
}

/**
 * @ingroup raw_raw
 * Set the callback function for received packets that match the
 * raw PCB's protocol and binding.
 *
 * The callback function MUST either
 * - eat the packet by calling pbuf_free() and returning non-zero. The
 *   packet will not be passed to other raw PCBs or other protocol layers.
 * - not free the packet, and return zero. The packet will be matched
 *   against further PCBs and/or forwarded to another protocol layers.
 */
void
raw_recv(struct raw_pcb *pcb, raw_recv_fn recv_fn, void *recv_arg)
{
  /* remember recv() callback and user data */
  pcb->recv = recv_fn;
  pcb->recv_arg = recv_arg;
}

#if PF_PKT_SUPPORT
/*
 * Send the raw IP packet through the given netif driver. Note that actually you cannot
 * modify the link layer header here. Packet need to be sent to driver as it is through the
 * given netif
 * @param pcb the raw pcb which to send
 * @param p the ethernet packet to send
 * @param ifindex the Interface index of the netif through which packet needs to be sent
 */
err_t
raw_pkt_sendto(struct raw_pcb *pcb, struct pbuf *p, u8_t ifindex)
{
  struct netif *netif = NULL;
  u8_t netifindex;
  LWIP_UNUSED_ARG(pcb);

  LWIP_DEBUGF(RAW_DEBUG | LWIP_DBG_TRACE, ("raw_pkt_sendto: ifindex=%d\n", ifindex));
  LWIP_ASSERT("p != NULL", p != NULL);

  netifindex = ifindex;

  if (ifindex == 0) {
    if (pcb->netifindex != 0) {
      netifindex = pcb->netifindex;
    } else {
      return ERR_NODEVADDR;
    }
  }

  /* Find the netif corresponding to the interface index */
  netif = netif_get_by_index(netifindex);
  if (netif == NULL) {
    LWIP_DEBUGF(RAW_DEBUG | LWIP_DBG_TRACE, ("netif not found for given ifindex (%u)\n", ifindex));
    return ERR_NODEVADDR;
  }

#if DRIVER_STATUS_CHECK
  if ((!netif_is_up(netif)) || (!netif_is_ready(netif))) {
#else
  if ((!netif_is_up(netif))) {
#endif
    LWIP_DEBUGF(RAW_DEBUG | LWIP_DBG_TRACE, ("netif was down for given ifindex (%u)\n", ifindex));
    return ERR_NETDOWN;
  }

  if ((p->tot_len - (SIZEOF_ETH_HDR - ETH_PAD_SIZE)) > netif->mtu) {
    LWIP_DEBUGF(RAW_DEBUG | LWIP_DBG_TRACE, ("Message too long (%u)\n", p->tot_len));
    return ERR_MSGSIZE;
  }

#if PF_PKT_SUPPORT
  if (pbuf_header(p, ETH_PAD_SIZE) == 0) {
    p->flags = (u16_t)(p->flags & ~(PBUF_FLAG_LLMCAST | PBUF_FLAG_LLBCAST | PBUF_FLAG_HOST));
    p->flags |= PBUF_FLAG_OUTGOING;
    raw_pkt_input(p, netif, pcb);
    (void)pbuf_header(p, -ETH_PAD_SIZE);
  }
#endif /* PF_PKT_SUPPORT */

  /*
   * For RAW packets of PF_PACKET family, do not modify the packets as it is
   * already supposed to contain the link layer header. So send directly to the driver
   */
  netif->drv_send(netif, p);
  LINK_STATS_INC(link.xmit);
  return ERR_OK;
}
#endif

/**
 * @ingroup raw_raw
 * Send the raw IP packet to the given address. Note that actually you cannot
 * modify the IP headers (this is inconsistent with the receive callback where
 * you actually get the IP headers), you can only specify the IP payload here.
 * It requires some more changes in lwIP. (there will be a raw_send() function
 * then.)
 *
 * @param pcb the raw pcb which to send
 * @param p the IP payload to send
 * @param ipaddr the destination address of the IP packet
 *
 */
err_t
raw_sendto(struct raw_pcb *pcb, struct pbuf *p, const ip_addr_t *ipaddr)
{
  err_t err;
  struct netif *netif = NULL;
  const ip_addr_t *src_ip = NULL;
  struct pbuf *q = NULL; /* q will be sent down the stack */
#if LWIP_SO_DONTROUTE
  rt_scope_t scope;
#endif
  s16_t header_size;

  if ((pcb == NULL) || (p == NULL) || (ipaddr == NULL) || !IP_ADDR_PCB_VERSION_MATCH(pcb, ipaddr)) {
    return ERR_VAL;
  }

#if LWIP_SO_DONTROUTE
  scope = ip_get_option(pcb, SOF_DONTROUTE) ? RT_SCOPE_LINK : RT_SCOPE_UNIVERSAL;
#endif

  LWIP_DEBUGF(RAW_DEBUG | LWIP_DBG_TRACE, ("raw_sendto\n"));

  header_size = (
#if LWIP_IPV4 && LWIP_IPV6
                  IP_IS_V6(ipaddr) ? IP6_HLEN : IP_HLEN);
#elif LWIP_IPV4
                  IP_HLEN);
#else
                  IP6_HLEN);
#endif

  if (pcb->hdrincl == 0) {
    /* not enough space to add an IP header to first pbuf in given p chain? */
    if (pbuf_header(p, header_size)) {
      /* allocate header in new pbuf */
      q = pbuf_alloc(PBUF_IP, 0, PBUF_RAM);
      /* new header pbuf could not be allocated? */
      if (q == NULL) {
        LWIP_DEBUGF(RAW_DEBUG | LWIP_DBG_TRACE | LWIP_DBG_LEVEL_SERIOUS, ("raw_sendto: could not allocate header\n"));
        return ERR_MEM;
      }
      if (p->tot_len != 0) {
#if LWIP_SO_PRIORITY
        q->priority = p->priority;
#endif /* LWIP_SO_PRIORITY */
        /* chain header q in front of given pbuf p */
        pbuf_chain(q, p);
      }
      /* { first pbuf q points to header pbuf } */
      LWIP_DEBUGF(RAW_DEBUG, ("raw_sendto: added header pbuf %p before given pbuf %p\n", (void *)q, (void *)p));
    } else {
      /* first pbuf q equals given pbuf */
      q = p;
      if (pbuf_header(q, (s16_t) - header_size)) {
        LWIP_ASSERT("Can't restore header we just removed!", 0);
        return ERR_MEM;
      }
    }
  }

  netif = ip_route_pcb(ipaddr, (struct ip_pcb *)pcb);
  if (netif == NULL) {
    LWIP_DEBUGF(RAW_DEBUG | LWIP_DBG_LEVEL_WARNING, ("raw_sendto: No route to "));
    ip_addr_debug_print(RAW_DEBUG | LWIP_DBG_LEVEL_WARNING, ipaddr);
    /* free any temporary header pbuf allocated by pbuf_header() */
    if (pcb->hdrincl == 0) {
      if (q != p) {
        (void)pbuf_free(q);
      }
    }
    return ERR_RTE;
  }

#if IP_SOF_BROADCAST
  if (IP_IS_V4(ipaddr)) {
    /* broadcast filter? */
    if (!ip_get_option(pcb, SOF_BROADCAST) && ip_addr_isbroadcast(ipaddr, netif)) {
      LWIP_DEBUGF(RAW_DEBUG | LWIP_DBG_LEVEL_WARNING,
                  ("raw_sendto: SOF_BROADCAST not enabled on pcb %p\n", (void *)pcb));
      /* free any temporary header pbuf allocated by pbuf_header() */
      if (pcb->hdrincl == 0) {
        if (q != p) {
          (void)pbuf_free(q);
        }
      }
      return ERR_ACCESS;
    }
  }
#endif /* IP_SOF_BROADCAST */

  if (ip_addr_isany(&pcb->local_ip) || ip_get_option(pcb, SOF_BINDNONUNICAST)) {
    /* use outgoing network interface IP address as source address */
    src_ip = ip_netif_get_local_ip(netif, ipaddr);
#if LWIP_IPV6
    if (src_ip == NULL) {
      if ((pcb->hdrincl == 0) && (q != p)) {
        (void)pbuf_free(q);
      }
      return ERR_RTE;
    }
#endif /* LWIP_IPV6 */
  } else {
    /* use RAW PCB local IP address as source address */
    src_ip = &pcb->local_ip;
  }

#if LWIP_IPV6
  /* If requested, based on the IPV6_CHECKSUM socket option per RFC3542,
     compute the checksum and update the checksum in the payload. */
  if (IP_IS_V6(ipaddr) && pcb->chksum_reqd) {
    u16_t chksum;

    if (p->len >= (pcb->chksum_offset + LWIP_IPV6_CHKSUM_LEN)) {
      switch (pcb->raw_proto) {
        case IP6_NEXTH_ICMP6:
          if (pcb->chksum_offset != IPV6_ICMP_CHKSUM_OFFSET) {
            LWIP_DEBUGF(RAW_DEBUG,
                        ("raw_sendto: chksum offset = %"U16_F" value not matching to proto length = %"U16_F" \n",
                         pcb->chksum_offset, p->len));
            if ((pcb->hdrincl == 0) && (q != p)) {
              (void)pbuf_free(q);
            }
            return ERR_VAL;
          }
          break;
        case IP6_NEXTH_UDP:
          if (pcb->chksum_offset != IPV6_UDP_CHKSUM_OFFSET) {
            LWIP_DEBUGF(RAW_DEBUG,
                        ("raw_sendto: chksum offset = %"U16_F" value not matching to proto length = %"U16_F" \n",
                         pcb->chksum_offset, p->len));
            if ((pcb->hdrincl == 0) && (q != p)) {
              (void)pbuf_free(q);
            }
            return ERR_VAL;
          }
          break;
        case IP6_NEXTH_TCP:
          if (pcb->chksum_offset != IPV6_TCP_CHKSUM_OFFSET) {
            LWIP_DEBUGF(RAW_DEBUG,
                        ("raw_sendto: chksum offset = %"U16_F" value not matching to proto length = %"U16_F" \n",
                         pcb->chksum_offset, p->len));
            if ((pcb->hdrincl == 0) && (q != p)) {
              (void)pbuf_free(q);
            }
            return ERR_VAL;
          }
          break;

        default:
          /* default proto will have to processed and the offset need to added */
          if ((pcb->hdrincl == 0) && (q != p)) {
            (void)pbuf_free(q);
            return ERR_VAL;
          }
          break;
      }

      /* Clear the checksum field before inserting checksum */
      if (memset_s(((u8_t *)p->payload) + pcb->chksum_offset, sizeof(u16_t), 0, sizeof(u16_t)) != EOK) {
        if ((pcb->hdrincl == 0) && (q != p)) {
          (void)pbuf_free(q);
        }
        return ERR_MEM;
      }
      chksum = ip6_chksum_pseudo(p, pcb->raw_proto, p->tot_len, ip_2_ip6(src_ip), ip_2_ip6(ipaddr));
      if (memcpy_s(((u8_t *)p->payload) + pcb->chksum_offset, sizeof(u16_t), &chksum, sizeof(u16_t)) != EOK) {
        if ((pcb->hdrincl == 0) && (q != p)) {
          (void)pbuf_free(q);
        }
        return ERR_MEM;
      }
    } else {
      LWIP_DEBUGF(RAW_DEBUG,
                  ("raw_sendto: chksum offset = %"U16_F" value is not within the packet length = %"U16_F" \n",
                   pcb->chksum_offset, p->len));
      if ((pcb->hdrincl == 0) && (q != p)) {
        (void)pbuf_free(q);
      }
      return ERR_VAL;
    }
  }
#endif

  NETIF_SET_HWADDRHINT(netif, &pcb->addr_hint);
#if LWIP_SO_DONTROUTE
  if (pcb->hdrincl == 0) {
    if ((scope == RT_SCOPE_LINK) && (q != NULL)) {
      q->flags |= PBUF_FLAG_IS_LINK_ONLY;
    }
  }
#endif /* LWIP_SO_DONTROUTE */
  /*
   * For IPv6 pcb->hdrincl will always 0. In that case condition
   * will be true and q will be pointing to valid pbuf.
   * For IPv4 pcb->hdrincl can be 0 or 1. In case of 0 q will be valid in
   * case of 1 flow will not come to if block it will go to else block.
   * So in both the case q will always valid . It won't lead to any invalid
   * memory access.
   */
  if (IP_IS_V6(ipaddr) || (pcb->hdrincl == 0)) {
#if LWIP_IPV6 && LWIP_MAC_SECURITY
    if (pcb->macsec_reqd != 0) {
      q->flags |= PBUF_FLAG_WITH_ENCRYPTION;
    }
#endif
#if LWIP_SO_PRIORITY
    q->priority = pcb->priority;
#endif /* LWIP_SO_PRIORITY */
    err = ip_output_if (q, src_ip, ipaddr, pcb->ttl, pcb->tos, pcb->raw_proto, netif);
  } else {
    struct ip_hdr *iphdr = NULL;
    struct pbuf *r = NULL;
    u16_t iphdr_hlen = 0;

    if ((netif->mtu != 0) && (p->tot_len > netif->mtu)) {
      return ERR_VAL;
    }

    if (p->tot_len < IP_HLEN) {
      LWIP_DEBUGF(RAW_DEBUG, ("raw_sendto: Packet length samller than IPv4 header length \n"));
      return ERR_VAL;
    }

    iphdr = (struct ip_hdr *)p->payload;
    if (iphdr == NULL) {
      return ERR_VAL;
    }
    /* obtain IP header length in bytes */
    iphdr_hlen = (u16_t)((u16_t)IPH_HL(iphdr) << 2);
    if (p->tot_len < iphdr_hlen) {
      LWIP_DEBUGF(RAW_DEBUG, ("raw_sendto: Packet length less than IP packet header length\n"));
      return ERR_VAL;
    }

    if (IPH_V(iphdr) != IP_PROTO_VERSION_4) {
      LWIP_DEBUGF(RAW_DEBUG, ("raw_sendto: Not an IPv4 packet \n"));
      return ERR_VAL;
    }

    /* allocate new packet buffer with space for link headers */
#if LWIP_NETIF_TX_SINGLE_PBUF
    /* Optimization: Avoiding a copy operation if there is only one pbuf */
    if (p->next != NULL) {
      r = pbuf_alloc(PBUF_LINK, p->tot_len, PBUF_RAM);
      if (r == NULL) {
        LWIP_DEBUGF(RAW_DEBUG, ("raw_sendto: allocating new pbuf failed \n"));
        return ERR_MEM;
      }
      /* copy the whole packet including ip header */
      if (pbuf_copy(r, p) != ERR_OK) {
        LWIP_DEBUGF(RAW_DEBUG, ("raw_sendto: copying to new pbuf failed \n"));
        (void)pbuf_free(r);
        return ERR_MEM;
      }
    } else {
      r = p;
      pbuf_ref(r);
    }

    /* Point to new memory, as it is going to be updated */
    iphdr = (struct ip_hdr *)r->payload;
#else
    r = pbuf_alloc(PBUF_IP, 0, PBUF_RAM);
    if (r == NULL) {
      LWIP_DEBUGF(RAW_DEBUG, ("raw_sendto: allocating new pbuf failed \n"));
      return ERR_MEM;
    }

    /* IP header may be modified, copy to local buffer */
    (void)pbuf_header(r, IP_HLEN);
    (void)pbuf_take(r, p->payload, IP_HLEN);

    /* skip header from incoming packet  */
    (void)pbuf_header(p, -IP_HLEN);
    pbuf_chain(r, p);

    /* Point to new memory, as it is going to be updated */
    iphdr = (struct ip_hdr *)r->payload;
#endif

    /* iphdr remains valid here, can be used directly */
    /* IP Header fields modified on sending by IP_HDRINCL */
    /* Filled in when zero */
    if (iphdr->src.addr == 0) {
      iphdr->src.addr = ip4_addr_get_u32(ip_2_ip4(src_ip));
    }

    /* Filled in when zero */
    if (IPH_ID(iphdr) == 0) {
      IPH_ID_SET(iphdr, ip4_get_ip_id());
      ip4_inc_ip_id();
    }

    /* Length & Checksum are always set */
    IPH_LEN_SET(iphdr, lwip_htons(r->tot_len));

    IPH_CHKSUM_SET(iphdr, 0);
#if CHECKSUM_GEN_IP
    IPH_CHKSUM_SET(iphdr, inet_chksum(iphdr, iphdr_hlen));
#endif

    IP_STATS_INC(ip.xmit);

    LWIP_DEBUGF(IP_DEBUG, ("ip4_output_if: %c%c%"U16_F"\n", netif->name[0], netif->name[1], (u16_t)netif->num));
    ip4_debug_print(r);

#if ENABLE_LOOPBACK
    if (ip4_addr_cmp(ip_2_ip4(ipaddr), netif_ip4_addr(netif))
#if !LWIP_HAVE_LOOPIF
        || ip4_addr_isloopback(ip_2_ip4(ipaddr))
#endif /* !LWIP_HAVE_LOOPIF */
       ) {
      /* Packet to self, enqueue it for loopback */
      LWIP_DEBUGF(IP_DEBUG, ("netif_loop_output()"));
      err = netif_loop_output(netif, r);
      (void)pbuf_free(r);
      return err;
    }

#if LWIP_MULTICAST_TX_OPTIONS
    if (ip_addr_ismulticast(ipaddr) && (r->flags & PBUF_FLAG_MCASTLOOP) != 0) {
      (void)netif_loop_output(netif, r);
    }
#endif /* LWIP_MULTICAST_TX_OPTIONS */
#endif /* ENABLE_LOOPBACK */
#if LWIP_SO_DONTROUTE
    if (scope == RT_SCOPE_LINK) {
      r->flags |= PBUF_FLAG_IS_LINK_ONLY;
    }
#endif /* LWIP_SO_DONTROUTE */

    LWIP_DEBUGF(RAW_DEBUG, ("raw_sendto: call netif->output()\n"));
    NETIF_SET_HWADDRHINT(netif, &pcb->addr_hint);
#if LWIP_IPV6 && LWIP_MAC_SECURITY
    if (pcb->macsec_reqd) {
      r->flags |= PBUF_FLAG_WITH_ENCRYPTION;
    }
#endif

#if LWIP_SO_PRIORITY
    r->priority = pcb->priority;
#endif /* LWIP_SO_PRIORITY */

    err = netif->output(netif, r, ip_2_ip4(ipaddr));
    (void)pbuf_free(r);
    NETIF_SET_HWADDRHINT(netif, NULL);
    return err;
  }

  NETIF_SET_HWADDRHINT(netif, NULL);

  /* did we chain a header earlier? */
  if ((pcb->hdrincl == 0) && (q != p)) {
    /* free the header */
    (void)pbuf_free(q);
  }
  return err;
}

/**
 * @ingroup raw_raw
 * Send the raw IP packet to the address given by raw_connect()
 *
 * @param pcb the raw pcb which to send
 * @param p the IP payload to send
 *
 */
err_t
raw_send(struct raw_pcb *pcb, struct pbuf *p)
{
  return raw_sendto(pcb, p, &pcb->remote_ip);
}

/**
 * @ingroup raw_raw
 * Remove an RAW PCB.
 *
 * @param pcb RAW PCB to be removed. The PCB is removed from the list of
 * RAW PCB's and the data structure is freed from memory.
 *
 * @see raw_new()
 */
void
raw_remove(struct raw_pcb *pcb)
{
  struct raw_pcb *pcb2 = NULL;
  /* pcb to be removed is first in list? */
  if (raw_pcbs == pcb) {
    /* make list start at 2nd pcb */
    raw_pcbs = raw_pcbs->next;
    /* pcb not 1st in list */
  } else {
    for (pcb2 = raw_pcbs; pcb2 != NULL; pcb2 = pcb2->next) {
      /* find pcb in raw_pcbs list */
      if (pcb2->next != NULL && pcb2->next == pcb) {
        /* remove pcb from list */
        pcb2->next = pcb->next;
        break;
      }
    }
  }
  memp_free(MEMP_RAW_PCB, pcb);
}

/**
 * @ingroup raw_raw
 * Create a RAW PCB.
 *
 * @return The RAW PCB which was created. NULL if the PCB data structure
 * could not be allocated.
 *
 * @param proto the protocol number of the IPs payload (e.g. IP_PROTO_ICMP)
 *
 * @see raw_remove()
 */
struct raw_pcb *
raw_new(u8_t proto)
{
  struct raw_pcb *pcb = NULL;

  LWIP_DEBUGF(RAW_DEBUG | LWIP_DBG_TRACE, ("raw_new\n"));

  pcb = (struct raw_pcb *)memp_malloc(MEMP_RAW_PCB);
  /* could allocate RAW PCB? */
  if (pcb != NULL) {
    /* initialize PCB to all zeroes */
    (void)memset_s(pcb, sizeof(struct raw_pcb), 0, sizeof(struct raw_pcb));
#if PF_PKT_SUPPORT
    pcb->proto.protocol = proto;
#else
    pcb->protocol = proto;
#endif

    pcb->ttl = RAW_TTL;
    pcb->next = raw_pcbs;
    raw_pcbs = pcb;
  }
  return pcb;
}

#if PF_PKT_SUPPORT
/*
 * Create a RAW PCB for Packet family.
 *
 * @return The RAW PCB which was created. NULL if the PCB data structure
 * could not be allocated.
 *
 * @param proto the protocol number of the IPs payload (e.g. IP_PROTO_ICMP)
 *
 * @see raw_remove()
 */
struct raw_pcb *
raw_pkt_new(u16_t proto)
{
  struct raw_pcb *pcb = NULL;

  LWIP_DEBUGF(RAW_DEBUG | LWIP_DBG_TRACE, ("raw_pkt_new\n"));

  pcb = (struct raw_pcb *)memp_malloc(MEMP_RAW_PCB);
  /* could allocate RAW PCB? */
  if (pcb != NULL) {
    /* initialize PCB to all zeroes */
    (void)memset_s(pcb, sizeof(struct raw_pcb), 0, sizeof(struct raw_pcb));
    pcb->proto.eth_proto = proto;
    pcb->ttl = RAW_TTL;
    pcb->next = pkt_raw_pcbs;
    pkt_raw_pcbs = pcb;

    if (proto == htons(ETHTYPE_ALL)) {
      pcb->all_next = all_pkt_raw_pcbs;
      all_pkt_raw_pcbs = pcb;
    }

#if LWIP_NETIF_PROMISC
    netif_start_promisc_mode (pcb->netifindex);
#endif
  }
  return pcb;
}

/*
 * Remove an RAW PCB of packet family type
 *
 * @param pcb RAW PCB to be removed. The PCB is removed from the list of
 * RAW PCB's and the data structure is freed from memory.
 *
 * @see raw_pkt_new()
 */
void
raw_pkt_remove(struct raw_pcb *pcb)
{
  struct raw_pcb *pcb2 = NULL;

  /* NULL check */
  if (pcb == NULL) {
    return;
  }

  /* pcb to be removed is first in all_pkt list? */
  if (all_pkt_raw_pcbs == pcb) {
    /* make list start at 2nd pcb */
    all_pkt_raw_pcbs = all_pkt_raw_pcbs->all_next;
    /* pcb not 1st in list */
  } else {
    for (pcb2 = all_pkt_raw_pcbs; pcb2 != NULL; pcb2 = pcb2->all_next) {
      /* find pcb in all_pkt_raw_pcbs list */
      if (pcb2->all_next == pcb) {
        /* remove pcb from list */
        pcb2->all_next = pcb->all_next;
      }
    }
  }

  /* pcb to be removed is first in list? */
  if (pkt_raw_pcbs == pcb) {
    /* make list start at 2nd pcb */
    pkt_raw_pcbs = pkt_raw_pcbs->next;
    /* pcb not 1st in list */
  } else {
    for (pcb2 = pkt_raw_pcbs; pcb2 != NULL; pcb2 = pcb2->next) {
      /* find pcb in raw_pcbs list */
      if (pcb2->next == pcb) {
        /* remove pcb from list */
        pcb2->next = pcb->next;
      }
    }
  }

#if LWIP_NETIF_PROMISC
  netif_stop_promisc_mode(pcb->netifindex);
#endif  /* LWIP_NETIF_PROMISC */
  memp_free(MEMP_RAW_PCB, pcb);
}

#if LWIP_NETIF_PROMISC
/* provides the count of pkt_raw_pcbs using this netif */
u8_t
pkt_raw_pcbs_using_netif(u8_t ifindex)
{
  struct raw_pcb *pcb = NULL;
  u8_t count = 0;

  for (pcb = pkt_raw_pcbs; pcb != NULL; pcb = pcb->next) {
    /* check for without bind and netif binded pakcet raw sockets */
    if ((pcb->netifindex == 0) || (pcb->netifindex == ifindex)) {
      count++;
    }
  }
  return count;
}
#endif /* LWIP_NETIF_PROMISC */
#endif /* PF_PKT_SUPPORT */

/**
 * @ingroup raw_raw
 * Create a RAW PCB for specific IP type.
 *
 * @return The RAW PCB which was created. NULL if the PCB data structure
 * could not be allocated.
 *
 * @param type IP address type, see @ref lwip_ip_addr_type definitions.
 * If you want to listen to IPv4 and IPv6 (dual-stack) packets,
 * supply @ref IPADDR_TYPE_ANY as argument and bind to @ref IP_ANY_TYPE.
 * @param proto the protocol number (next header) of the IPv6 packet payload
 *              (e.g. IP6_NEXTH_ICMP6)
 *
 * @see raw_remove()
 */
struct raw_pcb *
raw_new_ip_type(u8_t type, u8_t proto)
{
  struct raw_pcb *pcb = NULL;
  pcb = raw_new(proto);
#if LWIP_IPV4 && LWIP_IPV6
  if (pcb != NULL) {
    IP_SET_TYPE_VAL(pcb->local_ip,  type);
    IP_SET_TYPE_VAL(pcb->remote_ip, type);
  }
#else /* LWIP_IPV4 && LWIP_IPV6 */
  LWIP_UNUSED_ARG(type);
#endif /* LWIP_IPV4 && LWIP_IPV6 */
  return pcb;
}

/** This function is called from netif.c when address is changed
 *
 * @param old_addr IP address of the netif before change
 * @param new_addr IP address of the netif after change
 */
void
raw_netif_ip_addr_changed(const ip_addr_t *old_addr, const ip_addr_t *new_addr)
{
  struct raw_pcb *rpcb = NULL;

  if (!ip_addr_isany(old_addr) && !ip_addr_isany(new_addr)) {
    for (rpcb = raw_pcbs; rpcb != NULL; rpcb = rpcb->next) {
      /* PCB bound to current local interface address? */
      if (ip_addr_cmp(&rpcb->local_ip, old_addr)) {
        /* The PCB is bound to the old ipaddr and
         * is set to bound to the new one instead */
        ip_addr_copy(rpcb->local_ip, *new_addr);
      }
    }
  }
}

#endif /* LWIP_RAW */
