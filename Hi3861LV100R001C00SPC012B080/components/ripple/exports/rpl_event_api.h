/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2012-2020. All rights reserved.
 * Description: RPL Management APIs. Start/Stop/Configure etc
 * Author: NA
 * Create: 2019-04-03
 */

#ifndef _RPL_EVENT_API_H_
#define _RPL_EVENT_API_H_

#include "ripple.h"

typedef struct {
  uint8_t status; /* check DAO_ACK_STATUS_* status values */
  uint16_t mnid; /* Unique mesh node ID, valid only if status=DAO_ACK_STATUS_OK */
  uint8_t flags;
} rpl_node_join_stat_t;

typedef enum {
  RPL_EVT_UNUSED,

  /*
   * When: On receiving a new instance (typically through first DIO).
   * OnReturn: If the indication returns RPL_FAIL, then the node does not join this instance.
   * Parameter: rpl_cfg_t, Configuation of the instance
   */
  RPL_EVT_JOIN_INSTANCE,

  /*
   * When: Node join status. If node join is success, then the E2E path is established.
   * OnReturn: NA
   * Parameter: rpl_node_join_stat_t
   */
  RPL_EVT_NODE_JOIN_STATUS,

  /*
   * When: New Node routing entry is added or removed or updated on root.
   * OnReturn: NA
   * Parameter: rpl_routeinfo_t
   */
  RPL_EVT_NODE_ROUTE_UPDATE,
} rpl_event_type_e;

/**
 * @Description: Indicate RPL event
 *
 * @param evt - Event Identified
 * @param instID - Instance on which event is received
 * @param arg - Additional information of the event.
 *
 * @return OK/FAIL
 */
uint8_t rpl_event_indicate(uint16_t evt, inst_t inst_id, void *arg);

#endif /* _RPL_EVENT_API_H_ */
