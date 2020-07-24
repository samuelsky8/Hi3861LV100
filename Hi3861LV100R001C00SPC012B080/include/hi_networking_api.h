/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: mesh networking api.
 * Author: wangwenjie
 * Create: 2019-09-24
 */

#ifndef _HI_NETWORKING_API_H_
#define _HI_NETWORKING_API_H_
#include <hi_types_base.h>
#include "hi_wifi_api.h"

typedef enum hi_elect_result_category {
    HI_STA, // sta£¬only connect Wi-Fi router  such as mobile tv,
    HI_MBR, // power limited device, can join mesh but can't become mesh gate, such as lock
    HI_MG, // device can be sta ¡¢mesh gate andmbr
    HI_LEADE_CONFLICT // a leader get an other leder's announce
} hi_elect_result_category;

typedef hi_void (*hi_election_call)(const hi_u8 event);

hi_s32 hi_start_election(hi_election_call func);
hi_s32 hi_stop_election(hi_void);
hi_s32 hi_join_mesh_network(hi_u8 mode);
hi_s32 hi_quit_mesh_network(hi_void);

#endif
