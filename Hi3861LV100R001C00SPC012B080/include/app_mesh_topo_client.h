/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: app_mesh_topo_client.h
 * Author: hisilicon
 * Create: 2020-02-20
 */

#ifndef __APP_MESH_TOPO_CLIENT_H__
#define __APP_MESH_TOPO_CLIENT_H__
#ifdef LOSCFG_APP_MESH
#include "hi_stdlib.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

hi_s32 mesh_topo_mbrclient_start(hi_s32 ctx);

hi_s32 mesh_topo_mgclient_start(hi_s32 ctx);

hi_s32 mesh_topo_client_stop(hi_void);

#endif
#ifdef __cplusplus
#if __cplusplus
    }
#endif
#endif
#endif

