/*
 *Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2019. All rights reserved.
 *Description: Wi-Fi sigma common source
 *Create: 2019-05-03
 */

/*****************************************************************************
  头文件包含
*****************************************************************************/
#include "hi_msg.h"
#include "wfa_debug.h"
#include "wfa_types.h"
#include "hi_wifitest_common.h"

/*****************************************************************************
  全局变量定义
*****************************************************************************/
extern unsigned int sigma_queue_id;
extern unsigned int sigma_resp_queue_id;

/*****************************************************************************
  函数实现
*****************************************************************************/
 int sigma_queue_init(void)
 {
     unsigned int ret;

     /* 创建队列 */
     ret = hi_msg_queue_create(&sigma_queue_id, SIGMA_QUEUE_MSG_NUM, sizeof(hi_sys_queue_msg));
     if (WFA_SUCCESS!= ret) {
         DPRINT_ERR(WFA_ERR,"msg queue init fail\r\n");
         return WFA_FAILURE;
     }

     ret = hi_msg_queue_create(&sigma_resp_queue_id, SIGMA_QUEUE_MSG_NUM, sizeof(hi_sys_queue_msg));
     if (WFA_SUCCESS!= ret) {
         DPRINT_ERR(WFA_ERR,"resp queue init fail\r\n");
         return WFA_FAILURE;
     }

     return WFA_SUCCESS;
 }

