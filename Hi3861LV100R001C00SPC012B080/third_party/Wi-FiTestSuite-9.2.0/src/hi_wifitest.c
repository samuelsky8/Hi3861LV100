/*
 *Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2019. All rights reserved.
 *Description: Wi-Fi sigma test environment setup
 *Create: 2019-04-22
 */

/*****************************************************************************
  头文件包含
*****************************************************************************/
#include <stdio.h>
#include "wfa_debug.h"
#include "wfa_types.h"
#include "hi_wifitest_common.h"
#include "wfa_dut.h"
#include "hi_wifitest_uart.h"
#include "hi_wifitest.h"

hi_bool g_sigma_init = HI_FALSE;

/*****************************************************************************
   函数实现
*****************************************************************************/
unsigned int hi_sigma_init(void)
{
    if (g_sigma_init == HI_TRUE) {
        return WFA_SUCCESS;
    }

    unsigned int ret = sigma_queue_init();
    if (ret != WFA_SUCCESS) {
        DPRINT_ERR(WFA_ERR,"failed to create cmd queue!\n");
        return WFA_FAILURE;
    }

    ret = sigma_ca_Init();
    if (ret != WFA_SUCCESS) {
        DPRINT_ERR(WFA_ERR,"failed to create ca task!\n");
        return WFA_FAILURE;
    }

    ret = sigma_dut_init();
    if (ret != WFA_SUCCESS) {
        DPRINT_ERR(WFA_ERR,"failed to create dut task!\n");
        return WFA_FAILURE;
    }

    g_sigma_init = HI_TRUE;

    return WFA_SUCCESS;
}

