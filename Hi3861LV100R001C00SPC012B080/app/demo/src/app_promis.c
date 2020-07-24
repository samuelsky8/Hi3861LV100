/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: app_promis.c
 * Author: yangjiahai
 * Create: 2020-03-17
 */

/****************************************************************************
      1 ͷ�ļ�����
****************************************************************************/
#include "stdio.h"
#include "stdlib.h"
#include <hi_wifi_api.h>
#include <hi_errno.h>
#include "app_promis.h"
#include <hi_at.h>

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

/*****************************************************************************
 ��������  : ����ģʽ���հ��ϱ�
*****************************************************************************/
int hi_promis_recv(void* recv_buf, int frame_len, signed char rssi)
{
    hi_at_printf("resv buf: %u , len: %d , rssi: %c\r\n", *(unsigned int*)recv_buf, frame_len, rssi);

    return HI_ERR_SUCCESS;
}

/*****************************************************************************
 ��������  : ��������ģʽ
 �������  : ifname��vapģʽ���磺wlan0
 �������  : ��
 �� �� ֵ  : �ɹ�����HI_ERR_SUCCESS

 �޸���ʷ      :
  1.��    ��   : 2020��3��17��
    ��    ��   : y00521973
    �޸�����   : �����ɺ���
*****************************************************************************/
unsigned int hi_promis_start(const char *ifname)
{
    int ret;
    hi_wifi_ptype_filter filter = {0};

    filter.mdata_en = 1;
    filter.udata_en = 1;
    filter.mmngt_en = 1;
    filter.umngt_en = 1;

    hi_wifi_promis_set_rx_callback(hi_promis_recv);

    ret = hi_wifi_promis_enable(ifname, 1, &filter);
    if (ret != HI_ERR_SUCCESS) {
        hi_at_printf("hi_wifi_promis_enable:: set error!\r\n");
        return ret;
    }

    hi_at_printf("start promis SUCCESS!\r\n");

    return HI_ERR_SUCCESS;
}

/*****************************************************************************
 ��������  : �رջ���ģʽ
 �������  : ifname��vapģʽ���磺wlan0
 �������  : ��
 �� �� ֵ  : �ɹ�����HI_ERR_SUCCESS

 �޸���ʷ      :
  1.��    ��   : 2020��3��17��
    ��    ��   : y00521973
    �޸�����   : �����ɺ���
*****************************************************************************/
unsigned int hi_promis_stop(const char *ifname)
{
    int ret;
    hi_wifi_ptype_filter filter = {0};

    ret = hi_wifi_promis_enable(ifname, 0, &filter);
    if (ret != HI_ERR_SUCCESS) {
        hi_at_printf("hi_wifi_promis_enable:: set error!\r\n");
        return ret;
    }

    hi_at_printf("stop promis SUCCESS!\r\n");

    return HI_ERR_SUCCESS;
}

#ifdef __cplusplus
#if __cplusplus
    }
#endif
#endif
