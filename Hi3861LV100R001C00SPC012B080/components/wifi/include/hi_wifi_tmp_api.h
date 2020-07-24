/**
 * @defgroup hi_wifi WiFi API
 */
/**
 * @defgroup hi_wifi_tmp TMP
 * @ingroup hi_wifi
 */
/**
 * @file hi_wifi_tmp_api.h
 *
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2019. All rights reserved. \n
 * Description: header file for wifi api.CNcomment:������WiFi api�ӿ�ͷ�ļ�CNend\n
 * Author: Hisilicon \n
 * Create: 2019-01-03
 */

#ifndef __HI_WIFI_TMP_API_H__
#define __HI_WIFI_TMP_API_H__

#include "hi_wifi_api.h"

#ifdef __cplusplus
#if __cplusplus
    extern "C" {
#endif
#endif

/**
* @ingroup  hi_wifi_pm
* @brief    Set dhcp offload on/off.CNcomment:����dhcp offload ��/�رա�CNend
*
* @par Description:
*           Set dhcp offload on with ip address, or set dhcp offload off.
*           CNcomment:����arp offload�򿪡�����������Ӧip��ַ����������arp offload�رա�CNend
*
* @attention  NULL
* @param  ifname         [IN]     Type  #const char *, device name.
* @param  en             [IN]     Type  #unsigned char, dhcp offload type, 1-on, 0-off.
* @param  ip             [IN]     Type  #unsigned int *, ip address in network byte order.
*
* @retval #HISI_OK         Excute successfully
* @retval #Other           Error code
* @par Dependency:
*            @li hi_wifi_tmp_api.h: WiFi API
* @see  NULL
* @since Hi3861_V100R001C00
*/
unsigned char hi_wifi_dhcp_offload_setting(const char *ifname, unsigned char en, unsigned int ip);

#ifdef __cplusplus
#if __cplusplus
    }
#endif
#endif

#endif
