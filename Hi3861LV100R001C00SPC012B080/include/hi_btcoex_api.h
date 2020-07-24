/*
* Copyright (c) Huawei Technologies Co., Ltd. 2012-2019. All rights reserved.
* Description: ��������API�ӿ�
* Author: ʯ�� s00490621
* Create: 2019-12-02
*/

/**
* @defgroup hi_wifi_btcoex
* @ingroup hi_wifi_btcoex
*/

#ifndef __HI_BTCOEX_API_H__
#define __HI_BTCOEX_API_H__

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

/**
* @ingroup  hi_wifi_btcoex
* @brief    Set wifi & bt coexist on/off.
*           CNcomment:���������/�رա�CNend
*
* @par Description:
*           Set wifi & bt coexist on while wifi and bt are both turned on.
*           or set wifi & bt coexist off while bt is turned off.
*           CNcomment:wifi & bt ����ʱ��coexist���棬bt �ر�ʱ�ص�coexist���档CNend
*
* @attention  NULL
* @param  ifname          [IN]     Type  #const char *, device name.
* @param  func            [IN]     Type  #enable, whether to turn wifi & bt coexist on or off.
*
* @retval #HISI_OK         Excute successfully
* @retval #Other           Error code
* @par Dependency:
*            @li hi_btcoex_api.h: WiFi API
* @see  NULL
* @since Hi3861_V100R001C00
*/
hi_u32 hi_wifi_btcoex_enable(const hi_char *ifname, hi_bool enable, hi_u8 mode, hi_u8 share_ant);

#ifdef __cplusplus
#if __cplusplus
    }
#endif
#endif

#endif /* end of hi_btcoex_api.h */
