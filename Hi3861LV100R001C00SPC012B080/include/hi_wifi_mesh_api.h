/**
* @file hi_wifi_mesh_api.h
*
* Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2019. All rights reserved. \n
* Description: header file for wifi api.CNcomment:������WiFi Mesh api�ӿ�ͷ�ļ���CNend\n
* Author: Hisilicon \n
* Create: 2019-01-03
*/

/**
 * @defgroup hi_wifi_mesh WiFi Mesh Settings
 * @ingroup hi_wifi
 */

#ifndef __HI_WIFI_MESH_API_H__
#define __HI_WIFI_MESH_API_H__

#include "hi_wifi_api.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

/**
 * @ingroup hi_wifi_mesh
 *
 * max auth type length.CNcomment:�û��������֤��ʽ��󳤶�CNend
 */
#define WPA_MAX_AUTH_TYPE_INPUT_LEN     32

/**
 * @ingroup hi_wifi_mesh
 *
 * max usr ie length.CNcomment:�û�IE�ֶ���󳤶�CNend
 */
#define HI_WIFI_USR_IE_MAX_SIZE 352

/**
 * @ingroup hi_wifi_mesh
 *
 * Frame type that usr ies will insert into.CNcomment: ������ie�ֶε�֡����.CNend
 */
typedef enum  {
    HI_WIFI_FRAME_TYPE_BEACON    = bit(0),
    HI_WIFI_FRAME_TYPE_PROBE_REQ = bit(1),
    HI_WIFI_FRAME_TYPE_BUTT
} hi_wifi_frame_type;

/**
 * @ingroup hi_wifi_mesh
 *
 * Usr ie type to be inserted.CNcomment: ������ie�ֶ�����.CNend
 */
typedef enum  {
    HI_WIFI_USR_IE_TYPE_DEFAULT = 0,
    HI_WIFI_USR_IE_BUTT
} hi_wifi_usr_ie_type;

/**
 * @ingroup hi_wifi_basic
 * Struct of scan result.CNcomment:ɨ�����ṹ��CNend
 */
typedef struct {
    char ssid[HI_WIFI_MAX_SSID_LEN + 1];    /**< SSID ֻ֧��ASCII�ַ� */
    unsigned char bssid[HI_WIFI_MAC_LEN];   /**< BSSID */
    unsigned int channel;                   /**< �ŵ��� */
    hi_wifi_auth_mode auth;                 /**< ��֤���� */
    int rssi;                               /**< �ź�ǿ�� */
    unsigned char resv : 4;                 /**< Reserved */
    unsigned char hisi_mesh_flag : 1;       /**< HI MESH��־ */
    unsigned char is_mbr : 1;               /**< �Ƿ���MBR��־ */
    unsigned char accept_for_sta : 1;       /**< �Ƿ�����STA���� */
    unsigned char accept_for_peer : 1;      /**< �Ƿ�����Mesh AP���� */
    unsigned char bcn_prio;                 /**< BCN���ȼ� */
    unsigned char peering_num;              /**< �Զ����ӵ���Ŀ */
} hi_wifi_mesh_scan_result_info;

/**
 * @ingroup hi_wifi_mesh
 *
 * Struct of connected mesh.CNcomment:�����ӵ�peer�ṹ�塣CNend
 *
 */
typedef struct {
    unsigned char mac[HI_WIFI_MAC_LEN];       /**< �Զ�mac��ַ */
    unsigned char mesh_bcn_priority;          /**< BCN���ȼ� */
    unsigned char mesh_is_mbr : 1;            /**< �Ƿ���MBR */
    unsigned char mesh_block : 1;             /**< block�Ƿ���λ */
    unsigned char mesh_role : 1;              /**< mesh�Ľ�ɫ */
} hi_wifi_mesh_peer_info;

/**
 * @ingroup hi_wifi_mesh
 *
 * Struct of mesh's config.CNcomment:mesh���ò���CNend
 *
 */
typedef struct {
    char ssid[HI_WIFI_MAX_SSID_LEN + 1];     /**< SSID ֻ֧��ASCII�ַ� */
    char key[HI_WIFI_AP_KEY_LEN + 1];        /**< ���� */
    hi_wifi_auth_mode auth;                  /**< ��֤���ͣ�ֻ֧��HI_WIFI_SECURITY_OPEN��HI_WIFI_SECURITY_SAE */
    unsigned char channel;                   /**< �ŵ��� */
} hi_wifi_mesh_config;

/**
* @ingroup  hi_wifi_mesh
* @brief  Mesh disconnect peer by mac address.CNcomment:meshָ���Ͽ����ӵ����硣CNend
*
* @par Description:
*          Mesh disconnect peer by mac address.CNcomment:softapָ���Ͽ����ӵ����硣CNend
*
* @attention  NULL
* @param  addr             [IN]     Type  #const char *, peer mac address.CNcomment:�Զ�MAC��ַ��CNend
* @param  addr_len         [IN]     Type  #unsigned char, peer mac address length.CNcomment:�Զ�MAC��ַ���ȡ�CNend
*
* @retval #HISI_OK        Execute successfully.
* @retval #HISI_FAIL      Execute failed.
* @par Dependency:
*            @li hi_wifi_api.h: WiFi API
* @see  NULL
* @since Hi3861_V100R001C00
*/
int hi_wifi_mesh_disconnect(const unsigned char *addr, unsigned char addr_len);

/**
* @ingroup  hi_wifi_mesh
* @brief  Start mesh interface.CNcomment:����mesh��CNend
*
* @par Description:
*           Add mesh interface.CNcomment:����mesh��CNend
*
* @attention  1. The memories of <ifname> and <len> memories are requested by the caller.
*             CNcomment:1. <ifname>��<len>�ɵ����������ڴ�CNend
*             2. SSID only supports ASCII characters.
*                CNcomment:2. SSID ֻ֧��ASCII�ַ�.CNend
* @param config    [IN]     Type  #hi_wifi_mesh_config * mesh's configuration.CNcomment:mesh���á�CNend
*        ifname    [IN/OUT] Type  #char * mesh interface name.CNcomment:������mesh�ӿ����ơ�CNend
*        len       [IN/OUT] Type  #int * mesh interface name length.CNcomment:������mesh�ӿ����Ƶĳ��ȡ�CNend
*
* @retval #HISI_OK        Execute successfully.
* @retval #HISI_FAIL      Execute failed.
* @par Dependency:
*            @li hi_wifi_api.h: WiFi API
* @see  NULL
* @since Hi3861_V100R001C00
*/
int hi_wifi_mesh_start(hi_wifi_mesh_config *config, char *ifname, int *len);

/**
* @ingroup  hi_wifi_mesh
* @brief  Connect to mesh device by mac address.CNcomment:ͨ���Զ�mac��ַ����mesh��CNend
*
* @par Description:
*           Connect to mesh device by mac address.CNcomment:ͨ���Զ�mac��ַ����mesh��CNend
*
* @attention  NULL
* @param  mac             [IN]    Type  #const unsigned char * peer mac address.CNcomment:�Զ�mesh�ڵ��mac��ַ��CNend
*         len             [IN]    Type  #const int   the len of mac address.CNcomment:mac��ַ�ĳ��ȡ�CNend
* @retval #HISI_OK        Execute successfully.
* @retval #HISI_FAIL      Execute failed.
* @par Dependency:
*            @li hi_wifi_mesh_api.h: WiFi-MESH API
* @see  NULL
* @since Hi3861_V100R001C00
*/
int hi_wifi_mesh_connect(const unsigned char *mac, const int len);

/**
* @ingroup  hi_wifi_mesh
* @brief  Set mesh support/not support mesh peer connections.CNcomment:����mesh֧��/��֧��mesh peer���ӡ�CNend
*
* @par Description:
*           Set mesh support/not support mesh peer connections.CNcomment:����mesh֧��/��֧��mesh peer���ӡ�CNend
*
* @attention  1. Default support peer connect.CNcomment:1. Ĭ��֧��mesh peer���ӡ�CNend \n
*             2. The enable_peer_connect value can only be 1 or 0. CNcomment:2. enable_peer_connectֵֻ��Ϊ1��0��CNend
* @param  enable_accept_peer    [IN]    Type  #unsigned char flag to support mesh connection.
*                                             CNcomment:�Ƿ�֧��mesh���ӵı�־��CNend
*
* @retval #HISI_OK        Execute successfully.
* @retval #HISI_FAIL      Execute failed.
* @par Dependency:
*            @li hi_wifi_mesh_api.h: WiFi-MESH API
* @see  NULL
* @since Hi3861_V100R001C00
*/
int hi_wifi_mesh_set_accept_peer(unsigned char enable_peer_connect);

/**
* @ingroup  hi_wifi_mesh
* @brief  Set mesh support/not support mesh sta connections.CNcomment:����mesh֧��/��֧��mesh sta���ӡ�CNend
*
* @par Description:
*           Set mesh support/not support mesh sta connections.CNcomment:����mesh֧��/��֧��mesh sta���ӡ�CNend
*
* @attention 1. Default not support sta connect. CNcomment:1. Ĭ�ϲ�֧��mesh sta���ӡ�CNend \n
*            2. The enable_sta_connect value can only be 1 or 0. CNcomment:2. enable_sta_connectֵֻ��Ϊ1��0��CNend
* @param  enable_accept_sta    [IN]    Type  #unsigned char flag to support mesh sta connection.
*                                            CNcomment:�Ƿ�֧��sta���ӵı�־��CNend
*
* @retval #HISI_OK        Execute successfully.
* @retval #HISI_FAIL      Execute failed.
* @par Dependency:
*            @li hi_wifi_mesh_api.h: WiFi-MESH API
* @see  NULL
* @since Hi3861_V100R001C00
*/
int hi_wifi_mesh_set_accept_sta(unsigned char enable_sta_connect);

/**
* @ingroup  hi_wifi_mesh
* @brief  Set sta supports mesh capability.CNcomment:����sta֧��mesh������CNend
*
* @par Description:
*           Set sta supports mesh capability.CNcomment:sta֧��mesh������CNend
*
* @attention 1. Default is not mesh sta. CNcomment:1. Ĭ�ϲ���mesh sta��CNend \n
*            2. The enable value can only be 1 or 0.. CNcomment:2. enableֵֻ��Ϊ1��0��CNend
* @param  enable          [IN]    Type  #unsigned char flag of sta's ability to support mesh.
*                                       CNcomment:sta֧��mesh�����ı�־��CNend
*
* @retval #HISI_OK        Execute successfully.
* @retval #HISI_FAIL      Execute failed.
* @par Dependency:
*            @li hi_wifi_mesh_api.h: WiFi-MESH API
* @see  NULL
* @since Hi3861_V100R001C00
*/
int hi_wifi_set_mesh_sta(unsigned char enable);

/**
* @ingroup  hi_wifi_mesh
* @brief  Start mesh sta scan. CNcomment:mesh sta ɨ�衣CNend
*
* @par Description:
*           Start mesh sta scan. CNcomment:mesh sta ɨ�衣CNend
*
* @attention  NULL
* @param void.
*
* @retval #HISI_OK        Execute successfully.
* @retval #HISI_FAIL      Execute failed.
* @par Dependency:
*            @li hi_wifi_mesh_api.h: WiFi-MESH API
* @see  NULL
* @since Hi3861_V100R001C00
*/
int hi_wifi_mesh_sta_scan(void);

/**
* @ingroup  hi_wifi_mesh
* @brief  Start mesh sta advance scan.CNcomment:mesh sta �߼�ɨ�衣CNend
*
* @par Description:
*           Start mesh sta advance scan.
*
* @attention  1. Advance scan can scan with ssid only,channel only,bssid only,prefix_ssid only��
*             and the combination parameters scanning does not support.
*             CNcomment:1 .�߼�ɨ��ֱ𵥶�֧�� ssidɨ�裬�ŵ�ɨ�裬bssidɨ�裬ssidǰ׺ɨ��, ��֧����ϲ���ɨ�跽ʽ��CNend \n
*             2. Scanning mode, subject to the type set by scan_type.
*             CNcomment:2 .ɨ�跽ʽ����scan_type���������Ϊ׼��CNend
* @param  sp          [IN]    Type #hi_wifi_scan_params * parameters of scan.CNcomment:ɨ�������������CNend
*
* @retval #HISI_OK    Execute successfully.
* @retval #HISI_FAIL  Execute failed.
* @par Dependency:
*            @li hi_wifi_mesh_api.h: WiFi-MESH API
* @see  NULL
* @since Hi3861_V100R001C00
*/
int hi_wifi_mesh_sta_advance_scan(hi_wifi_scan_params *sp);

/**
* @ingroup  hi_wifi_mesh
* @brief  Start mesh peer scan. CNcomment:mesh peer ɨ�衣CNend
*
* @par Description:
*           Start mesh peer scan. CNcomment:mesh peer ɨ�衣CNend
*
* @attention  NULL
* @param void
*
* @retval #HISI_OK        Execute successfully.
* @retval #HISI_FAIL      Execute failed.
* @par Dependency:
*            @li hi_wifi_mesh_api.h: WiFi-MESH API
* @see  NULL
* @since Hi3861_V100R001C00
*/
int hi_wifi_mesh_scan(void);

/**
* @ingroup  hi_wifi_mesh
* @brief  Start mesh peer advance scan.CNcomment:mesh peer �߼�ɨ�衣CNend
*
* @par Description:
*           Start mesh peer advance scan.CNcomment:mesh peer �߼�ɨ�衣CNend
*
* @attention  1. Advance scan can scan with ssid only,channel only,bssid only,prefix_ssid only��
*             and the combination parameters scanning does not support.
*             CNcomment:1 .�߼�ɨ��ֱ𵥶�֧�� ssidɨ�裬�ŵ�ɨ�裬bssidɨ�裬ssidǰ׺ɨ��, ��֧����ϲ���ɨ�跽ʽ��CNend \n
*             2. Scanning mode, subject to the type set by scan_type.
*             CNcomment:2 .ɨ�跽ʽ����scan_type���������Ϊ׼��CNend
* @param  sp          [IN]    Type  #hi_wifi_scan_params * mesh's scan parameters.CNcomment:mesh peer֧�ֵ�ɨ�跽ʽ��CNend
*
* @retval #HISI_OK    Execute successfully.
* @retval #HISI_FAIL  Execute failed.
* @par Dependency:
*            @li hi_wifi_mesh_api.h: WiFi-MESH API
* @see  NULL
* @since Hi3861_V100R001C00
*/
int hi_wifi_mesh_advance_scan(hi_wifi_scan_params *sp);

/**
* @ingroup  hi_wifi_mesh
* @brief  Get the results of mesh peer scan.CNcomment:��ȡ mesh peer ɨ������Ľ����CNend
*
* @par Description:
*           Get the results of mesh peer scan..CNcomment:��ȡ mesh peer ɨ������Ľ����CNend
*
* @attention  1.ap_list: malloc by user.CNcomment:1.ɨ�������������û���̬����CNend \n
*             2.ap_list max size: (hi_wifi_mesh_scan_result_info ap_list) * 64.
*             CNcomment:2.ap_list ���Ϊ��hi_wifi_mesh_scan_result_info ap_list��* 64��CNend \n
*             3.ap_num:Parameters can be passed in to specify the number of scanned results.The maximum is 64.
*             CNcomment:3.���Դ��������ָ����ȡɨ�赽�Ľ�����������Ϊ64��CNend \n
*             4.If the callback function of the reporting user is used,
*             ap_num refers to bss_num in event_wifi_scan_done.
*             CNcomment:4.���ʹ���ϱ��û��Ļص�������ap_num�ο�event_wifi_scan_done�е�bss_num��CNend \n
*             5.ap_num should be same with number of hi_wifi_mesh_scan_result_info structures applied,
*             Otherwise, it will cause memory overflow.
*             CNcomment:5.ap_num�������hi_wifi_mesh_scan_result_info�ṹ������һ�£������������ڴ������CNend \n
*             6. SSID only supports ASCII characters.
*                CNcomment:6. SSID ֻ֧��ASCII�ַ�.CNend
* @param  ap_list         [IN/OUT]    Type #hi_wifi_mesh_scan_result_info * ap_list.CNcomment:ɨ�赽�Ľ����CNend
*         ap_num          [IN/OUT]    Type #unsigned int * number of scan result.CNcomment:ɨ�赽��������Ŀ��CNend
*
* @retval #HISI_OK        Execute successfully.
* @retval #HISI_FAIL      Execute failed.
* @par Dependency:
*            @li hi_wifi_mesh_api.h: WiFi-MESH API
* @see  NULL
* @since Hi3861_V100R001C00
*/
int hi_wifi_mesh_scan_results(hi_wifi_mesh_scan_result_info *ap_list, unsigned int *ap_num);

/**
* @ingroup  hi_wifi_mesh
* @brief  Get the results of mesh sta scan.CNcomment:��ȡ mesh sta ɨ������Ľ����CNend
*
* @par Description:
*           Get the results of mesh sta scan..CNcomment:��ȡ mesh sta ɨ������Ľ����CNend
*
* @attention  1.ap_list: malloc by user.CNcomment:1.ɨ�������������û���̬����CNend \n
*             2.max size: (hi_wifi_mesh_scan_result_info ap_list) * 64.
*             CNcomment:2.�㹻�Ľṹ���С�����Ϊ��hi_wifi_mesh_scan_result_info ap_list��* 64��CNend \n
*             3.ap_num:Parameters can be passed in to specify the number of scanned results.The maximum is 64.
*             CNcomment:3.���Դ��������ָ����ȡɨ�赽�Ľ�����������Ϊ64��CNend \n
*             4.If the callback function of the reporting user is used,
*             ap_num refers to bss_num in event_wifi_scan_done.
*             CNcomment:4.���ʹ���ϱ��û��Ļص�������ap_num�ο�event_wifi_scan_done�е�bss_num��CNend \n
*             5.ap_num should be same with number of hi_wifi_mesh_scan_result_info structures applied,Otherwise,
*             it will cause memory overflow.
*             CNcomment:5.ap_num�������hi_wifi_mesh_scan_result_info�ṹ������һ�£������������ڴ������CNend \n
*             6. SSID only supports ASCII characters.
*                CNcomment:6. SSID ֻ֧��ASCII�ַ�.CNend
* @param  ap_list         [IN/OUT]    Type #hi_wifi_mesh_scan_result_info * ap_list.CNcomment:ɨ�赽�Ľ����CNend
*         ap_num          [IN/OUT]    Type #unsigned int * number of scan result.CNcomment:ɨ�赽��������Ŀ��CNend
*
* @retval #HISI_OK        Execute successfully.
* @retval #HISI_FAIL      Execute failed.
* @par Dependency:
*            @li hi_wifi_mesh_api.h: WiFi-MESH API
* @see  NULL
* @since Hi3861_V100R001C00
*/
int hi_wifi_mesh_sta_scan_results(hi_wifi_mesh_scan_result_info *ap_list, unsigned int *ap_num);

/**
* @ingroup  hi_wifi_mesh
* @brief  Close mesh interface.CNcomment:ֹͣmesh�ӿڡ�CNend
*
* @par Description:
*           Close mesh interface.CNcomment:ֹͣmesh�ӿڡ�CNend
*
* @attention  NULL
* @param  NULL
*
* @retval #HISI_OK        Execute successfully.
* @retval #HISI_FAIL      Execute failed.
* @par Dependency:
*            @li hi_wifi_mesh_api.h: WiFi-MESH API
* @see  NULL
* @since Hi3861_V100R001C00
*/
int hi_wifi_mesh_stop(void);

/**
* @ingroup  hi_wifi_mesh
* @brief  Get all user's information of mesh.CNcomment:mesh��ȡ�����ӵ�peer����Ϣ��CNend
*
* @par Description:
*           Get all user's information of mesh.CNcomment:mesh��ȡ�����ӵ�peer����Ϣ��CNend
*
* @attention  NULL
* @param  peer_list        [OUT]     Type  #hi_wifi_mesh_peer_info *, peer information.CNcomment:���ӵ�peer��Ϣ��CNend
*         peer_num         [OUT]     Type  #unsigned int *, peer number.CNcomment:peer�ĸ�����CNend
*
* @retval #HISI_OK        Execute successfully.
* @retval #HISI_FAIL      Execute failed.
* @par Dependency:
*            @li hi_wifi_api.h: WiFi API
* @see  NULL
* @since Hi3861_V100R001C00
*/
int hi_wifi_mesh_get_connected_peer(hi_wifi_mesh_peer_info *peer_list, unsigned int *peer_num);

/**
* @ingroup  hi_wifi_mesh
* @brief  Add user IEs to mesh management frame.CNcomment:��mesh����֡������û�IE�ֶΡ�CNend
*
* @par Description:
*           Add user IEs to mesh management frame.CNcomment:��mesh����֡������û�IE�ֶΡ�CNend
*
* @attention  Only be used for mesh interfaces. CNcomment:������mesh�ӿ�ʹ�á�CNend
* @param  iftype          [IN]     Type  #hi_wifi_iftype, interface type,should be HI_WIFI_IFTYPE_STATION or
*                                         HI_WIFI_IFTYPE_MESH_POINT.
*                                         CNcomment:�ӿ�����,ȡֵHI_WIFI_IFTYPE_STATION��HI_WIFI_IFTYPE_MESH_POINT��CNend
*         fram_type       [IN]     Type  #hi_wifi_frame_type, frame type��HI_WIFI_IFTYPE_STATION iftype only supports
*                                         Probe Request.
*                                         CNcomment:֡����, HI_WIFI_IFTYPE_STATION �ӿ�����ֻ֧��Probe Request֡��CNend
*         usr_ie_type     [IN]     Type  #usr_ie_type, user IE type, default set zero.CNcomment:�û�IE���ͣ�Ĭ����Ϊ0��CNend
*         ie              [IN]     Type  #const unsigned char *, user IE value.CNcomment:�û�IE�ֶ����ݡ�CNend
*         ie_len          [IN]     Type  #unsigned short, user IE length.CNcomment:�û�IE�ֶ����ݳ��ȡ�CNend
* @retval #HISI_OK        Execute successfully.
* @retval #HISI_FAIL      Execute failed.
* @par Dependency:
*            @li hi_wifi_api.h: WiFi API
* @see  NULL
* @since Hi3861_V100R001C00
*/
int hi_wifi_add_usr_app_ie(hi_wifi_iftype iftype, hi_wifi_frame_type fram_type,
                           hi_wifi_usr_ie_type usr_ie_type, const unsigned char *ie, unsigned short ie_len);

/**
* @ingroup  hi_wifi_mesh
* @brief  Delete user IEs from mesh management frame.CNcomment:��mesh����֡��ɾ���û�IE�ֶΡ�CNend
*
* @par Description:
*           Delete user IEs from mesh management frame.CNcomment:��mesh����֡��ɾ���û�IE�ֶΡ�CNend
*
* @attention  Only be used for mesh interfaces. CNcomment:������mesh�ӿ�ʹ�á�CNend
* @param  iftype          [IN]     Type  #hi_wifi_iftype, interface type,should be HI_WIFI_IFTYPE_STATION or
*                                         HI_WIFI_IFTYPE_MESH_POINT.
*                                         CNcomment:�ӿ�����,ȡֵHI_WIFI_IFTYPE_STATION��HI_WIFI_IFTYPE_MESH_POINT��CNend
*         fram_type       [IN]     Type  #hi_wifi_frame_type, frame type��HI_WIFI_IFTYPE_STATION iftype only supports
*                                         Probe Request.
*                                         CNcomment:֡����, HI_WIFI_IFTYPE_STATION �ӿ�����ֻ֧��Probe Request֡��CNend
*         usr_ie_type     [IN]     Type  #usr_ie_type, user IE type, default set zero.CNcomment:�û�IE���ͣ�Ĭ����Ϊ0��CNend
* @retval #HISI_OK        Execute successfully.
* @retval #HISI_FAIL      Execute failed.
* @par Dependency:
*            @li hi_wifi_api.h: WiFi API
* @see  NULL
* @since Hi3861_V100R001C00
*/
int hi_wifi_delete_usr_app_ie(hi_wifi_iftype iftype, hi_wifi_frame_type fram_type, hi_wifi_usr_ie_type usr_ie_type);

#ifdef __cplusplus
#if __cplusplus
    }
#endif
#endif

#endif /* end of hi_wifi_mesh_api.h */
