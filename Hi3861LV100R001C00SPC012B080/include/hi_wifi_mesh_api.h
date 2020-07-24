/**
* @file hi_wifi_mesh_api.h
*
* Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2019. All rights reserved. \n
* Description: header file for wifi api.CNcomment:描述：WiFi Mesh api接口头文件。CNend\n
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
 * max auth type length.CNcomment:用户输入的认证方式最大长度CNend
 */
#define WPA_MAX_AUTH_TYPE_INPUT_LEN     32

/**
 * @ingroup hi_wifi_mesh
 *
 * max usr ie length.CNcomment:用户IE字段最大长度CNend
 */
#define HI_WIFI_USR_IE_MAX_SIZE 352

/**
 * @ingroup hi_wifi_mesh
 *
 * Frame type that usr ies will insert into.CNcomment: 待插入ie字段的帧类型.CNend
 */
typedef enum  {
    HI_WIFI_FRAME_TYPE_BEACON    = bit(0),
    HI_WIFI_FRAME_TYPE_PROBE_REQ = bit(1),
    HI_WIFI_FRAME_TYPE_BUTT
} hi_wifi_frame_type;

/**
 * @ingroup hi_wifi_mesh
 *
 * Usr ie type to be inserted.CNcomment: 待插入ie字段类型.CNend
 */
typedef enum  {
    HI_WIFI_USR_IE_TYPE_DEFAULT = 0,
    HI_WIFI_USR_IE_BUTT
} hi_wifi_usr_ie_type;

/**
 * @ingroup hi_wifi_basic
 * Struct of scan result.CNcomment:扫描结果结构体CNend
 */
typedef struct {
    char ssid[HI_WIFI_MAX_SSID_LEN + 1];    /**< SSID 只支持ASCII字符 */
    unsigned char bssid[HI_WIFI_MAC_LEN];   /**< BSSID */
    unsigned int channel;                   /**< 信道号 */
    hi_wifi_auth_mode auth;                 /**< 认证类型 */
    int rssi;                               /**< 信号强度 */
    unsigned char resv : 4;                 /**< Reserved */
    unsigned char hisi_mesh_flag : 1;       /**< HI MESH标志 */
    unsigned char is_mbr : 1;               /**< 是否是MBR标志 */
    unsigned char accept_for_sta : 1;       /**< 是否允许STA接入 */
    unsigned char accept_for_peer : 1;      /**< 是否允许Mesh AP接入 */
    unsigned char bcn_prio;                 /**< BCN优先级 */
    unsigned char peering_num;              /**< 对端连接的数目 */
} hi_wifi_mesh_scan_result_info;

/**
 * @ingroup hi_wifi_mesh
 *
 * Struct of connected mesh.CNcomment:已连接的peer结构体。CNend
 *
 */
typedef struct {
    unsigned char mac[HI_WIFI_MAC_LEN];       /**< 对端mac地址 */
    unsigned char mesh_bcn_priority;          /**< BCN优先级 */
    unsigned char mesh_is_mbr : 1;            /**< 是否是MBR */
    unsigned char mesh_block : 1;             /**< block是否置位 */
    unsigned char mesh_role : 1;              /**< mesh的角色 */
} hi_wifi_mesh_peer_info;

/**
 * @ingroup hi_wifi_mesh
 *
 * Struct of mesh's config.CNcomment:mesh配置参数CNend
 *
 */
typedef struct {
    char ssid[HI_WIFI_MAX_SSID_LEN + 1];     /**< SSID 只支持ASCII字符 */
    char key[HI_WIFI_AP_KEY_LEN + 1];        /**< 密码 */
    hi_wifi_auth_mode auth;                  /**< 认证类型，只支持HI_WIFI_SECURITY_OPEN和HI_WIFI_SECURITY_SAE */
    unsigned char channel;                   /**< 信道号 */
} hi_wifi_mesh_config;

/**
* @ingroup  hi_wifi_mesh
* @brief  Mesh disconnect peer by mac address.CNcomment:mesh指定断开连接的网络。CNend
*
* @par Description:
*          Mesh disconnect peer by mac address.CNcomment:softap指定断开连接的网络。CNend
*
* @attention  NULL
* @param  addr             [IN]     Type  #const char *, peer mac address.CNcomment:对端MAC地址。CNend
* @param  addr_len         [IN]     Type  #unsigned char, peer mac address length.CNcomment:对端MAC地址长度。CNend
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
* @brief  Start mesh interface.CNcomment:开启mesh。CNend
*
* @par Description:
*           Add mesh interface.CNcomment:开启mesh。CNend
*
* @attention  1. The memories of <ifname> and <len> memories are requested by the caller.
*             CNcomment:1. <ifname>和<len>由调用者申请内存CNend
*             2. SSID only supports ASCII characters.
*                CNcomment:2. SSID 只支持ASCII字符.CNend
* @param config    [IN]     Type  #hi_wifi_mesh_config * mesh's configuration.CNcomment:mesh配置。CNend
*        ifname    [IN/OUT] Type  #char * mesh interface name.CNcomment:创建的mesh接口名称。CNend
*        len       [IN/OUT] Type  #int * mesh interface name length.CNcomment:创建的mesh接口名称的长度。CNend
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
* @brief  Connect to mesh device by mac address.CNcomment:通过对端mac地址连接mesh。CNend
*
* @par Description:
*           Connect to mesh device by mac address.CNcomment:通过对端mac地址连接mesh。CNend
*
* @attention  NULL
* @param  mac             [IN]    Type  #const unsigned char * peer mac address.CNcomment:对端mesh节点的mac地址。CNend
*         len             [IN]    Type  #const int   the len of mac address.CNcomment:mac地址的长度。CNend
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
* @brief  Set mesh support/not support mesh peer connections.CNcomment:设置mesh支持/不支持mesh peer连接。CNend
*
* @par Description:
*           Set mesh support/not support mesh peer connections.CNcomment:设置mesh支持/不支持mesh peer连接。CNend
*
* @attention  1. Default support peer connect.CNcomment:1. 默认支持mesh peer连接。CNend \n
*             2. The enable_peer_connect value can only be 1 or 0. CNcomment:2. enable_peer_connect值只能为1或0。CNend
* @param  enable_accept_peer    [IN]    Type  #unsigned char flag to support mesh connection.
*                                             CNcomment:是否支持mesh连接的标志。CNend
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
* @brief  Set mesh support/not support mesh sta connections.CNcomment:设置mesh支持/不支持mesh sta连接。CNend
*
* @par Description:
*           Set mesh support/not support mesh sta connections.CNcomment:设置mesh支持/不支持mesh sta连接。CNend
*
* @attention 1. Default not support sta connect. CNcomment:1. 默认不支持mesh sta连接。CNend \n
*            2. The enable_sta_connect value can only be 1 or 0. CNcomment:2. enable_sta_connect值只能为1或0。CNend
* @param  enable_accept_sta    [IN]    Type  #unsigned char flag to support mesh sta connection.
*                                            CNcomment:是否支持sta连接的标志。CNend
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
* @brief  Set sta supports mesh capability.CNcomment:设置sta支持mesh能力。CNend
*
* @par Description:
*           Set sta supports mesh capability.CNcomment:sta支持mesh能力。CNend
*
* @attention 1. Default is not mesh sta. CNcomment:1. 默认不是mesh sta。CNend \n
*            2. The enable value can only be 1 or 0.. CNcomment:2. enable值只能为1或0。CNend
* @param  enable          [IN]    Type  #unsigned char flag of sta's ability to support mesh.
*                                       CNcomment:sta支持mesh能力的标志。CNend
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
* @brief  Start mesh sta scan. CNcomment:mesh sta 扫描。CNend
*
* @par Description:
*           Start mesh sta scan. CNcomment:mesh sta 扫描。CNend
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
* @brief  Start mesh sta advance scan.CNcomment:mesh sta 高级扫描。CNend
*
* @par Description:
*           Start mesh sta advance scan.
*
* @attention  1. Advance scan can scan with ssid only,channel only,bssid only,prefix_ssid only，
*             and the combination parameters scanning does not support.
*             CNcomment:1 .高级扫描分别单独支持 ssid扫描，信道扫描，bssid扫描，ssid前缀扫描, 不支持组合参数扫描方式。CNend \n
*             2. Scanning mode, subject to the type set by scan_type.
*             CNcomment:2 .扫描方式，以scan_type传入的类型为准。CNend
* @param  sp          [IN]    Type #hi_wifi_scan_params * parameters of scan.CNcomment:扫描网络参数设置CNend
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
* @brief  Start mesh peer scan. CNcomment:mesh peer 扫描。CNend
*
* @par Description:
*           Start mesh peer scan. CNcomment:mesh peer 扫描。CNend
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
* @brief  Start mesh peer advance scan.CNcomment:mesh peer 高级扫描。CNend
*
* @par Description:
*           Start mesh peer advance scan.CNcomment:mesh peer 高级扫描。CNend
*
* @attention  1. Advance scan can scan with ssid only,channel only,bssid only,prefix_ssid only，
*             and the combination parameters scanning does not support.
*             CNcomment:1 .高级扫描分别单独支持 ssid扫描，信道扫描，bssid扫描，ssid前缀扫描, 不支持组合参数扫描方式。CNend \n
*             2. Scanning mode, subject to the type set by scan_type.
*             CNcomment:2 .扫描方式，以scan_type传入的类型为准。CNend
* @param  sp          [IN]    Type  #hi_wifi_scan_params * mesh's scan parameters.CNcomment:mesh peer支持的扫描方式。CNend
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
* @brief  Get the results of mesh peer scan.CNcomment:获取 mesh peer 扫描网络的结果。CNend
*
* @par Description:
*           Get the results of mesh peer scan..CNcomment:获取 mesh peer 扫描网络的结果。CNend
*
* @attention  1.ap_list: malloc by user.CNcomment:1.扫描结果参数。由用户动态申请CNend \n
*             2.ap_list max size: (hi_wifi_mesh_scan_result_info ap_list) * 64.
*             CNcomment:2.ap_list 最大为（hi_wifi_mesh_scan_result_info ap_list）* 64。CNend \n
*             3.ap_num:Parameters can be passed in to specify the number of scanned results.The maximum is 64.
*             CNcomment:3.可以传入参数，指定获取扫描到的结果数量，最大为64。CNend \n
*             4.If the callback function of the reporting user is used,
*             ap_num refers to bss_num in event_wifi_scan_done.
*             CNcomment:4.如果使用上报用户的回调函数，ap_num参考event_wifi_scan_done中的bss_num。CNend \n
*             5.ap_num should be same with number of hi_wifi_mesh_scan_result_info structures applied,
*             Otherwise, it will cause memory overflow.
*             CNcomment:5.ap_num和申请的hi_wifi_mesh_scan_result_info结构体数量一致，否则可能造成内存溢出。CNend \n
*             6. SSID only supports ASCII characters.
*                CNcomment:6. SSID 只支持ASCII字符.CNend
* @param  ap_list         [IN/OUT]    Type #hi_wifi_mesh_scan_result_info * ap_list.CNcomment:扫描到的结果。CNend
*         ap_num          [IN/OUT]    Type #unsigned int * number of scan result.CNcomment:扫描到的网络数目。CNend
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
* @brief  Get the results of mesh sta scan.CNcomment:获取 mesh sta 扫描网络的结果。CNend
*
* @par Description:
*           Get the results of mesh sta scan..CNcomment:获取 mesh sta 扫描网络的结果。CNend
*
* @attention  1.ap_list: malloc by user.CNcomment:1.扫描结果参数。由用户动态申请CNend \n
*             2.max size: (hi_wifi_mesh_scan_result_info ap_list) * 64.
*             CNcomment:2.足够的结构体大小，最大为（hi_wifi_mesh_scan_result_info ap_list）* 64。CNend \n
*             3.ap_num:Parameters can be passed in to specify the number of scanned results.The maximum is 64.
*             CNcomment:3.可以传入参数，指定获取扫描到的结果数量，最大为64。CNend \n
*             4.If the callback function of the reporting user is used,
*             ap_num refers to bss_num in event_wifi_scan_done.
*             CNcomment:4.如果使用上报用户的回调函数，ap_num参考event_wifi_scan_done中的bss_num。CNend \n
*             5.ap_num should be same with number of hi_wifi_mesh_scan_result_info structures applied,Otherwise,
*             it will cause memory overflow.
*             CNcomment:5.ap_num和申请的hi_wifi_mesh_scan_result_info结构体数量一致，否则可能造成内存溢出。CNend \n
*             6. SSID only supports ASCII characters.
*                CNcomment:6. SSID 只支持ASCII字符.CNend
* @param  ap_list         [IN/OUT]    Type #hi_wifi_mesh_scan_result_info * ap_list.CNcomment:扫描到的结果。CNend
*         ap_num          [IN/OUT]    Type #unsigned int * number of scan result.CNcomment:扫描到的网络数目。CNend
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
* @brief  Close mesh interface.CNcomment:停止mesh接口。CNend
*
* @par Description:
*           Close mesh interface.CNcomment:停止mesh接口。CNend
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
* @brief  Get all user's information of mesh.CNcomment:mesh获取已连接的peer的信息。CNend
*
* @par Description:
*           Get all user's information of mesh.CNcomment:mesh获取已连接的peer的信息。CNend
*
* @attention  NULL
* @param  peer_list        [OUT]     Type  #hi_wifi_mesh_peer_info *, peer information.CNcomment:连接的peer信息。CNend
*         peer_num         [OUT]     Type  #unsigned int *, peer number.CNcomment:peer的个数。CNend
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
* @brief  Add user IEs to mesh management frame.CNcomment:在mesh管理帧中添加用户IE字段。CNend
*
* @par Description:
*           Add user IEs to mesh management frame.CNcomment:在mesh管理帧中添加用户IE字段。CNend
*
* @attention  Only be used for mesh interfaces. CNcomment:仅限于mesh接口使用。CNend
* @param  iftype          [IN]     Type  #hi_wifi_iftype, interface type,should be HI_WIFI_IFTYPE_STATION or
*                                         HI_WIFI_IFTYPE_MESH_POINT.
*                                         CNcomment:接口类型,取值HI_WIFI_IFTYPE_STATION或HI_WIFI_IFTYPE_MESH_POINT。CNend
*         fram_type       [IN]     Type  #hi_wifi_frame_type, frame type，HI_WIFI_IFTYPE_STATION iftype only supports
*                                         Probe Request.
*                                         CNcomment:帧类型, HI_WIFI_IFTYPE_STATION 接口类型只支持Probe Request帧。CNend
*         usr_ie_type     [IN]     Type  #usr_ie_type, user IE type, default set zero.CNcomment:用户IE类型，默认设为0。CNend
*         ie              [IN]     Type  #const unsigned char *, user IE value.CNcomment:用户IE字段内容。CNend
*         ie_len          [IN]     Type  #unsigned short, user IE length.CNcomment:用户IE字段内容长度。CNend
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
* @brief  Delete user IEs from mesh management frame.CNcomment:在mesh管理帧中删除用户IE字段。CNend
*
* @par Description:
*           Delete user IEs from mesh management frame.CNcomment:在mesh管理帧中删除用户IE字段。CNend
*
* @attention  Only be used for mesh interfaces. CNcomment:仅限于mesh接口使用。CNend
* @param  iftype          [IN]     Type  #hi_wifi_iftype, interface type,should be HI_WIFI_IFTYPE_STATION or
*                                         HI_WIFI_IFTYPE_MESH_POINT.
*                                         CNcomment:接口类型,取值HI_WIFI_IFTYPE_STATION或HI_WIFI_IFTYPE_MESH_POINT。CNend
*         fram_type       [IN]     Type  #hi_wifi_frame_type, frame type，HI_WIFI_IFTYPE_STATION iftype only supports
*                                         Probe Request.
*                                         CNcomment:帧类型, HI_WIFI_IFTYPE_STATION 接口类型只支持Probe Request帧。CNend
*         usr_ie_type     [IN]     Type  #usr_ie_type, user IE type, default set zero.CNcomment:用户IE类型，默认设为0。CNend
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
