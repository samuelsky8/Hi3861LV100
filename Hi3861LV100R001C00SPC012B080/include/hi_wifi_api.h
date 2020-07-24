/**
* @file hi_wifi_api.h
*
* Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2019. All rights reserved. \n
* Description: header file for wifi api.CNcomment:������WiFi api�ӿ�ͷ�ļ�.CNend\n
* Author: Hisilicon \n
* Create: 2019-01-03
*/

/**
 * @defgroup hi_wifi_basic WiFi Basic Settings
 * @ingroup hi_wifi
 */

#ifndef __HI_WIFI_API_H__
#define __HI_WIFI_API_H__

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

/**
 * mac transform string.CNcomment:��ַתΪ�ַ���.CNend
 */
#ifndef MACSTR
#define MACSTR "%02x:%02x:%02x:%02x:%02x:%02x"
#endif

#ifndef MAC2STR
#define mac2str(a) (a)[0], (a)[1], (a)[2], (a)[3], (a)[4], (a)[5]
#endif

#ifndef bit
#define bit(x) (1U << (x))
#endif

/**
 * @ingroup hi_wifi_basic
 *
 * TKIP of cipher mode.CNcomment:���ܷ�ʽΪTKIP.CNend
 */
#define WIFI_CIPHER_TKIP                 bit(3)

/**
 * @ingroup hi_wifi_basic
 *
 * CCMP of cipher mode.CNcomment:���ܷ�ʽΪCCMP.CNend
 */
#define WIFI_CIPHER_CCMP                 bit(4)

#define WIFI_24G_CHANNEL_NUMS 14

/**
 * @ingroup hi_wifi_basic
 *
 * max interiface name length.CNcomment:����ӿ�����󳤶�.CNend
 */
#define WIFI_IFNAME_MAX_SIZE             16

/**
 * @ingroup hi_wifi_basic
 *
 * The minimum timeout of a single reconnection.CNcomment:��С����������ʱʱ��.CNend
 */
#define WIFI_MIN_RECONNECT_TIMEOUT   2

/**
 * @ingroup hi_wifi_basic
 *
 * The maximum timeout of a single reconnection, representing an infinite number of loop reconnections.
 * CNcomment:��󵥴�������ʱʱ�䣬��ʾ���޴�ѭ������.CNend
 */
#define WIFI_MAX_RECONNECT_TIMEOUT   65535

/**
 * @ingroup hi_wifi_basic
 *
 * The minimum auto reconnect interval.CNcomment:��С�Զ��������ʱ��.CNend
 */
#define WIFI_MIX_RECONNECT_PERIOD    1

/**
 * @ingroup hi_wifi_basic
 *
 * The maximum auto reconnect interval.CNcomment:����Զ��������ʱ��.CNend
 */
#define WIFI_MAX_RECONNECT_PERIOD   65535

/**
 * @ingroup hi_wifi_basic
 *
 * The minmum times of auto reconnect.CNcomment:��С�Զ��������Ӵ���.CNend
 */
#define WIFI_MIN_RECONNECT_TIMES    1

/**
 * @ingroup hi_wifi_basic
 *
 * The maximum times of auto reconnect.CNcomment:����Զ��������Ӵ���.CNend
 */
#define WIFI_MAX_RECONNECT_TIMES   65535

/**
 * @ingroup hi_wifi_basic
 *
 * max scan number of ap.CNcomment:֧��ɨ��ap�������Ŀ.CNend
 */
#define WIFI_SCAN_AP_LIMIT               64

/**
 * @ingroup hi_wifi_basic
 *
 * length of status buff.CNcomment:��ȡ����״̬�ַ����ĳ���.CNend
 */
#define WIFI_STATUS_BUF_LEN_LIMIT        512

/**
 * @ingroup hi_wifi_basic
 *
 * Decimal only WPS pin code length.CNcomment:WPS��ʮ����pin�볤��.CNend
 */
#define WIFI_WPS_PIN_LEN             8

/**
 * @ingroup hi_wifi_basic
 *
 * default max num of station.CNcomment:Ĭ��֧�ֵ�station������.CNend
 */
#define WIFI_DEFAULT_MAX_NUM_STA         6

/**
 * @ingroup hi_wifi_basic
 *
 * return success value.CNcomment:���سɹ���ʶ.CNend
 */
#define HISI_OK                         0

/**
 * @ingroup hi_wifi_basic
 *
 * return failed value.CNcomment:����ֵ�����ʶ.CNend
 */
#define HISI_FAIL                       (-1)

/**
 * @ingroup hi_wifi_basic
 *
 * Max length of SSID.CNcomment:SSID��󳤶ȶ���.CNend
 */
#define HI_WIFI_MAX_SSID_LEN  32

/**
 * @ingroup hi_wifi_basic
 *
 * Length of MAC address.CNcomment:MAC��ַ���ȶ���.CNend
 */
#define HI_WIFI_MAC_LEN        6

/**
 * @ingroup hi_wifi_basic
 *
 * String length of bssid, eg. 00:00:00:00:00:00.CNcomment:bssid�ַ������ȶ���(00:00:00:00:00:00).CNend
 */
#define HI_WIFI_TXT_ADDR_LEN   17

/**
 * @ingroup hi_wifi_basic
 *
 * Length of Key.CNcomment:KEY ���볤�ȶ���.CNend
 */
#define HI_WIFI_AP_KEY_LEN     64

/**
 * @ingroup hi_wifi_basic
 *
 * Maximum  length of Key.CNcomment:KEY ������볤��.CNend
 */
#define HI_WIFI_MAX_KEY_LEN    64

/**
 * @ingroup hi_wifi_basic
 *
 * Return value of invalid channel.CNcomment:��Ч�ŵ�����ֵ.CNend
 */
#define HI_WIFI_INVALID_CHANNEL 0xFF

/**
 * @ingroup hi_wifi_basic
 *
 * Index of Vendor IE.CNcomment:Vendor IE �������.CNend
 */
#define HI_WIFI_VENDOR_IE_MAX_IDX 1

/**
 * @ingroup hi_wifi_basic
 *
 * Max length of Vendor IE.CNcomment:Vendor IE ��󳤶�.CNend
 */
#define HI_WIFI_VENDOR_IE_MAX_LEN 255

/**
 * @ingroup hi_wifi_basic
 *
 * Length range of frame for user use(24-1400).CNcomment:�û����Ʊ��ĳ��ȷ�Χ(24-1400).CNend
 */
#define HI_WIFI_CUSTOM_PKT_MAX_LEN 1400
#define HI_WIFI_CUSTOM_PKT_MIN_LEN 24

/**
 * @ingroup hi_wifi_basic
 *
 * Length of psk.CNcomment:psk�ĳ���.CNend
 */
#define HI_WIFI_STA_PSK_LEN                 32

/**
 * @ingroup hi_wifi_basic
 *
 * Max num of retry.CNcomment:����ش���������.CNend
 * Max time of retry.CNcomment:����ش������ʱ��.CNend
 */
#define HI_WIFI_RETRY_MAX_NUM               15
#define HI_WIFI_RETRY_MAX_TIME              200

/**
 * @ingroup hi_wifi_basic
 *
 * Reporting data type of monitor mode.CNcomment:����ģʽ�ϱ�����������.CNend
 */
typedef enum {
    HI_WIFI_MONITOR_OFF,                /**< close monitor mode. CNcomment: �رջ���ģʽ.CNend */
    HI_WIFI_MONITOR_MCAST_DATA,         /**< report multi-cast data frame. CNcomment: �ϱ��鲥(�㲥)���ݰ�.CNend */
    HI_WIFI_MONITOR_UCAST_DATA,         /**< report single-cast data frame. CNcomment: �ϱ��������ݰ�.CNend */
    HI_WIFI_MONITOR_MCAST_MANAGEMENT,   /**< report multi-cast mgmt frame. CNcomment: �ϱ��鲥(�㲥)�����.CNend */
    HI_WIFI_MONITOR_UCAST_MANAGEMENT,   /**< report sigle-cast mgmt frame. CNcomment: �ϱ����������.CNend */

    HI_WIFI_MONITOR_BUTT
} hi_wifi_monitor_mode;

/**
 * @ingroup hi_wifi_basic
 *
 * Definition of protocol frame type.CNcomment:Э�鱨�����Ͷ���.CNend
 */
typedef enum {
    HI_WIFI_PKT_TYPE_BEACON,        /**< Beacon packet. CNcomment: Beacon��.CNend */
    HI_WIFI_PKT_TYPE_PROBE_REQ,     /**< Probe Request packet. CNcomment: Probe Request��.CNend */
    HI_WIFI_PKT_TYPE_PROBE_RESP,    /**< Probe Response packet. CNcomment: Probe Response��.CNend */
    HI_WIFI_PKT_TYPE_ASSOC_REQ,     /**< Assoc Request packet. CNcomment: Assoc Request��.CNend */
    HI_WIFI_PKT_TYPE_ASSOC_RESP,    /**< Assoc Response packet. CNcomment: Assoc Response��.CNend */

    HI_WIFI_PKT_TYPE_BUTT
}hi_wifi_pkt_type;

/**
 * @ingroup hi_wifi_iftype
 *
 * Interface type of wifi.CNcomment:wifi �ӿ�����.CNend
 */
typedef enum {
    HI_WIFI_IFTYPE_UNSPECIFIED,
    HI_WIFI_IFTYPE_ADHOC,
    HI_WIFI_IFTYPE_STATION,
    HI_WIFI_IFTYPE_AP,
    HI_WIFI_IFTYPE_AP_VLAN,
    HI_WIFI_IFTYPE_WDS,
    HI_WIFI_IFTYPE_MONITOR,
    HI_WIFI_IFTYPE_MESH_POINT,
    HI_WIFI_IFTYPE_P2P_CLIENT,
    HI_WIFI_IFTYPE_P2P_GO,
    HI_WIFI_IFTYPE_P2P_DEVICE,

    HI_WIFI_IFTYPES_BUTT
} hi_wifi_iftype;

/**
 * @ingroup hi_wifi_basic
 *
 * Definition of bandwith type.CNcomment:�ӿڴ�����.CNend
 */
typedef enum {
    HI_WIFI_BW_HIEX_5M,     /**< խ��5M���� */
    HI_WIFI_BW_HIEX_10M,    /**< խ��10M���� */
    HI_WIFI_BW_LEGACY_20M,  /**< 20M���� */
    HI_WIFI_BW_BUTT         /**< hi_wifi_bwö�ٶ��� */
} hi_wifi_bw;

/**
 * @ingroup hi_wifi_basic
 *
 * The protocol mode of softap and station interfaces.CNcomment:softap��station�ӿڵ�protocolģʽ.CNend
 */
typedef enum {
    HI_WIFI_PHY_MODE_11BGN, /**< 802.11BGN ģʽ */
    HI_WIFI_PHY_MODE_11BG,  /**< 802.11BG ģʽ */
    HI_WIFI_PHY_MODE_11B,   /**< 802.11B ģʽ */
    HI_WIFI_PHY_MODE_BUTT   /**< hi_wifi_protocol_modeö�ٶ��� */
} hi_wifi_protocol_mode;

/**
 * @ingroup hi_wifi_basic
 *
 * Authentification type enum.CNcomment:��֤����(�������粻֧��HI_WIFI_SECURITY_WPAPSK).CNend
 */
typedef enum {
    HI_WIFI_SECURITY_OPEN,                  /**< ��֤����:���� */
    HI_WIFI_SECURITY_WEP,                   /**< ��֤����:WEP */
    HI_WIFI_SECURITY_WPA2PSK,               /**< ��֤����:WPA2-PSK */
    HI_WIFI_SECURITY_WPAPSK_WPA2PSK_MIX,    /**< ��֤����:WPA-PSK/WPA2-PSK��� */
    HI_WIFI_SECURITY_WPAPSK,                /**< ��֤����:WPAPSK */
    HI_WIFI_SECURITY_WPA,                   /**< ��֤����:WPA */
    HI_WIFI_SECURITY_WPA2,                  /**< ��֤����:WPA2 */
    HI_WIFI_SECURITY_SAE,                   /**< ��֤����:SAE */
    HI_WIFI_SECURITY_UNKNOWN                /**< ������֤����:UNKNOWN */
} hi_wifi_auth_mode;

/**
 * @ingroup hi_wifi_basic
 *
 * Encryption type enum.CNcoment:��������.CNend
 *
 */
typedef enum {
    HI_WIFI_PARIWISE_UNKNOWN,               /**< ��������:UNKNOWN */
    HI_WIFI_PAIRWISE_AES,                   /**< ��������:AES     */
    HI_WIFI_PAIRWISE_TKIP,                  /**< ��������:TKIP     */
    HI_WIFI_PAIRWISE_TKIP_AES_MIX           /**< ��������:TKIP AES��� */
} hi_wifi_pairwise;

/**
 * @ingroup hi_wifi_basic
 *
 * PMF type enum.CNcomment:PMF����֡����ģʽ����.CNend
 */
typedef enum {
    HI_WIFI_MGMT_FRAME_PROTECTION_CLOSE,        /**< ����֡����ģʽ:�ر� */
    HI_WIFI_MGMT_FRAME_PROTECTION_OPTIONAL,     /**< ����֡����ģʽ:��ѡ */
    HI_WIFI_MGMT_FRAME_PROTECTION_REQUIRED      /**< ����֡����ģʽ:���� */
} hi_wifi_pmf_options;

/**
 * @ingroup hi_wifi_basic
 *
 * Type of connect's status.CNcomment:����״̬.CNend
 */
typedef enum {
    HI_WIFI_DISCONNECTED,   /**< ����״̬:δ���� */
    HI_WIFI_CONNECTED,      /**< ����״̬:������ */
} hi_wifi_conn_status;

/**
 * @ingroup hi_wifi_basic
 *
 * wifi's operation mode.CNcomment:wifi�Ĺ���ģʽ.CNend
 */
typedef enum {
    HI_WIFI_MODE_INFRA = 0,               /**< STAģʽ */
    HI_WIFI_MODE_AP    = 2,               /**< AP ģʽ */
    HI_WIFI_MODE_MESH  = 5                /**< MESH ģʽ */
} hi_wifi_mode;

/**
 * @ingroup hi_wifi_basic
 *
 * Event type of WiFi event.CNcomment:WiFi���¼�����.CNend
 */
typedef enum {
    HI_WIFI_EVT_UNKNOWN,             /**< UNKNOWN */
    HI_WIFI_EVT_SCAN_DONE,           /**< STAɨ����� */
    HI_WIFI_EVT_CONNECTED,           /**< ������ */
    HI_WIFI_EVT_DISCONNECTED,        /**< �Ͽ����� */
    HI_WIFI_EVT_WPS_TIMEOUT,         /**< WPS�¼���ʱ */
    HI_WIFI_EVT_MESH_CONNECTED,      /**< MESH������ */
    HI_WIFI_EVT_MESH_DISCONNECTED,   /**< MESH�Ͽ����� */
    HI_WIFI_EVT_AP_START,            /**< AP���� */
    HI_WIFI_EVT_STA_CONNECTED,       /**< AP��STA������ */
    HI_WIFI_EVT_STA_DISCONNECTED,    /**< AP��STA�Ͽ����� */
    HI_WIFI_EVT_STA_FCON_NO_NETWORK, /**< STA��������,ɨ�費������ */
    HI_WIFI_EVT_MESH_CANNOT_FOUND,   /**< MESH����ɨ�����Զ� */
    HI_WIFI_EVT_MESH_SCAN_DONE,      /**< MESHɨ����� */
    HI_WIFI_EVT_MESH_STA_SCAN_DONE,  /**< MESH STAɨ����� */
    HI_WIFI_EVT_AP_SCAN_DONE,        /**< APɨ����� */
    HI_WIFI_EVT_BUTT                 /**< hi_wifi_event_typeö�ٶ��� */
} hi_wifi_event_type;

/**
 * @ingroup hi_wifi_basic
 *
 * Scan type enum.CNcomment:ɨ������.CNend
 */
typedef enum {
    HI_WIFI_BASIC_SCAN,             /**< ��ͨɨ�� */
    HI_WIFI_CHANNEL_SCAN,           /**< ָ���ŵ�ɨ�� */
    HI_WIFI_SSID_SCAN,              /**< ָ��SSIDɨ�� */
    HI_WIFI_SSID_PREFIX_SCAN,       /**< SSIDǰ׺ɨ�� */
    HI_WIFI_BSSID_SCAN,             /**< ָ��BSSIDɨ�� */
} hi_wifi_scan_type;

/**
 * @ingroup hi_wifi_basic
 *
 * WPA PSK usage type.CNcomment: WPA PSKʹ�ò���.CNend
 */
typedef enum {
    HI_WIFI_WPA_PSK_NOT_USE,        /**< ��ʹ�� */
    HI_WIFI_WPA_PSK_USE_INNER,      /**< ʹ���ڲ�PSK */
    HI_WIFI_WPA_PSK_USE_OUTER,      /**< ʹ���ⲿPSK */
} hi_wifi_wpa_psk_usage_type;

/**
 * @ingroup hi_wifi_basic
 *
 * parameters of scan.CNcomment:station��mesh�ӿ�scan����.CNend
 */
typedef struct {
    char ssid[HI_WIFI_MAX_SSID_LEN + 1];    /**< SSID ֻ֧��ASCII�ַ� */
    unsigned char bssid[HI_WIFI_MAC_LEN];   /**< BSSID */
    unsigned char ssid_len;                 /**< SSID���� */
    unsigned char channel;                  /**< �ŵ��ţ�ȡֵ��Χ1-14����ͬ����ȡֵ��Χ�в��� */
    hi_wifi_scan_type scan_type;            /**< ɨ������ */
} hi_wifi_scan_params;

/**
 * @ingroup hi_wifi_basic
 *
 * Struct of scan result.CNcomment:ɨ�����ṹ��.CNend
 */
typedef struct {
    char ssid[HI_WIFI_MAX_SSID_LEN + 1];    /**< SSID ֻ֧��ASCII�ַ� */
    unsigned char bssid[HI_WIFI_MAC_LEN];   /**< BSSID */
    unsigned int channel;                   /**< �ŵ��ţ�ȡֵ��Χ1-14����ͬ����ȡֵ��Χ�в��� */
    hi_wifi_auth_mode auth;                 /**< ��֤���� */
    int rssi;                               /**< �ź�ǿ�� */
    unsigned char wps_flag : 1;             /**< WPS��ʶ */
    unsigned int wps_session : 1;           /**< WPS��ʶ PBC-0/PIN-1 */
    unsigned char wmm : 1;                  /**< WMM��ʶ */
    unsigned char resv : 1;                 /**< Reserved */
    unsigned char hisi_mesh_flag : 1;       /**< HI MESH��ʶ */
} hi_wifi_ap_info;

/**
 * @ingroup hi_wifi_basic
 *
 * Struct of connect parameters.CNcomment:station���ӽṹ��.CNend
 */
typedef struct {
    char ssid[HI_WIFI_MAX_SSID_LEN + 1];    /**< SSID ֻ֧��ASCII�ַ�*/
    hi_wifi_auth_mode auth;                 /**< ��֤���� */
    char key[HI_WIFI_MAX_KEY_LEN + 1];      /**< ��Կ */
    unsigned char bssid[HI_WIFI_MAC_LEN];   /**< BSSID */
    hi_wifi_pairwise pairwise;              /**< ���ܷ�ʽ, ��ѡ������ָ��ʱ��Ϊ0 */
} hi_wifi_assoc_request;

/**
 * @ingroup hi_wifi_basic
 *
 * Struct of fast connect parameters.CNcomment:station�������ӽṹ��.CNend
 */
typedef struct {
    hi_wifi_assoc_request req;                  /**< �������� */
    unsigned char channel;                      /**< �ŵ��ţ�ȡֵ��Χ1-14����ͬ����ȡֵ��Χ�в��� */
    unsigned char psk[HI_WIFI_STA_PSK_LEN];     /**< psk�� ʹ��hi_wifi_psk_calc_and_store()ʱ�˲���������д */
    hi_wifi_wpa_psk_usage_type psk_flag;        /**< ����psk�ı�־, ��ѡ,����ָ��ʱ��Ϊ0 */
} hi_wifi_fast_assoc_request;

/**
 * @ingroup hi_wifi_basic
 *
 * Status of sta's connection.CNcomment:��ȡstation����״̬.CNend
 */
typedef struct {
    char ssid[HI_WIFI_MAX_SSID_LEN + 1];    /**< SSID ֻ֧��ASCII�ַ� */
    unsigned char bssid[HI_WIFI_MAC_LEN];   /**< BSSID */
    unsigned int channel;                   /**< �ŵ��ţ�ȡֵ��Χ1-14����ͬ����ȡֵ��Χ�в��� */
    hi_wifi_conn_status status;             /**< ����״̬ */
} hi_wifi_status;

/**
 * @ingroup hi_wifi_basic
 *
 * Event type of wifi scan done.CNcomment:ɨ������¼�.CNend
 */
typedef struct {
    unsigned short bss_num;                 /**< ɨ�赽��ap��Ŀ */
} event_wifi_scan_done;

/**
 * @ingroup hi_wifi_basic
 *
 * Event type of wifi connected CNcomment:wifi��connect�¼���Ϣ.CNend
 */
typedef struct {
    char ssid[HI_WIFI_MAX_SSID_LEN + 1];    /**< SSID ֻ֧��ASCII�ַ� */
    unsigned char bssid[HI_WIFI_MAC_LEN];   /**< BSSID */
    unsigned char ssid_len;                 /**< SSID���� */
    char ifname[WIFI_IFNAME_MAX_SIZE + 1];  /**< �ӿ����� */
} event_wifi_connected;

/**
 * @ingroup hi_wifi_basic
 *
 * Event type of wifi disconnected.CNcomment:wifi�ĶϿ��¼���Ϣ.CNend
 */
typedef struct {
    unsigned char bssid[HI_WIFI_MAC_LEN];    /**< BSSID */
    unsigned short reason_code;              /**< �Ͽ�ԭ�� */
    char ifname[WIFI_IFNAME_MAX_SIZE + 1];   /**< �ӿ����� */
} event_wifi_disconnected;

/**
 * @ingroup hi_wifi_basic
 *
 * Event type of ap connected sta.CNcomment:ap����sta�¼���Ϣ.CNend
 */
typedef struct {
    char addr[HI_WIFI_MAC_LEN];    /**< ����AP��sta��ַ */
} event_ap_sta_connected;

/**
 * @ingroup hi_wifi_basic
 *
 * Event type of ap disconnected sta.CNcomment:ap�Ͽ�sta�¼���Ϣ.CNend
 */
typedef struct {
    unsigned char addr[HI_WIFI_MAC_LEN];    /**< AP�Ͽ�STA��MAC��ַ */
    unsigned short reason_code;             /**< AP�Ͽ����ӵ�ԭ��ֵ */
} event_ap_sta_disconnected;

/**
 * @ingroup hi_wifi_basic
 *
 * Event type of mesh connected.CNcomment:mesh��connect�¼���Ϣ.CNend
 */
typedef struct {
    unsigned char addr[HI_WIFI_MAC_LEN];    /**< MESH���ӵ�peer MAC��ַ */
} event_mesh_connected;

/**
 * @ingroup hi_wifi_basic
 *
 * Event type of mesh disconnected.CNcomment:mesh��disconnect�¼���Ϣ.CNend
 */
typedef struct {
    unsigned char addr[HI_WIFI_MAC_LEN];    /**< MESH�Ͽ����ӵ�peer MAC��ַ */
    unsigned short reason_code;             /**< MESH�Ͽ����ӵ�reason code */
} event_mesh_disconnected;

/**
 * @ingroup hi_wifi_basic
 *
 * Event type wifi information.CNcomment:wifi���¼���Ϣ��.CNend
 */
typedef union {
    event_wifi_scan_done wifi_scan_done;            /**< WIFIɨ������¼���Ϣ */
    event_wifi_connected wifi_connected;            /**< WIFI�����¼���Ϣ */
    event_wifi_disconnected wifi_disconnected;      /**< WIFI�Ͽ������¼���Ϣ */
    event_ap_sta_connected ap_sta_connected;        /**< AP�����¼���Ϣ */
    event_ap_sta_disconnected ap_sta_disconnected;  /**< AP�Ͽ������¼���Ϣ */
    event_mesh_connected mesh_connected;            /**< MESH�����¼���Ϣ */
    event_mesh_disconnected mesh_disconnected;      /**< MESH�Ͽ������¼���Ϣ */
} hi_wifi_event_info;

/**
 * @ingroup hi_wifi_basic
 *
 * Struct of WiFi event.CNcomment:WiFi�¼��ṹ��.CNend
 *
 */
typedef struct {
    hi_wifi_event_type event;   /**< �¼����� */
    hi_wifi_event_info info;    /**< �¼���Ϣ */
} hi_wifi_event;

/**
 * @ingroup hi_wifi_basic
 *
 * Struct of softap's basic config.CNcomment:softap��������.CNend
 *
 */
typedef struct {
    char ssid[HI_WIFI_MAX_SSID_LEN + 1];    /**< SSID : ֻ֧��ASCII�ַ� */
    char key[HI_WIFI_AP_KEY_LEN + 1];       /**< ���� */
    unsigned char channel_num;              /**< �ŵ��ţ�ȡֵ��Χ1-14����ͬ����ȡֵ��Χ�в��� */
    int ssid_hidden;                        /**< �Ƿ�����SSID */
    hi_wifi_auth_mode authmode;             /**< ��֤��ʽ */
    hi_wifi_pairwise pairwise;              /**< ���ܷ�ʽ����ѡ������ָ��ʱ��Ϊ0 */
} hi_wifi_softap_config;

/**
 * @ingroup hi_wifi_basic
 *
 * mac address of softap's user.CNcomment:��softap������station mac��ַ.CNend
 *
 */
typedef struct {
    unsigned char mac[HI_WIFI_MAC_LEN];     /**< MAC address.CNcomment:��softap������station mac��ַ.CNend */
} hi_wifi_ap_sta_info;

/**
 * @ingroup hi_wifi_basic
 *
 * Struct of frame filter config in monitor mode.CNcomment:����ģʽ���Ľ��չ�������.CNend
 */
typedef struct {
    char mdata_en : 1;  /**< get multi-cast data frame flag. CNcomment: ʹ�ܽ����鲥(�㲥)���ݰ�.CNend */
    char udata_en : 1;  /**< get single-cast data frame flag. CNcomment: ʹ�ܽ��յ������ݰ�.CNend */
    char mmngt_en : 1;  /**< get multi-cast mgmt frame flag. CNcomment: ʹ�ܽ����鲥(�㲥)�����.CNend */
    char umngt_en : 1;  /**< get single-cast mgmt frame flag. CNcomment: ʹ�ܽ��յ��������.CNend */
    char resvd    : 4;  /**< reserved bits. CNcomment: �����ֶ�.CNend */
} hi_wifi_ptype_filter;

/**
 * @ingroup hi_wifi_basic
 *
 * Struct of WPA psk calc config.CNcomment:����WPA psk��Ҫ���õĲ���.CNend
 */
typedef struct {
    unsigned char ssid[HI_WIFI_MAX_SSID_LEN + 1]; /**< SSID ֻ֧��ASCII�ַ� */
    char key[HI_WIFI_AP_KEY_LEN + 1];             /**< ���� */
}hi_wifi_sta_psk_config;

/**
 * @ingroup hi_wifi_basic
 *
 * callback function definition of monitor mode.CNcommment:����ģʽ�հ��ص��ӿڶ���.CNend
 */
typedef int (*hi_wifi_promis_cb)(void* recv_buf, int frame_len, signed char rssi);

/**
 * @ingroup hi_wifi_basic
 *
 * callback function definition of wifi event.CNcommment:wifi�¼��ص��ӿڶ���.CNend
 */
typedef void (*hi_wifi_event_cb)(const hi_wifi_event *event);

/**
* @ingroup  hi_wifi_basic
* @brief  Wifi initialize.CNcomment:wifi��ʼ��.CNend
*
* @par Description:
        Wifi driver initialize.CNcomment:wifi������ʼ����������wifi�豸.CNend
*
* @attention  NULL
* @param  vap_res_num   [IN]  Type #const unsigned char, vap num[rang: 1-3].CNcomment:vap��Դ������ȡֵ[1-3].CNend
* @param  user_res_num  [IN]  Type #const unsigned char, user resource num[1-7].
*           CNcomment:�û���Դ��������vapʱ����ȡֵ[1-7].CNend
*
* @retval #HISI_OK  Excute successfully
* @retval #Other    Error code
* @par Dependency:
*            @li hi_wifi_api.h: WiFi API
* @see  NULL
* @since Hi3861_V100R001C00
*/
int hi_wifi_init(const unsigned char vap_res_num, const unsigned char user_res_num);

/**
* @ingroup  hi_wifi_basic
* @brief  Wifi de-initialize.CNcomment:wifiȥ��ʼ��.CNend
*
* @par Description:
*           Wifi driver de-initialize.CNcomment:wifi����ȥ��ʼ��.CNend
*
* @attention  NULL
* @param  NULL
*
* @retval #HISI_OK  Excute successfully
* @retval #Other    Error code
* @par Dependency:
*            @li hi_wifi_api.h: WiFi API
* @see  NULL
* @since Hi3861_V100R001C00
*/
int hi_wifi_deinit(void);

/**
* @ingroup  hi_wifi_basic
* @brief  Set protocol mode of sta.CNcomment:����station�ӿڵ�protocolģʽ.CNend
*
* @par Description:
*           Set protocol mode of sta, set before calling hi_wifi_sta_start().\n
*           CNcomment:����station�ӿڵ�protocolģʽ, ��sta start֮ǰ����.CNend
*
* @attention  Default mode 802.11BGN CNcomment:Ĭ��ģʽ 802.11BGN.CNend
* @param  mode            [IN]     Type #hi_wifi_protocol_mode, protocol mode.
*
* @retval #HISI_OK        Execute successfully.
* @retval #HISI_FAIL      Execute failed.
* @par Dependency:
*            @li hi_wifi_api.h: WiFi API
* @see  NULL
* @since Hi3861_V100R001C00
*/
int hi_wifi_sta_set_protocol_mode(hi_wifi_protocol_mode mode);

/**
* @ingroup  hi_wifi_basic
* @brief  Get protocol mode of.CNcomment:��ȡstation�ӿڵ�protocolģʽ.CNend
*
* @par Description:
*           Get protocol mode of station.CNcomment:��ȡstation�ӿڵ�protocolģʽ.CNend
*
* @attention  NULL
* @param      NULL
*
* @retval #hi_wifi_protocol_mode protocol mode.
* @par Dependency:
*            @li hi_wifi_api.h: WiFi API
* @see  NULL
* @since Hi3861_V100R001C00
*/
hi_wifi_protocol_mode hi_wifi_sta_get_protocol_mode(void);

/**
* @ingroup  hi_wifi_basic
* @brief  Config pmf settings of sta.CNcomment:����station��pmf.CNend
*
* @par Description:
*           Config pmf settings of sta, set before sta start.CNcomment:����station��pmf, ��sta start֮ǰ����.CNend
*
* @attention  Default pmf enum value 1. CNcomment:Ĭ��pmfö��ֵ1.CNend
* @param  pmf           [IN]     Type #hi_wifi_pmf_options, pmf enum value.CNcoment:pmfö��ֵ.CNend
*
* @retval #HISI_OK        Execute successfully.
* @retval #HISI_FAIL      Execute failed.
* @par Dependency:
*            @li hi_wifi_api.h: WiFi API
* @see  NULL
* @since Hi3861_V100R001C00
*/
int hi_wifi_set_pmf(hi_wifi_pmf_options pmf);

/**
* @ingroup  hi_wifi_basic
* @brief  Get pmf settings of sta.CNcomment:��ȡstation��pmf����.CNend
*
* @par Description:
*           Get pmf settings of sta.CNcomment:��ȡstation��pmf����.CNend
*
* @attention  NULL
* @param      NULL
*
* @retval #hi_wifi_pmf_options pmf enum value.
* @par Dependency:
*            @li hi_wifi_api.h: WiFi API
* @see  NULL
* @since Hi3861_V100R001C00
*/
hi_wifi_pmf_options hi_wifi_get_pmf(void);

/**
* @ingroup  hi_wifi_basic
* @brief  Start wifi station.CNcomment:����STA.CNend
*
* @par Description:
*           Start wifi station.CNcomment:����STA.CNend
*
* @attention  1. Multiple interfaces of the same type are not supported.CNcomment:1. ��֧��ʹ�ö��ͬ���ͽӿ�.CNend\n
*             2. Dual interface coexistence support: STA + AP or STA + MESH.
*                CNcomment:2. ˫�ӿڹ���֧�֣�STA + AP or STA + MESH.CNend\n
*             3. Start timeout 5s.CNcomment:3. ������ʱʱ��5s.CNend\n
*             4. The memories of <ifname> and <len> memories are requested by the caller.\n
*                CNcomment:4. <ifname>��<len>�ɵ����������ڴ�.CNend
* @param  ifname          [IN/OUT]     Type #char *, device name.CNcomment:�ӿ���.CNend
* @param  len             [IN/OUT]     Type #int *, length of device name.CNcomment:�ӿ�������.CNend
*
* @retval #HISI_OK        Execute successfully.
* @retval #HISI_FAIL      Execute failed.
* @par Dependency:
*            @li hi_wifi_api.h: WiFi API
* @see  NULL
* @since Hi3861_V100R001C00
*/
int hi_wifi_sta_start(char *ifname, int *len);

/**
* @ingroup  hi_wifi_basic
* @brief  Close wifi station.CNcomment:�ر�STA.CNend
*
* @par Description:
*           Close wifi station.CNcomment:�ر�STA.CNend
*
* @attention  NULL
* @param  NULL
*
* @retval #HISI_OK        Execute successfully.
* @retval #HISI_FAIL      Execute failed.
* @par Dependency:
*            @li hi_wifi_api.h: WiFi API
* @see  NULL
* @since Hi3861_V100R001C00
*/
int hi_wifi_sta_stop(void);

/**
* @ingroup  hi_wifi_basic
* @brief  Start sta basic scanning in all channels.CNcomment:station����ȫ�ŵ�����ɨ��.CNend
*
* @par Description:
*           Start sta basic scanning in all channels.CNcomment:����stationȫ�ŵ�����ɨ��.CNend
*
* @attention  NULL
* @param     NULL
*
* @retval #HISI_OK        Execute successfully.
* @retval #HISI_FAIL      Execute failed.
* @par Dependency:
*            @li hi_wifi_api.h: WiFi API
* @see  NULL
* @since Hi3861_V100R001C00
*/
int hi_wifi_sta_scan(void);

/**
* @ingroup  hi_wifi_basic
* @brief  Start station scanning with specified parameter.CNcomment:stationִ�д��ض�������ɨ��.CNend
*
* @par Description:
*           Start station scanning with specified parameter.CNcomment:stationִ�д��ض�������ɨ��.CNend
*
* @attention  1. advance scan can scan with ssid only,channel only,bssid only,prefix_ssid only��
*                and the combination parameters scanning does not support.\n
*             CNcomment:1. �߼�ɨ��ֱ𵥶�֧�� ssidɨ�裬�ŵ�ɨ�裬bssidɨ�裬ssidǰ׺ɨ��, ��֧����ϲ���ɨ�跽ʽ.CNend\n
*             2. Scanning mode, subject to the type set by scan_type.
*              CNcomment:2 .ɨ�跽ʽ����scan_type���������Ϊ׼��CNend
*             3. SSID only supports ASCII characters.\n
*                CNcomment:3. SSID ֻ֧��ASCII�ַ�.CNend
* @param  sp            [IN]    Type #hi_wifi_scan_params * parameters of scan.CNcomment:ɨ�������������.CNend
*
* @retval #HISI_OK        Execute successfully.
* @retval #HISI_FAIL      Execute failed.
* @par Dependency:
*            @li hi_wifi_api.h: WiFi API
* @see  NULL
* @since Hi3861_V100R001C00
*/
int hi_wifi_sta_advance_scan(hi_wifi_scan_params *sp);

/**
* @ingroup  hi_wifi_basic
* @brief  station����ɨ�衣
*
* @par Description:
*           Get station scan result.CNcomment:��ȡstationɨ����.CNend
* @attention  1. The memories of <ap_list> and <ap_num> memories are requested by the caller. \n
*             The <ap_list> size up to : sizeof(hi_wifi_ap_info ap_list) * 64. \n
*             CNcomment:1. <ap_list>��<ap_num>�ɵ����������ڴ�, \n
*             <ap_list>size���Ϊ��sizeof(hi_wifi_ap_info ap_list) * 64.CNend \n
*             2. ap_num: parameters can be passed in to specify the number of scanned results.The maximum is 64. \n
*             CNcomment:2. ap_num: ���Դ��������ָ����ȡɨ�赽�Ľ�����������Ϊ64��CNend \n
*             3. If the user callback function is used, ap num refers to bss_num in event_wifi_scan_done. \n
*             CNcomment:3. ���ʹ���ϱ��û��Ļص�������ap_num�ο�event_wifi_scan_done�е�bss_num��CNend \n
*             4. ap_num should be same with number of hi_wifi_ap_info structures applied,
*                Otherwise, it will cause memory overflow. \n
*             CNcomment:4. ap_num�������hi_wifi_ap_info�ṹ������һ�£������������ڴ������CNend \n
*             5. SSID only supports ASCII characters.\n
*             CNcomment:5. SSID ֻ֧��ASCII�ַ�.CNend
* @param  ap_list         [IN/OUT]    Type #hi_wifi_ap_info * scan result.CNcomment:ɨ��Ľ��.CNend
* @param  ap_num          [IN/OUT]    Type #unsigned int *, number of scan result.CNcomment:ɨ�赽��������Ŀ.CNend
*
* @retval #HISI_OK        Execute successfully.
* @retval #HISI_FAIL      Execute failed.
* @par Dependency:
*            @li hi_wifi_api.h: WiFi API
* @see  NULL
* @since Hi3861_V100R001C00
*/
int hi_wifi_sta_scan_results(hi_wifi_ap_info *ap_list, unsigned int *ap_num);

/**
* @ingroup  hi_wifi_basic
* @brief  sta start connect.CNcomment:station������������.CNend
*
* @par Description:
*           sta start connect.CNcomment:station������������.CNend
*
* @attention  1.<ssid> and <bssid> cannot be empty at the same time. CNcomment:1. <ssid>��<bssid>����ͬʱΪ��.CNend\n
*             2. When <auth_type> is set to OPEN, the <passwd> parameter is not required.
*                CNcomment:2. <auth_type>����ΪOPENʱ������<passwd>����.CNend\n
*             3. This function is non-blocking.CNcomment:3. �˺���Ϊ������ʽ.CNend\n
*             4. Pairwise can be set, default is 0.CNcomment:4. pairwise ������, Ĭ��Ϊ0.CNend\n
*             5. If the station is already connected to a network, disconnect the existing connection and
*                then connect to the new network.\n
*                CNcomment:5. ��station�ѽ���ĳ�����磬���ȶϿ��������ӣ�Ȼ������������.CNend\n
*             6. If the wrong SSID, BSSID or key is passed in, the HISI_OK will be returned,
*                but sta cannot connect the ap.
*                CNcomment:6. �����������ssid��bssid���߲���ȷ�����룬���سɹ���������apʧ�ܡ�CNend\n
*             7. SSID only supports ASCII characters.
*                CNcomment:7. SSID ֻ֧��ASCII�ַ�.CNend

* @param  req    [IN]    Type #hi_wifi_assoc_request * connect parameters of network.CNcomment:���������������.CNend
* @retval #HISI_OK        Execute successfully.
* @retval #HISI_FAIL      Execute failed.
* @par Dependency:
*            @li hi_wifi_api.h: WiFi API
* @see  NULL
* @since Hi3861_V100R001C00
*/
int hi_wifi_sta_connect(hi_wifi_assoc_request *req);

/**
* @ingroup  hi_wifi_basic
* @brief  Start fast connect.CNcomment:station���п�����������.CNend
*
* @par Description:
*           Start fast connect.CNcomment:station���п�����������.CNend
*
* @attention  1. <ssid> and <bssid> cannot be empty at the same time. CNcomment:1��<ssid>��<bssid>����ͬʱΪ��.CNend\n

*             2. When <auth_type> is set to OPEN, the <passwd> parameter is not required.
*                CNcomment:2��<auth_type>����ΪOPENʱ������<passwd>����.CNend\n
*             3. <chn> There are differences in the range of values, and China is 1-13.
*                CNcomment:3��<chn>ȡֵ��Χ��ͬ�����в��죬�й�Ϊ1-13.CNend\n
*             4. This function is non-blocking.4���˺���Ϊ������ʽ.CNend\n
*             5. Pairwise can be set, set to zero by default.CNcomment:5. pairwise ������,Ĭ������.CNend\n
*             6. <psk>��<psk_flag> are optional parameters, set to zero by default.
*                CNcomment:6. <psk>��<psk_flag>Ϊ��ѡ����������ʹ��ʱ��0.CNend\n
*             7. If the wrong SSID, BSSID or key is passed in, the HISI_FAIL will be returned,
*                and sta cannot connect the ap.
*                CNcomment:7. �����������ssid��bssid���߲���ȷ�����룬����ʧ�ܲ�������apʧ�ܡ�CNend\n
*             8. SSID only supports ASCII characters.
*                CNcomment:8. SSID ֻ֧��ASCII�ַ�.CNend
* @param fast_request [IN] Type #hi_wifi_fast_assoc_request *,fast connect parameters. CNcomment:���������������.CNend

* @retval #HISI_OK        Execute successfully.
* @retval #HISI_FAIL      Execute failed.
* @par Dependency:
*            @li hi_wifi_api.h: WiFi API
* @see  NULL
* @since Hi3861_V100R001C00
*/
int hi_wifi_sta_fast_connect(hi_wifi_fast_assoc_request *fast_request);

/**
* @ingroup  hi_wifi_basic
* @brief  Disconnect from network.CNcomment:station�Ͽ�����������.CNend
*
* @par Description:
*           Disconnect from network.CNcomment:station�Ͽ�����������.CNend
*
* @attention  NULL
* @param  NULL
*
* @retval #HISI_OK        Execute successfully.
* @retval #HISI_FAIL      Execute failed.
* @par Dependency:
*            @li hi_wifi_api.h: WiFi API
* @see  NULL
* @since Hi3861_V100R001C00
*/
int hi_wifi_sta_disconnect(void);

/**
* @ingroup  hi_wifi_basic
* @brief  Set reconnect policy.CNcomment:station�������������������.CNend
*
* @par Description:
*           Set reconnect policy.CNcomment:station�������������������.CNend
*
* @attention  1. The reconnection policy will be triggered after the station become disconnected.\n
*             CNcomment:1. ��������ʹ�ܺ󣬽���station�Ͽ����Ӻ󴥷���Ч.CNend\n
*             2. The Settings will take effect on the next reconnect timer.\n
*             CNcomment:2. �������ݽ�����һ��������ʱ��Ч.CNend\n
*             3. After calling station connect/disconnect or station stop, stop reconnecting.
*             CNcomment:3. ����station connect/disconnect��station stop��ֹͣ����.CNend\n
*             4. If the target network cannot be found by scanning,
                 the reconnection policy cannot trigger to take effect.\n
*             CNcomment:4. ��ɨ�費��Ŀ�����磬���������޷�������Ч.CNend\n
*             5. When the <seconds> value is 65535, it means infinite loop reconnection.
*             CNcomment:5. <seconds>ȡֵΪ65535ʱ����ʾ���޴�ѭ������.CNend\n
*             6. When the <period> value is 0, it means only a single attempt to reconnect.
*             CNcomment:6. <period>ȡֵΪ0ʱ����ʾ�����γ�������.CNend\n
*             7. When the <max_try_count> value is 0, it means only a single attempt to reconnect.
*             CNcomment:7. <max_try_count>ȡֵΪ0ʱ����ʾ�����γ�������.CNend\n
* @param  enable        [IN]    Type #int enable reconnect.0-disable/1-enable.CNcomment:ʹ�������������.CNend
* @param  seconds       [IN]    Type #unsigned int reconnect timeout in seconds for once,range:[2-65535].
*                                                  CNcomment:����������ʱʱ��,ȡֵ[2-65535].CNend
* @param  period        [IN]    Type #unsigned int reconnect period in seconds.CNcomment:�����������.CNend
* @param  max_try_count [IN]    Type #unsigned int max reconnect try count number.CNcomment:�����������.CNend
*
* @retval #HISI_OK        Execute successfully.
* @retval #HISI_FAIL      Execute failed.
* @par Dependency:
*            @li hi_wifi_api.h: WiFi API
* @see  NULL
* @since Hi3861_V100R001C00
*/
int hi_wifi_sta_set_reconnect_policy(int enable, unsigned int seconds,
    unsigned int period, unsigned int max_try_count);

/**
* @ingroup  hi_wifi_basic
* @brief  Get status of sta.CNcomment:��ȡstation���ӵ�����״̬.CNend
*
* @par Description:
*           Get status of sta.CNcomment:��ȡstation���ӵ�����״̬.CNend
*
* @attention  NULL
* @param  connect_status  [IN/OUT]    Type #hi_wifi_status *, connect status�� memory is requested by the caller.
*                                                             CNcomment:����״̬, �ɵ����������ڴ�.CNend
*
* @retval #HISI_OK        Execute successfully.
* @retval #HISI_FAIL      Execute failed.
* @par Dependency:
*            @li hi_wifi_api.h: WiFi API
* @see  NULL
* @since Hi3861_V100R001C00
*/
int hi_wifi_sta_get_connect_info(hi_wifi_status *connect_status);

/**
* @ingroup  hi_wifi_basic
* @brief  Start pbc connect in WPS.CNcomment:����WPS����pbc����.CNend
*
* @par Description:
*           Start pbc connect in WPS.CNcomment:����WPS����pbc����.CNend
*
* @attention  1. bssid can be NULL or MAC. CNcomment:1. bssid ����ָ��mac������NULL.CNend
* @param  bssid   [IN]  Type #unsigned char * mac address
*
* @retval #HISI_OK        Execute successfully.
* @retval #HISI_FAIL      Execute failed.
* @par Dependency:
*            @li hi_wifi_api.h: WiFi API
* @see  NULL
* @since Hi3861_V100R001C00
*/
int hi_wifi_sta_wps_pbc(unsigned char *bssid);

/**
* @ingroup  hi_wifi_basic
* @brief  Start pin connect in WPS.CNcomment:WPSͨ��pin����������.CNend
*
* @par Description:
*           Start pin connect in WPS.CNcomment:WPSͨ��pin����������.CNend
*
* @attention  1. Bssid can be NULL or MAC. CNcomment:1. bssid ����ָ��mac������NULL.CNend \n
*             2. Decimal only WPS pin code length is 8 Bytes.CNcomment:2. WPS��pin�����ʮ���ƣ�����Ϊ8 Bytes.CNend
* @param  pin      [IN]   Type #char * pin code
* @param  bssid    [IN]   Type #unsigned char * mac address
*
* @retval #HISI_OK        Execute successfully.
* @retval #HISI_FAIL      Execute failed.
* @par Dependency:
*            @li hi_wifi_api.h: WiFi API
* @see  NULL
* @since Hi3861_V100R001C00
*/
int hi_wifi_sta_wps_pin(char *pin, unsigned char *bssid);

/**
* @ingroup  hi_wifi_basic
* @brief  Get pin code.CNcomment:WPS��ȡpin��.CNend
*
* @par Description:
*           Get pin code.CNcomment:WPS��ȡpin��.CNend
*
* @attention  Decimal only WPS pin code length is 8 Bytes.CNcomment:WPS��pin�����ʮ���ƣ�����Ϊ8 Bytes.CNend
* @param  pin    [IN/OUT]   Type #char *, pin code buffer, should be obtained, length is 9 Bytes.
*                                                               The memory is requested by the caller.\n
*                                       CNcomment:����ȡpin��,����Ϊ9 Bytes���ɵ����������ڴ�.CNend
* @param  len    [IN]   Type #int, length of pin code
*
* @retval #HISI_OK        Execute successfully.
* @retval #HISI_FAIL      Execute failed.
* @par Dependency:
*            @li hi_wifi_api.h: WiFi API
* @see  NULL
* @since Hi3861_V100R001C00
*/
int hi_wifi_sta_wps_pin_get(char* pin, unsigned int len);

/**
* @ingroup  hi_wifi_basic
* @brief  WPA PSK Calculate.CNcomment:����WPA PSK.CNend
*
* @par Description:
*           PSK Calculate.CNcomment:����psk.CNend
*
* @attention  1. support only WPA PSK. CNcomment:1. ֻ֧��WPA psk����.CNend
*             2. SSID only supports ASCII characters. CNcomment:2. SSID ֻ֧��ASCII�ַ�.CNend
* @param  psk_config    [IN]    Type #hi_wifi_sta_psk_config
* @param  get_psk       [IN/OUT]   Type #const unsigned char *��Psk to be obtained, length is 32 Bytes.
*                                                               The memory is requested by the caller.
*                                       CNcomment:����ȡpsk,����Ϊ32 Bytes���ɵ����������ڴ�.CNend
* @param  psk_len       [IN]    Type #unsigned int
* @retval #HISI_OK        Execute successfully.
* @retval #HISI_FAIL      Execute failed.
* @par Dependency:
*            @li hi_wifi_api.h: WiFi API
* @see  NULL
* @since Hi3861_V100R001C00
*/
int hi_wifi_psk_calc(hi_wifi_sta_psk_config psk_config, unsigned char *get_psk, unsigned int psk_len);

/**
* @ingroup  hi_wifi_basic
* @brief  WPA PSK Calculate��then keep it inside .CNcomment:����WPA PSK, �����ڲ�����.CNend
*
* @par Description:
*           psk Calculate.CNcomment:����psk.CNend
*
* @attention  1. support only WPA PSK. CNcomment:1. ֻ֧��WPA psk����.CNend
*             2. SSID only supports ASCII characters. CNcomment:2. SSID ֻ֧��ASCII�ַ�.CNend
* @param  psk_config    [IN]    Type #hi_wifi_sta_psk_config
* @retval #HISI_OK        Execute successfully.
* @retval #HISI_FAIL      Execute failed.
* @par Dependency:
*            @li hi_wifi_api.h: WiFi API
* @see  NULL
* @since Hi3861_V100R001C00
*/
int hi_wifi_psk_calc_and_store(hi_wifi_sta_psk_config psk_config);

/**
* @ingroup  hi_wifi_basic
* @brief  register user callback interface.CNcomment:ע��ص������ӿ�.CNend
*
* @par Description:
*           register user callback interface.CNcomment:ע��ص������ӿ�.CNend
*
* @attention  NULL
* @param  event_cb  [OUT]    Type #hi_wifi_event_cb *, event callback .CNcomment:�ص�����.CNend
*
* @retval #HISI_OK        Execute successfully.
* @retval #HISI_FAIL      Execute failed.
* @par Dependency:
*            @li hi_wifi_api.h: WiFi API
* @see  NULL
* @since Hi3861_V100R001C00
*/
int hi_wifi_register_event_callback(hi_wifi_event_cb event_cb);

/**
* @ingroup  hi_wifi_basic
* @brief  Set protocol mode of softap.CNcomment:����softap�ӿڵ�protocolģʽ.CNend
*
* @par Description:
*           Set protocol mode of softap.CNcomment:����softap�ӿڵ�protocolģʽ.CNend\n
*           Initiallize config, set before softap start.CNcomment:��ʼ����,��softap start֮ǰ����.CNend
*
* @attention  Default mode(802.11BGN) CNcomment:Ĭ��ģʽ��802.11BGN��.CNend
* @param  mode            [IN]     Type  #hi_wifi_protocol_mode protocol mode.
*
* @retval #HISI_OK        Execute successfully.
* @retval #HISI_FAIL      Execute failed.
* @par Dependency:
*            @li hi_wifi_api.h: WiFi API
* @see  NULL
* @since Hi3861_V100R001C00
*/
int hi_wifi_softap_set_protocol_mode(hi_wifi_protocol_mode mode);

/**
* @ingroup  hi_wifi_basic
* @brief  Get protocol mode of softap.CNcomment:��ȡsoftap�ӿڵ�protocolģʽ.CNend
*
* @par Description:
*           Get protocol mode of softap.CNcomment:��ȡsoftap�ӿڵ�protocolģʽ.CNend
*
* @attention  NULL
* @param      NULL
*
* @retval #hi_wifi_protocol_mode protocol mode.
* @par Dependency:
*            @li hi_wifi_api.h: WiFi API
* @see  NULL
* @since Hi3861_V100R001C00
*/
hi_wifi_protocol_mode hi_wifi_softap_get_protocol_mode(void);

/**
* @ingroup  hi_wifi_basic
* @brief  Set softap's beacon interval.CNcomment:����softap��beacon����.CNend
*
* @par Description:
*           Set softap's beacon interval.CNcomment:����softap��beacon����.CNend
*           Initialized config sets before interface starts.CNcomment:��ʼ����softap����֮ǰ����.CNend
*
* @attention  NULL
* @param  beacon_period      [IN]     Type  #int beacon period in milliseconds, range(33ms~1000ms), default(100ms)
*
* @retval #HISI_OK        Execute successfully.
* @retval #HISI_FAIL      Execute failed.
* @par Dependency:
*            @li hi_wifi_api.h: WiFi API
* @see  NULL
* @since Hi3861_V100R001C00
*/
int hi_wifi_softap_set_beacon_period(int beacon_period);

/**
* @ingroup  hi_wifi_basic
* @brief  Set softap's dtim count.CNcomment:����softap��dtim����.CNend
*
* @par Description:
*           Set softap's dtim count.CNcomment:����softap��dtim����.CNend
*           Initialized config sets before interface starts.CNcomment:��ʼ����softap����֮ǰ����.CNend
*
* @attention  NULL
* @param  dtim_period     [IN]     Type  #int, dtim period , range(1~30), default(2)
*
* @retval #HISI_OK        Execute successfully.
* @retval #HISI_FAIL      Execute failed.
* @par Dependency:
*            @li hi_wifi_api.h: WiFi API
* @see  NULL
* @since Hi3861_V100R001C00
*/
int hi_wifi_softap_set_dtim_period(int dtim_period);

/**
* @ingroup  hi_wifi_basic
* @brief  Set update time of softap's group key.CNcomment:����softap�鲥��Կ����ʱ��.CNend
*
* @par Description:
*           Set update time of softap's group key.CNcomment:����softap�鲥��Կ����ʱ��.CNend\n
*           Initialized config sets before interface starts.CNcomment:��ʼ����softap����֮ǰ����.CNend\n
*           If you need to use the rekey function, it is recommended to use WPA+WPA2-PSK + CCMP encryption.
*           CNcomment:����Ҫʹ��rekey���ܣ��Ƽ�ʹ��WPA+WPA2-PSK + CCMP���ܷ�ʽ.CNend
*
* @attention  When using wpa2psk-only + CCMP encryption, rekey is forced to 86400s by default.
*    CNcomment:��ʹ��wpa2psk-only + CCMP���ܷ�ʽʱ  ��rekeyĬ��ǿ�Ƹ�Ϊ 86400.CNend
* @param  wpa_group_rekey [IN]     Type  #int, update time in seconds, range(30s-86400s), default(86400s)
*                                   CNcomment:����ʱ������Ϊ��λ����Χ��30s-86400s��,Ĭ�ϣ�86400s��.CNend
*
* @retval #HISI_OK        Execute successfully.
* @retval #HISI_FAIL      Execute failed.
* @par Dependency:
*            @li hi_wifi_api.h: WiFi API
* @see  NULL
* @since Hi3861_V100R001C00
*/
int hi_wifi_softap_set_group_rekey(int wifi_group_rekey);

/**
* @ingroup  hi_wifi_basic
* @brief  Set short-gi of softap.CNcomment:����softap��SHORT-GI����.CNend
*
* @par Description:
*           Enable or disable short-gi of softap.CNcomment:��������ر�softap��SHORT-GI����.CNend\n
*           Initialized config sets before interface starts.CNcomment:��ʼ����softap����֮ǰ����.CNend
* @attention  NULL
* @param  flag            [IN]    Type  #int, enable(1) or disable(0). default enable(1).
                                        CNcomment:ʹ�ܱ�־��Ĭ��ʹ�ܣ�1��.CNend
*
* @retval #HISI_OK        Execute successfully.
* @retval #HISI_FAIL      Execute failed.
* @par Dependency:
*            @li hi_wifi_api.h: WiFi API
* @see  NULL
* @since Hi3861_V100R001C00
*/
int hi_wifi_softap_set_shortgi(int flag);

/**
* @ingroup  hi_wifi_basic
* @brief  Start softap interface.CNcomment:����SoftAP.CNend
*
* @par Description:
*           Start softap interface.CNcomment:����SoftAP.CNend
*
* @attention  1. Multiple interfaces of the same type are not supported.CNcomment:��֧��ʹ�ö��ͬ���ͽӿ�.CNend\n
*             2. Dual interface coexistence support: STA + AP. CNcomment:˫�ӿڹ���֧�֣�STA + AP.CNend \n
*             3. Start timeout 5s.CNcomment:������ʱʱ��5s��CNend \n
*             4. Softap key length range(8 Bytes - 64 Bytes).CNcomment:softap key���ȷ�Χ��8 Bytes - 64 Bytes��.CNend \n
*             5. Only support auth mode as bellow: \n
*                 HI_WIFI_SECURITY_WPAPSK_WPA2PSK_MIX, \n
*                 HI_WIFI_SECURITY_WPA2PSK, \n
*                 HI_WIFI_SECURITY_OPEN \n
*                CNcomment:5. ֻ֧��������֤ģʽ��\n
*                 HI_WIFI_SECURITY_WPAPSK_WPA2PSK_MIX, \n
*                 HI_WIFI_SECURITY_WPA2PSK, \n
*                 HI_WIFI_SECURITY_OPEN.CNend \n
*             6. The memories of <ifname> and <len> memories are requested by the caller.\n
*                CNcomment:6. <ifname>��<len>�ɵ����������ڴ�.CNend
*             7. SSID only supports ASCII characters. \n
*                CNcomment:7. SSID ֻ֧��ASCII�ַ�.CNend
* @param  conf            [IN]      Type  #hi_wifi_softap_config * softap's configuration.CNcomment:SoftAP����.CNend
* @param  ifname          [IN/OUT]  Type  #char interface name.CNcomment:�ӿ�����.CNend
* @param  len             [IN/OUT]  Type  #int * interface name length.CNcomment:�ӿ����ֳ���.CNend
*
* @retval #HISI_OK        Execute successfully.
* @retval #HISI_FAIL      Execute failed.
* @par Dependency:
*            @li hi_wifi_api.h: WiFi API
* @see  NULL
* @since Hi3861_V100R001C00
*/
int hi_wifi_softap_start(hi_wifi_softap_config *conf, char *ifname, int *len);

/**
* @ingroup  hi_wifi_basic
* @brief  Close softap interface.CNcomment:�ر�SoftAP.CNend
*
* @par Description:
*           Close softap interface.CNcomment:�ر�SoftAP.CNend
*
* @attention  NULL
* @param  NULL
*
* @retval #HISI_OK        Execute successfully.
* @retval #HISI_FAIL      Execute failed.
* @par Dependency:
*            @li hi_wifi_api.h: WiFi API
* @see  NULL
* @since Hi3861_V100R001C00
*/
int hi_wifi_softap_stop(void);

/**
* @ingroup  hi_wifi_basic
* @brief  Get all user's information of softap.CNcomment:softap��ȡ�����ӵ�station����Ϣ.CNend
*
* @par Description:
*           Get all user's information of softap.CNcomment:softap��ȡ�����ӵ�station����Ϣ.CNend
*
* @attention  1. parameter of sta_num max value is 6.CNcomment:1. sta_num ���ֵ��6.CNend\n
*             2. The memories of <sta_list> and <sta_num> memories are requested by the caller.\n
*                CNcomment:2. <sta_list>��<sta_num>�ɵ����������ڴ�.CNend
* @param  sta_list        [IN/OUT]  Type  #hi_wifi_ap_sta_info *, station information.CNcomment:STA��Ϣ.CNend
* @param  sta_num         [IN/OUT]  Type  #unsigned int *, station number.CNcomment:STA����.CNend
*
* @retval #HISI_OK        Execute successfully.
* @retval #HISI_FAIL      Execute failed.
* @par Dependency:
*            @li hi_wifi_api.h: WiFi API
* @see  NULL
* @since Hi3861_V100R001C00
*/
int hi_wifi_softap_get_connected_sta(hi_wifi_ap_sta_info *sta_list, unsigned int *sta_num);

/**
* @ingroup  hi_wifi_basic
* @brief  Softap deauth user by mac address.CNcomment:softapָ���Ͽ����ӵ�station����.CNend
*
* @par Description:
*          Softap deauth user by mac address.CNcomment:softapָ���Ͽ����ӵ�station����.CNend
*
* @attention  NULL
* @param  addr             [IN]     Type  #const char *, station mac address.CNcomment:MAC��ַ.CNend
* @param  addr_len         [IN]     Type  #unsigned char, station mac address length.CNcomment:MAC��ַ����.CNend
*
* @retval #HISI_OK        Execute successfully.
* @retval #HISI_FAIL      Execute failed.
* @par Dependency:
*            @li hi_wifi_api.h: WiFi API
* @see  NULL
* @since Hi3861_V100R001C00
*/
int hi_wifi_softap_deauth_sta(const unsigned char *addr, unsigned char addr_len);

/**
* @ingroup  hi_wifi_basic
* @brief  set mac address.CNcomment:����MAC��ַ.CNend
*
* @par Description:
*           Set original mac address.CNcomment:������ʼmac��ַ.CNend\n
*           mac address will increase or recycle when adding or deleting device.
*           CNcomment:����豸mac��ַ������ɾ���豸���ն�Ӧ��mac��ַ.CNend
*
* @attention  NULL
* @param  mac_addr          [IN]     Type #char *, mac address.CNcomment:MAC��ַ.CNend
* @param  mac_len           [IN]     Type #unsigned char, mac address length.CNcomment:MAC��ַ����.CNend
*
* @retval #HISI_OK  Excute successfully
* @retval #Other    Error code
* @par Dependency:
*            @li hi_wifi_api.h: WiFi API
* @see  NULL
* @since Hi3861_V100R001C00
*/
int hi_wifi_set_macaddr(const char *mac_addr, unsigned char mac_len);

/**
* @ingroup  hi_wifi_basic
* @brief  get mac address.CNcomment:��ȡMAC��ַ.CNend
*
* @par Description:
*           Get original mac address.CNcomment:��ȡmac��ַ.CNend\n
*           mac address will increase or recycle when adding device or deleting device.
*           CNcomment:����豸mac��ַ������ɾ���豸���ն�Ӧ��mac��ַ.CNend
*
* @attention  NULL
* @param  mac_addr          [OUT]    Type #char *, mac address.
* @param  mac_len           [IN]     Type #unsigned char, mac address length.
*
* @retval #HISI_OK  Excute successfully
* @retval #Other    Error code
* @par Dependency:
*            @li hi_wifi_api.h: WiFi API
* @see  NULL
* @since Hi3861_V100R001C00
*/
int hi_wifi_get_macaddr(char *mac_addr, unsigned char mac_len);

/**
* @ingroup  hi_wifi_basic
* @brief  Set country code.CNcomment:���ù�����.CNend
*
* @par Description:
*           Set country code(two uppercases).CNcomment:���ù����룬��������д�ַ����.CNend
*
* @attention  1.Before setting the country code, you must call hi_wifi_init to complete the initialization.
*             CNcomment:���ù�����֮ǰ���������hi_wifi_init��ʼ�����.CNend\n
*             2.cc_lenӦ���ڵ���3.CNcomment:cc_len should be greater than or equal to 3.CNend
* @param  cc               [IN]     Type  #char *, country code.CNcomment:������.CNend
* @param  cc_len           [IN]     Type  #unsigned char, country code length.CNcomment:�����볤��.CNend
*
* @retval #HISI_OK  Excute successfully
* @retval #Other           Error code
* @par Dependency:
*            @li hi_wifi_api.h: WiFi API
* @see  NULL
* @since Hi3861_V100R001C00
*/
int hi_wifi_set_country(const char *cc, unsigned char cc_len);

/**
* @ingroup  hi_wifi_basic
* @brief  Get country code.CNcomment:��ȡ������.CNend
*
* @par Description:
*           Get country code.CNcomment:��ȡ�����룬��������д�ַ����.CNend
*
* @attention  1.Before getting the country code, you must call hi_wifi_init to complete the initialization.
*             CNcomment:��ȡ������֮ǰ���������hi_wifi_init��ʼ�����.CNend
* @param  cc               [OUT]     Type  #char *, country code.CNcomment:������.CNend
* @param  len              [IN/OUT]  Type  #int *, country code length.CNcomment:�����볤��.CNend
*
* @retval #HISI_OK  Excute successfully
* @retval #Other           Error code
* @par Dependency:
*            @li hi_wifi_api.h: WiFi API
* @see  NULL
* @since Hi3861_V100R001C00
*/
int hi_wifi_get_country(char *cc, int *len);

/**
* @ingroup  hi_wifi_basic
* @brief  Set bandwidth.CNcomment:���ô���.CNend
*
* @par Description:
*           Set bandwidth, support 5M/10M/20M.CNcomment:���ýӿڵĹ�������֧��5M 10M 20M���������.CNend
*
* @attention  NULL
* @param  ifname           [IN]     Type  #const char *, interface name.CNcomment:�ӿ���.CNend
* @param  ifname_len       [IN]     Type  #unsigned char, interface name length.CNcomment:�ӿ�������.CNend
* @param  bw               [IN]     Type  #hi_wifi_bw, bandwidth enum.CNcomment:����.CNend
*
* @retval #HISI_OK  Excute successfully
* @retval #Other           Error code
* @par Dependency:
*            @li hi_wifi_api.h: WiFi API
* @see  NULL
* @since Hi3861_V100R001C00
*/
int hi_wifi_set_bandwidth(const char *ifname, unsigned char ifname_len, hi_wifi_bw bw);

/**
* @ingroup  hi_wifi_basic
* @brief  Get bandwidth.CNcomment:��ȡ����.CNend
*
* @par Description:
*           Get bandwidth.CNcomment:��ȡ����.CNend
*
* @attention  NULL
* @param  ifname           [IN]     Type  #const char *, interface name.CNcomment:�ӿ���.CNend
* @param  ifname_len       [IN]     Type  #unsigned char, interface name length.CNcomment:�ӿ�������.CNend
*
* @retval #bandwidth enum.CNcomment:�����ö��ֵ.CNend
* @par Dependency:
*            @li hi_wifi_api.h: WiFi API
* @see  NULL
* @since Hi3861_V100R001C00
*/
hi_wifi_bw hi_wifi_get_bandwidth(const char *ifname, unsigned char ifname_len);

/**
* @ingroup  hi_wifi_basic
* @brief  Set channel.CNcomment:�����ŵ�.CNend
*
* @par Description:
*           Set channel.CNcomment:�����ŵ�.CNend
*
* @attention  NULL
* @param  ifname           [IN]     Type  #const char *, interface name.CNcomment:�ӿ���.CNend
* @param  ifname_len       [IN]     Type  #unsigned char, interface name length.CNcomment:�ӿ�������.CNend
* @param  channel          [IN]     Type  #int *, listen channel.CNcomment:�ŵ���.CNend
*
* @retval #HISI_OK  Excute successfully
* @retval #Other           Error code
* @par Dependency:
*            @li hi_wifi_api.h: WiFi API
* @see  NULL
* @since Hi3861_V100R001C00
*/
int hi_wifi_set_channel(const char *ifname, unsigned char ifname_len, int channel);

/**
* @ingroup  hi_wifi_basic
* @brief  Get channel.CNcomment:��ȡ�ŵ�.CNend
*
* @par Description:
*           Get channel.CNcomment:��ȡ�ŵ�.CNend
*
* @attention  NULL
* @param  ifname           [IN]     Type  #const char *, interface name.CNcomment:�ӿ���.CNend
* @param  ifname_len       [IN]     Type  #unsigned char, interface name length.CNcomment:�ӿ�������.CNend
*
* @retval #HI_WIFI_INVALID_CHANNEL
* @retval #Other                   chanel value.
* @par Dependency:
*            @li hi_wifi_api.h: WiFi API
* @see  NULL
* @since Hi3861_V100R001C00
*/
int hi_wifi_get_channel(const char *ifname, unsigned char ifname_len);

/**
* @ingroup  hi_wifi_basic
* @brief  Set monitor mode.CNcomment:���û���ģʽ.CNend
*
* @par Description:
*           Enable/disable monitor mode of interface.CNcomment:����ָ���ӿڵĻ���ģʽʹ��.CNend
*
* @attention  NULL
* @param  ifname           [IN]     Type  #const char * interface name.CNcomment:�ӿ���.CNend
* @param  enable           [IN]     Type  #int enable(1) or disable(0).CNcomment:����/�ر�.CNend
* @param  filter           [IN]     Type  #hi_wifi_ptype_filter * filtered frame type enum.CNcomment:�����б�.CNend
*
* @retval #HI_ERR_SUCCESS  Excute successfully
* @retval #Other           Error code
* @par Dependency:
*            @li hi_wifi_api.h: WiFi API
* @see  NULL
* @since Hi3861_V100R001C00
*/
int hi_wifi_promis_enable(const char *ifname, int enable, const hi_wifi_ptype_filter *filter);

/**
* @ingroup  hi_wifi_basic
* @brief  Register receive callback in monitor mode.CNcomment:ע�����ģʽ���հ��ص�����.CNend
*
* @par Description:
*           Register receive callback in monitor mode.CNcomment:ע�����ģʽ���հ��ص�����.CNend\n
*           Wifi driver will put the receive frames to this callback.
*           CNcomment:����������ģʽ���յ��ı��ĵݽ���ע��Ļص���������.CNend
*
* @attention  NULL
* @param  data_cb          [IN]     Type  #hi_wifi_promis_cb callback function pointer.CNcomment:����ģʽ�ص�����.CNend
*
* @retval #HI_ERR_SUCCESS  Excute successfully
* @retval #Other           Error code
* @par Dependency:
*            @li hi_wifi_api.h: WiFi API
* @see  NULL
* @since Hi3861_V100R001C00
*/
int hi_wifi_promis_set_rx_callback(hi_wifi_promis_cb data_cb);

/**
* @ingroup  hi_wifi_basic
* @brief    Open/close system power save.CNcomment:����/�ر�WiFi�͹���ģʽ������Ԥ������ʱ��.CNend
*
* @par Description:
*           Open/close system power save.CNcomment:����/�ر�WiFi�͹���ģʽ������Ԥ������ʱ��.CNend
*
* @attention  NULL
* @param  enable     [IN] Type  #unsigned char, enable(1) or disable(0).CNcomment:����/�ر�WiFi�͹���.CNend
* @param  sleep_time [IN] Type  #unsigned int, expected sleep time(uint: ms). CNcomment:Ԥ������ʱ��(��λ: ����),
*                               �ο���Ч��Χ33ms~4000ms, ׼ȷ��ʱ�����dtim*beacon��sleep_timeֵ����,
*                               �رյ͹��Ļ��߲�������Ч����ʱ��ʱ��Ҫ��sleep_time����Ϊ0(����ʱ���ɹ�����ap����).CNend
*
* @retval #HI_ERR_SUCCESS  Excute successfully
* @retval #Other           Error code
* @par Dependency:
*            @li hi_wifi_api.h: WiFi API
* @see  NULL
* @since Hi3861_V100R001C00
*/
int hi_wifi_set_pm_switch(unsigned char enable, unsigned int sleep_time);

/**
* @ingroup  hi_wifi_basic
* @brief    Set arp offload on/off.CNcomment:����arp offload ��/�ر�.CNend
*
* @par Description:
*           Set arp offload on with ip address, or set arp offload off.
*           CNcomment:����arp offload�򿪡�����������Ӧip��ַ����������arp offload�ر�.CNend
*
* @attention  NULL
* @param  ifname          [IN]     Type  #const char *, device name.
* @param  en              [IN]     Type  #unsigned char, arp offload type, 1-on, 0-off.
* @param  ip              [IN]     Type  #unsigned int, ip address in network byte order, eg:192.168.50.4 -> 0x0432A8C0.
*
* @retval #HISI_OK         Excute successfully
* @retval #Other           Error code
* @par Dependency:
*            @li hi_wifi_api.h: WiFi API
* @see  NULL
* @since Hi3861_V100R001C00
*/
unsigned char hi_wifi_arp_offload_setting(const char *ifname, unsigned char en, unsigned int ip);

/**
* @ingroup  hi_wifi_basic
* @brief    Set nd offload on/off.CNcomment:����nd offload ��/�ر�.CNend
*
* @par Description:
*           Set nd offload on with ipv6 address, or set nd offload off.
*           CNcomment:����nd offload�򿪡�����������Ӧipv6��ַ����������nd offload�ر�.CNend
*
* @attention  NULL
* @param  ifname          [IN]     Type  #const char *, device name.
* @param  en              [IN]     Type  #unsigned char, nd offload type, 1-on, 0-off.
* @param  ip              [IN]     Type  #unsigned int, ipv6 address, eg:FE80::8A11:31FF:FE30:F463.
*
* @retval #HISI_OK         Excute successfully
* @retval #Other           Error code
* @par Dependency:
*            @li hi_wifi_api.h: WiFi API
* @see  NULL
* @since Hi3861_V100R001C00
*/
unsigned char hi_wifi_nd_offload_setting(const char *ifname, unsigned char en, unsigned char *ip6);

/**
* @ingroup  hi_wifi_basic
* @brief  Set tx power.CNcomment:���÷��͹�������.CNend
*
* @par Description:
*           Set maximum tx power.CNcomment:����ָ���ӿڵķ��͹�������.CNend
*
* @attention  1/only softAP can set maximum tx power.CNcomment:ֻ��AP������������͹���.CNend
*             2/should start softAP before set tx power.CNcomment:ֻ����AP start֮��ſ�������.CNend
* @param  ifname           [IN]     Type  #const char * interface name.
* @param  power            [IN]     Type  #int maximum tx power value, range (0-19]dBm.
*
* @retval #HI_ERR_SUCCESS  Excute successfully
* @retval #Other           Error code
* @par Dependency:
*            @li hi_wifi_api.h: WiFi API
* @see  NULL
* @since Hi3861_V100R001C00
*/
int hi_wifi_set_txpower_up_limit(const char *ifname, int power);

/**
* @ingroup  hi_wifi_basic
* @brief  Get tx power.CNcomment:��ȡ���͹�������.CNend
*
* @par Description:
*           Get maximum tx power setting.CNcomment:��ȡ�ӿڵ�����͹�������ֵ.CNend
*
* @attention  NULL
* @param  ifname           [IN]     Type  #const char * interface name.
*
* @retval #tx power value.
* @par Dependency:
*            @li hi_wifi_api.h: WiFi API
* @see  NULL
* @since Hi3861_V100R001C00
*/
int hi_wifi_get_txpower_up_limit(const char *ifname);

/**
* @ingroup  hi_wifi_basic
* @brief  Get rssi value.CNcomment:��ȡrssiֵ.CNend
*
* @par Description:
*           Get current rssi of ap which sta connected to.CNcomment:��ȡsta��ǰ������ap��rssiֵ.CNend
*
* @attention  NULL
* @param  NULL
*
* @retval #0x7F          Invalid value.
* @retval #Other         rssi
* @par Dependency:
*            @li hi_wifi_api.h: WiFi API
* @see  NULL
* @since Hi3861_V100R001C00
*/
int hi_wifi_sta_get_ap_rssi(void);

/**
* @ingroup  hi_wifi_basic
* @brief  Set sta pm mode.CNcomment:����STA��FAST_PS��PSPOLL_PS��uapsd�͹���ģʽ.CNend
*
* @par Description:
*           Set sta pm mode.CNcomment:����STA��FAST_PS��PSPOLL_PS��uapsd�͹���ģʽ.CNend
*
* @attention  1.CNcomment:mode��Χ��0~2, 0:FAST_PS; 1:PSPOLL_PS; 2:uapsd.CNend\n
*             2.CNcomment:��API��Ҫ��STA start֮������sta CONN����֮ǰ����.CNend
* @param  mode    [IN]  Type  #unsigned char, pm mode.CNcomment:����ĵ͹���ģʽ,0:FAST_PS; 1:PSPOLL_PS; 2:uapsd.CNend
*
* @retval #HISI_OK  Excute successfully
* @retval #Other           Error code
* @par Dependency:
*            @li hi_wifi_api.h: WiFi API
* @see  NULL
* @since Hi3861_V100R001C00
*/
unsigned int hi_wifi_set_sta_pm_mode(unsigned char mode);

/**
* @ingroup  hi_wifi_basic
* @brief  Set retry params.CNcomment:��������ش�����.CNend
*
* @par Description:
*           Set retry params.CNcomment:����ָ���ӿڵ�����ش�����.CNend
*
* @attention  1.CNcomment:��API��Ҫ��STA��AP start֮�����.CNend
* @param  ifname    [IN]     Type  #const char * interface name.CNcomment:�ӿ���.CNend
* @param  type      [IN]     Type  #unsigned char retry type.
*                            CNcomment:0:�����ش�������֡��; 1:�����ش�������֡��; 2:ʱ���ش�.CNend
* @param  limit     [IN]     Type  #unsigned char limit value.
*                            CNcomment:�ش�����(0~15��)/�ش�ʱ��(0~200��ʱ������,ʱ������10ms).CNend
*
* @retval #HISI_OK  Excute successfully
* @retval #Other           Error code
* @par Dependency:
*            @li hi_wifi_api.h: WiFi API
* @see  NULL
* @since Hi3861_V100R001C00
*/
unsigned int hi_wifi_set_retry_params(const char *ifname, unsigned char type, unsigned char limit);

/**
* @ingroup  hi_wifi_basic
* @brief  Set cca threshold.CNcomment:����CCA����.CNend
*
* @par Description:
*           Set cca threshold.CNcomment:����CCA����.CNend
*
* @attention  1.CNcomment:threshold���÷�Χ��-128~126ʱ����ֵ�̶�Ϊ����ֵ.CNend\n
*             2.CNcomment:threshold����ֵΪ127ʱ���ָ�Ĭ����ֵ-62dBm����ʹ�ܶ�̬����.CNend
* @param  ifname          [IN]     Type #char *, device name. CNcomment:�ӿ���.CNend
* @param  threshold       [IN]     Type #char, threshold. CNcomment:����ֵ.CNend
*
* @retval #HISI_OK  Excute successfully
* @retval #Other           Error code
*
* @par Dependency:
*            @li hi_wifi_api.h: WiFi API
* @see  NULL
* @since Hi3861_V100R001C00
*/
unsigned int hi_wifi_set_cca_threshold(const char* ifname, signed char threshold);

/**
* @ingroup  hi_wifi_basic
* @brief  Set tx power offset.CNcomment:���÷��͹���ƫ��.CNend
*
* @par Description:
*           Set tx power offset.CNcomment:���÷��͹���ƫ��.CNend
*
* @attention  1.CNcomment:offset���÷�Χ��-150~30����λ0.1dB.����������Χ����ӽ��ı߽�ֵ����CNend\n
*             2.CNcomment:offset����,���ܻ�Ӱ���ŵ�����ƽ̹�Ⱥ�evm.CNend
* @param  ifname          [IN]     Type #char *, device name. CNcomment:�ӿ���.CNend
* @param  offset          [IN]     Type #signed short, offset. CNcomment:����ֵ.CNend
*
* @retval #HISI_OK  Excute successfully
* @retval #Other           Error code
*
* @par Dependency:
*            @li hi_wifi_api.h: WiFi API
* @see  NULL
* @since Hi3861_V100R001C00
*/
unsigned int hi_wifi_set_tx_pwr_offset(const char* ifname, signed short offset);

/**
* @ingroup  hi_wifi_basic
* @brief  Send a custom frame.CNcomment:�����û����Ʊ���.CNend
*
* @par Description:
*           Send a custom frame.CNcomment:�����û����Ʊ���.CNend
*
* @attention  1.CNcomment:���֧�ַ���1400�ֽڵı���.CNend\n
*             2.CNcomment:�����밴��802.11Э���ʽ��װ.CNend\n
*             3.CNcomment:���ù���֡���ʷ���,���ͳ���Ч�ʽϵ�.CNend\n
*             4.CNcomment:����ֵ����ʾ�����Ƿ�ɹ����뷢�Ͷ���,����ʾ�տڷ���״̬.CNend\n
* @param  ifname        [IN]     Type #char *, device name. CNcomment:�ӿ���.CNend
* @param  data          [IN]     Type #unsigned char *, frame. CNcomment:֡����.CNend
* @param  len           [IN]     Type #unsigned int *, frame length. CNcomment:֡����.CNend
*
* @retval #HISI_OK  Excute successfully
* @retval #Other           Error code
*
* @par Dependency:
*            @li hi_wifi_api.h: WiFi API
* @see  NULL
* @since Hi3861_V100R001C00
*/
int hi_wifi_send_custom_pkt(const char* ifname, const unsigned char *data, unsigned int len);

#ifdef __cplusplus
#if __cplusplus
    }
#endif
#endif

#endif /* end of hi_wifi_api.h */
