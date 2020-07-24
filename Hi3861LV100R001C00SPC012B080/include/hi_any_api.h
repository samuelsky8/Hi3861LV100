/**
* @file hi_any_api.h
*
* Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2020. All rights reserved. \n
* Description: header file for ANY api.CNcomment:������ANY api�ӿ�ͷ�ļ���CNend\n
* Author: Hisilicon \n
* Create: 2019-01-03
*/

/**
 * @defgroup hi_any_api ANY�ӿ�
 * @ingroup hi_wifi
 */

#ifndef __HI_ANY_API_H__
#define __HI_ANY_API_H__

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

/**
 * @ingroup hi_wifi_any
 *
 * Max length of data for a single ANY transmit.CNcomment:����ANY���������������ݳ��ȡ�CNend
 */
#define WIFI_ANY_MAX_USER_DATA 250
/**
 * @ingroup hi_wifi_any
 *
 * Length of key in octets used in ANY communication.CNcomment:ANY����ͨ�ŵ���Կ���ȣ��̶�Ϊ16�ֽڡ�CNend
 */
#define WIFI_ANY_KEY_LEN       16
/**
 * @ingroup hi_wifi_any
 *
 * Length of MAC address.CNcomment:MAC��ַ���ȶ���CNend
 */
#define WIFI_ANY_MAC_LEN        6
/**
 * @ingroup hi_wifi_any
 *
 * Max length of wlan ssid(for driver).CNcomment:wifi����SSID��󳤶�,+1Ϊ\0Ԥ���ռ�CNend
 */
#define WIFI_ANY_MAX_SSID_LEN       (32 + 1)

/**
 * @ingroup hi_wifi_any
 *
 * Struct of peer's information.CNcomment:�û����������õĶԶ��豸��Ϣ����CNend
 */
typedef struct {
    unsigned char mac[WIFI_ANY_MAC_LEN];  /**< �շ������ĶԶ�MAC��ַ */
    unsigned char channel;                /**< �Զ������ŵ��ţ������Ը���Ϣ�����洢��0xFF��ʾ��ǰ�ŵ� */
    bool          has_key;                /**< �Ƿ�����ͨ����Կ��������true������key�д�����Կ��������false */
    unsigned char key[WIFI_ANY_KEY_LEN];  /**< ���ڼ���ͨ�ŵ���Կ��������Կ�̶�Ϊ16�ֽڳ��� */
} hi_wifi_any_peer_info;

/**
 * @ingroup hi_wifi_any
 *
 * Struct of information of ANY device discovered.CNcomment:ɨ�跢�ֵ�ANY�豸�Ĳ�������CNend
 */
typedef struct {
    unsigned char bssid[WIFI_ANY_MAC_LEN];      /**< BSSID,���Զ�ΪSTA��Ϊ��MAC��ַ */
    unsigned char channel;                      /**< �ŵ��ţ�ȡֵ��Χ1-14����ͬ����ȡֵ��Χ�в��� */
    unsigned char sta_flag;                     /**< true��ʾ�Զ���STA������Ϊ��ͨAP */
    unsigned char ssid[WIFI_ANY_MAX_SSID_LEN];  /**< SSID */
    unsigned char ssid_len;                     /**< SSID�ַ������� */
    char          rssi;                         /**< �ź�ǿ�� */
    unsigned char resv;                         /**< ���� */
} hi_wifi_any_device;

/**
* @ingroup  hi_wifi_any
* @brief  Callback function invoked when ANY scan is finished.CNcomment:ANYɨ����ɻص�����CNend
*
* @par Description:
*           When registered,the driver uses this callback to deliver ANY devices found after an ANY scan. \n
*           CNcomment:ע��ûص�����֮������ÿ�����ANYɨ����øýӿڷ���������ϲ�.CNend
*
* @attention  1. This function is called in driver context,should not be blocked or do long time waiting.\n
                 CNcomment:1. �ûص����������������̣߳�����������ʱ��ȴ�.CNend \n
*             2. The memories of <devices> are requested and freed by the driver automatically.\n
*                CNcomment:2. <devices>�����������ڴ棬Ҳ�������ͷţ��ص��в�Ӧ�ͷ�.CNend
* @param  devices [IN]  Type  #hi_wifi_any_device *, array of poniter of ANY devices found.CNcomment:���ֵ�ANY�豸��Ϣ,
*                       �ò���Ϊָ�����͵����顣CNend
* @param  num     [IN]  Type  #unsigned char, the number of ANY devices found, maximum is 32.CNcomment:���ֵ��豸����,
*                       ��󲻳���32.CNend
*
* @retval #void �޷���ֵ
* @par Dependency:
*            @li hi_any_api.h: ANY API
* @see  hi_wifi_any_discover_peer
* @since Hi3861_V100R001C00
*/
typedef void (*hi_wifi_any_scan_result_cb)(hi_wifi_any_device *devices[], unsigned char num);

/**
* @ingroup  hi_wifi_any
* @brief  Callback function for ANY RX.CNcomment:ANY�������ջص�����CNend
*
* @par Description:
*           When registered,the driver uses this callback to deliver data received. \n
*           CNcomment:ע��ûص�����֮�������յ�ANY��������øûص��������ݸ��ϲ�Ӧ��.CNend
*
* @attention  1. This function is called in driver context,should not be blocked or do long time waiting.\n
                 CNcomment:1. �ûص����������������̣߳�����������ʱ��ȴ�.CNend\n
*             2. The memories of <mac> and <data> are requested and freed by the driver.\n
*                CNcomment:2. <mac>��<data>�����������ڴ�,Ҳ�������ͷţ��ص��в�Ӧ�ͷ�.CNend
* @param  mac        [IN]  Type  #unsigned char *, MAC address with 6 octets length.CNcomment:6�ֽڳ���MAC��ַ.CNend
* @param  data       [IN]  Type  #unsigned char *, the address of data received.CNcomment:���յ����ݵĻ����ַ.CNend
* @param  len        [IN]  Type  #unsigned short, the length in octet of data received.CNcomment:���յ����ݳ��ȣ�
*                                ���Ϊ250�ֽ�.CNend
* @param  seqnum     [IN]  Type  #unsigned char, the sequence number of the ANY frame, range [0-255].
*                                CNcomment:���յ���ANY֡�����к�,��Χ0-255.CNend
*
* @retval #void �޷���ֵ
* @par Dependency:
*            @li hi_any_api.h: ANY API
* @see  hi_wifi_any_set_callback
* @since Hi3861_V100R001C00
*/
typedef void (*hi_wifi_any_recv_cb)(unsigned char *mac, unsigned char *data, unsigned short len, unsigned char seqnum);

/**
* @ingroup  hi_wifi_any
* @brief  Callback function for ANY TX.CNcomment:ANY�������ͻص�����CNend
*
* @par Description:
*           When registered,the driver uses this callback to notify whether an ACK has received. \n
*           CNcomment:ע��ûص�����֮�����������ͽ��(�Ƿ��յ�ACK)�������ϲ�Ӧ��.CNend
*
* @attention  1. This function is called in driver context,should not be blocked or do long time waiting.\n
                 CNcomment:1. �ûص����������������̣߳�����������ʱ��ȴ�.CNend \n
*             2. The memories of <mac> are requested and freed by the driver.\n
*                CNcomment:2. <mac>�����������ڴ棬Ҳ�������ͷţ��ص��в�Ӧ�ͷ�.CNend
* @param  mac        [IN]  Type  #unsigned char *, MAC address with 6 octets length.CNcomment:6�ֽڳ���MAC��ַ.CNend
* @param  status     [IN]  Type  #unsigned char, the result of a single transmit.CNcomment:���η��͵Ľ��.CNend
* @param  seqnum     [IN]  Type  #unsigned char, the sequence number of the ANY frame, range [0-255].
*                                CNcomment:���յ���ANY֡�����к�,��Χ0-255.CNend
*
* @retval #1               Data transmit successfully with an ACK received
* @retval #Other           Error code
* @par Dependency:
*            @li hi_any_api.h: ANY API
* @see  hi_wifi_any_set_callback
* @since Hi3861_V100R001C00
*/
typedef void (*hi_wifi_any_send_complete_cb)(unsigned char *mac, unsigned char status, unsigned char seqnum);

/**
 * @ingroup hi_wifi_any
 *
 * Struct of ANY callback function.CNcomment:ANY�շ��ص��ӿڶ���CNend
 */
typedef struct {
    hi_wifi_any_send_complete_cb send_cb; /**< ANY������������ص����������ڽ��������ͽ���������ϲ� */
    hi_wifi_any_recv_cb recv_cb;          /**< ANY�������������ص����������ڽ��������յ����ݴ��ݸ��ϲ� */
} hi_wifi_any_callback;

/**
* @ingroup  hi_wifi_any
* @brief  Use this funtion to initialize ANY feature.CNcomment:ANY���ܳ�ʼ������CNend
*
* @par Description:
*           Use this funtion to initialize ANY feature.CNcomment:ANY���ܳ�ʼ������CNend
*
* @attention  A device shall be intialized only once, do de-initialzing first before perform a new initialization.\n
              CNcomment:һ���豸ֻ����һ�γ�ʼ�������³�ʼ��֮ǰ��Ҫ�ȵ���ȥANY��ʼ��.CNend \n
* @param  seqnum     [IN]  Type  #const char *, the interface name used to TX/RX ANY frames, eg.wlan0/ap0/mesh0.
*                                CNcomment:�����շ�ANY���ĵĽӿ����ƣ�����ֵΪ"wlan0","ap0"��"mesh0".CNend
*
* @retval #HI_ERR_SUCCESS  Excute successfully
* @retval #Other           Error code
* @par Dependency:
*            @li hi_any_api.h: ANY API
* @see  NULL
* @since Hi3861_V100R001C00
*/
int hi_wifi_any_init(const char *ifname);

/**
* @ingroup  hi_wifi_any
* @brief  Use this funtion to de-initialize ANY feature.CNcomment:ANY����ȥ��ʼ������CNend
*
* @par Description:
*           Use this funtion to de-initialize ANY feature.CNcomment:ANY����ȥ��ʼ������CNend
*
* @attention  NULL
* @param  NULL
*
* @retval #HI_ERR_SUCCESS  Excute successfully
* @retval #Other           Error code
* @par Dependency:
*            @li hi_any_api.h: ANY API
* @see  NULL
* @since Hi3861_V100R001C00
*/
int hi_wifi_any_deinit(void);

/**
* @ingroup  hi_wifi_any
* @brief  Register callback functions for ANY TX and RX.CNcomment:ע��ANY�������ͻص������ͽ��ջص�����CNend
*
* @par Description:
*           Register callback functions for ANY TX and RX.CNcomment:ע��ANY�������ͻص������ͽ��ջص�����CNend
*
* @attention  APP shall implement the TX/RX callbacks and register them to driver through this function.\n
              CNcomment:��Ҫ�û��Լ�ʵ�ָûص��������ܲ�ͨ�������ӿ�ע�������.CNend
* @param  send_cb  [IN]  Type  #hi_wifi_any_send_complete_cb, callback function for ANY TX.
*                              CNcomment:ANY�������ͻص�����.CNend
* @param  recv_cb  [IN]  Type  #hi_wifi_any_recv_cb, callback function for ANY RX.
*                              CNcomment:ANY�������ջص�����.CNend
*
* @retval #void    �޷���ֵ
* @par Dependency:
*            @li hi_any_api.h: ANY API
* @see  hi_wifi_any_send_complete_cb | hi_wifi_any_recv_cb
* @since Hi3861_V100R001C00
*/
void hi_wifi_any_set_callback(hi_wifi_any_send_complete_cb send_cb, hi_wifi_any_recv_cb recv_cb);

/**
* @ingroup  hi_wifi_any
* @brief    Send ANY frame to specific mac address.CNcomment:��ָ��MAC��ַ���豸����ANY���ݡ�CNend
*
* @par Description:
*           Frame TX interface of ANY, specify frame's sequece number by seq. \n
*           the mac_len shall be constant 6 and data_len for a frame should not exceed 250 octets. \n
*           CNcomment:ANY���ķ��ͽӿڣ�����ͨ��seqָ���ñ��ĵķ������кš�\n
*           ����MAC��ַ���ȹ̶���6�ֽڣ������͵����ݳ���data_len���ܳ���250�ֽ� CNend
*
* @attention     The memories of <mac> and <data> are requested and freed by user APP.\n
*                CNcomment:<mac>��<data>�ڴ����û�����͹���ִ����ɺ����������ͷ�.CNend
* @param  mac        [IN]  Type  #const unsigned char *, destination MAC address, it may be unicast or broadcast.
*                                CNcomment:6�ֽڳ���Ŀ��MAC��ַ, ��Ϊ�������߹㲥��ַ, ��֧���鲥��ַ.CNend
* @param  mac_len    [IN]  Type  #unsigned char, length of MAC address which shall be 6 in octet.
*                                CNcomment:MAC��ַ����, ��Ϊ6�ֽ�.CNend
* @param  data       [IN]  Type  #unsigned char *, the address of data.CNcomment:���������ݵĻ����ַ.CNend
* @param  len        [IN]  Type  #unsigned short, the length in octet of data, maximum is 250.
*                                CNcomment:�����͵����ݳ���, ���Ϊ250�ֽ�.CNend
* @param  seqnum     [IN]  Type  #unsigned char, the sequence number of the ANY frame, range [0-255].
*                                CNcomment:�����͵�ANY֡�����к�,��Χ0-255.CNend
*
* @retval #HI_ERR_SUCCESS  Excute successfully
* @retval #Other           Error code
* @par Dependency:
*            @li hi_any_api.h: ANY API
* @see  hi_wifi_any_send_complete_cb
* @since Hi3861_V100R001C00
*/
int hi_wifi_any_send(const unsigned char *mac, unsigned char mac_len, unsigned char *data,
                     unsigned short data_len, unsigned char seq);

/**
* @ingroup  hi_wifi_any
* @brief    Add information of ANY peer device.CNcomment:���ANY�Զ��豸��Ϣ��CNend
*
* @par Description:
*           Add information of ANY peer device(mac address, channel and key). \n
*           the number of peer devices must not exceed 16, among which the encrypted must not exceed 6. \n
*           CNcomment:��ӶԶ��豸��MAC��ַ�������ŵ���Ϣ�����ڼ���ͨ�ŵ���Կ��\n
*                     �Զ��豸�������16�������м���ͨ�ŵĶԶ˸������6����CNend
*
* @attention   1. The driver just stores the channels of peer devices.\n
*                 It will not switch to a channel automatically which differs with the current channel. \n
*                 CNcomment:1. ����������Զ��豸���ŵ��ţ�ͨ�Ź��̲����Զ��е���Ӧ�ŵ�.CNend \n
*              2. The memories of <peer_info> are requested and freed by user APP.\n
*                 CNcomment:2. <peer_info>�ڴ����û����������ӿ��в����ͷ�.CNend
* @param  peer_info       [IN]     Type  #hi_wifi_any_peer_info *, information of peer device.
*                                  CNcomment:�Զ��豸����Ϣ.CNend
*
* @retval #HI_ERR_SUCCESS  Excute successfully
* @retval #Other           Error code
* @par Dependency:
*            @li hi_any_api.h: ANY API
* @see  NULL
* @since Hi3861_V100R001C00
*/
int hi_wifi_any_add_peer(const hi_wifi_any_peer_info *peer_info);

/**
* @ingroup  hi_wifi_any
* @brief    Delete specific peer device.CNcomment:ɾ��ָ��MAC��ַ�ĶԶ��豸��Ϣ��CNend
*
* @par Description:
*           Delete peer device specified by MAC address, the <len> should be constant 6. \n
*           CNcomment:ɾ��ָ��MAC��ַ�ĶԶ��豸��Ϣ,MAC��ַ������̶���6�ֽڡ�CNend
*
* @attention  The memories of <mac> are requested and freed by user APP. \n
*             CNcomment:<mac>�ڴ����û�����͹���ִ����ɺ����������ͷ�.CNend
* @param  mac   [IN]     Type  #const unsigned char *, peer device's MAC address.
*                        CNcomment:��ɾ���ĶԶ��豸��MAC��ַ.CNend
* @param  len   [IN]     Type  #unsigned char, length of MAC address which shall be constant 6.
*                        CNcomment:�Զ��豸��MAC��ַ���ȣ��̶���6�ֽ�.CNend
*
* @retval #HI_ERR_SUCCESS  Excute successfully
* @retval #Other           Error code
* @par Dependency:
*            @li hi_any_api.h: ANY API
* @see  NULL
* @since Hi3861_V100R001C00
*/
int hi_wifi_any_del_peer(const unsigned char *mac, unsigned char len);

/**
* @ingroup  hi_wifi_any
* @brief    Get ANY peer device's information by index.CNcomment:��ȡָ�������ĶԶ��豸��Ϣ��CNend
*
* @par Description:
*           Get ANY peer device's information by index.Index starts from 0 and should not exceed 15. \n
*           CNcomment:��ȡָ�������ĶԶ��豸��Ϣ�����д����index��0��ʼָ����ѯ�ڼ����Զˣ�����ܳ���15��CNend
*
* @attention  The memories of <peer> are requested and freed by user APP. \n
*             CNcomment:<peer>�ڴ����û�����͹�������������ѯ������Ϣ.CNend
* @param  index           [IN]     Type  #unsigned char, peer device's index, start from 0.
*                                  CNcomment:����ѯ�ĶԶ��豸����������0��ʼ.CNend
* @param  peer            [OUT]    Type  #hi_wifi_any_peer_info *, peer device's information.
*                                  CNcomment:��ѯ���ĶԶ��豸����Ϣ.CNend
*
* @retval #HI_ERR_SUCCESS  Excute successfully
* @retval #Other           Error code
* @par Dependency:
*            @li hi_any_api.h: ANY API
* @see  NULL
* @since Hi3861_V100R001C00
*/
int hi_wifi_any_fetch_peer(unsigned char index, hi_wifi_any_peer_info *peer);

/**
* @ingroup  hi_wifi_any
* @brief    Start ANY scan and register callback to handle scan results. \n
*           CNcomment:����ANYɨ�貢ע��ص���������ɨ�����֮��Ľ����CNend
*
* @par Description:
*           Start ANY scan and register callback to handle scan results. \n
*           The limit to the number of peers discoverd is 32 for a single scan. \n
*           CNcomment:����ANYɨ�貢ע��ص���������ɨ�����֮��Ľ��,����ɨ����෵��32���Զ��豸��Ϣ��CNend
*
* @attention  NULL
* @param  p_fn_cb    [IN]     Type  #hi_wifi_any_scan_result_cb, callback function to handle scan results.
*                             CNcomment:���û�ʵ�ֵĻص�����, ɨ�����֮���������øûص�����ɨ����.CNend
*
* @retval #HI_ERR_SUCCESS  Excute successfully
* @retval #Other           Error code
* @par Dependency:
*            @li hi_any_api.h: ANY API
* @see  hi_wifi_any_scan_result_cb
* @since Hi3861_V100R001C00
*/
int hi_wifi_any_discover_peer(hi_wifi_any_scan_result_cb p_fn_cb);

#ifdef __cplusplus
#if __cplusplus
    }
#endif
#endif

#endif /* end of hi_any_api.h */

