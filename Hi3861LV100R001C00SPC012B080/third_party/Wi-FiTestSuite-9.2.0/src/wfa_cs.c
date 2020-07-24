/****************************************************************************
Copyright (c) 2016 Wi-Fi Alliance.  All Rights Reserved

Permission to use, copy, modify, and/or distribute this software for any purpose with or
without fee is hereby granted, provided that the above copyright notice and this permission
notice appear in all copies.

THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES WITH
REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT,
INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING
FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT,
NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH
THE USE OR PERFORMANCE OF THIS SOFTWARE.

******************************************************************************/

/*
 *   File: wfa_cs.c -- configuration and setup
 *   This file contains all implementation for the dut setup and control
 *   functions, such as network interfaces, ip address and wireless specific
 *   setup with its supplicant.
 *
 *   The current implementation is to show how these functions
 *   should be defined in order to support the Agent Control/Test Manager
 *   control commands. To simplify the current work and avoid any GPL licenses,
 *   the functions mostly invoke shell commands by calling linux system call,
 *   system("<commands>").
 *
 *   It depends on the differnt device and platform, vendors can choice their
 *   own ways to interact its systems, supplicants and process these commands
 *   such as using the native APIs.
 *
 *
 */
#include "los_typedef.h"
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include "hi_sem.h"
#include "lwip/netifapi.h"
#include "wfa_portall.h"
#include "wfa_debug.h"
#include "wfa_ver.h"
#include "wfa_main.h"
#include "wfa_types.h"
#include "wfa_ca.h"
#include "wfa_tlv.h"
#include "wfa_tg.h"
#include "wfa_cmds.h"
#include "wfa_rsp.h"
#ifdef WFA_WMM_PS_EXT
#include "wfa_wmmps.h"
#endif
#include "hi_wifitest_wifi.h"
#include "hi_reset.h"
#include "hi_wifi_api.h"
#include <hi_time.h>

#define STA_DHCP_ENABLE  1
#define STA_DHCP_DISABLE 0
#define DEFAULT_BA_POLICY 1
#define DEFAULT_BA_BUFF_SIZE 64
#define DEFAULT_BA_TIMEOUT 0
#define DEFAULT_REASSOC_ENABLE 1
#define DEFAULT_REASSOC_TIMEOUT 60
#define SIGMA_STA_ASSOCIATE_TIMEOUT 60000

extern dutCmdResponse_t gGenericResp;
extern hi_wifi_assoc_request g_wpa_assoc_params;
extern struct hostapd_conf g_sigma_hapd_conf;
extern int use_hostapd;

extern caStaSetIpConfig_t g_ipconfig_param;
int g_ap_isorno_complete = -1;
char g_sigma_cmdstr[WFA_CMD_STR_SZ] = {0};

hi_wifi_softap_config g_ap_set_secu = {0};
extern unsigned int g_wait_sta_associate_sem;
hi_bool g_is_associate_by_sigma_flag = 0;
hi_bool g_dhcp_is_enable = 0;
extern void hi_wifi_hipriv(int argc, const unsigned char *argv[]);

/*
 * agtCmdProcGetVersion(): response "ca_get_version" command to controller
 *  input:  cmd --- not used
 *          valLen -- not used
 *  output: parms -- a buffer to store the version info response.
 */
int agtCmdProcGetVersion(int len, BYTE *parms, int *respLen, BYTE *respBuf)
{
    dutCmdResponse_t *getverResp = &gGenericResp;
    hi_unref_param(len);
    hi_unref_param(parms);

    DPRINT_INFO(WFA_OUT, "entering agtCmdProcGetVersion ...\n");
    getverResp->status = STATUS_COMPLETE;
    wSTRNCPY(getverResp->cmdru.version, WFA_SYSTEM_VER, WFA_VERNAM_LEN);

    wfaEncodeTLV(WFA_GET_VERSION_RESP_TLV, sizeof(dutCmdResponse_t), (BYTE *)getverResp, respBuf);

    *respLen = WFA_TLV_HDR_LEN + sizeof(dutCmdResponse_t);
    DPRINT_INFO(WFA_OUT, "respBuf addr6: %p\n", respBuf);
    DPRINT_INFO(WFA_OUT, "tlvtag:%d, tlvlen:%d, tlvstatus:%d\n", ((wfaTLV *)respBuf)->tag,
            ((wfaTLV *)respBuf)->len, ((dutCmdResponse_t *)(respBuf + 4))->status);

    return WFA_SUCCESS;
}

int wfaStaSetWireless(int len, BYTE *caCmdBuf, int *respLen, BYTE *respBuf)
{
    dutCmdResponse_t *staWirelessResp = &gGenericResp;
    hi_unref_param(len);
    hi_unref_param(caCmdBuf);

    staWirelessResp->status = STATUS_INVALID;

    wfaEncodeTLV(WFA_STA_SET_WIRELESS_RESP_TLV, 4, (BYTE *)staWirelessResp, respBuf);
    *respLen = WFA_TLV_HDR_LEN + 4;
    return WFA_SUCCESS;
}

/*
 * wfaStaAssociate():
 *    The function is to force the station wireless I/F to re/associate
 *    with the AP.
 */
int wfaStaAssociate(int len, BYTE *caCmdBuf, int *respLen, BYTE *respBuf)
{
    dutCommand_t *assoc = (dutCommand_t *)caCmdBuf;
    dutCmdResponse_t *staAssocResp = &gGenericResp;
    int ret = WFA_FAILURE;
    hi_unref_param(len);

    DPRINT_INFO(WFA_OUT, "entering wfaStaAssociate ...\n");

    if(assoc->cmdsu.assoc.wps == WFA_DISABLED){
        if(assoc->cmdsu.assoc.ssid[0] != '\0'){
            g_is_associate_by_sigma_flag = 1;

            memcpy_s(g_wpa_assoc_params.ssid, HI_WIFI_MAX_SSID_LEN + 1,
                 assoc->cmdsu.assoc.ssid, strlen(assoc->cmdsu.assoc.ssid) + 1);
            ret = sigma_wpa_connect(assoc->intf);
            if(ret != WFA_SUCCESS){
                DPRINT_WARNING(WFA_OUT, "sigma_wpa_connect fail\n");
                staAssocResp->status = STATUS_ERROR;
                wfaEncodeTLV(WFA_STA_ASSOCIATE_RESP_TLV, 4, (BYTE *)staAssocResp, respBuf);
                *respLen = WFA_TLV_HDR_LEN + 4;

                return WFA_SUCCESS;
            }

            hi_sem_wait(g_wait_sta_associate_sem, SIGMA_STA_ASSOCIATE_TIMEOUT);

            staAssocResp->status = STATUS_COMPLETE;
            wfaEncodeTLV(WFA_STA_ASSOCIATE_RESP_TLV, 4, (BYTE *)staAssocResp, respBuf);
            *respLen = WFA_TLV_HDR_LEN + 4;

            return WFA_SUCCESS;
        }
    }else{
        //todo: wps function
    }

    /*
     * Then report back to control PC for completion.
     * This does not have failed/error status. The result only tells
     * a completion.
     */
    staAssocResp->status = STATUS_COMPLETE;
    wfaEncodeTLV(WFA_STA_ASSOCIATE_RESP_TLV, 4, (BYTE *)staAssocResp, respBuf);
    *respLen = WFA_TLV_HDR_LEN + 4;

    return WFA_SUCCESS;
}


char g_ifconfig_msg[WFA_BUFF_512] = {0};
/*
 * wfaStaGetIpConfig():
 * This function is to retriev the ip info including
 *     1. dhcp enable
 *     2. ip address
 *     3. mask
 *     4. primary-dns
 *     5. secondary-dns
 *
 *     The current implementation is to use a script to find these information
 *     and store them in a file.
 */
int wfaStaGetIpConfig(int len, BYTE *caCmdBuf, int *respLen, BYTE *respBuf)
{
    int ret = 0;
    dutCmdResponse_t *ipconfigResp = &gGenericResp;
    hi_unref_param(len);
    hi_unref_param(caCmdBuf);
    caStaGetIpConfigResp_t *ifinfo = &ipconfigResp->cmdru.getIfconfig;

    char mask_str[SIGMA_IPADDR_GET_LEN] = {0};
    char ip_str[SIGMA_IPADDR_GET_LEN] = {0};
    char dns_pri[WFA_IP_ADDR_STR_LEN] = {0};
    char dns_sec[WFA_IP_ADDR_STR_LEN] = {0};

    if (g_dhcp_is_enable == 1) {
        if (sigma_start_dhcp("wlan0") != WFA_SUCCESS) {
            DPRINT_INFO(WFA_OUT, "wfaStaGetIpConfig sigma_start_dhcp fail...\n");
            return WFA_FAILURE;
        }
        ifinfo->isDhcp = 1;
        DPRINT_INFO(WFA_OUT, "wfaStaGetIpConfig delay.........\n");
        hi_udelay(6000000); /* 6000000 us */
    } else {
        ifinfo->isDhcp = 0;
    }

    ret = sigma_get_ipaddr(ip_str, SIGMA_IPADDR_GET_LEN, mask_str, SIGMA_IPADDR_GET_LEN);
    if(ret != WFA_SUCCESS){
        ipconfigResp->status = STATUS_ERROR;
        wfaEncodeTLV(WFA_STA_GET_IP_CONFIG_RESP_TLV, 4, (BYTE *)ipconfigResp, respBuf);
        *respLen = WFA_TLV_HDR_LEN + 4;
        DPRINT_ERR(WFA_ERR, "failed to execute ifconfig\n");
        return WFA_FAILURE;
    }

    if (strcpy_s(ifinfo->ipaddr, WFA_IP_ADDR_STR_LEN, ip_str) != EOK) {
        DPRINT_INFO(WFA_OUT, "wfaStaGetIpConfig :: strcpy_s is null\n");
        return WFA_FAILED;
    }
    if (strcpy_s(ifinfo->mask, WFA_IP_ADDR_STR_LEN, mask_str) != EOK) {
        DPRINT_INFO(WFA_OUT, "wfaStaGetIpConfig :: strcpy_s is null\n");
        return WFA_FAILED;
    }

    memset(&(ifinfo->dns), 0, sizeof(ifinfo->dns));
    ret = sigma_get_dns(dns_pri, WFA_IP_ADDR_STR_LEN, dns_sec, WFA_IP_ADDR_STR_LEN);
    if(ret != WFA_SUCCESS){
        ipconfigResp->status = STATUS_ERROR;
        wfaEncodeTLV(WFA_STA_GET_IP_CONFIG_RESP_TLV, 4, (BYTE *)ipconfigResp, respBuf);
        *respLen = WFA_TLV_HDR_LEN + 4;
        DPRINT_ERR(WFA_ERR, "failed to execute dns -a\n");
        return WFA_FAILURE;
    }

    if (strcpy_s(ifinfo->dns[0], WFA_IP_ADDR_STR_LEN, dns_pri) != EOK) {
        DPRINT_INFO(WFA_OUT, "wfaStaGetIpConfig :: strcpy_s is null\n");
        return WFA_FAILED;
    }

    if (strcpy_s(ifinfo->dns[1], WFA_IP_ADDR_STR_LEN, dns_sec) != EOK) {
        DPRINT_INFO(WFA_OUT, "wfaStaGetIpConfig :: strcpy_s is null\n");
        return WFA_FAILED;
    }

    /*
    * Report back the results
    */
    ipconfigResp->status = STATUS_COMPLETE;
    wfaEncodeTLV(WFA_STA_GET_IP_CONFIG_RESP_TLV, sizeof(dutCmdResponse_t), (BYTE *)ipconfigResp, respBuf);

    *respLen = WFA_TLV_HDR_LEN + sizeof(dutCmdResponse_t);
    return WFA_SUCCESS;
}


int wfaStaSetIpConfig(int len, BYTE *caCmdBuf, int *respLen, BYTE *respBuf)
{
    dutCommand_t *setIpConf = (dutCommand_t *)caCmdBuf;
    caStaSetIpConfig_t *ipconfig = &setIpConf->cmdsu.ipconfig;
    dutCmdResponse_t *staSetIpResp = &gGenericResp;
    hi_unref_param(len);

    DPRINT_INFO(WFA_OUT, "entering wfaStaSetIpConfig %s...\n", ipconfig->intf);

    if(ipconfig->isDhcp == STA_DHCP_ENABLE){
        g_dhcp_is_enable = 1;
    } else {
        memset_s(&g_ipconfig_param, sizeof(caStaSetIpConfig_t), 0, sizeof(caStaSetIpConfig_t));
        memcpy_s(&g_ipconfig_param, sizeof(caStaSetIpConfig_t), ipconfig, sizeof(caStaSetIpConfig_t));
        sigma_sta_set_ip();
    }
    /*
     * report status
     */
    staSetIpResp->status = STATUS_COMPLETE;
    wfaEncodeTLV(WFA_STA_SET_IP_CONFIG_RESP_TLV, 4, (BYTE *)staSetIpResp, respBuf);
    *respLen = WFA_TLV_HDR_LEN + 4;

    return WFA_SUCCESS;
}

int wfaStaIsConnected(int len, BYTE *caCmdBuf, int *respLen, BYTE *respBuf)
{
    dutCommand_t *connStat = (dutCommand_t *)caCmdBuf;
    dutCmdResponse_t *staConnectResp = &gGenericResp;
    char *ifname = connStat->intf;
    int ret = WFA_FAILURE;
    hi_unref_param(len);

    DPRINT_INFO(WFA_OUT, "Entering isConnected ...\n");

    ret = sigma_is_sta_connected(ifname);

    if(ret == WFA_SUCCESS){
        staConnectResp->cmdru.connected = 1;
        DPRINT_INFO(WFA_OUT, "wfaStaIsConnected connected = 1 ...\n");
    } else if (ret == WFA_ERROR) {
        staConnectResp->cmdru.connected = 0;
        DPRINT_INFO(WFA_OUT, "wfaStaIsConnected connected = 0 ...\n");
    }

    /*
    * Report back the status: Complete or Failed.
    */
    staConnectResp->status = STATUS_COMPLETE;

    wfaEncodeTLV(WFA_STA_IS_CONNECTED_RESP_TLV, sizeof(dutCmdResponse_t), (BYTE *)staConnectResp, respBuf);
    *respLen = WFA_TLV_HDR_LEN + sizeof(dutCmdResponse_t);

    return WFA_SUCCESS;
}

int wfaStaGetBSSID(int len, BYTE *caCmdBuf, int *respLen, BYTE *respBuf)
{
    unsigned char string[WFA_MAC_ADDR_STR_LEN] = {0};
    hi_unref_param(len);
    int ret = WFA_FAILURE;
    dutCommand_t *getBssid = (dutCommand_t *)caCmdBuf;
    dutCmdResponse_t *bssidResp = &gGenericResp;

    DPRINT_INFO(WFA_OUT, "Entering wfaStaGetBSSID ...\n");

    ret = sigma_get_bssid(string, WFA_MAC_ADDR_STR_LEN, getBssid->intf);
    if(ret == WFA_ERROR){
        bssidResp->status = STATUS_ERROR;

        wfaEncodeTLV(WFA_STA_GET_BSSID_RESP_TLV, 4, (BYTE *)bssidResp, respBuf);
        *respLen = WFA_TLV_HDR_LEN + 4;

        return WFA_FAILURE;
    }

    if (memcpy_s(bssidResp->cmdru.bssid, WFA_MAC_ADDR_STR_LEN, string, WFA_MAC_ADDR_STR_LEN) != EOK) {
        DPRINT_INFO(WFA_OUT, "wfaStaGetBSSID :: memcpy_s is null\n");
        return WFA_FAILED;
    }
    bssidResp->status = STATUS_COMPLETE;
    wfaEncodeTLV(WFA_STA_GET_BSSID_RESP_TLV, sizeof(dutCmdResponse_t), (BYTE *)bssidResp, respBuf);
    *respLen = WFA_TLV_HDR_LEN + sizeof(dutCmdResponse_t);

    return WFA_SUCCESS;
}

int wfaStaGetInfo(int len, BYTE *caCmdBuf, int *respLen, BYTE *respBuf)
{
    dutCmdResponse_t infoResp;
    dutCommand_t *getInfo = (dutCommand_t *)caCmdBuf;
    hi_unref_param(len);
    /*
     * Normally this is called to retrieve the vendor information
     * from a interface, no implement yet
     */
    sprintf(infoResp.cmdru.info, "interface,%s,vendor,XXX,cardtype,802.11b/g/n", getInfo->intf);

    infoResp.status = STATUS_COMPLETE;
    wfaEncodeTLV(WFA_STA_GET_INFO_RESP_TLV, sizeof(infoResp), (BYTE *)&infoResp, respBuf);
    *respLen = WFA_TLV_HDR_LEN + sizeof(infoResp);

    return WFA_SUCCESS;
}

int wfaDeviceGetInfo(int len, BYTE *caCmdBuf, int *respLen, BYTE *respBuf)
{
    dutCmdResponse_t *infoResp = &gGenericResp;
    hi_unref_param(len);
    hi_unref_param(caCmdBuf);

    /*a vendor can fill in the proper info or anything non-disclosure */
    caDeviceGetInfoResp_t dinfo = {"MyVendor", "DutModel", WFA_SYSTEM_VER, "Firmware,1.0"};

    DPRINT_INFO(WFA_OUT, "Entering wfaDeviceGetInfo ...\n");

    memcpy(&infoResp->cmdru.devInfo, &dinfo, sizeof(caDeviceGetInfoResp_t));

    infoResp->status = STATUS_COMPLETE;
    wfaEncodeTLV(WFA_DEVICE_GET_INFO_RESP_TLV, sizeof(dutCmdResponse_t), (BYTE *)infoResp, respBuf);
    *respLen = WFA_TLV_HDR_LEN + sizeof(dutCmdResponse_t);

    return WFA_SUCCESS;
}

/*
 *  wfaSetMode():
 *  The function is to set the wireless interface with a given mode (possible
 *  adhoc)
 *  Input parameters:
 *    1. I/F
 *    2. ssid
 *    3. mode adhoc or managed
 *    4. encType
 *    5. channel
 *    6. key(s)
 *    7. active  key
 */
int wfaStaSetMode(int len, BYTE *caCmdBuf, int *respLen, BYTE *respBuf)
{
    caStaSetMode_t *setmode = (caStaSetMode_t *)caCmdBuf;
    dutCmdResponse_t *SetModeResp = &gGenericResp;
    int i;
    unsigned int count = 0;
    hi_unref_param(len);
    /*
     * re-create the interface with the given mode
     */
    if(setmode->mode == 1){
        DPRINT_ERR(WFA_ERR, "adhoc mode is not supported yet!\n");
        SetModeResp->status = STATUS_ERROR;
        wfaEncodeTLV(WFA_STA_SET_MODE_RESP_TLV, 4, (BYTE *)SetModeResp, respBuf);
        *respLen = WFA_TLV_HDR_LEN + 4;

        return WFA_FAILURE;
    }

    if(setmode->encpType == ENCRYPT_WEP){
        g_wpa_assoc_params.auth = HI_WIFI_SECURITY_WEP;
        for(i=0; i<4; i++){
           if(setmode->keys[i][0] != '\0'){
                count++;
           }
        }

        if(count == 0){
           DPRINT_ERR(WFA_OUT, "unvalid key value received from UCC!\n");
           SetModeResp->status = STATUS_INVALID;
           wfaEncodeTLV(WFA_STA_SET_MODE_RESP_TLV, 4, (BYTE *)SetModeResp, respBuf);
           *respLen = WFA_TLV_HDR_LEN + 4;

           return WFA_FAILURE;
        }else if(count == 1){
            for(i=0; i<4; i++){
                if(setmode->keys[i][0] != '\0'){
                    break;
                }
            }
            memcpy_s(g_wpa_assoc_params.key, HI_WIFI_MAX_KEY_LEN + 1,
                 setmode->keys[i], strlen(setmode->keys[i]) + 1);
        }else{
            /* set active key */
            i = setmode->activeKeyIdx;
            if(setmode->keys[i][0] != '\0'){
                memcpy_s(g_wpa_assoc_params.key, HI_WIFI_MAX_KEY_LEN + 1,
                     setmode->keys[i], strlen(setmode->keys[i]) + 1);
            }else{
                DPRINT_ERR(WFA_ERR, "The key specified by activeKeyIdx is NULL\n");
                SetModeResp->status = STATUS_INVALID;
                wfaEncodeTLV(WFA_STA_SET_MODE_RESP_TLV, 4, (BYTE *)SetModeResp, respBuf);
                *respLen = WFA_TLV_HDR_LEN + 4;

                return WFA_FAILURE;
            }
        }
     }else{
         g_wpa_assoc_params.auth = HI_WIFI_SECURITY_OPEN;
     }

    /*
        * set SSID
        */
    if(setmode->ssid[0] != '\0'){
        memcpy_s(g_wpa_assoc_params.ssid, HI_WIFI_MAX_SSID_LEN + 1,
             setmode->ssid, strlen(setmode->ssid) + 1);
    }

    SetModeResp->status = STATUS_COMPLETE;
    wfaEncodeTLV(WFA_STA_SET_MODE_RESP_TLV, 4, (BYTE *)SetModeResp, respBuf);
    *respLen = WFA_TLV_HDR_LEN + 4;

    return WFA_SUCCESS;

}

int wfaStaReAssociate(int len, BYTE *caCmdBuf, int *respLen, BYTE *respBuf)
{
    dutCommand_t *assoc = (dutCommand_t *)caCmdBuf;
    char *ifname = assoc->intf;
    dutCmdResponse_t *staAssocResp = &gGenericResp;
    int ret = WFA_FAILURE;
    int auto_reconnect_enable = DEFAULT_REASSOC_ENABLE;
    int auto_reconnect_timeout = DEFAULT_REASSOC_TIMEOUT;
    hi_unref_param(len);

    struct netif *reasso_netif = NULL;
    DPRINT_INFO(WFA_OUT, "entering wfaStaReAssociate ...\n");
    /*
     * if bssid appears, station should associate with the specific
     * BSSID AP at its initial association.
     * If it is different to the current associating AP, it will be forced to
     * roam the new AP
     */
    if(assoc->cmdsu.assoc.bssid[0] != '\0')
    {
        /* if (the first association) */
        /* just do initial association to the BSSID */
        if(sigma_is_sta_connected(ifname) != WFA_SUCCESS){

            if(assoc->cmdsu.assoc.bssid[0] != '\0'){
                memcpy_s(g_wpa_assoc_params.bssid, HI_WIFI_TXT_ADDR_LEN + 1,
                     assoc->cmdsu.assoc.bssid, strlen(assoc->cmdsu.assoc.bssid));
            }

            if(assoc->cmdsu.assoc.ssid[0] != '\0'){
                memcpy_s(g_wpa_assoc_params.ssid, HI_WIFI_TXT_ADDR_LEN + 1,
                     assoc->cmdsu.assoc.ssid, strlen(assoc->cmdsu.assoc.ssid) + 1);
            }

            ret = sigma_wpa_connect(ifname);
            if(ret != WFA_SUCCESS){
                staAssocResp->status = STATUS_ERROR;

                wfaEncodeTLV(WFA_STA_REASSOCIATE_RESP_TLV, 4, (BYTE *)staAssocResp, respBuf);
                *respLen = WFA_TLV_HDR_LEN + 4;

                return WFA_FAILURE;
            }

            hi_sem_wait(g_wait_sta_associate_sem, HI_SYS_WAIT_FOREVER);
        }else{
            hi_wifi_sta_set_reconnect_policy(auto_reconnect_enable, auto_reconnect_timeout, DEFAULT_REASSOC_TIMEOUT, 1);
        }
    }
    else
    {
        reasso_netif = netifapi_netif_find(ifname);
        /*
              * ¨a?ifconfig down
              */
        netifapi_netif_set_down(reasso_netif);
        netifapi_netif_set_link_down(reasso_netif);
        /*
              * ¨a?ifconfig up
              */
        netifapi_netif_set_link_up(reasso_netif);
        netifapi_netif_set_up(reasso_netif);

        ret = sigma_wpa_connect(ifname);
        if(ret != WFA_SUCCESS){
            staAssocResp->status = STATUS_ERROR;

            wfaEncodeTLV(WFA_STA_REASSOCIATE_RESP_TLV, 4, (BYTE *)staAssocResp, respBuf);
            *respLen = WFA_TLV_HDR_LEN + 4;

            return WFA_FAILURE;
        }

        hi_sem_wait(g_wait_sta_associate_sem, HI_SYS_WAIT_FOREVER);
    }

     /*
      * Then report back to control PC for completion.
      * This does not have failed/error status. The result only tells
      * a completion.
      */
     staAssocResp->status = STATUS_COMPLETE;
     wfaEncodeTLV(WFA_STA_REASSOCIATE_RESP_TLV, 4, (BYTE *)staAssocResp, respBuf);
     *respLen = WFA_TLV_HDR_LEN + 4;
     return WFA_SUCCESS;
}

int wfaStaSendADDBA(int len, BYTE *caCmdBuf, int *respLen, BYTE *respBuf)
{
    caStaSetSendADDBA_t *staSendADDBA = (caStaSetSendADDBA_t *)caCmdBuf;
    dutCmdResponse_t *staSendADDBAResp = &gGenericResp;
    hi_unref_param(len);
    char set_para[4][2] = {0}; /* 4行2列二维数组 */

    if (staSendADDBA->intf[0] != '\0' && staSendADDBA->tid != 0xFFFF && staSendADDBA->destMac[0] != '\0') {

        sprintf(set_para[0], "%d", staSendADDBA->tid);
        sprintf(set_para[1], "%d", DEFAULT_BA_POLICY);
        sprintf(set_para[2], "%d", DEFAULT_BA_BUFF_SIZE);  /* 2: 元素行数 */
        sprintf(set_para[3], "%d", DEFAULT_BA_TIMEOUT);    /* 3 : 元素行数 */

        printf("%s\n", set_para[0]);
        printf("%s\n", set_para[1]);
        printf("%s\n", set_para[2]); /* 2 : 元素行数 */
        printf("%s\n", set_para[3]); /* 3 : 元素行数 */

        char* addba_req_cmd[] = {staSendADDBA->intf, "addba_req", staSendADDBA->destMac, set_para[0], set_para[1],
            set_para[2], set_para[3]}; /* 2、3 : 元素行数 */
        (void)hi_wifi_hipriv(7, (const unsigned char**)addba_req_cmd);  /* 配置addba_req 7: 入参参数个数 */

    }else{
        DPRINT_ERR(WFA_ERR, "Invalid ADDBA command!\n");
        staSendADDBAResp->status = STATUS_INVALID;

        wfaEncodeTLV(WFA_STA_SET_SEND_ADDBA_RESP_TLV, 4, (BYTE *)staSendADDBAResp, respBuf);
        *respLen = WFA_TLV_HDR_LEN + 4;
        return WFA_FAILURE;
    }

    staSendADDBAResp->status = STATUS_COMPLETE;

    wfaEncodeTLV(WFA_STA_SET_SEND_ADDBA_RESP_TLV, 4, (BYTE *)staSendADDBAResp, respBuf);
    *respLen = WFA_TLV_HDR_LEN + 4;
    return WFA_SUCCESS;

}

int wfaStaResetDefault(int len, BYTE *caCmdBuf, int *respLen, BYTE *respBuf)
{
    caStaResetDefault_t *reset = (caStaResetDefault_t *)caCmdBuf;
    dutCmdResponse_t *ResetResp = &gGenericResp;
    int ret = WFA_FAILURE;
    hi_unref_param(len);
    DPRINT_INFO(WFA_OUT, "Entering wfaStaResetDefault ...\n");

    if(reset->prog[0] != '\0'){
        if(strcasecmp(reset->prog, "PMF") == 0){
            sigma_wpa_stop();
            ret = hi_wifi_set_pmf(HI_WIFI_MGMT_FRAME_PROTECTION_CLOSE);
            if(ret != WFA_SUCCESS){
                DPRINT_ERR(WFA_ERR, "failed to set pmf!\n");
                ResetResp->status = STATUS_ERROR;
            }

            sigma_wpa_start("11n");
        }else{
            DPRINT_ERR(WFA_ERR, "invalid prog!\n");
            ResetResp->status = STATUS_ERROR;
        }
    }

    ResetResp->status = STATUS_COMPLETE;
    wfaEncodeTLV(WFA_STA_RESET_DEFAULT_RESP_TLV, 4, (BYTE *)ResetResp, respBuf);
    *respLen = WFA_TLV_HDR_LEN + 4;

    return WFA_SUCCESS;
}

int wfaStaDisconnect(int len, BYTE *caCmdBuf, int *respLen, BYTE *respBuf)
{
    hi_unref_param(len);
    hi_unref_param(caCmdBuf);
    dutCmdResponse_t *staDiscResp = &gGenericResp;

    DPRINT_INFO(WFA_OUT, "Entering wfaStaDisconnect ...\n");

    sigma_wpa_disconnect();

    staDiscResp->status = STATUS_COMPLETE;

    wfaEncodeTLV(WFA_STA_DISCONNECT_RESP_TLV, 4, (BYTE *)staDiscResp, respBuf);
    *respLen = WFA_TLV_HDR_LEN + 4;

    return WFA_SUCCESS;
}


/* Supporting Functions */
void wfaSendPing(tgPingStart_t *staPing, int *interval, int streamid)
{
    int totalpkts;

    totalpkts = (int)(staPing->duration * staPing->frameRate);

    printf("CS : The Stream ID is %d\n",streamid);
    printf("IPtype : %i\n",staPing->iptype);

    if (staPing->iptype == 2)
    {
        printf("ping ipv6 is not supported yet!\n");
    }
    else
    {
        sigma_send_ping(staPing, *interval, totalpkts);
    }
}

int wfaStopPing(dutCmdResponse_t *stpResp, int streamid)
{
    sigma_stop_ping(stpResp);
    hi_unref_param(streamid);
    printf("after scan sent count %i\n", stpResp->cmdru.pingStp.sendCnt);
    printf("after scan replied count %i\n", stpResp->cmdru.pingStp.repliedCnt);

    return WFA_SUCCESS;
}

/*
 *  Since WEP is optional, this function could be used to replace
 *  wfaSetEncryption() if necessary.
 */
int wfaSetEncryption(int len, BYTE *caCmdBuf, int *respLen, BYTE *respBuf)
{
    hi_unref_param(len);
    caStaSetEncryption_t *setEncryp = (caStaSetEncryption_t *)caCmdBuf;
    dutCmdResponse_t *setEncrypResp = &gGenericResp;
    int i;
    unsigned int count = 0;

    /*
       * set SSID
       */
    memcpy_s(g_wpa_assoc_params.ssid, HI_WIFI_MAX_SSID_LEN + 1,
         setEncryp->ssid, strlen(setEncryp->ssid) + 1);

    /*
       * set encryption cipher and active key
       */
    if(setEncryp->encpType == 1){
       g_wpa_assoc_params.auth = HI_WIFI_SECURITY_WEP;
       for(i=0; i<4; i++){
          if(setEncryp->keys[i][0] != '\0'){
               count++;
          }
       }

       if(count == 0){
           DPRINT_ERR(WFA_OUT, "unvalid key value received from UCC!\n");
           setEncrypResp->status = STATUS_ERROR;
           wfaEncodeTLV(WFA_STA_SET_ENCRYPTION_RESP_TLV, 4, (BYTE *)setEncrypResp, respBuf);
           *respLen = WFA_TLV_HDR_LEN + 4;

           return WFA_SUCCESS;
       }else if(count == 1){
           for(i=0; i<4; i++){
               if(setEncryp->keys[i][0] != '\0'){
                   break;
               }
           }
           memcpy_s(g_wpa_assoc_params.key, HI_WIFI_MAX_KEY_LEN + 1,
                setEncryp->keys[i], strlen(setEncryp->keys[i]) + 1);
       }else{
           /* set active key */
           i = setEncryp->activeKeyIdx;
           if(setEncryp->keys[i][0] != '\0'){
               memcpy_s(g_wpa_assoc_params.key, HI_WIFI_MAX_KEY_LEN + 1,
                    setEncryp->keys[i], strlen(setEncryp->keys[i]) + 1);
           }else{
               DPRINT_ERR(WFA_ERR, "The key specified by activeKeyIdx is NULL\n");
               setEncrypResp->status = STATUS_ERROR;
               wfaEncodeTLV(WFA_STA_SET_ENCRYPTION_RESP_TLV, 4, (BYTE *)setEncrypResp, respBuf);
               *respLen = WFA_TLV_HDR_LEN + 4;

               return WFA_SUCCESS;
           }
       }
    }else{
        g_wpa_assoc_params.auth = HI_WIFI_SECURITY_OPEN;
    }

    setEncrypResp->status = STATUS_COMPLETE;
    wfaEncodeTLV(WFA_STA_SET_ENCRYPTION_RESP_TLV, 4, (BYTE *)setEncrypResp, respBuf);
    *respLen = WFA_TLV_HDR_LEN + 4;

     return WFA_SUCCESS;
 }

/*
 * The function is to set
 *   1. ssid
 *   2. passPhrase
 *   3. keyMangementType - wpa/wpa2
 *   4. encrypType - tkip or aes-ccmp
 */
int wfaStaSetPSK(int len, BYTE *caCmdBuf, int *respLen, BYTE *respBuf)
{
    hi_unref_param(len);
    caStaSetPSK_t *setPSK = (caStaSetPSK_t *)caCmdBuf;
    dutCmdResponse_t *setPskResp = &gGenericResp;
    hi_wifi_auth_mode current_pmf = WFA_DISABLED;
    /*
       * set SSID
       */
    if(setPSK->ssid[0] != '\0'){
        memcpy_s(g_wpa_assoc_params.ssid, HI_WIFI_MAX_SSID_LEN + 1,
             setPSK->ssid, strlen(setPSK->ssid) + 1);
    }

    /*
       * set key
       */
    if(setPSK->passphrase[0] != '\0'){
        memcpy_s(g_wpa_assoc_params.key, HI_WIFI_MAX_KEY_LEN + 1,
         setPSK->passphrase, strlen(setPSK->passphrase) + 1);
    }

    /*
       * set Key Management type
       */
    if((strcasecmp(setPSK->keyMgmtType, "wpa2") == 0) ||
        (strcasecmp(setPSK->keyMgmtType, "wpa2-psk") == 0)){
        g_wpa_assoc_params.auth = HI_WIFI_SECURITY_WPA2PSK;
    }else if ((strcasecmp(setPSK->keyMgmtType, "wpa2-wpa-psk") == 0) ||
        (strcasecmp(setPSK->keyMgmtType, "wpa2-wpa") == 0)){
        g_wpa_assoc_params.auth = HI_WIFI_SECURITY_WPAPSK_WPA2PSK_MIX;
    }else{
        DPRINT_ERR(WFA_ERR,"invalid Key Management type!\n");
        setPskResp->status = STATUS_ERROR;
        wfaEncodeTLV(WFA_STA_SET_PSK_RESP_TLV, 4, (BYTE *)setPskResp, respBuf);
        *respLen = WFA_TLV_HDR_LEN + 4;
        return WFA_SUCCESS;
    }


    if(setPSK->encpType == ENCRYPT_TKIP){
        g_wpa_assoc_params.pairwise = HI_WIFI_PAIRWISE_TKIP;
    }else if(setPSK->encpType == ENCRYPT_AESCCMP) {
        g_wpa_assoc_params.pairwise = HI_WIFI_PAIRWISE_AES;
    }else{
    }


    /*
       * set PMF
       */
    if((setPSK->pmf != WFA_INVALID_BOOL) && (setPSK->pmf < WFA_F_REQUIRED)){
        current_pmf = hi_wifi_get_pmf();
        DPRINT_INFO(WFA_OUT,"pmf -%d-\n", current_pmf);
        if(current_pmf != setPSK->pmf){
            sigma_wpa_stop();
            hi_wifi_set_pmf(setPSK->pmf);
            sigma_wpa_start("11n");
        }
        sigma_sta_set_ip();
    }

    /*
       * set MIC Algorithm
       */
    if(setPSK->micAlg[0] != '\0'){
        if(strcasecmp(setPSK->micAlg, "SHA-1") == 0){
        }else if(strcasecmp(setPSK->micAlg, "SHA-256") == 0){
            DPRINT_WARNING(WFA_OUT,"SHA-256 has not been supported yet!\n");
        }else{
            DPRINT_WARNING(WFA_OUT,"invalid micAlg arguments!\n");
        }
    }

    if(setPSK->prog[0] != '\0'){
        DPRINT_ERR(WFA_ERR,"prog is not supported!\n");
        setPskResp->status = STATUS_ERROR;
    }

    setPskResp->status = STATUS_COMPLETE;
    wfaEncodeTLV(WFA_STA_SET_PSK_RESP_TLV, 4, (BYTE *)setPskResp, respBuf);
    *respLen = WFA_TLV_HDR_LEN + 4;

    return WFA_SUCCESS;
}

/*
 * wfaStaGetMacAddress()
 *    This function is to retrieve the MAC address of a wireless I/F.
 */
int wfaStaGetMacAddress(int len, BYTE *caCmdBuf, int *respLen, BYTE *respBuf)
{
    dutCmdResponse_t *getmacResp = &gGenericResp;
    char mac_str[WFA_MAC_ADDR_STR_LEN] = {0};
    int ret = WFA_FAILURE;
    hi_unref_param(len);
    hi_unref_param(caCmdBuf);

    ret = sigma_get_macaddr(mac_str, WFA_MAC_ADDR_STR_LEN);
    if(ret != WFA_SUCCESS){

        DPRINT_ERR(WFA_ERR, "failed to execute ifconfig\n");

        getmacResp->status = STATUS_ERROR;
        wfaEncodeTLV(WFA_STA_GET_MAC_ADDRESS_RESP_TLV, 4, (BYTE *)getmacResp, respBuf);
        *respLen = WFA_TLV_HDR_LEN + 4;
        return WFA_SUCCESS;
    }

    if (memcpy_s(getmacResp->cmdru.mac, WFA_MAC_ADDR_STR_LEN, mac_str, WFA_MAC_ADDR_STR_LEN) != EOK) {
        DPRINT_INFO(WFA_OUT, "sigma_get_ipaddr :: memcpy_s is null\n");
        return WFA_FAILED;
    }
    DPRINT_INFO(WFA_OUT, MACSTR, mac2str(getmacResp->cmdru.mac));

    getmacResp->status = STATUS_COMPLETE;
    wfaEncodeTLV(WFA_STA_GET_MAC_ADDRESS_RESP_TLV, sizeof(dutCmdResponse_t), (BYTE *)getmacResp, respBuf);
    *respLen = WFA_TLV_HDR_LEN + sizeof(dutCmdResponse_t);

    return WFA_SUCCESS;
}

/*
 * This is used to set a temporary MAC address of an interface
 */
int wfaStaSetMacAddr(int len, BYTE *caCmdBuf, int *respLen, BYTE *respBuf)
{
    int ret = WFA_FAILURE;
    hi_unref_param(len);
    dutCommand_t *cmd = (dutCommand_t *)caCmdBuf;
    dutCmdResponse_t *staCmdResp = &gGenericResp;

    ret = sigma_set_macaddr(cmd->cmdsu.macaddr);
    if(ret != WFA_SUCCESS){
        DPRINT_ERR(WFA_ERR, "sigma set macaddr fail!\n");
    }

    staCmdResp->status = STATUS_COMPLETE;

    wfaEncodeTLV(WFA_STA_SET_MAC_ADDRESS_RESP_TLV, 4, (BYTE *)staCmdResp, respBuf);
    *respLen = WFA_TLV_HDR_LEN + 4;

    return WFA_SUCCESS;
}

/*
 * This funciton is to retrieve a list of interfaces and return
 * the list back to Agent control.
 * ********************************************************************
 * Note: We intend to make this WLAN interface name as a hardcode name.
 * Therefore, for a particular device, you should know and change the name
 * for that device while doing porting. The MACRO "WFA_STAUT_IF" is defined in
 * the file "inc/wfa_ca.h". If the device OS is not linux-like, this most
 * likely is hardcoded just for CAPI command responses.
 * *******************************************************************
 *
 */
int wfaDeviceListIF(int len, BYTE *caCmdBuf, int *respLen, BYTE *respBuf)
{
   dutCmdResponse_t *infoResp = &gGenericResp;
   dutCommand_t *ifList = (dutCommand_t *)caCmdBuf;
   caDeviceListIFResp_t *ifListResp = &infoResp->cmdru.ifList;
   hi_unref_param(len);
   DPRINT_INFO(WFA_OUT, "Entering wfaDeviceListIF ...\n");

   switch(ifList->cmdsu.iftype)
   {
      case IF_80211:
      infoResp->status = STATUS_COMPLETE;
      ifListResp->iftype = IF_80211;
      strcpy(ifListResp->ifs[0], WFA_STAUT_IF);
      strcpy(ifListResp->ifs[1], "NULL");
      strcpy(ifListResp->ifs[2], "NULL");
      break;
      case IF_ETH:
      infoResp->status = STATUS_COMPLETE;
      ifListResp->iftype = IF_ETH;
      strcpy(ifListResp->ifs[0], "eth0");
      strcpy(ifListResp->ifs[1], "NULL");
      strcpy(ifListResp->ifs[2], "NULL");
      break;
      default:
      {
         infoResp->status = STATUS_ERROR;
         wfaEncodeTLV(WFA_DEVICE_LIST_IF_RESP_TLV, 4, (BYTE *)infoResp, respBuf);
         *respLen = WFA_TLV_HDR_LEN + 4;

         return WFA_SUCCESS;
      }
   }

   wfaEncodeTLV(WFA_DEVICE_LIST_IF_RESP_TLV, sizeof(dutCmdResponse_t), (BYTE *)infoResp, respBuf);
   *respLen = WFA_TLV_HDR_LEN + sizeof(dutCmdResponse_t);

   return WFA_SUCCESS;
}

int wfaStaSet11n(int len, BYTE *caCmdBuf, int *respLen, BYTE *respBuf)
{
    dutCmdResponse_t infoResp;
    dutCmdResponse_t *v11nParamsResp = &infoResp;
    hi_unref_param(len);
    caSta11n_t * v11nParams = (caSta11n_t *)caCmdBuf;

    DPRINT_INFO(WFA_OUT, "Inside wfaStaSet11n function....\n");

    if(v11nParams->addba_reject != 0xFF && v11nParams->addba_reject < 2)
    {
        if(v11nParams->addba_reject == WFA_ENABLED){
            DPRINT_INFO(WFA_OUT, "set_addba_reject disable is not supported\n");
            v11nParamsResp->status = STATUS_ERROR;

        }

    }

    if(v11nParams->ampdu != 0xFF && v11nParams->ampdu < 2)
    {
        /* 规则6.6：禁止使用内存操作类危险函数 例外(1)对固定长度的数组进行初始化 */
        memset(g_sigma_cmdstr, 0, sizeof(g_sigma_cmdstr));
        sprintf(g_sigma_cmdstr, "%d", v11nParams->ampdu);

        char* ampdu_tx_on_cmd[] = {v11nParams->intf, "ampdu_tx_on", g_sigma_cmdstr};
        (void)hi_wifi_hipriv(3, (const unsigned char**)ampdu_tx_on_cmd);  /* 设置ampdu_tx_on  3: 入参参数个数 */
        DPRINT_INFO(WFA_OUT, "g_sigma_cmdstr :: %s\n", g_sigma_cmdstr);
    }

    if(v11nParams->amsdu != 0xFF && v11nParams->amsdu < 2)
    {
        /* 规则6.6：禁止使用内存操作类危险函数 例外(1)对固定长度的数组进行初始化 */
        memset(g_sigma_cmdstr, 0, sizeof(g_sigma_cmdstr));
        sprintf(g_sigma_cmdstr, "%d", v11nParams->amsdu);
        DPRINT_INFO(WFA_OUT, "g_sigma_cmdstr :: %s\n", g_sigma_cmdstr);

        if (v11nParams->amsdu == 1) { /* 开启时需要配置tid和max_num 关闭时这两个参数无意义 */
            char* amsdu_tx_on_cmd[] = {v11nParams->intf, "amsdu_tx_on", g_sigma_cmdstr, "0", "8"};
            (void)hi_wifi_hipriv(5, (const unsigned char**)amsdu_tx_on_cmd);  /* 设置amsdu_tx_on  5: 入参参数个数 */

        } else if (v11nParams->amsdu == 0) { /* 关闭时不需要配置tid和max_num */
            char* amsdu_tx_on_cmd[] = {v11nParams->intf, "amsdu_tx_on", g_sigma_cmdstr};
            (void)hi_wifi_hipriv(3, (const unsigned char**)amsdu_tx_on_cmd);  /* 设置amsdu_tx_on  3: 入参参数个数 */
        }
    }

    if(v11nParams->greenfield != 0xFF && v11nParams->greenfield < 2)
    {
        if(v11nParams->greenfield == WFA_ENABLED){
            DPRINT_ERR(WFA_ERR, "set_greenfield is not supported\n");
            v11nParamsResp->status = STATUS_ERROR;

        }
    }

    if(v11nParams->mcs32 != 0xFF)
    {
        if(v11nParams->mcs32 == WFA_ENABLED)
        {
            DPRINT_ERR(WFA_ERR, "mcs32 is not supported\n");
            v11nParamsResp->status = STATUS_ERROR;

        }
    }

    if (v11nParams->mcs_fixedrate[0] != '\0')
    {
        /* 规则6.6：禁止使用内存操作类危险函数 例外(1)对固定长度的数组进行初始化 */
        memset(g_sigma_cmdstr, 0, sizeof(g_sigma_cmdstr));
        sprintf(g_sigma_cmdstr, "%s", v11nParams->mcs_fixedrate); /* Valid values are:0-31 */

        char* set_mcs_cmd[] = {v11nParams->intf, "mcs", g_sigma_cmdstr};
        (void)hi_wifi_hipriv(3, (const unsigned char**)set_mcs_cmd);  /* 设置set_mcs  3: 入参参数个数 */
        DPRINT_INFO(WFA_OUT, "g_sigma_cmdstr :: %s\n", g_sigma_cmdstr);
    }

    if(v11nParams->rifs_test != 0xFF && v11nParams->rifs_test < 2)
    {
        if(v11nParams->rifs_test == WFA_ENABLED)
        {
            DPRINT_ERR(WFA_ERR, "set_rifs_test is not supported\n");
            v11nParamsResp->status = STATUS_ERROR;

        }
    }

    if(v11nParams->sgi20 != 0xFF && v11nParams->sgi20 < 2)
    {
        /* 规则6.6：禁止使用内存操作类危险函数 例外(1)对固定长度的数组进行初始化 */
        memset(g_sigma_cmdstr, 0, sizeof(g_sigma_cmdstr));
        sprintf(g_sigma_cmdstr, "%d", v11nParams->sgi20);

        char* set_shortgi20_cmd[] = {v11nParams->intf, "set_shortgi20", g_sigma_cmdstr};
        (void)hi_wifi_hipriv(3, (const unsigned char**)set_shortgi20_cmd);  /* 设置shortgi20  3: 入参参数个数 */
        DPRINT_INFO(WFA_OUT, "g_sigma_cmdstr :: %s\n", g_sigma_cmdstr);
    }

    if(v11nParams->smps != 0xFFFF)
    {
        DPRINT_ERR(WFA_ERR, "set_smps is not supported\n");
        v11nParamsResp->status = STATUS_ERROR;
    }

    if(v11nParams->stbc_rx != 0xFFFF)
    {
        if(v11nParams->stbc_rx != 1){
            DPRINT_ERR(WFA_ERR, "set_stbc_rx only support 1 stream\n");
            v11nParamsResp->status = STATUS_ERROR;

        }
        /* 规则6.6：禁止使用内存操作类危险函数 例外(1)对固定长度的数组进行初始化 */
        memset(g_sigma_cmdstr, 0, sizeof(g_sigma_cmdstr));
        sprintf(g_sigma_cmdstr, "%d", v11nParams->stbc_rx);

        char* sta_stbc_cmd[] = {v11nParams->intf, "set_stbc_cap", g_sigma_cmdstr};
        (void)hi_wifi_hipriv(3, (const unsigned char**)sta_stbc_cmd);  /* 设置stbc  3: 入参参数个数 */
        DPRINT_INFO(WFA_OUT, "g_sigma_cmdstr :: %s\n", g_sigma_cmdstr);
    }

    if(v11nParams->width[0] != '\0')
    {
        if(strcasecmp(v11nParams->width, "20") != 0){
            DPRINT_ERR(WFA_ERR, "set_11n_channel_width only fixed in 20Mhz!\n");
            v11nParamsResp->status = STATUS_ERROR;
        }
    }

    if(v11nParams->_40_intolerant != 0xFF && v11nParams->_40_intolerant < 2)
    {
        if(v11nParams->_40_intolerant == WFA_ENABLED){
            v11nParamsResp->status = STATUS_ERROR;
            DPRINT_ERR(WFA_ERR, "set_40_intolerant is not supported!\n");

        }
    }

    if(v11nParams->txsp_stream != 0 && v11nParams->txsp_stream <4)
    {
        if(v11nParams->txsp_stream != 1){
            DPRINT_ERR(WFA_ERR, "set_txsp_stream is fixed in 1 stream!\n");
            v11nParamsResp->status = STATUS_ERROR;
        }
    }

    if(v11nParams->rxsp_stream != 0 && v11nParams->rxsp_stream < 4)
    {
        if(v11nParams->rxsp_stream != 1){
            DPRINT_ERR(WFA_ERR, "set_rxsp_stream is fixed in 1 stream!\n");
            v11nParamsResp->status = STATUS_ERROR;
        }
    }

    v11nParamsResp->status = STATUS_COMPLETE;
    wfaEncodeTLV(WFA_STA_SET_11N_RESP_TLV, 4, (BYTE *)v11nParamsResp, respBuf);
    *respLen = WFA_TLV_HDR_LEN + 4;
    return WFA_SUCCESS;
}


int wfaStaPresetParams(int len, BYTE *caCmdBuf, int *respLen, BYTE *respBuf)
{
   dutCmdResponse_t *PresetParamsResp = &gGenericResp;
   caStaPresetParameters_t *presetParams = (caStaPresetParameters_t *)caCmdBuf;
   hi_unref_param(len);
   BYTE presetDone = 1;

   DPRINT_INFO(WFA_OUT, "Inside wfaStaPresetParameters function ...\n");

   if (presetParams->supplicant == eWpaSupplicant){
        presetDone = 1;
   }

   if (presetDone){
      PresetParamsResp->status = STATUS_COMPLETE;
   }
   else{
      PresetParamsResp->status = STATUS_INVALID;
   }

   wfaEncodeTLV(WFA_STA_PRESET_PARAMETERS_RESP_TLV, 4, (BYTE *)PresetParamsResp, respBuf);
   *respLen = WFA_TLV_HDR_LEN + 4;

   return WFA_SUCCESS;
}

int wfaApSetWireless(int len, BYTE *caCmdBuf, int *respLen, BYTE *respBuf)
{
    int ret = WFA_FAILURE;
    hi_unref_param(len);
    caApSetWireless_t *cmd = (caApSetWireless_t *)caCmdBuf;
    dutCmdResponse_t *apWirelessResp = &gGenericResp;
    hi_wifi_protocol_mode phy_mode = HI_WIFI_PHY_MODE_BUTT;
    struct netif *sigma_netif = NULL;
    char str[32] = {0}; /* 32 数组元素个数 */

    DPRINT_INFO(WFA_OUT, "enter wfaApSetWireless....\n");
    sigma_netif = netifapi_netif_find(cmd->programArgs.args.intf);

    /* IFCONFIG DOWN */
    netifapi_netif_set_down(sigma_netif);
    netifapi_netif_set_link_down(sigma_netif);

    /* CHANNEL */
    if(cmd->programArgs.args.channel_flag == APSETWIRELESS_FLAG){
        sprintf(str, "%d", cmd->programArgs.args.channel);

        char* set_freq_cmd[] = {cmd->programArgs.args.intf, "freq", str};
        (void)hi_wifi_hipriv(3, (const unsigned char**)set_freq_cmd);  /* 设置信道 3: 入参参数个数 */
        DPRINT_INFO(WFA_OUT, "enter wal_sigma_set_channel......str = %s\n", str);
    }

    /* COUNTRYCODE */
    if (cmd->programArgs.args.countryCode_flag == APSETWIRELESS_FLAG) {
        /* 规则6.6：禁止使用内存操作类危险函数 例外(1)对固定长度的数组进行初始化 */
        memset(str, 0, sizeof(str));
        char* set_countrycode_cmd[] = {cmd->programArgs.args.intf, "setcountry", cmd->programArgs.args.countryCode};
        (void)hi_wifi_hipriv(3, (const unsigned char**)set_countrycode_cmd);  /* 设置国家码  3: 入参参数个数 */
        DPRINT_INFO(WFA_OUT, "enter wal_sigma_set_countryCode......%s\n", cmd->programArgs.args.countryCode);
    }

    /* IFCONFIG UP */
    netifapi_netif_set_link_up(sigma_netif);
    netifapi_netif_set_up(sigma_netif);

    /* BCNINT */
    if(cmd->programArgs.args.bcnint_flag == APSETWIRELESS_FLAG){
        DPRINT_INFO(WFA_OUT, "enter hi_wifi_softap_set_beacon_int......\n");
        ret = hi_wifi_softap_set_beacon_period(atoi(cmd->programArgs.args.bcnint));
        if( ret != WFA_SUCCESS){
            DPRINT_INFO(WFA_OUT, "hi_wifi_softap_set_beacon_int error\n");
            return ret;
        }
    }

    /* DTIM */
    if(cmd->programArgs.args.dtim_flag == APSETWIRELESS_FLAG) {
        DPRINT_INFO(WFA_OUT, "enter hi_wifi_softap_set_dtim_period......\n");
        ret = hi_wifi_softap_set_dtim_period(cmd->programArgs.args.dtim);
        if( ret != WFA_SUCCESS) {
            DPRINT_INFO(WFA_OUT, "hi_wifi_softap_set_dtim_period error\n");
            return ret;
        }
    }

    /* MODE */
    if(cmd->programArgs.args.mode_flag == APSETWIRELESS_FLAG){
        DPRINT_INFO(WFA_OUT, "enter mode ......\n");
        if (strncmp(cmd->programArgs.args.mode, "11n", 3) == 0) {
            phy_mode = HI_WIFI_PHY_MODE_11BGN;
        } else if (strncmp(cmd->programArgs.args.mode, "11g", 3) == 0) {
            phy_mode = HI_WIFI_PHY_MODE_11BG;
        } else if (strncmp(cmd->programArgs.args.mode, "11b", 3) == 0) {
            phy_mode = HI_WIFI_PHY_MODE_11B;
        } else {
            phy_mode = HI_WIFI_PHY_MODE_BUTT;
        }
        ret = hi_wifi_softap_set_protocol_mode(phy_mode);
        if( ret != WFA_SUCCESS){
            DPRINT_INFO(WFA_OUT, "hi_wifi_softap_phy_mode error\n");
            return ret;
        }
    }

    /* RTS */
    if(cmd->programArgs.args.rts_flag == APSETWIRELESS_FLAG){
        /* 规则6.6：禁止使用内存操作类危险函数 例外(1)对固定长度的数组进行初始化 */
        memset(str, 0, sizeof(str));
        sprintf(str, "%d", cmd->programArgs.args.rts);

        char* rts_threshold_cmd[] = {cmd->programArgs.args.intf, "rts_threshold", str};
        (void)hi_wifi_hipriv(3, (const unsigned char**)rts_threshold_cmd);  /* 设置rts_threshold  3: 入参参数个数 */
        DPRINT_INFO(WFA_OUT, "str :: %s\n", str);
    }

    /* FRGMNT */
    if(cmd->programArgs.args.frgmnt_flag == APSETWIRELESS_FLAG){
        /* 规则6.6：禁止使用内存操作类危险函数 例外(1)对固定长度的数组进行初始化 */
        memset(str, 0, sizeof(str));
        sprintf(str,"%d",cmd->programArgs.args.frgmnt);

        char* frag_threshold_cmd[] = {cmd->programArgs.args.intf, "frag_threshold", str};
        (void)hi_wifi_hipriv(3, (const unsigned char**)frag_threshold_cmd);  /* 设置frag_threshold  3: 入参参数个数 */
        DPRINT_INFO(WFA_OUT, "str :: %s\n", str);
    }

    /* PWRSAVE */
    if(cmd->programArgs.args.pwrSave_flag == APSETWIRELESS_FLAG){
        DPRINT_INFO(WFA_OUT, "enter wal_sigma_set_pwrSave......\n");
        char* pm_set_switch_cmd[] = {cmd->programArgs.args.intf, "set_sta_pm_on", cmd->programArgs.args.pwrSave};
        (void)hi_wifi_hipriv(3, (const unsigned char**)pm_set_switch_cmd);  /* 3: 入参参数个数 */
        DPRINT_INFO(WFA_OUT, "pwrSave : %s\n", cmd->programArgs.args.pwrSave);
    }

    /* SGI20 */
    if(cmd->programArgs.args.sgi20_flag == APSETWIRELESS_FLAG){
        if(cmd->programArgs.args.sgi20 == WFA_ENABLED){
            DPRINT_INFO(WFA_OUT, "wifi_ap_set_short_GI_off on\n");
            ret = hi_wifi_softap_set_shortgi(0);
        } else if(cmd->programArgs.args.sgi20 == WFA_DISABLED){
            DPRINT_INFO(WFA_OUT, "hi_wifi_softap_set_shortgi off\n");
            ret = hi_wifi_softap_set_shortgi(1);
        } else {
            DPRINT_INFO(WFA_OUT, "sgi20 type error\n");
            return WFA_FAILED;
        }
    }


    /* MCS_FIXEDRATE */
    if(cmd->programArgs.args.mcsFixedRate_flag == APSETWIRELESS_FLAG){
        /* 规则6.6：禁止使用内存操作类危险函数 例外(1)对固定长度的数组进行初始化 */
        memset(str, 0, sizeof(str));
        sprintf(str,"%d",cmd->programArgs.args.mcsFixedRate);

        if((phy_mode == HI_WIFI_PHY_MODE_11B) || (phy_mode == HI_WIFI_PHY_MODE_11BG)) {
            char* set_rate_cmd[] = {cmd->programArgs.args.intf, "rate", str};
            (void)hi_wifi_hipriv(3, (const unsigned char**)set_rate_cmd);  /* 设置set_rate  3: 入参参数个数 */
            DPRINT_INFO(WFA_OUT, "str :: %s\n", str);

        } else if(phy_mode == HI_WIFI_PHY_MODE_11BGN) {
            char* set_mcs_cmd[] = {cmd->programArgs.args.intf, "mcs", str};
            (void)hi_wifi_hipriv(3, (const unsigned char**)set_mcs_cmd);  /* 设置set_mcs  3: 入参参数个数 */
            DPRINT_INFO(WFA_OUT, "str :: %s\n", str);

        } else {
            DPRINT_INFO(WFA_ERR, "EIRE MODE error\n");
            return ret;
        }
    }

    /* AMPDU */
    if(cmd->programArgs.args.ampdu_flag == APSETWIRELESS_FLAG){
        DPRINT_INFO(WFA_OUT, "enter wal_sigma_set_ampdu......\n");
        /* 规则6.6：禁止使用内存操作类危险函数 例外(1)对固定长度的数组进行初始化 */
        memset(str, 0, sizeof(str));
        sprintf(str, "%d", cmd->programArgs.args.ampdu);

        char* ampdu_tx_on_cmd[] = {cmd->programArgs.args.intf, "ampdu_tx_on", str};
        (void)hi_wifi_hipriv(3, (const unsigned char**)ampdu_tx_on_cmd);  /* 设置ampdu_tx_on  3: 入参参数个数 */
        DPRINT_INFO(WFA_OUT, "str :: %s\n", str);
    }

    /* AMSDU */
    if(cmd->programArgs.args.amsdu_flag == APSETWIRELESS_FLAG){
        DPRINT_INFO(WFA_OUT, "enter wal_sigma_set_amsdu......\n");
        /* 规则6.6：禁止使用内存操作类危险函数 例外(1)对固定长度的数组进行初始化 */
        memset(str, 0, sizeof(str));
        sprintf(str, "%d", cmd->programArgs.args.amsdu);
        DPRINT_INFO(WFA_OUT, "str :: %s\n", str);

        if (cmd->programArgs.args.amsdu == 1) { /* 开启时需要配置tid和max_num 关闭时这两个参数无意义 */
            char* amsdu_tx_on_cmd[] = {cmd->programArgs.args.intf, "amsdu_tx_on", str, "0", "8"};
            (void)hi_wifi_hipriv(5, (const unsigned char**)amsdu_tx_on_cmd);  /* 设置amsdu_tx_on  5: 入参参数个数 */
        } else if (cmd->programArgs.args.amsdu == 0) {    /* 关闭时不需要配置tid和max_num */
            char* amsdu_tx_on_cmd[] = {cmd->programArgs.args.intf, "amsdu_tx_on", str};
            (void)hi_wifi_hipriv(3, (const unsigned char**)amsdu_tx_on_cmd);  /* 设置amsdu_tx_on  3: 入参参数个数 */
        } else {
            DPRINT_INFO(WFA_OUT, "amsdu param error......\n");
        }
    }

    /* PWR_CONST */
    if(cmd->programArgs.args.pwrConst_flag == APSETWIRELESS_FLAG){
        /* 规则6.6：禁止使用内存操作类危险函数 例外(1)对固定长度的数组进行初始化 */
        memset(str, 0, sizeof(str));
        sprintf(str, "%d", cmd->programArgs.args.pwrConst);
        DPRINT_INFO(WFA_OUT, "enter wal_sigma_set_pwrConst......\n");

        char* txpower_cmd[] = {cmd->programArgs.args.intf, "txpower", str};
        (void)hi_wifi_hipriv(3, (const unsigned char**)txpower_cmd);  /* 设置txpower  3: 入参参数个数 */
        DPRINT_INFO(WFA_OUT, "str :: %s\n", str);
    }

    if(ret != WFA_SUCCESS){
        apWirelessResp->status = STATUS_ERROR;
    } else {
        apWirelessResp->status = STATUS_COMPLETE;
    }

    wfaEncodeTLV(WFA_AP_SET_WIRELESS_RESP_TLV, 4, (BYTE *)apWirelessResp, respBuf);
    *respLen = WFA_TLV_HDR_LEN + 4;
    return WFA_SUCCESS;
}

extern void start_dhcps(struct netif *pst_lwip_netif);
int wfaApSetSecurity(int len, BYTE *caCmdBuf, int *respLen, BYTE *respBuf)
{
    int ret = WFA_FAILURE;
    hi_unref_param(len);

    apSetSetCurity_t *cmd = (apSetSetCurity_t *)caCmdBuf;
    dutCmdResponse_t *apSecurity = &gGenericResp;
    hi_wifi_protocol_mode phy_mode = HI_WIFI_PHY_MODE_BUTT;

    ret = memset_s(&g_ap_set_secu, sizeof(hi_wifi_softap_config), 0, sizeof(hi_wifi_softap_config));
    if( ret != WFA_SUCCESS){
        DPRINT_INFO(WFA_OUT, "memset_s error\n");
        return ret;
    }

    if (strncmp(cmd->name, "11n", 3) == 0) {
        phy_mode = HI_WIFI_PHY_MODE_11BGN;
    } else if (strncmp(cmd->name, "11g", 3) == 0) {
        phy_mode = HI_WIFI_PHY_MODE_11BG;
    } else if (strncmp(cmd->name, "11b", 3) == 0) {
        phy_mode = HI_WIFI_PHY_MODE_11B;
    } else {
        phy_mode = HI_WIFI_PHY_MODE_BUTT;
    }

    if (!strcasecmp(cmd->keyMgnt, "NONE")) {
        g_ap_set_secu.authmode = HI_WIFI_SECURITY_OPEN;
    } else if (!strcasecmp(cmd->keyMgnt, "WPAPSK")) {
        g_ap_set_secu.authmode = HI_WIFI_SECURITY_WPAPSK;
    } else if (!strcasecmp(cmd->keyMgnt, "WPA2PSK")) {
        g_ap_set_secu.authmode = HI_WIFI_SECURITY_WPA2PSK;
    } else if (!strcasecmp(cmd->keyMgnt, "WPA2PSKMixed")) {
        g_ap_set_secu.authmode = HI_WIFI_SECURITY_WPAPSK_WPA2PSK_MIX;
    } else {
        DPRINT_INFO(WFA_OUT, "keyMgnt type error\n");
        return ret;
    }

    ret = memcpy_s(g_ap_set_secu.key,sizeof(g_ap_set_secu.key),cmd->pskType, sizeof(cmd->pskType));
    if( ret != WFA_SUCCESS){
        DPRINT_INFO(WFA_OUT, "memcpy_s error\n");
        return ret;
    }
    ret = memcpy_s(g_ap_set_secu.ssid,sizeof(g_ap_set_secu.key),cmd->ssid, sizeof(cmd->ssid));
    if( ret != WFA_SUCCESS){
        DPRINT_INFO(WFA_OUT, "memcpy_s error\n");
        return ret;
    }

    g_ap_set_secu.channel_num = 0x06;
    ret = memset_s(cmd->interface,sizeof(cmd->interface),0,sizeof(cmd->interface));
    if( ret != WFA_SUCCESS){
        DPRINT_INFO(WFA_OUT, "memset_s error\n");
        return ret;
    }
    hi_wifi_softap_set_protocol_mode(phy_mode);
    g_ap_isorno_complete = hi_wifi_softap_start(&g_ap_set_secu, cmd->name, &(cmd->lenth));
    if(g_ap_isorno_complete != WFA_SUCCESS){
        apSecurity->status = STATUS_ERROR;
    } else {
        apSecurity->status = STATUS_COMPLETE;
    }

    wfaEncodeTLV(WFA_AP_SET_SECURITY_RESP_TLV, 4, (BYTE *)apSecurity, respBuf);
    *respLen = WFA_TLV_HDR_LEN + 4;
    return WFA_SUCCESS;
}

int wfaApDeauthSta(int len, BYTE *caCmdBuf, int *respLen, BYTE *respBuf)
{
    int ret = WFA_FAILURE;
    hi_unref_param(len);
    apdeauthsta_t *cmd = (apdeauthsta_t *)caCmdBuf;
    dutCmdResponse_t *apdeauthsta = &gGenericResp;
    unsigned char mac_addr[WFA_MAC_ADDR_STR_LEN + 1] = {0};

    ret = str_to_addr(cmd->stamacaddress, mac_addr);
    if (ret != WFA_SUCCESS) {
        DPRINT_INFO(WFA_OUT, "wfaApDeauthSta str_to_addr error\n");
        return WFA_FAILURE;
    }

    ret = hi_wifi_softap_deauth_sta(mac_addr, WFA_MAC_ADDR_STR_LEN);
    if(ret != WFA_SUCCESS){
        apdeauthsta->status = STATUS_ERROR;
    } else {
        apdeauthsta->status = STATUS_COMPLETE;
    }
    wfaEncodeTLV(WFA_AP_DEAUTH_STA_RESP_TLV, 4, (BYTE *)apdeauthsta, respBuf);
    *respLen = WFA_TLV_HDR_LEN + 4;
    return WFA_SUCCESS;
}

int wfaApSetPmf(int len, BYTE *caCmdBuf, int *respLen, BYTE *respBuf)
{
    hi_unref_param(len);
    apsetpmf_t *cmd = (apsetpmf_t *)caCmdBuf;
    dutCmdResponse_t *apsetpmf = &gGenericResp;

    DPRINT_INFO(WFA_OUT, "pmf:%s\n", cmd->pmf);
    /* AP 不支持pmf设置 */
    apsetpmf->status = STATUS_COMPLETE;

    wfaEncodeTLV(WFA_AP_SET_PMF_RESP_TLV, 4, (BYTE *)apsetpmf, respBuf);
    *respLen = WFA_TLV_HDR_LEN + 4;
    return WFA_SUCCESS;
}

int wfaStaSetPwrSave(int len, BYTE *caCmdBuf, int *respLen, BYTE *respBuf)
{
    hi_unref_param(len);
    stasetpwrsave_t *cmd = (stasetpwrsave_t *)caCmdBuf;
    dutCmdResponse_t *stasetpwrsave = &gGenericResp;
    char* set_ps_mode_cmd[] = {cmd->intf, "set_ps_mode", "3"};
    (void)hi_wifi_hipriv(3, (const unsigned char**)set_ps_mode_cmd);  /* 配置为ps poll 3: 入参参数个数 */

    char* pm_set_switch_cmd[] = {cmd->intf, "set_sta_pm_on", cmd->mode};
    (void)hi_wifi_hipriv(3, (const unsigned char**)pm_set_switch_cmd);  /* 进入到低功耗模式 3: 入参参数个数 */
    DPRINT_INFO(WFA_OUT, "cmd->intf:%s, cmd->mode:%s\n", cmd->intf, cmd->mode);

    stasetpwrsave->status = STATUS_COMPLETE;
    wfaEncodeTLV(WFA_STA_SET_PWRSAVE_RESP_TLV, 4, (BYTE *)stasetpwrsave, respBuf);
    *respLen = WFA_TLV_HDR_LEN + 4;
    return WFA_SUCCESS;
}

int wfaStaSetSecurity(int len, BYTE *caCmdBuf, int *respLen, BYTE *respBuf)
{
    int ret = WFA_FAILURE;
    hi_unref_param(len);
    caStaSetSecurity_t *cmd = (caStaSetSecurity_t *)caCmdBuf;
    dutCmdResponse_t *stesecurity = &gGenericResp;
    hi_wifi_assoc_request stasetsecu;

    DPRINT_INFO(WFA_OUT, "Security type:%s\n",cmd->type);
    if(strcasecmp(cmd->type,"PSK") == 0){

        /* SSID */
        ret = memcpy_s(stasetsecu.ssid,sizeof(cmd->ssid),cmd->ssid, sizeof(cmd->ssid));
        if( ret != WFA_SUCCESS){
            DPRINT_INFO(WFA_OUT, "memcpy_s error\n");
            return ret;
        }

        /* keyMgmtType */
        if (!strcasecmp(cmd->keyMgmtType, "wpa2")) {
            stasetsecu.auth = HI_WIFI_SECURITY_WPA2PSK;
        } else {
            DPRINT_INFO(WFA_ERR, "keyMgmtType Type error\n");
            return ret;
        }

        /* encpType */
        if(!strcasecmp(cmd->encpType, "Tkip")) {
            stasetsecu.pairwise = HI_WIFI_PAIRWISE_TKIP;
        } else if(!strcasecmp(cmd->encpType, "aes-ccmp")) {
            stasetsecu.pairwise = HI_WIFI_PAIRWISE_AES;
        } else {
            DPRINT_INFO(WFA_ERR, "encpType type error\n");
            return WFA_FAILURE;
        }

        /* pmf */
        if(!strcasecmp(cmd->pmf, "Required")) {
            ret = hi_wifi_set_pmf(HI_WIFI_MGMT_FRAME_PROTECTION_REQUIRED);
            if(ret != WFA_SUCCESS){
                DPRINT_INFO(WFA_OUT, "pmf Required error\n");
                return ret;
            }
        } else if (!strcasecmp(cmd->pmf, "Optional")) {
            ret = hi_wifi_set_pmf(HI_WIFI_MGMT_FRAME_PROTECTION_OPTIONAL);
            if(ret != WFA_SUCCESS){
                DPRINT_INFO(WFA_OUT, "pmf Optional error\n");
                return ret;
            }
        } else {
            ret = hi_wifi_set_pmf(HI_WIFI_MGMT_FRAME_PROTECTION_CLOSE);
            if(ret != WFA_SUCCESS){
                DPRINT_INFO(WFA_OUT, "pmf Disable error\n");
                return ret;
            }
        }

    } else {
        DPRINT_INFO(WFA_OUT, "Security type error\n");
        return ret;
    }

    ret = hi_wifi_sta_connect(&stasetsecu);
    if(ret == WFA_SUCCESS){
        stesecurity->status = STATUS_COMPLETE;
    } else {
        stesecurity->status = STATUS_ERROR;
    }

    wfaEncodeTLV(WFA_STA_SET_SECURITY_RESP_TLV,4, (BYTE *)stesecurity, respBuf);
    *respLen = WFA_TLV_HDR_LEN + 4;
    return WFA_SUCCESS;
}


/* STA_SET_UAPSD */
int wfaStaSetUAPSD(int len, BYTE *caCmdBuf, int *respLen, BYTE *respBuf)
{
    hi_unref_param(len);
    caStaSetUAPSD_t *cmd = (caStaSetUAPSD_t *)caCmdBuf;
    dutCmdResponse_t *stasetuapsd = &gGenericResp;
    struct netif *sigma_netif = NULL;

    /* wlan0 */
    sigma_netif = netifapi_netif_find(cmd->intf);
    if(sigma_netif == NULL){
        DPRINT_INFO(WFA_ERR, "netifapi_netif_find ERROR\n");
        return WFA_FAILURE;
    }

    /* IFCONFIG DOWN */
    netifapi_netif_set_down(sigma_netif);
    netifapi_netif_set_link_down(sigma_netif);

    char* uapsd_en_cap_cmd[] = {cmd->intf, "uapsd_en_cap", "1"};
    (void)hi_wifi_hipriv(3, (const unsigned char**)uapsd_en_cap_cmd);  /* 使能uapsd能力 3: 入参参数个数 */
    DPRINT_INFO(WFA_OUT, "name ::%d,%d,%d,%d,%d\n", cmd->maxSPLength, cmd->acVO, cmd->acVI, cmd->acBK, cmd->acBE);

    char set_para[5][2] = {0};   /* 5行2列二维数组 */
    sprintf(set_para[0], "%d", cmd->maxSPLength);
    sprintf(set_para[1], "%d", cmd->acVO);
    sprintf(set_para[2], "%d", cmd->acVI);     /* 2 设置uapsd输入参数 */
    sprintf(set_para[3], "%d", cmd->acBK);     /* 3 设置uapsd输入参数 */
    sprintf(set_para[4], "%d", cmd->acBE);     /* 4 设置uapsd输入参数 */

    printf("%d  %s\n", cmd->acVO, set_para[1]);
    printf("%d  %s\n", cmd->acVI, set_para[2]);  /* 2 设置uapsd输入参数 */
    printf("%d  %s\n", cmd->acBK, set_para[3]);  /* 3 设置uapsd输入参数 */
    printf("%d  %s\n", cmd->acBE, set_para[4]);  /* 4 设置uapsd输入参数 */

    char* set_uapsd_para_cmd[] = {cmd->intf, "set_uapsd_para", set_para[0], set_para[1],
        set_para[2], set_para[3], set_para[4]};  /* 2、3、4 设置uapsd输入参数 */
    (void)hi_wifi_hipriv(7, (const unsigned char**)set_uapsd_para_cmd); /* 设置uapsd参数 7: 入参参数个数 */
    stasetuapsd->status = STATUS_COMPLETE;

    /* IFCONFIG UP */
    netifapi_netif_set_link_up(sigma_netif);
    netifapi_netif_set_up(sigma_netif);

    wfaEncodeTLV(WFA_STA_SET_UAPSD_RESP_TLV, 4, (BYTE *)stasetuapsd, respBuf);
    *respLen = WFA_TLV_HDR_LEN + 4;
    return WFA_SUCCESS;
}

int wfaApGetMacAddress(int len, BYTE *caCmdBuf, int *respLen, BYTE *respBuf)
{
    int ret = WFA_FAILURE;
    hi_unref_param(len);
    apgetmacaddress_t *cmd = (apgetmacaddress_t *)caCmdBuf;
    dutCmdResponse_t *apgetmacaddr = &gGenericResp;

    struct netif *pst_lwip_netif = NULL;
    pst_lwip_netif = netifapi_netif_find(cmd->interface);
    if(pst_lwip_netif == NULL)
    {
        DPRINT_INFO(WFA_OUT, "pst_lwip_netif is null\n");
        return ret;
    }

    DPRINT_INFO(WFA_OUT, MACSTR, mac2str(pst_lwip_netif->hwaddr));
    printf("\n");

    wSTRNCPY(apgetmacaddr->cmdru.mac, (const char *)pst_lwip_netif->hwaddr, WFA_MAC_ADDR_STR_LEN);
    DPRINT_INFO(WFA_OUT, MACSTR, mac2str(apgetmacaddr->cmdru.mac));
    apgetmacaddr->status = STATUS_COMPLETE;
    wfaEncodeTLV(WFA_AP_GET_MAC_ADDRESS_RESP_TLV, sizeof(dutCmdResponse_t), (BYTE *)apgetmacaddr, respBuf);
    *respLen = WFA_TLV_HDR_LEN + sizeof(dutCmdResponse_t);

    return WFA_SUCCESS;
}

int wfaApCaVersion(int len, BYTE *caCmdBuf, int *respLen, BYTE *respBuf)
{
    hi_unref_param(len);
    hi_unref_param(caCmdBuf);
    dutCmdResponse_t *getverResp = &gGenericResp;
    wSTRNCPY(getverResp->cmdru.version, AP_CA_VERSION, AP_CA_VERSION_LEN);
    getverResp->status = STATUS_COMPLETE;

    wfaEncodeTLV(WFA_AP_CA_VERSION_RESP_TLV, sizeof(dutCmdResponse_t), (BYTE *)getverResp, respBuf);
    *respLen = WFA_TLV_HDR_LEN + sizeof(dutCmdResponse_t);
    return WFA_SUCCESS;
}

int wfaApReboot(int len, BYTE *caCmdBuf, int *respLen, BYTE *respBuf)
{
    hi_unref_param(len);
    apRoot_t* cmd = (apRoot_t *)caCmdBuf;
    dutCmdResponse_t *reboot = &gGenericResp;
    int ret;

    if (hi_wifi_softap_stop() != WFA_SUCCESS) {
        return WFA_FAILURE;
    }

    ret = sigma_start_hapd(cmd->name, &(cmd->length));
    if (ret != WFA_SUCCESS) {
        reboot->status = STATUS_ERROR;
        g_ap_isorno_complete = 0;
    } else {
        reboot->status = STATUS_COMPLETE;
        g_ap_isorno_complete = 1;
    }

    wfaEncodeTLV(WFA_AP_REBOOT_RESP_TLV, 4, (BYTE *)reboot, respBuf);
    *respLen = WFA_TLV_HDR_LEN + 4;
    return WFA_SUCCESS;
}

int wfaApConfigCommit(int len, BYTE *caCmdBuf, int *respLen, BYTE *respBuf)
{
    hi_unref_param(len);
    hi_unref_param(caCmdBuf);
    dutCmdResponse_t *apconfigcommit = &gGenericResp;

    if(g_ap_isorno_complete != -1){
        apconfigcommit->status = STATUS_COMPLETE;
    } else {
        apconfigcommit->status = STATUS_ERROR;
    }
    wfaEncodeTLV(WFA_AP_CONFIG_COMMIT_RESP_TLV, 4, (BYTE *)apconfigcommit, respBuf);
    *respLen = WFA_TLV_HDR_LEN + 4;
    return WFA_SUCCESS;
}

int wfaApResetDefault(int len, BYTE *caCmdBuf, int *respLen, BYTE *respBuf)
{
    hi_unref_param(len);
    apResetDefault_t *cmd = (apResetDefault_t *)caCmdBuf;
    dutCmdResponse_t *apresetdefault = &gGenericResp;
    int ret;
    cmd->lenth = 0;
    if (hi_wifi_softap_stop() != WFA_SUCCESS) {
        return WFA_FAILURE;
    }

    ret = sigma_start_hapd(cmd->name, &(cmd->lenth));
    if (ret != WFA_SUCCESS) {
        apresetdefault->status = STATUS_ERROR;
        g_ap_isorno_complete = 0;
    } else {
        apresetdefault->status = STATUS_COMPLETE;
        g_ap_isorno_complete = 1;
    }

    wfaEncodeTLV(WFA_AP_RESET_DEFAULT_RESP_TLV,4, (BYTE *)apresetdefault, respBuf);
    *respLen = WFA_TLV_HDR_LEN + 4;
    return WFA_SUCCESS;
}

int wfaApGetInfo(int len, BYTE *caCmdBuf, int *respLen, BYTE *respBuf)
{
    hi_unref_param(len);
    hi_unref_param(caCmdBuf);
    dutCmdResponse_t *apgetinfo = &gGenericResp;

    wSTRNCPY(apgetinfo->cmdru.version, AP_CA_VERSION, AP_CA_VERSION_LEN);
    wSTRNCPY(apgetinfo->cmdru.devInfo.firmware,AP_FIRMWARE_VERSION,AP_FIRMWARE_VERSION_LEN);

    apgetinfo->status = STATUS_COMPLETE;
    wfaEncodeTLV(WFA_AP_GET_INFO_RESP_TLV, sizeof(dutCmdResponse_t), (BYTE *)apgetinfo, respBuf);
    *respLen = WFA_TLV_HDR_LEN + sizeof(dutCmdResponse_t);
    return WFA_SUCCESS;
}

