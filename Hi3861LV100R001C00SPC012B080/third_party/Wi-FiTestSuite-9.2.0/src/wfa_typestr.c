/****************************************************************************
*
* Copyright (c) 2016 Wi-Fi Alliance
*
* Permission to use, copy, modify, and/or distribute this software for any
* purpose with or without fee is hereby granted, provided that the above
* copyright notice and this permission notice appear in all copies.
*
* THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
* WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
* MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
* SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER
* RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT,
* NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE
* USE OR PERFORMANCE OF THIS SOFTWARE.
*
*****************************************************************************/

/*
 *  wfa_typestr.c:
 *  global array of the mapping of command types, command strings
 *  to attached processing function
 *
 */

#include "wfa_types.h"
#include "wfa_tlv.h"
#include "wfa_agtctrl.h"

extern int cmdProcNotDefinedYet(char *, BYTE *, int *);
extern int xcCmdProcGetVersion(char *, BYTE *, int *);
extern int xcCmdProcAgentConfig(char *, BYTE *, int *);
extern int xcCmdProcAgentSend(char *, BYTE *, int *);
extern int xcCmdProcAgentRecvStart(char *, BYTE *, int *);
extern int xcCmdProcAgentRecvStop(char *, BYTE *, int *);
extern int xcCmdProcAgentReset(char *, BYTE *, int *);
extern int xcCmdProcStaGetIpConfig(char *, BYTE *, int *);
extern int xcCmdProcStaSetIpConfig(char *, BYTE *, int *);
extern int xcCmdProcStaGetMacAddress(char *pcmdStr, BYTE *, int *);
extern int xcCmdProcStaSetMacAddress(char *pcmdStr, BYTE *, int *);
extern int xcCmdProcStaIsConnected(char *pcmdStr, BYTE *, int *);

extern int xcCmdProcStaGetBSSID(char *pcmdStr, BYTE *, int *);

extern int xcCmdProcStaSetEncryption(char *pcmdStr, BYTE *, int *);
extern int xcCmdProcStaSetPSK(char *pcmdStr, BYTE *, int *);

extern int xcCmdProcDeviceGetInfo(char *pcmdStr, BYTE *, int *);
extern int xcCmdProcDeviceListIF(char *pcmdStr, BYTE *, int *);
extern int xcCmdProcStaAssociate(char *pcmdStr, BYTE *, int *);
extern int xcCmdProcStaSetUAPSD(char *pcmdStr, BYTE *, int *);
extern int xcCmdProcStaGetInfo(char *pcmdStr, BYTE *, int *);
extern int xcCmdProcAgentSendPing(char *pcmdStr, BYTE *, int *);
extern int xcCmdProcAgentStopPing(char *pcmdStr, BYTE *, int *);

extern int xcCmdProcStaSetMode(char *pcmStr, BYTE *, int *);

extern int xcCmdProcStaSet11n(char *pcmStr, BYTE *, int *);
extern int xcCmdProcStaSetWireless(char *pcmStr, BYTE *, int *);
extern int xcCmdProcApSetWireless(char *pcmdStr, BYTE *aBuf, int *aLen);
extern int xcCmdProcApSetSecurity(char *pcmdStr, BYTE *aBuf, int *aLen);
extern int xcCmdProcStaSendADDBA(char *pcmStr, BYTE *, int *);
extern int xcCmdProcStaResetDefault(char *, BYTE *, int *);
extern int xcCmdProcStaDisconnect(char *, BYTE *, int *);
extern int xcCmdProcStaPresetTestParameters(char *pcmdStr, BYTE *aBuf, int *aLen);

extern int xcCmdProcStaReAssociate(char *pcmStr, BYTE*, int *);
extern int xcCmdProcStaResetDefault(char *pcmdStr, BYTE *aBuf, int *aLen);
extern int xcCmdProcApDeauthSta(char *pcmdStr, BYTE *aBuf, int *aLen);
extern int xcCmdProcApSetPmf(char *pcmdStr, BYTE *aBuf, int *aLen);
extern int xcCmdProcStaSetPwrsave(char *pcmdStr, BYTE *aBuf, int *aLen);
extern int xcCmdProcStaSetSecurity(char *pcmdStr, BYTE *aBuf, int *aLen);
extern int xcCmdProcStaSetUapsd(char *pcmdStr, BYTE *aBuf, int *aLen);
extern int xcCmdApGetMacAddress(char *pcmdStr, BYTE *aBuf, int *aLen);
extern int xcCmdProcApCaVersion(char *pcmdStr, BYTE *aBuf, int *aLen);
extern int xcCmdProcApReboot(char *pcmdStr, BYTE *aBuf, int *aLen);
extern int xcCmdProcApConfigCommit(char *pcmdStr, BYTE *aBuf, int *aLen);
extern int xcCmdProcApResetDefault(char *pcmdStr, BYTE *aBuf, int *aLen);
extern int xcCmdProcApGetInfo(char *pcmdStr, BYTE *aBuf, int *aLen);

/*
 * Initialize a command name table to its defined type and process function
 */
typeNameStr_t nameStr[] =
{
    {0,                   "NO_USED_STRING", NULL},
    {WFA_GET_VERSION_TLV, "ca_get_version", xcCmdProcGetVersion},
    {WFA_TRAFFIC_SEND_PING_TLV, "traffic_send_ping", xcCmdProcAgentSendPing},
    {WFA_TRAFFIC_STOP_PING_TLV, "traffic_stop_ping", xcCmdProcAgentStopPing},
    {WFA_TRAFFIC_AGENT_CONFIG_TLV, "traffic_agent_config", xcCmdProcAgentConfig},
    {WFA_TRAFFIC_AGENT_SEND_TLV, "traffic_agent_send", xcCmdProcAgentSend},
    {WFA_TRAFFIC_AGENT_RESET_TLV, "traffic_agent_reset", xcCmdProcAgentReset},
    {WFA_TRAFFIC_AGENT_RECV_START_TLV, "traffic_agent_receive_start", xcCmdProcAgentRecvStart},
    {WFA_TRAFFIC_AGENT_RECV_STOP_TLV, "traffic_agent_receive_stop", xcCmdProcAgentRecvStop},
    //Control Commands
    {WFA_STA_GET_IP_CONFIG_TLV, "sta_get_ip_config", xcCmdProcStaGetIpConfig},
    {WFA_STA_SET_IP_CONFIG_TLV, "sta_set_ip_config", xcCmdProcStaSetIpConfig},
    {WFA_STA_GET_MAC_ADDRESS_TLV, "sta_get_mac_address", xcCmdProcStaGetMacAddress},
    {WFA_STA_SET_MAC_ADDRESS_TLV, "sta_set_macaddr", xcCmdProcStaSetMacAddress},
    {WFA_STA_IS_CONNECTED_TLV, "sta_is_connected", xcCmdProcStaIsConnected},
    {WFA_STA_GET_BSSID_TLV, "sta_get_bssid", xcCmdProcStaGetBSSID},
    {WFA_STA_SET_ENCRYPTION_TLV, "sta_set_encryption", xcCmdProcStaSetEncryption},
    {WFA_STA_SET_PSK_TLV, "sta_set_psk", xcCmdProcStaSetPSK},
    {WFA_STA_ASSOCIATE_TLV, "sta_associate", xcCmdProcStaAssociate},
    {WFA_DEVICE_LIST_IF_TLV, "device_list_interfaces", xcCmdProcDeviceListIF},
    {WFA_DEVICE_GET_INFO_TLV, "device_get_info", xcCmdProcDeviceGetInfo},
    {WFA_STA_GET_INFO_TLV, "sta_get_info", xcCmdProcStaGetInfo},
    {WFA_STA_SET_MODE_TLV, "sta_set_mode", xcCmdProcStaSetMode},
//    {WFA_STA_SET_UAPSD_TLV, "sta_set_uapsd", xcCmdProcStaSetUAPSD},
    {WFA_STA_DISCONNECT_TLV, "sta_disconnect", xcCmdProcStaDisconnect},
    {WFA_STA_REASSOCIATE_TLV, "sta_reassociate", xcCmdProcStaReAssociate},
//    {WFA_STA_SET_SECURITY_TLV, "sta_set_security", xcCmdProcStaSetSecurity},
//    {WFA_STA_SET_PWRSAVE_TLV, "sta_set_pwrsave", xcCmdProcStaSetPwrSave},
    {WFA_STA_RESET_DEFAULT_TLV, "sta_reset_default", xcCmdProcStaResetDefault},
    {WFA_STA_SET_11N_TLV, "sta_set_11n", xcCmdProcStaSet11n},
    {WFA_STA_SET_WIRELESS_TLV, "sta_set_wireless", xcCmdProcStaSetWireless},
    {WFA_STA_SEND_ADDBA_TLV, "sta_send_addba", xcCmdProcStaSendADDBA},
    {WFA_AP_SET_WIRELESS_TLV, "ap_set_wireless", xcCmdProcApSetWireless},
    {WFA_AP_SET_SECURITY_TLV, "ap_set_security", xcCmdProcApSetSecurity},
    {WFA_AP_SET_PMF_RESP_TLV, "ap_set_pmf", xcCmdProcApSetPmf},
    {WFA_AP_DEAUTH_STA_RESP_TLV, "ap_deauth_sta", xcCmdProcApDeauthSta},
    {WFA_STA_SET_PWRSAVE_RESP_TLV,"sta_set_pwrsave", xcCmdProcStaSetPwrsave},
    {WFA_STA_SET_SECURITY_RESP_TLV, "sta_set_security", xcCmdProcStaSetSecurity},
    {WFA_STA_SET_UAPSD_RESP_TLV, "sta_set_uapsd", xcCmdProcStaSetUapsd},
    {WFA_AP_GET_MAC_ADDRESS_RESP_TLV, "ap_get_mac_address", xcCmdApGetMacAddress},
    {WFA_AP_CA_VERSION_TLV, "ap_ca_version", xcCmdProcApCaVersion},
    {WFA_AP_REBOOT_TLV, "ap_reboot", xcCmdProcApReboot},
    {WFA_AP_CONFIG_COMMIT_TLV, "ap_config_commit", xcCmdProcApConfigCommit},
    {WFA_AP_RESET_DEFAULT_TLV, "ap_reset_default", xcCmdProcApResetDefault},
    {WFA_AP_GET_INFO_TLV, "ap_get_info", xcCmdProcApGetInfo},
    {WFA_STA_PRESET_PARAMETERS_TLV, "sta_preset_testparameters", xcCmdProcStaPresetTestParameters},

    {-1, "", NULL},
};
