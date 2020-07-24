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
 * File: wfa_cmdtbl.c
 *   The file contains a predefined function array. The command process and
 *   execution functions of a DUT traffic generator and control will be
 *   registered in the array/table by the order of the defined commands TLV
 *   values.
 *
 *
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "wfa_debug.h"
#include "wfa_types.h"
#include "wfa_main.h"
#include "wfa_tlv.h"
#include "wfa_tg.h"
#include "wfa_ca.h"
#include "wfa_agt.h"
#include "wfa_rsp.h"

int NotDefinedYet(int len, unsigned char *params, int *respLen, BYTE *respBuf);
extern int agtCmdProcGetVersion(int len, BYTE *parms, int *respLen, BYTE *respBuf);

/* globally define the function table */
xcCommandFuncPtr gWfaCmdFuncTbl[WFA_STA_COMMANDS_END] =
{
    /* Traffic Agent Commands */
    NotDefinedYet,            /*    None                               (0) */
    agtCmdProcGetVersion,     /*    WFA_GET_VERSION_TLV                (1) */
    wfaTGSendPing,            /*    WFA_TRAFFIC_SEND_PING_TLV          (2) */
    wfaTGStopPing,            /*    WFA_TRAFFIC_STOP_PING_TLV          (3) */
    wfaTGConfig,              /*    WFA_TRAFFIC_AGENT_CONFIG_TLV       (4) */
    wfaTGSendStart,           /*    WFA_TRAFFIC_AGENT_SEND_TLV         (5) */
    wfaTGRecvStart,           /*    WFA_TRAFFIC_AGENT_RECV_START_TLV   (6) */
    wfaTGRecvStop,            /*    WFA_TRAFFIC_AGENT_RECV_STOP_TLV    (7) */
    wfaTGReset,               /*    WFA_TRAFFIC_AGENT_RESET_TLV        (8) */
    NotDefinedYet,            /*    WFA_TRAFFIC_AGENT_STATUS_TLV       (9) */
    /* Control and Configuration Commands */
    wfaStaGetIpConfig,        /*    WFA_STA_GET_IP_CONFIG_TLV          (10)*/
    wfaStaSetIpConfig,        /*    WFA_STA_SET_IP_CONFIG_TLV          (11)*/
    wfaStaGetMacAddress,      /*    WFA_STA_GET_MAC_ADDRESS_TLV        (12)*/
    wfaStaSetMacAddr,         /*    WFA_STA_SET_MAC_ADDRESS_TLV        (13)*/
    wfaStaIsConnected,        /*    WFA_STA_IS_CONNECTED_TLV           (14)*/
    wfaStaGetBSSID,           /*    WFA_STA_GET_BSSID_TLV              (16)*/
    wfaSetEncryption,         /*    WFA_STA_SET_ENCRYPTION_TLV         (18)*/
    wfaStaSetPSK,             /*    WFA_STA_SET_PSK_TLV                (19)*/
    wfaStaSetUAPSD,           /*    WFA_STA_SET_UAPSD_TLV              (21)*/
    wfaStaAssociate,          /*    WFA_STA_ASSOCIATE_TLV              (22)*/
    wfaStaGetInfo,            /*    WFA_STA_GET_INFO_TLV               (27)*/
    wfaDeviceGetInfo,         /*    WFA_DEVICE_GET_INFO_TLV            (28)*/
    wfaDeviceListIF,          /*    WFA_DEVICE_LIST_IF_TLV]            (29)*/
    wfaStaSetMode,            /*    WFA_STA_SET_MODE                   (31)*/
    wfaStaReAssociate,        /*    WFA_STA_REASSOCIATE                (34)*/
    wfaStaSetPwrSave,         /*    WFA_STA_SET_PWRSAVE                (35)*/
    wfaStaSet11n,             /*    WFA_STA_SET_11n_TLV                (41)*/
    wfaStaSetWireless,        /*    WFA_STA_SET_WIRELESS_TLV           (42)*/
    wfaStaSendADDBA,          /*    WFA_STA_SEND_ADDBA_TLV             (43)*/
    wfaStaResetDefault,       /*    WFA_STA_RESET_DEFAULT_TLV          (46)*/
    wfaStaDisconnect,         /*    WFA_STA_DISCONNECT_TLV             (47)*/
    wfaStaSetSecurity,        /*    WFA_STA_SET_SECURITY_TLV           (49)*/
    wfaApSetWireless,
    wfaApSetSecurity,
    wfaApSetPmf,              /*  AP_SET_PMF  */
    wfaApReboot,              /*  AP_REBOOT  */
    wfaApConfigCommit,        /*  AP_CONFIG_COMMIT  */
    wfaApResetDefault,        /*  AP_RESET_DEFAULT  */
    wfaApGetInfo,             /*  AP_GET_INFO  */
    wfaApDeauthSta,           /*  AP_DEAUTH_STA  */
    wfaApGetMacAddress,       /*   WFA_AP_GET_MAC_ADDRESS_TLV */
    wfaApCaVersion,           /*   AP_CA_VERSION */
    wfaStaPresetParams,       /*    WFA_STA_PRESET_PARAMETERS          (37)*/
};


/*
 * NotDefinedYet(): a dummy function
 */
int NotDefinedYet(int len, unsigned char *params, int *respLen, BYTE *respBuf)
{
    DPRINT_WARNING(WFA_WNG, "The command processing function not defined.\n");
    hi_unref_param(len);
    hi_unref_param(params);
    hi_unref_param(respLen);
    hi_unref_param(respBuf);

    /* need to send back a response */
    return WFA_SUCCESS;
}
