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
 *       File: wfa_ca_resp.c
 *       All functions are designated to handle the command responses from
 *       a DUT and inform TM the command status.
 *       They will be called by Control Agent.
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
#include "wfa_rsp.h"
#include "wfa_ca_resp.h"
#include "wfa_cmds.h"
#include "hi_types_base.h"
#include "hi_wifi_api.h"

char gRespStr[WFA_BUFF_1K]; /* 跑到8个流的时候，需要将空间扩大 */
extern int sigma_uart_send(char *paData, unsigned int ausDataSize);

dutCommandRespFuncPtr wfaCmdRespProcFuncTbl[WFA_STA_RESPONSE_END+1] =
{
    caCmdNotDefinedYet,
    wfaGetVersionResp,                   /* WFA_GET_VERSION_RESP_TLV - WFA_STA_COMMANDS_END                  (1) */
    wfaTrafficAgentPingStartResp,        /* WFA_TRAFFIC_SEND_PING_RESP_TLV - WFA_STA_COMMANDS_END            (2) */
    wfaTrafficAgentPingStopResp,         /* WFA_TRAFFIC_STOP_PING_RESP_TLV - WFA_STA_COMMANDS_END            (3) */
    wfaTrafficAgentConfigResp,           /* WFA_TRAFFIC_AGENT_CONFIG_RESP_TLV - WFA_STA_COMMANDS_END         (4) */
    wfaTrafficAgentSendResp,             /* WFA_TRAFFIC_AGENT_SEND_RESP_TLV - WFA_STA_COMMANDS_END           (5) */
    wfaStaGenericResp,                   /* WFA_TRAFFIC_AGENT_RECV_START_RESP_TLV - WFA_STA_COMMANDS_END     (6) */
    wfaTrafficAgentRecvStopResp,         /* WFA_TRAFFIC_AGENT_RECV_STOP_RESP_TLV - WFA_STA_COMMANDS_END      (7) */
    wfaStaGenericResp,                   /* WFA_TRAFFIC_AGENT_RESET_RESP_TLV - WFA_STA_COMMANDS_END          (8) */
    caCmdNotDefinedYet,                  /* WFA_TRAFFIC_AGENT_STATUS_RESP_TLV - WFA_STA_COMMANDS_END         (9) */
    wfaStaGetIpConfigResp,               /* WFA_STA_GET_IP_CONFIG_RESP_TLV - WFA_STA_COMMANDS_END           (10) */
    wfaStaGenericResp,                   /* WFA_STA_SET_IP_CONFIG_RESP_TLV - WFA_STA_COMMANDS_END           (11) */
    wfaStaGetMacAddressResp,             /* WFA_STA_GET_MAC_ADDRESS_RESP_TLV - WFA_STA_COMMANDS_END         (12) */
    wfaStaGenericResp,                   /* WFA_STA_SET_MAC_ADDRESS_RESP_TLV - WFA_STA_COMMANDS_END         (13) */
    wfaStaIsConnectedResp,               /* WFA_STA_IS_CONNECTED_RESP_TLV - WFA_STA_COMMANDS_END            (14) */
    wfaStaGetBSSIDResp,                  /* WFA_STA_GET_BSSID_RESP_TLV - WFA_STA_COMMANDS_END               (16) */
    wfaStaSetEncryptionResp,             /* WFA_STA_SET_ENCRYPTION_RESP_TLV - WFA_STA_COMMANDS_END          (18) */
    wfaStaGenericResp,                   /* WFA_STA_SET_PSK_RESP_TLV - WFA_STA_COMMANDS_END                 (19) */
    wfaStaGenericResp,                   /* WFA_STA_SET_UAPSD_RESP_TLV - WFA_STA_COMMANDS_END               (21) */
    wfaStaGenericResp,                   /* WFA_STA_ASSOCIATE_RESP_TLV - WFA_STA_COMMANDS_END               (22) */
    wfaStaGetInfoResp,                   /* WFA_STA_GET_INFO_RESP_TLV - WFA_STA_COMMANDS_END                (27) */
    wfaDeviceGetInfoResp,                /* WFA_DEVICE_GET_INFO_RESP_TLV - WFA_STA_COMMANDS_END             (28) */
    wfaDeviceListIFResp,                 /* WFA_DEVICE_LIST_IF_RESP_TLV - WFA_STA_COMMANDS_END              (29) */
    wfaStaGenericResp,                   /* WFA_STA_SET_MODE_RESP_TLV - WFA_STA_COMMANDS_END                (31) */
    wfaStaGenericResp,                   /* WFA_STA_REASSOCIATE_RESP_TLV - WFA_STA_COMMANDS_END             (34) */
    wfaStaGenericResp,                   /* WFA_STA_SET_PWRSAVE_RESP_TLV - WFA_STA_CMMANDS_END              (35) */
    wfaStaGenericResp,                   /* WFA_STA_SET_11N_RESP_TLV                                        (41)*/
    wfaStaGenericResp,                   /* WFA_STA_SET_WIRELESS_RESP_TLV                                   (42)*/
    wfaStaGenericResp,                   /* WFA_STA_SET_SEND_ADDBA_RESP_TLV                                 (43)*/
    wfaStaGenericResp,                   /* WFA_STA_RESET_DEFAULT_RESP_TLV                                  (46)*/
    wfaStaGenericResp,                   /* WFA_STA_DISCONNECT_RESP_TLV                                     (47)*/
    wfaStaGenericResp,                   /* WFA_STA_SET_SECURITY_RESP_TLV                                   (49)*/
    wfaApGenericResp,                    /* WFA_AP_SET_WIRELESS_RESP_TLV                                    (84)*/
    wfaApGenericResp,                    /* WFA_AP_SET_SECURITY_RESP_TLV                                    (85)*/
    wfaApGenericResp,                    /*  AP_SET_PMF  */
    wfaApGenericResp,                    /*  AP_REBOOT  */
    wfaApGenericResp,                    /*  AP_CONFIG_COMMIT  */
    wfaApGenericResp,                    /*  AP_RESET_DEFAULT  */
    wfaApGetInfoResp,                    /*  AP_GET_INFO  */
    wfaApGenericResp,                    /*  AP_DEAUTH_STA */
    wfaApGetMacAddrResp,                 /*  AP_GET_MAC_ADDRESS */
    wfaApCaVersionResp,                  /*  AP_CA_VERSION */
    wfaStaGenericResp,
};

int caCmdNotDefinedYet(BYTE *cmdBuf)
{
    int done;
    hi_unref_param(cmdBuf);
    memset_s(gRespStr, WFA_BUFF_1K, 0, WFA_BUFF_1K);
    sprintf(gRespStr, "status,ERROR,Command Not Defined\r\n");
    /* make sure if getting send error, will close the socket */
    sigma_uart_send(gRespStr, strlen(gRespStr));

    done = 0;

    return done;
}

int wfaTrafficAgentConfigResp(BYTE *cmdBuf)
{
    int done=0;
    dutCmdResponse_t *agtConfigResp = (dutCmdResponse_t *)(cmdBuf + 4);

    DPRINT_INFO(WFA_OUT, "Entering wfaTrafficAgentConfigResp ...\n");
    memset_s(gRespStr, WFA_BUFF_1K, 0, WFA_BUFF_1K);

    switch(agtConfigResp->status)
    {
        case STATUS_RUNNING:
        DPRINT_INFO(WFA_OUT, "wfaTrafficAgentConfig running ...\n");
        done = 1;
        break;
        case STATUS_COMPLETE:
        sprintf(gRespStr, "status,COMPLETE,streamID,%i\r\n", agtConfigResp->streamId);
        break;
        default:
        sprintf(gRespStr, "status,INVALID\r\n");
    }

    sigma_uart_send(gRespStr, strlen(gRespStr));
    return done;

}

int wfaTrafficAgentSendResp(BYTE *cmdBuf)
{
    int done=1,i;
    char copyBuf[WFA_TRAFFIC_COPY_BUFFER];
    int errorStatus = 0;
    wfaTLV *ptlv = (wfaTLV *)cmdBuf;
    int len = ptlv->len;
    int numStreams;
    dutCmdResponse_t *statResp = (dutCmdResponse_t *)(cmdBuf + 4);

    DPRINT_INFO(WFA_OUT, "Entering wfaTrafficAgentSendResp ...\n");
    memset_s(gRespStr, WFA_BUFF_1K, 0, WFA_BUFF_1K);

    numStreams = (len/sizeof(dutCmdResponse_t));
    printf("total %i streams\n", numStreams);

    if (numStreams > WFA_MAX_TRAFFIC_STREAMS) {
        DPRINT_INFO(WFA_OUT, "numStreams is bigger the max traffic streams ...\n");
        return WFA_ERROR;
    }

    if(numStreams == 0){
        sprintf(gRespStr, "status,INVALID\r\n");
    }else{
        for(i=0; i<numStreams; i++)
        {
            if(statResp->status != STATUS_COMPLETE)
            {
                errorStatus = 1;
            }
        }

        if(errorStatus)
        {
            sprintf(gRespStr, "status,ERROR");
        }
        else
        {
            sprintf(gRespStr, "status,COMPLETE,streamID,");
            for(i=0; i<numStreams; i++)
            {
                sprintf(copyBuf, " %i", statResp[i].streamId);
                strncat(gRespStr, copyBuf, sizeof(copyBuf)-1);
            }

            printf("streamids %s\n", gRespStr);

            strncat(gRespStr, ",txFrames,", 10);
            for(i=0; i<numStreams; i++)
            {
                sprintf(copyBuf, "%i ", statResp[i].cmdru.stats.txFrames);
                strncat(gRespStr, copyBuf, sizeof(copyBuf)-1);
            }

                strncat(gRespStr, ",rxFrames,", 10);
                for(i=0; i<numStreams; i++)
                {
                    sprintf(copyBuf, "%i ", statResp[i].cmdru.stats.rxFrames);
                    strncat(gRespStr, copyBuf, sizeof(copyBuf)-1);
                }

                strncat(gRespStr, ",txPayloadBytes,", 16);
                for(i=0; i<numStreams; i++)
                {
                    sprintf(copyBuf, "%llu ", statResp[i].cmdru.stats.txPayloadBytes);
                    strncat(gRespStr, copyBuf, sizeof(copyBuf)-1);
                }

                strncat(gRespStr, ",rxPayloadBytes,", 16);
                for(i=0; i<numStreams; i++)
                {
                    sprintf(copyBuf, " %llu ", statResp[i].cmdru.stats.rxPayloadBytes);
                    strncat(gRespStr, copyBuf, sizeof(copyBuf)-1);
                }
                strncat(gRespStr, ",outOfSequenceFrames,", 21);
                for(i=0; i<numStreams; i++)
                {
                    sprintf(copyBuf, "%i ", statResp[i].cmdru.stats.outOfSequenceFrames);
                    strncat(gRespStr, copyBuf, sizeof(copyBuf)-1);
                }

                printf("jitter %lu\n", statResp[i].cmdru.stats.jitter);
                strncat(gRespStr, "\r\n", 4);
        }
    }

    sigma_uart_send(gRespStr, strlen(gRespStr));

    return done;


}

int wfaTrafficAgentRecvStopResp(BYTE *cmdBuf)
{
    int done=1;
    int i = 0;
    int errorStatus = 0;
    char copyBuf[WFA_TRAFFIC_COPY_BUFFER];
    BYTE *dutRsp = cmdBuf+4;
    BYTE *startRsp = dutRsp;
    wfaTLV *ptlv = (wfaTLV *)cmdBuf;
    int len = ptlv->len;
    int numStreams = len/sizeof(dutCmdResponse_t);

    if (numStreams > WFA_MAX_TRAFFIC_STREAMS) {
        DPRINT_INFO(WFA_OUT, "numStreams is bigger the max traffic streams ...\n");
        return WFA_ERROR;
    }

    DPRINT_INFO(WFA_OUT, "Entering wfaTrafficAgentRecvStopResp ...\n");
    memset_s(gRespStr, WFA_BUFF_1K, 0, WFA_BUFF_1K);

    dutCmdResponse_t statResp[WFA_MAX_TRAFFIC_STREAMS];
    for(i=0; i<numStreams; i++)
    {
        dutRsp = startRsp + i * sizeof(dutCmdResponse_t);
        memcpy(&statResp[i], dutRsp, sizeof(dutCmdResponse_t));
    }
    for(i=0; i<numStreams; i++)
    {
        if(statResp[i].status != STATUS_COMPLETE)
            errorStatus = 1;
    }
    if(errorStatus)
    {
        sprintf(gRespStr, "status,ERROR");
    }
    else
    {
        sprintf(gRespStr, "status,COMPLETE,streamID,");
        for(i=0; i<numStreams; i++)
        {
            sprintf(copyBuf, " %d", statResp[i].streamId);
            strncat(gRespStr, copyBuf, sizeof(copyBuf)-1);
        }
        strncat(gRespStr, ",txFrames,", 10);
        for(i=0; i<numStreams; i++)
        {
            sprintf(copyBuf, " %u", statResp[i].cmdru.stats.txFrames);
            strncat(gRespStr, copyBuf, sizeof(copyBuf)-1);
        }
        strncat(gRespStr, ",rxFrames,", 10);
        for(i=0; i<numStreams; i++)
        {
            sprintf(copyBuf, " %u", statResp[i].cmdru.stats.rxFrames);
            strncat(gRespStr, copyBuf, sizeof(copyBuf)-1);
        }
        strncat(gRespStr, ",txPayloadBytes,", 16);
        for(i=0; i<numStreams; i++)
        {
            sprintf(copyBuf, " %llu", statResp[i].cmdru.stats.txPayloadBytes);
            strncat(gRespStr, copyBuf, sizeof(copyBuf)-1);
        }
        strncat(gRespStr, ",rxPayloadBytes,", 16);
        for(i=0; i<numStreams; i++)
        {
            sprintf(copyBuf, " %llu", statResp[i].cmdru.stats.rxPayloadBytes);
            strncat(gRespStr, copyBuf, sizeof(copyBuf)-1);
        }
        strncat(gRespStr, ",outOfSequenceFrames,", 21);
        for(i=0; i<numStreams; i++)
        {
            sprintf(copyBuf, " %d", statResp[i].cmdru.stats.outOfSequenceFrames);
            strncat(gRespStr, copyBuf, sizeof(copyBuf)-1);
        }
        strncat(gRespStr, "\r\n", 4);
    }

    sigma_uart_send(gRespStr, strlen(gRespStr));
    printf("gRespStr = %s", gRespStr);
    return done;

}

int wfaTrafficAgentPingStartResp(BYTE *cmdBuf)
{
    int done=0;
    dutCmdResponse_t *staPingResp = (dutCmdResponse_t *) (cmdBuf + 4);

    DPRINT_INFO(WFA_OUT, "Entering wfaTrafficAgentPingStartResp ...\n");
    memset_s(gRespStr, WFA_BUFF_1K, 0, WFA_BUFF_1K);

    switch(staPingResp->status)
    {
        case STATUS_RUNNING:
        DPRINT_INFO(WFA_OUT, "wfaTrafficAgentPingStart running ...\n");
        done = 1;
        break;

        case STATUS_COMPLETE:
        sprintf(gRespStr, "status,COMPLETE,streamID,%i\r\n", staPingResp->streamId);
        break;

        default:
        sprintf(gRespStr, "status,INVALID\r\n");
    }

    sigma_uart_send(gRespStr, strlen(gRespStr));
    DPRINT_INFO(WFA_OUT, " %s\n", gRespStr);

    return done;

}

int wfaTrafficAgentPingStopResp(BYTE *cmdBuf)
{
    int done=0;
    dutCmdResponse_t *stpResp = (dutCmdResponse_t *) (cmdBuf + 4);
    memset_s(gRespStr, WFA_BUFF_1K, 0, WFA_BUFF_1K);

    switch(stpResp->status)
    {
        case STATUS_RUNNING:
        DPRINT_INFO(WFA_OUT, "wfaTrafficAgentPingStop running ...\n");
        done = 1;
        break;

        case STATUS_COMPLETE:
        {
            sprintf(gRespStr, "status,COMPLETE,sent,%d,replies,%d\r\n",
                 stpResp->cmdru.pingStp.sendCnt,
                 stpResp->cmdru.pingStp.repliedCnt);
                 DPRINT_INFO(WFA_OUT, "%s\n", gRespStr);
            break;
        }

        default:
        sprintf(gRespStr, "status,INVALID\r\n");
        DPRINT_INFO(WFA_OUT, " %s\n", gRespStr);
    }

    sigma_uart_send(gRespStr, strlen(gRespStr));
    return done;

}

int wfaStaIsConnectedResp(BYTE *cmdBuf)
{
    int done=0;
    dutCmdResponse_t *connectedResp = (dutCmdResponse_t *)(cmdBuf + 4);

    DPRINT_INFO(WFA_OUT, "Entering wfaStaIsConnectedResp ...\n");
    memset_s(gRespStr, WFA_BUFF_1K, 0, WFA_BUFF_1K);

    switch(connectedResp->status)
    {
        case STATUS_RUNNING:
        DPRINT_INFO(WFA_OUT, "wfaStaIsConnectd running ...\n");
        done = 1;
        break;

        case STATUS_COMPLETE:
        sprintf(gRespStr, "status,COMPLETE,connected,%i\r\n", connectedResp->cmdru.connected);
        break;

        case STATUS_ERROR:
        sprintf(gRespStr, "status,ERROR\r\n");
        break;
        default:
        sprintf(gRespStr, "status,INVALID\r\n");
    }

    sigma_uart_send(gRespStr, strlen(gRespStr));

    return done;

}

int wfaStaGetBSSIDResp(BYTE *cmdBuf)
{
    int done=0;
    dutCmdResponse_t *getBssidResp = (dutCmdResponse_t *) (cmdBuf + 4);

    DPRINT_INFO(WFA_OUT, "Entering wfaStaGetBSSIDResp ...\n");
    memset_s(gRespStr, WFA_BUFF_1K, 0, WFA_BUFF_1K);

    switch(getBssidResp->status)
    {
        case STATUS_RUNNING:
        DPRINT_INFO(WFA_OUT, "wfaStaGetBSSID running ...\n");
        done = 1;
        break;

        case STATUS_COMPLETE:
        sprintf(gRespStr, "status,COMPLETE," "%02x:%02x:%02x:%02x:%02x:%02x\r\n", mac2str(getBssidResp->cmdru.bssid));
        printf("status,COMPLETE\n");
        break;
        case STATUS_ERROR:
        printf("status,ERROR\n");
        sprintf(gRespStr, "status,COMPLETE,mac,00:00:00:00:00:00\r\n");
        break;
        default:
        sprintf(gRespStr, "status,COMPLETE,mac,00:00:00:00:00:00\r\n");
        printf("unknown status\n");
    }
    sigma_uart_send(gRespStr, strlen(gRespStr));

    return done;

}

int wfaStaGetInfoResp(BYTE *cmdBuf)
{
    dutCmdResponse_t *infoResp = (dutCmdResponse_t *)(cmdBuf + 4);
    int done = 0;
    memset_s(gRespStr, WFA_BUFF_1K, 0, WFA_BUFF_1K);

    switch(infoResp->status)
    {
        case STATUS_RUNNING:
        DPRINT_INFO(WFA_OUT, "wfaStaGetInfo running ...\n");
        done = 1;
        break;

        case STATUS_COMPLETE:
        sprintf(gRespStr, "status,COMPLETE,%s\r\n", infoResp->cmdru.info);
        DPRINT_INFO(WFA_OUT, "info: %s\n", infoResp->cmdru.info);
        break;

        default:
        sprintf(gRespStr, "status,INVALID\r\n");
    }

    sigma_uart_send(gRespStr, strlen(gRespStr));

    return done;

}

int wfaDeviceGetInfoResp(BYTE *cmdBuf)
{
    int done=1;
    dutCmdResponse_t *devInfoResp = (dutCmdResponse_t *) (cmdBuf + 4);
    caDeviceGetInfoResp_t *dinfo = &devInfoResp->cmdru.devInfo;
    memset_s(gRespStr, WFA_BUFF_1K, 0, WFA_BUFF_1K);

    switch(devInfoResp->status)
    {
        case STATUS_RUNNING:
        DPRINT_INFO(WFA_OUT, "wfaDeviceGetInfo running ...\n");
        done = 1;
        break;

        case STATUS_COMPLETE:
        /*
        if(dinfo->firmware[0] != '\0' || dinfo->firmware[0] != '\n')
               sprintf(gRespStr, "status,COMPLETE,firmware,%s\r\n", dinfo->firmware);
        else
        */
        sprintf(gRespStr, "status,COMPLETE,vendor,%s,model,%s,version,%s\r\n",
            dinfo->vendor, dinfo->model, dinfo->version);
        DPRINT_INFO(WFA_OUT, "%s\n", gRespStr);
        break;

        default:
        sprintf(gRespStr, "status,INVALID\r\n");
        DPRINT_INFO(WFA_OUT, " %s\n", gRespStr);
    }

    sigma_uart_send(gRespStr, strlen(gRespStr));

    return done;

}

int wfaDeviceListIFResp(BYTE *cmdBuf)
{
    int done=0, i;
    dutCmdResponse_t *devListIfResp = (dutCmdResponse_t *) (cmdBuf + 4);
    caDeviceListIFResp_t *ifResp = &devListIfResp->cmdru.ifList;

    DPRINT_INFO(WFA_OUT, "DevList interface %d\n", devListIfResp->status);
    memset_s(gRespStr, WFA_BUFF_1K, 0, WFA_BUFF_1K);

    switch(devListIfResp->status)
    {
       case STATUS_RUNNING:
       DPRINT_INFO(WFA_OUT, "wfaDeviceListIF running ...\n");
       done = 1;
       break;

       case STATUS_COMPLETE:
       if(ifResp->iftype == IF_80211)
       {
          sprintf(gRespStr, "status,COMPLETE,interfaceType,802.11,interfaceID");
          DPRINT_INFO(WFA_OUT, "%s\n", gRespStr);
          DPRINT_INFO(WFA_OUT, "%s\n", ifResp->ifs[0]);
       }
       else if(ifResp->iftype == IF_ETH)
          sprintf(gRespStr, "status,COMPLETE,interfaceType,Ethernet,interfaceID");

       for(i=0; i<1; i++)
       {
         if(ifResp->ifs[i][0] != '\0')
         {
            strncat(gRespStr,",", 4);
            strncat(gRespStr, ifResp->ifs[i], sizeof(ifResp->ifs[i]));
            strncat(gRespStr, "\r\n", 4);
         }
       }

       DPRINT_INFO(WFA_OUT, "%s\n", gRespStr);
       break;

       default:
       sprintf(gRespStr, "status,INVALID\r\n");
       DPRINT_INFO(WFA_OUT, " %s\n", gRespStr);
    }

    sigma_uart_send(gRespStr, strlen(gRespStr));

    return done;

}

int wfaStaGetIpConfigResp(BYTE *cmdBuf)
{
    int done=0;
    dutCmdResponse_t *getIpConfigResp = (dutCmdResponse_t *) (cmdBuf + 4);

    DPRINT_INFO(WFA_OUT, "Entering wfaStaGetIpConfigResp ...\n");
    memset_s(gRespStr, WFA_BUFF_1K, 0, WFA_BUFF_1K);

    switch(getIpConfigResp->status)
    {
        case STATUS_RUNNING:
        DPRINT_INFO(WFA_OUT, "wfaStaGetIpConfig running ...\n");
        done = 1;
        break;

        case STATUS_ERROR:
        sprintf(gRespStr, "status,ERROR\r\n");
        break;

        case STATUS_COMPLETE:
        if(strlen(getIpConfigResp->cmdru.getIfconfig.dns[0]) == 0)
                *getIpConfigResp->cmdru.getIfconfig.dns[0] = '\0';
        if(strlen(getIpConfigResp->cmdru.getIfconfig.dns[1]) == 0)
                *getIpConfigResp->cmdru.getIfconfig.dns[1] = '\0';

        sprintf(gRespStr, "status,COMPLETE,dhcp,%i,ip,%s,mask,%s,primary-dns,%s,secondary-dns,%s\r\n",
                      getIpConfigResp->cmdru.getIfconfig.isDhcp,
                      getIpConfigResp->cmdru.getIfconfig.ipaddr,
                      getIpConfigResp->cmdru.getIfconfig.mask,
                      getIpConfigResp->cmdru.getIfconfig.dns[0],
                      getIpConfigResp->cmdru.getIfconfig.dns[1]);
        break;

        default:
        sprintf(gRespStr, "status,INVALID\r\n");
    }

    sigma_uart_send(gRespStr, strlen(gRespStr));
    return done;
}


int wfaGetVersionResp(BYTE *cmdBuf)
{
    int done=0;
    dutCmdResponse_t *getverResp =(dutCmdResponse_t *)(cmdBuf + 4);
    memset_s(gRespStr, WFA_BUFF_1K, 0, WFA_BUFF_1K);

    switch(getverResp->status)
    {
        case STATUS_RUNNING:
        DPRINT_INFO(WFA_OUT, "wfaGetVersion running ...\n");
        done = 1;
        break;

        case STATUS_COMPLETE:
        sprintf(gRespStr, "status,COMPLETE,version,%s\r\n", getverResp->cmdru.version);
        break;
        default:
        sprintf(gRespStr, "status,INVALID\r\n");
    }

    sigma_uart_send(gRespStr, strlen(gRespStr));

    return done ;
}

int wfaStaGetMacAddressResp(BYTE *cmdBuf)
{
    int done=0;
    dutCmdResponse_t *getmacResp = (dutCmdResponse_t *) (cmdBuf + 4);

    DPRINT_INFO(WFA_OUT, "Entering wfaStaGetMacAddressResp ...\n");
    memset_s(gRespStr, WFA_BUFF_1K, 0, WFA_BUFF_1K);

    switch(getmacResp->status)
    {
        case STATUS_RUNNING:
        DPRINT_INFO(WFA_OUT, "wfaStaGetMacAddress running ...\n");
        done = 1;
        break;

        case STATUS_COMPLETE:
            sprintf(gRespStr, "status,COMPLETE," "%02x:%02x:%02x:%02x:%02x:%02x\r\n", mac2str(getmacResp->cmdru.mac));
            printf("status,COMPLETE\n");
        break;

        case STATUS_ERROR:
        printf("status,ERROR\n");
        sprintf(gRespStr, "status,COMPLETE,mac,00:00:00:00:00:00\r\n");
        break;

        default:
        sprintf(gRespStr, "status,COMPLETE,mac,00:00:00:00:00:00\r\n");
        printf("unknown status\n");
    }

    sigma_uart_send(gRespStr, strlen(gRespStr));

    return done ;
}

int wfaStaSetEncryptionResp(BYTE *cmdBuf)
{
    int done=0;
    dutCmdResponse_t *getBssidResp = (dutCmdResponse_t *) (cmdBuf + 4);

    DPRINT_INFO(WFA_OUT, "Entering wfaStaSetEncryptionResp ...\n");
    memset_s(gRespStr, WFA_BUFF_1K, 0, WFA_BUFF_1K);

    switch(getBssidResp->status)
    {
        case STATUS_RUNNING:
        DPRINT_INFO(WFA_OUT, "wfaStaSetEncryption running ...\n");
        done = 1;
        break;

        case STATUS_COMPLETE:
        sprintf(gRespStr, "status,COMPLETE\r\n");
        printf("status,COMPLETE\r\n");
        DPRINT_INFO(WFA_OUT, " %s\n", gRespStr);
        break;

        case STATUS_ERROR:
        sprintf(gRespStr, "status,ERROR\r\n");
        printf("status,ERROR\r\n");
        break;

        default:
        sprintf(gRespStr, "status,INVALID\r\n");
        DPRINT_INFO(WFA_OUT, " %s\n", gRespStr);
    }

    sigma_uart_send(gRespStr, strlen(gRespStr));

    return done;
}


int wfaStaGenericResp(BYTE *cmdBuf)
{
    int done=0;
    dutCmdResponse_t *setwmmResp = (dutCmdResponse_t *) (cmdBuf + 4);
    memset_s(gRespStr, WFA_BUFF_1K, 0, WFA_BUFF_1K);

    switch(setwmmResp->status)
    {
        case STATUS_RUNNING:
        done = 1;
        break;

        case STATUS_COMPLETE:
        sprintf(gRespStr, "status,COMPLETE\r\n");
        printf("status,COMPLETE\r\n");
        DPRINT_INFO(WFA_OUT, " %s\n", gRespStr);
        break;

        case STATUS_ERROR:
        sprintf(gRespStr, "status,ERROR\r\n");
        printf("status,COMPLETE\r\n");
        DPRINT_INFO(WFA_OUT, " %s\n", gRespStr);
        break;

        default:
        sprintf(gRespStr, "status,INVALID\r\n");
        DPRINT_INFO(WFA_OUT, " %s\n", gRespStr);
    }

    sigma_uart_send(gRespStr, strlen(gRespStr));

    return done;
}

int wfaApGenericResp(BYTE *cmdBuf)
{
    int done=0;
    dutCmdResponse_t *setwmmResp = (dutCmdResponse_t *) (cmdBuf + 4);
    memset_s(gRespStr, WFA_BUFF_1K, 0, WFA_BUFF_1K);

    switch(setwmmResp->status)
    {
        case STATUS_RUNNING:
        done = 1;
        break;

        case STATUS_COMPLETE:
        sprintf(gRespStr, "status,COMPLETE\r\n");
        printf("status,COMPLETE\r\n");
        DPRINT_INFO(WFA_OUT, " %s\n", gRespStr);
        break;

        case STATUS_ERROR:
        sprintf(gRespStr, "status,ERROR\r\n");
        printf("status,COMPLETE\r\n");
        DPRINT_INFO(WFA_OUT, " %s\n", gRespStr);
        break;

        default:
        sprintf(gRespStr, "status,INVALID\r\n");
        DPRINT_INFO(WFA_OUT, " %s\n", gRespStr);
    }

    sigma_uart_send(gRespStr, strlen(gRespStr));

    return done;
}

int wfaApGetMacAddrResp(BYTE *cmdBuf)
{
    int done=0;
    dutCmdResponse_t *getmacResp = (dutCmdResponse_t *) (cmdBuf + 4);
    DPRINT_INFO(WFA_OUT, "Entering wfaApGetMacAddrResp ...\n");
    memset_s(gRespStr, WFA_BUFF_1K, 0, WFA_BUFF_1K);

    switch(getmacResp->status)
    {
        case STATUS_RUNNING:
        DPRINT_INFO(WFA_OUT, "wfaApGetMacAddrResp running ...\n");
        done = 1;
        break;

        case STATUS_COMPLETE:
        sprintf(gRespStr, "status,COMPLETE," MACSTR, mac2str(getmacResp->cmdru.mac));
        printf("status,COMPLETE\n");
        break;

        case STATUS_ERROR:
        printf("status,ERROR\n");
        sprintf(gRespStr, "status,COMPLETE,mac,00:00:00:00:00:00\r\n");
        break;

        default:
        sprintf(gRespStr, "status,COMPLETE,mac,00:00:00:00:00:00\r\n");
        printf("unknown status\n");
    }

    sigma_uart_send(gRespStr, strlen(gRespStr));
    return done ;
}

int wfaApCaVersionResp(BYTE *cmdBuf)
{
    int done=0;
    dutCmdResponse_t *getverResp =(dutCmdResponse_t *)(cmdBuf + 4);
    memset_s(gRespStr, WFA_BUFF_1K, 0, WFA_BUFF_1K);

    switch(getverResp->status)
    {
        case STATUS_RUNNING:
        DPRINT_INFO(WFA_OUT, "wfaApCaVersion running ...\n");
        done = 1;
        break;

        case STATUS_COMPLETE:
        sprintf(gRespStr, "status,COMPLETE,%s\r\n", getverResp->cmdru.version);
        break;
        default:
        sprintf(gRespStr, "status,INVALID\r\n");
    }

    sigma_uart_send(gRespStr, strlen(gRespStr));
    return done ;
}

int wfaApGetInfoResp(BYTE *cmdBuf)
{
    int done=1;
    dutCmdResponse_t *devInfoResp = (dutCmdResponse_t *) (cmdBuf + 4);
    memset_s(gRespStr, WFA_BUFF_1K, 0, WFA_BUFF_1K);

    switch(devInfoResp->status)
    {
        case STATUS_RUNNING:
        DPRINT_INFO(WFA_OUT, "wfaDeviceGetInfo running ...\n");
        done = 1;
        break;

        case STATUS_COMPLETE:
        sprintf(gRespStr, "status,COMPLETE,%s,%s,%s,%s\r\n",
            "interface","24G",devInfoResp->cmdru.version, devInfoResp->cmdru.devInfo.firmware);
        DPRINT_INFO(WFA_OUT, "%s\n", gRespStr);
        break;

        default:
        sprintf(gRespStr, "status,INVALID\r\n");
        DPRINT_INFO(WFA_OUT, " %s\n", gRespStr);
    }

    sigma_uart_send(gRespStr, strlen(gRespStr));
    return done;
}

