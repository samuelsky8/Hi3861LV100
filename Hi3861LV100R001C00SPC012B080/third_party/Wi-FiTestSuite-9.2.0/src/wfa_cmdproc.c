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
 *      File: wfa_cmdproc.c
 *      Library functions to handle all string command parsing and convert it
 *      to an internal format for DUT. They should be called by Control Agent
 *      and Test console while receiving commands from CLI or TM
 *
 */

#include <stdio.h>
#include "string.h"
#include "wfa_debug.h"
#include "wfa_types.h"
#include "wfa_tlv.h"
#include "wfa_tg.h"
#include "wfa_ca.h"
#include "wfa_cmds.h"
#include "wfa_miscs.h"
#include "wfa_agtctrl.h"
#include <stdlib.h>

extern void printProfile(tgProfile_t *);
int wfaStandardBoolParsing (char *str);

/* command KEY WORD String table */
typeNameStr_t keywordStr[] =
{
    { KW_PROFILE,      "profile",       NULL},
    { KW_DIRECTION,    "direction",     NULL},
    { KW_DIPADDR,      "destination",   NULL},
    { KW_DPORT,        "destinationport",  NULL},
    { KW_SIPADDR,      "source",        NULL},
    { KW_SPORT,        "sourceport",    NULL},
    { KW_FRATE,        "framerate",     NULL},
    { KW_DURATION,     "duration",      NULL},
    { KW_PLOAD,        "payloadsize",   NULL},
    { KW_TCLASS,       "trafficClass",  NULL},    /* It is to indicate WMM traffic pattern */
    { KW_STREAMID,     "streamid",      NULL},
    { KW_STARTDELAY,   "startdelay",    NULL},     /* It is used to schedule multi-stream test such as WMM */
    { KW_NUMFRAME,     "numframes",     NULL},
    { KW_USESYNCCLOCK, "useSyncClock",  NULL},
    { KW_USERPRIORITY, "userpriority",  NULL},
    { KW_MAXCNT,       "maxcnt",        NULL},
};

/* profile type string table */
typeNameStr_t profileStr[] =
{
    { PROF_FILE_TX, "file_transfer", NULL},
    { PROF_MCAST,   "multicast",     NULL},
    { PROF_IPTV,    "iptv",          NULL},       /* This is used for WMM, confused? */
    { PROF_TRANSC,  "transaction",   NULL},       /* keep for temporary backward compat., will be removed */
    { PROF_START_SYNC,    "start_sync",    NULL},
    { PROF_CALI_RTD,    "cali_rtd",    NULL},
    { PROF_UAPSD,  "uapsd",   NULL}
};

/* direction string table */
typeNameStr_t direcStr[] =
{
    { DIRECT_SEND,  "send",          NULL},
    { DIRECT_RECV,  "receive",       NULL}
};


/*
 * cmdProcNotDefinedYet(): a dummy function
 */
int cmdProcNotDefinedYet(char *pcmdStr, char *buf, int *len)
{
    printf("The command processing function not defined.\n");
    hi_unref_param(pcmdStr);
    hi_unref_param(buf);
    hi_unref_param(len);
    /* need to send back a response */

    return (WFA_SUCCESS);
}

/*
 *  xcCmdProcGetVersion(): process the command get_version string from TM
 *                         to convert it into a internal format
 *  input:        pcmdStr -- a string pointer to the command string
 */
int xcCmdProcGetVersion(char *pcmdStr, BYTE *aBuf, int *aLen)
{
    printf("start xcCmdProcGetVersion ...\n");
    hi_unref_param(pcmdStr);
    if (aBuf == NULL) {
        printf("%s line%d\r\n", __FUNCTION__, __LINE__);
        return WFA_FAILURE;
    }
    /* encode the tag without values */
    wfaEncodeTLV(WFA_GET_VERSION_TLV, 0, NULL, aBuf);

    *aLen = 4;

    return WFA_SUCCESS;
}

/*
 *  xcCmdProcAgentConfig(): process the command traffic_agent_config string
 *                          from TM to convert it into a internal format
 *  input:        pcmdStr -- a string pointer to the command string
 */
int xcCmdProcAgentConfig(char *pcmdStr, BYTE *aBuf, int *aLen)
{
    char *str;
    unsigned int i = 0;
    int j = 0;
    int kwcnt = 0;
    wfaTLV *hdr = (wfaTLV *)aBuf;
    tgProfile_t tgpf = {0, 0, "", -1, "", -1, 0, 0, 0, TG_WMM_AC_BE, 0, 0};
    tgProfile_t *pf = &tgpf;
    int userPrio = 0;

    DPRINT_INFO(WFA_OUT, "start xcCmdProcAgentConfig ...\n");
    DPRINT_INFO(WFA_OUT, "params:  %s\n", pcmdStr);

    if(aBuf == NULL)
        return WFA_FAILURE;

    while((str = strtok_r(NULL, ",", (char **)&pcmdStr)) != NULL)
    {
        for(i = 0; i<sizeof(keywordStr)/sizeof(typeNameStr_t); i++)
        {
            if(strcasecmp(str, keywordStr[i].name) == 0)
            {
                switch(keywordStr[i].type)
                {
                case  KW_PROFILE:
                    str = strtok_r(NULL, ",", (char **)&pcmdStr);
                    if(isString(str) == WFA_FAILURE)
                    {
                        DPRINT_ERR(WFA_ERR, "Incorrect profile keyword format\n");
                        return WFA_FAILURE;
                    }

                    for(j = 0; j < PROF_LAST; j++)
                    {
                        if(strcasecmp(str, profileStr[j].name) == 0)
                        {
                            pf->profile = profileStr[j].type;
                        }
                    }

                    DPRINT_INFO(WFA_OUT, "profile type %i\n", pf->profile);
                    kwcnt++;
                    str = NULL;
                    break;

                case KW_DIRECTION:
                    str = strtok_r(NULL, ",", (char **)&pcmdStr);
                    if(isString(str) == WFA_FAILURE)
                    {
                        DPRINT_ERR(WFA_ERR, "Incorrect direction keyword format\n");
                        return WFA_FAILURE;
                    }

                    if(strcasecmp(str, "send") == 0)
                    {
                        pf->direction = DIRECT_SEND;
                    }
                    else if(strcasecmp(str, "receive") == 0)
                    {
                        pf->direction = DIRECT_RECV;
                    }
                    else
                        printf("Don't know direction\n");

                    DPRINT_INFO(WFA_OUT, "direction %i\n", pf->direction);
                    kwcnt++;
                    str = NULL;
                    break;

                case KW_DIPADDR: /* dest ip address */
                    memcpy(pf->dipaddr, strtok_r(NULL, ",", &pcmdStr), IPV4_ADDRESS_STRING_LEN);
                    if(isIpV4Addr(pf->dipaddr) == WFA_FAILURE)
                    {
                        DPRINT_ERR(WFA_ERR, "Incorrect ipaddr format\n");
                        return WFA_FAILURE;
                    }
                    DPRINT_INFO(WFA_OUT, "dipaddr %s\n", pf->dipaddr);

                    kwcnt++;
                    str = NULL;
                    break;

                case KW_DPORT:
                    str = strtok_r(NULL, ",", &pcmdStr);
                    if(isNumber(str) == WFA_FAILURE)
                    {
                        DPRINT_ERR(WFA_ERR, "Incorrect port number format\n");
                        return WFA_FAILURE;
                    }
                    DPRINT_INFO(WFA_OUT, "dport %s\n", str);
                    pf->dport = atoi(str);

                    kwcnt++;
                    str = NULL;
                    break;

                case KW_SIPADDR:
                    memcpy(pf->sipaddr, strtok_r(NULL, ",", &pcmdStr), IPV4_ADDRESS_STRING_LEN);

                    if(isIpV4Addr(pf->sipaddr) == WFA_FAILURE)
                    {
                        DPRINT_ERR(WFA_ERR, "Incorrect ipaddr format\n");
                        return WFA_FAILURE;
                    }
                    DPRINT_INFO(WFA_OUT, "sipaddr %s\n", pf->sipaddr);
                    kwcnt++;
                    str = NULL;
                    break;

                case KW_SPORT:
                    str = strtok_r(NULL, ",", &pcmdStr);
                    if(isNumber(str) == WFA_FAILURE)
                    {
                        DPRINT_ERR(WFA_ERR, "Incorrect port number format\n");
                        return WFA_FAILURE;
                    }
                    DPRINT_INFO(WFA_OUT, "sport %s\n", str);
                    pf->sport = atoi(str);

                    kwcnt++;
                    str = NULL;
                    break;

                case KW_FRATE:
                    str = strtok_r(NULL, ",", &pcmdStr);
                    if(isNumber(str) == WFA_FAILURE)
                    {
                        DPRINT_ERR(WFA_ERR, "Incorrect frame rate format\n");
                        return WFA_FAILURE;
                    }
                    DPRINT_INFO(WFA_OUT, "framerate %s\n", str);
                    pf->rate = atoi(str);
                    kwcnt++;
                    str = NULL;
                    break;

                case KW_DURATION:
                    str = strtok_r(NULL, ",", &pcmdStr);
                    if(isNumber(str) == WFA_FAILURE)
                    {
                        DPRINT_ERR(WFA_ERR, "Incorrect duration format\n");
                        return WFA_FAILURE;
                    }
                    DPRINT_INFO(WFA_OUT, "duration %s\n", str);
                    pf->duration = atoi(str);
                    kwcnt++;
                    str = NULL;
                    break;

                case KW_PLOAD:
                    str = strtok_r(NULL, ",", &pcmdStr);
                    if(isNumber(str) == WFA_FAILURE)
                    {
                        DPRINT_ERR(WFA_ERR, "Incorrect payload format\n");
                        return WFA_FAILURE;
                    }
                    DPRINT_INFO(WFA_OUT, "payload %s\n", str);
                    pf->pksize = atoi(str);
                    kwcnt++;
                    str = NULL;
                    break;

                case KW_STARTDELAY:
                    str = strtok_r(NULL, ",", &pcmdStr);
                    if(isNumber(str) == WFA_FAILURE)
                    {
                        DPRINT_ERR(WFA_ERR, "Incorrect startDelay format\n");
                        return WFA_FAILURE;
                    }
                    DPRINT_INFO(WFA_OUT, "startDelay %s\n", str);
                    pf->startdelay = atoi(str);
                    kwcnt++;
                    str = NULL;
                    break;

                case KW_MAXCNT:
                    str = strtok_r(NULL, ",", &pcmdStr);
                    if(isNumber(str) == WFA_FAILURE)
                    {
                        DPRINT_ERR(WFA_ERR, "Incorrect max count format\n");
                        return WFA_FAILURE;
                    }
                    pf->maxcnt = atoi(str);
                    kwcnt++;
                    str = NULL;
                    break;

                case KW_TCLASS:
                    str = strtok_r(NULL, ",", &pcmdStr);

                    // if user priority is used, tclass is ignored.
                    if(userPrio == 1)
                        break;

                    if(strcasecmp(str, "voice") == 0 )
                    {
                        pf->trafficClass = TG_WMM_AC_VO;
                    }
                    else if(strcasecmp(str, "Video") == 0 )
                    {
                        pf->trafficClass = TG_WMM_AC_VI;
                    }
                    else if(strcasecmp(str, "Background") == 0 )
                    {
                        pf->trafficClass = TG_WMM_AC_BK;
                    }
                    else if(strcasecmp(str, "BestEffort") == 0 )
                    {
                        pf->trafficClass = TG_WMM_AC_BE;
                    }
                    else
                    {
                        pf->trafficClass = TG_WMM_AC_BE;
                    }

                    kwcnt++;
                    str = NULL;
                    break;

                case KW_USERPRIORITY:
                    str = strtok_r(NULL, ",", &pcmdStr);

                    if( strcasecmp(str, "6") == 0 )
                    {
                        pf->trafficClass = TG_WMM_AC_UP6;
                    }
                    else if( strcasecmp(str, "7") == 0 )
                    {
                        pf->trafficClass = TG_WMM_AC_UP7;
                    }
                    else if( strcasecmp(str, "5") == 0 )
                    {
                        pf->trafficClass = TG_WMM_AC_UP5;
                    }
                    else if( strcasecmp(str, "4") == 0 )
                    {
                        pf->trafficClass = TG_WMM_AC_UP4;
                    }
                    else if( strcasecmp(str, "1") == 0 )
                    {
                        pf->trafficClass = TG_WMM_AC_UP1;
                    }
                    else if( strcasecmp(str, "2") == 0 )
                    {
                        pf->trafficClass = TG_WMM_AC_UP2;
                    }
                    else if( strcasecmp(str, "0") == 0 )
                    {
                        pf->trafficClass = TG_WMM_AC_UP0;
                    }
                    else if( strcasecmp(str, "3") == 0)
                    {
                        pf->trafficClass = TG_WMM_AC_UP3;
                    }

                    // if User Priority is used
                    userPrio = 1;

                    kwcnt++;
                    str = NULL;
                    break;

                case KW_STREAMID:
                    kwcnt++;
                    break;

                case KW_NUMFRAME:
                    str = strtok_r(NULL, ",", &pcmdStr);
                    if(isNumber(str) == WFA_FAILURE)
                    {
                        DPRINT_ERR(WFA_ERR, "Incorrect numframe format\n");
                        return WFA_FAILURE;
                    }
                    DPRINT_INFO(WFA_OUT, "num frame %s\n", str);
                    kwcnt++;
                    str = NULL;
                    break;

                case KW_USESYNCCLOCK:
                    str = strtok_r(NULL, ",", &pcmdStr);
                    if(isNumber(str) == WFA_FAILURE)
                    {
                        DPRINT_ERR(WFA_ERR, "Incorrect sync clock format\n");
                        return WFA_FAILURE;
                    }
                    DPRINT_INFO(WFA_OUT, "sync clock %s\n", str);
                    kwcnt++;
                    str = NULL;
                    break;

                default:
                    ;
                } /* switch */

                if(str==NULL)
                    break;
            }  /* if */
        } /* for */
    } /* while */

#if 0
    if(kwcnt < 8)
    {
        printf("Incorrect command, missing parameters\n");
        return WFA_FAILURE;
    }
#endif

    printProfile(pf);
    hdr->tag =  WFA_TRAFFIC_AGENT_CONFIG_TLV;
    hdr->len = sizeof(tgProfile_t);

    memcpy(aBuf+4, pf, sizeof(tgpf));

    *aLen = 4+sizeof(tgProfile_t);

    return WFA_SUCCESS;
}

/*
 * xcCmdProcAgentSend(): Process and send the Control command
 *                       "traffic_agent_send"
 * input - pcmdStr  parameter string pointer
 * return - WFA_SUCCESS or WFA_FAILURE;
 */
int xcCmdProcAgentSend(char *pcmdStr, BYTE *aBuf, int *aLen)
{
    wfaTLV *hdr = (wfaTLV *)aBuf;
    char *str, *sid;
    int strid;
    int id_cnt = 0;

    if(aBuf == NULL)
        return WFA_FAILURE;

    memset(aBuf, 0, 512);

    DPRINT_INFO(WFA_OUT, "Entering xcCmdProcAgentSend ...\n");
    /* there is only one stream for baseline. Will support
     * multiple streams later.
     */
    str = strtok_r(NULL, ",", &pcmdStr);

    if(str == NULL || str[0] == '\0')
        return WFA_FAILURE;

    /* take the stream ids */
    if(strcasecmp(str, "streamid") != 0)
    {
        DPRINT_ERR(WFA_ERR, "invalid type name\n");
        return WFA_FAILURE;
    }

    /*
     * To handle there are multiple stream ids such as WMM
     */
    while(1)
    {
        sid = strtok_r (NULL, " ", &pcmdStr);
        if(sid == NULL)
            break;

        printf("sid %s\n", sid);
        if(isNumber(sid) == WFA_FAILURE)
            continue;

        strid = atoi(sid);
        printf("id %i\n", strid);
        id_cnt++;

        memcpy(aBuf+4*id_cnt, (char *)&strid, 4);
    }

    hdr->tag =  WFA_TRAFFIC_AGENT_SEND_TLV;
    hdr->len = 4*id_cnt;  /* multiple 4s if more streams */

    *aLen = 4 + 4*id_cnt;

#if 1
    {
        int i;
        for(i = 0; i< *aLen; i++)
            printf("%x ", aBuf[i]);

        printf("\n");
    }
#endif


    return WFA_SUCCESS;
}

/*
 * xcCmdProcAgentReset(): Process and send the Control command
 *                       "traffic_agent_reset"
 * input - pcmdStr  parameter string pointer
 * return - WFA_SUCCESS or WFA_FAILURE;
 */
int xcCmdProcAgentReset(char *pcmdStr, BYTE *aBuf, int *aLen)
{
    wfaTLV *hdr = (wfaTLV *)aBuf;
    hi_unref_param(pcmdStr);
    DPRINT_INFO(WFA_OUT, "Entering xcCmdProcAgentReset ...\n");

    if(aBuf == NULL)
        return WFA_FAILURE;

    memset(aBuf, 0, *aLen);

    hdr->tag =  WFA_TRAFFIC_AGENT_RESET_TLV;
    hdr->len = 0;  /* multiple 4s if more streams */

    *aLen = 4;

    return WFA_SUCCESS;
}

/*
 * xcCmdProcAgentRecvStart(): Process and send the Control command
 *                       "traffic_agent_receive_start"
 * input - pcmdStr  parameter string pointer
 * return - WFA_SUCCESS or WFA_FAILURE;
 */
int xcCmdProcAgentRecvStart(char *pcmdStr, BYTE *aBuf, int *aLen)
{

    wfaTLV *hdr = (wfaTLV *)aBuf;
    char *str, *sid;
    int strid;
    int id_cnt = 0;

    DPRINT_INFO(WFA_OUT, "Entering xcCmdProcAgentRecvStart ...%s\n", pcmdStr);

    if(aBuf == NULL)
        return WFA_FAILURE;

    memset(aBuf, 0, *aLen);

    /* there is only one stream for baseline. Will support
     * multiple streams later.
     */
    str = strtok_r(NULL, ",", &pcmdStr);

    if(str == NULL || str[0] == '\0')
    {
        DPRINT_ERR(WFA_ERR, "Null string\n");
        return WFA_FAILURE;
    }


    if(strcasecmp(str, "streamid") != 0)
    {
        DPRINT_ERR(WFA_ERR, "invalid type name\n");
        return WFA_FAILURE;
    }

    while(1)
    {
        sid = strtok_r (NULL, " ", &pcmdStr);
        if(sid == NULL)
            break;

        if(isNumber(sid) == WFA_FAILURE)
            continue;

        strid = atoi(sid);
        id_cnt++;

        memcpy(aBuf+4*id_cnt, (char *)&strid, 4);
    }

    hdr->tag =  WFA_TRAFFIC_AGENT_RECV_START_TLV;
    hdr->len = 4*id_cnt;  /* multiple 4s if more streams */

    *aLen = 4 + 4*id_cnt;

#if 1
    {
        int i;
        for(i = 0; i< *aLen; i++)
            printf("%x ", aBuf[i]);

        printf("\n");
    }
#endif
    return WFA_SUCCESS;
}

/*
 * xcCmdProcAgentRecvStop(): Process and send the Control command
 *                       "traffic_agent_receive_stop"
 * input - pcmdStr  parameter string pointer
 * return - WFA_SUCCESS or WFA_FAILURE;
 */
int xcCmdProcAgentRecvStop(char *pcmdStr, BYTE *aBuf, int *aLen)
{
    wfaTLV *hdr = (wfaTLV *)aBuf;
    char *str, *sid;
    int strid;
    int id_cnt = 0;

    DPRINT_INFO(WFA_OUT, "Entering xcCmdProcAgentRecvStop ...\n");

    if(aBuf == NULL)
        return WFA_FAILURE;

    memset(aBuf, 0, *aLen);

    /* there is only one stream for baseline. Will support
     * multiple streams later.
     */
    str = strtok_r(NULL, ",", &pcmdStr);

    if(str == NULL || str[0] == '\0')
        return WFA_FAILURE;

    if(strcasecmp(str, "streamid") != 0)
    {
        DPRINT_ERR(WFA_ERR, "invalid type name\n");
        return WFA_FAILURE;
    }
    while(1)
    {
        sid = strtok_r (NULL, " ", &pcmdStr);
        if(sid == NULL)
            break;

        if(isNumber(sid) == WFA_FAILURE)
            continue;

        strid = atoi(sid);
        id_cnt++;

        memcpy(aBuf+4*id_cnt, (char *)&strid, 4);
    }

    hdr->tag =  WFA_TRAFFIC_AGENT_RECV_STOP_TLV;
    hdr->len = 4*id_cnt;  /* multiple 4s if more streams */

    *aLen = 4 + 4*id_cnt;

    return WFA_SUCCESS;
}

int xcCmdProcAgentSendPing(char *pcmdStr, BYTE *aBuf, int *aLen)
{
    wfaTLV *hdr = (wfaTLV *)aBuf;
    tgPingStart_t *staping = (tgPingStart_t *) (aBuf+sizeof(wfaTLV));
    char *str;

    if(aBuf == NULL){
        return WFA_FAILURE;
    }
    memset(aBuf, 0, *aLen);

    for(;;)
    {
        str = strtok_r(NULL, ",", &pcmdStr);
        if(str == NULL || str[0] == '\0')
            break;

        if(strcasecmp(str, "destination") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            strncpy(staping->dipaddr, str, 39);
            DPRINT_INFO(WFA_OUT, "destination %s\n", staping->dipaddr);
        }
        if(strcasecmp(str, "frameSize") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            staping->frameSize=atoi(str);
            DPRINT_INFO(WFA_OUT, "framesize %i\n", staping->frameSize);
        }
        if(strcasecmp(str, "frameRate") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            staping->frameRate=atoi(str);
            DPRINT_INFO(WFA_OUT, "framerate %d\n", staping->frameRate);
        }
        if(strcasecmp(str, "duration") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            staping->duration=atoi(str);
            DPRINT_INFO(WFA_OUT, "duration %i\n", staping->duration);
        }
        if(strcasecmp(str, "iptype") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            staping->iptype=atoi(str);
            DPRINT_INFO(WFA_OUT, "iptype %i\n", staping->iptype);
        }
    }

    hdr->tag =  WFA_TRAFFIC_SEND_PING_TLV;
    hdr->len = sizeof(tgPingStart_t);

    *aLen = hdr->len + 4;

    return WFA_SUCCESS;
}

int xcCmdProcAgentStopPing(char *pcmdStr, BYTE *aBuf, int *aLen)
{
    wfaTLV *hdr = (wfaTLV *)aBuf;
    char *str;
    int strid;
    str = strtok_r(NULL, ",", &pcmdStr);

    if(aBuf == NULL)
        return WFA_FAILURE;

    memset(aBuf, 0, *aLen);

    if(str == NULL || str[0] == '\0')
        return WFA_FAILURE;

    if(strcasecmp(str, "streamid") == 0)
        str = strtok_r(NULL, ",", &pcmdStr);
    else
    {
        DPRINT_ERR(WFA_ERR, "invalid type name\n");
        return WFA_FAILURE;
    }

    if(isNumber(str) == WFA_FAILURE)
        return WFA_FAILURE;

    strid = atoi(str);

    memcpy(aBuf+4, (char *)&strid, 4);

    hdr->tag =  WFA_TRAFFIC_STOP_PING_TLV;
    hdr->len = 4;  /* multiple 4s if more streams */

    *aLen = 8;

    return WFA_SUCCESS;
}

int xcCmdProcStaGetIpConfig(char *pcmdStr, BYTE *aBuf, int *aLen)
{
    int slen;
    char *str = NULL;
    dutCommand_t getipconf;
    memset(&getipconf, 0, sizeof(dutCommand_t));

    DPRINT_INFO(WFA_OUT, "Entering xcCmdProcStaGetIpConfig ...\n");

    if(aBuf == NULL)
        return WFA_FAILURE;

    memset(aBuf, 0, *aLen);

    str = strtok_r(NULL, ",", &pcmdStr);
    str = strtok_r(NULL, ",", &pcmdStr);
    if(str == NULL)
        return WFA_FAILURE;


    slen = strlen(str);
    memcpy(getipconf.intf, str, slen);
    wfaEncodeTLV(WFA_STA_GET_IP_CONFIG_TLV, sizeof(dutCommand_t), (BYTE *)&getipconf, aBuf);

    *aLen = 4+sizeof(getipconf);

    return WFA_SUCCESS;
}

int xcCmdProcStaSetIpConfig(char *pcmdStr, BYTE *aBuf, int *aLen)
{
    dutCommand_t staSetIpConfig;
    caStaSetIpConfig_t *setip = (caStaSetIpConfig_t *)&staSetIpConfig.cmdsu.ipconfig;
    caStaSetIpConfig_t defparams = {"", 0, "", "", "", "", "", 1};
    char *str;

    if(aBuf == NULL)
        return WFA_FAILURE;

    memset(aBuf, 0, *aLen);
    memcpy(setip, &defparams, sizeof(caStaSetIpConfig_t));

    for(;;)
    {
        str = strtok_r(NULL, ",", &pcmdStr);
        if(str == NULL || str[0] == '\0')
            break;

        if(strcasecmp(str, "interface") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            strncpy(setip->intf, str, 15);
            DPRINT_INFO(WFA_OUT, "interface %s\n", setip->intf);
        }
        else if(strcasecmp(str, "dhcp") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            setip->isDhcp = atoi(str);
            DPRINT_INFO(WFA_OUT, "dhcp %i\n", setip->isDhcp);
        }
        else if(strcasecmp(str, "ip") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            strncpy(setip->ipaddr, str, 15);
            DPRINT_INFO(WFA_OUT, "ip %s\n", setip->ipaddr);
        }
        else if(strcasecmp(str, "mask") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            strncpy(setip->mask, str, 15);
            DPRINT_INFO(WFA_OUT, "mask %s\n", setip->mask);
        }
        else if(strcasecmp(str, "defaultGateway") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            strncpy(setip->defGateway, str, 15);
            DPRINT_INFO(WFA_OUT, "gw %s\n", setip->defGateway);
        }
        else if(strcasecmp(str, "primary-dns") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            strncpy(setip->pri_dns, str, 15);
            DPRINT_INFO(WFA_OUT, "dns p %s\n", setip->pri_dns);
        }
        else if(strcasecmp(str, "secondary-dns") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            strncpy(setip->sec_dns, str, 15);
            DPRINT_INFO(WFA_OUT, "dns s %s\n", setip->sec_dns);
        }
        else if(strcasecmp(str, "type") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            setip->type = atoi(str);
            DPRINT_INFO(WFA_OUT, "type %i\n", setip->type);
        }
        else
        {
            DPRINT_ERR(WFA_ERR, "invalid command %s\n",str);
            return WFA_FAILURE;
        }
    }

    wfaEncodeTLV(WFA_STA_SET_IP_CONFIG_TLV, sizeof(staSetIpConfig), (BYTE *)&staSetIpConfig, aBuf);

    *aLen = 4+sizeof(staSetIpConfig);

    return WFA_SUCCESS;
}

int xcCmdProcStaGetMacAddress(char *pcmdStr, BYTE *aBuf, int *aLen)
{
    int slen;
    char *str = NULL;
    dutCommand_t getmac;

    DPRINT_INFO(WFA_OUT, "Entering xcCmdProcStaGetMacAddress ...\n");

    if(aBuf == NULL)
        return WFA_FAILURE;

    memset(aBuf, 0, *aLen);

    memset(&getmac, 0, sizeof(getmac));
    str = strtok_r(NULL, ",", &pcmdStr);
    str = strtok_r(NULL, ",", &pcmdStr);
    if(str == NULL)
        return WFA_FAILURE;

    slen = strlen(str);
    memcpy(getmac.intf, str, slen);
    wfaEncodeTLV(WFA_STA_GET_MAC_ADDRESS_TLV, sizeof(getmac), (BYTE *)&getmac, aBuf);

    *aLen = 4+sizeof(getmac);

    return WFA_SUCCESS;
}

int xcCmdProcStaSetMacAddress(char *pcmdStr, BYTE *aBuf, int *aLen)
{
    char *str = NULL;
    dutCommand_t setmac;

    DPRINT_INFO(WFA_OUT, "Entering xcCmdProcStaSetMacAddress ...\n");

    if(aBuf == NULL)
        return WFA_FAILURE;

    memset(aBuf, 0, *aLen);

    for(;;)
    {
        str = strtok_r(NULL, ",", &pcmdStr);
        if(str == NULL || str[0] == '\0')
            break;

        if(strcasecmp(str, "interface") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            strncpy(setmac.intf, str, 15);
            DPRINT_INFO(WFA_OUT, "interface %s\n", setmac.intf);
        }
        else if(strcasecmp(str, "mac") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            strncpy(setmac.cmdsu.macaddr, str, 17);
            DPRINT_INFO(WFA_OUT, "mac %s\n", setmac.cmdsu.macaddr);
        }
    }

    wfaEncodeTLV(WFA_STA_SET_MAC_ADDRESS_TLV, sizeof(setmac), (BYTE *)&setmac, aBuf);

    *aLen = 4+sizeof(setmac);

    return WFA_SUCCESS;
}

int xcCmdProcStaIsConnected(char *pcmdStr, BYTE *aBuf, int *aLen)
{
    int slen;
    char *str = NULL;
    dutCommand_t isconnected;

    DPRINT_INFO(WFA_OUT, "Entering xcCmdProcStaIsConnected\n");

    memset(&isconnected, 0, sizeof(isconnected));

    if(aBuf == NULL)
        return WFA_FAILURE;

    memset(aBuf, 0, *aLen);

    str = strtok_r(NULL, ",", &pcmdStr);
    str = strtok_r(NULL, ",", &pcmdStr);
    if(str == NULL)
        return WFA_FAILURE;

    slen = strlen(str);
    memcpy(isconnected.intf, str, slen);
    wfaEncodeTLV(WFA_STA_IS_CONNECTED_TLV, sizeof(isconnected), (BYTE *)&isconnected, aBuf);

    *aLen = 4+sizeof(isconnected);

    return WFA_SUCCESS;
}

int xcCmdProcStaGetBSSID(char *pcmdStr, BYTE *aBuf, int *aLen)
{
    char *str = NULL;
    dutCommand_t getbssid;

    DPRINT_INFO(WFA_OUT, "Entering xcCmdProcStaGetBSSID ...\n");

    if(aBuf == NULL){
        return WFA_FAILURE;
    }
    memset(aBuf, 0, *aLen);

    memset(&getbssid, 0, sizeof(getbssid));
    str = strtok_r(NULL, ",", &pcmdStr);
    str = strtok_r(NULL, ",", &pcmdStr);
    if(str == NULL){
        return WFA_FAILURE;
    }

    memcpy(getbssid.intf, str, WFA_IF_NAME_LEN-1);
    getbssid.intf[WFA_IF_NAME_LEN-1] = '\0';
    wfaEncodeTLV(WFA_STA_GET_BSSID_TLV, sizeof(getbssid), (BYTE *)&getbssid, aBuf);

    *aLen = 4+sizeof(getbssid);

    return WFA_SUCCESS;
}

int  xcCmdProcStaSetEncryption(char *pcmdStr, BYTE *aBuf, int *aLen)
{
    caStaSetEncryption_t *setencryp = (caStaSetEncryption_t *) (aBuf+sizeof(wfaTLV));
    char *str;
    caStaSetEncryption_t defparams = {"", "", 0, {"", "", "", ""}, 0};

    if(aBuf == NULL)
        return WFA_FAILURE;

    memset(aBuf, 0, *aLen);
    memcpy((void *)setencryp, (void *)&defparams, sizeof(caStaSetEncryption_t));

    for(;;)
    {
        str = strtok_r(NULL, ",", &pcmdStr);
        if(str == NULL || str[0] == '\0')
            break;

        if(strcasecmp(str, "interface") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            strncpy(setencryp->intf, str, 15);
        }
        else if(strcasecmp(str, "ssid") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            strncpy(setencryp->ssid, str, 64);
        }
        else if(strcasecmp(str, "encpType") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            if(strcasecmp(str, "wep") == 0)
                setencryp->encpType = ENCRYPT_WEP;
            else
                setencryp->encpType = 0;
        }
        else if(strcasecmp(str, "key1") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            strncpy((char *)setencryp->keys[0], str, 26);
            DPRINT_INFO(WFA_OUT, "%s\n", setencryp->keys[0]);
            setencryp->activeKeyIdx = 0;
        }
        else if(strcasecmp(str, "key2") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            strncpy((char *)setencryp->keys[1], str, 26);
            DPRINT_INFO(WFA_OUT, "%s\n", setencryp->keys[1]);
        }
        else if(strcasecmp(str, "key3") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            strncpy((char *)setencryp->keys[2], str, 26);
            DPRINT_INFO(WFA_OUT, "%s\n", setencryp->keys[2]);
        }
        else if(strcasecmp(str, "key4") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            strncpy((char *)setencryp->keys[3], str, 26);
            DPRINT_INFO(WFA_OUT, "%s\n", setencryp->keys[3]);
        }
        else if(strcasecmp(str, "activeKey") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            setencryp->activeKeyIdx =  atoi(str);
        }
        else
        {
            DPRINT_INFO(WFA_WNG, "Incorrect Command, check syntax\n");
        }
    }

    wfaEncodeTLV(WFA_STA_SET_ENCRYPTION_TLV, sizeof(caStaSetEncryption_t), (BYTE *)setencryp, aBuf);

    *aLen = 4+sizeof(caStaSetEncryption_t);

    return WFA_SUCCESS;
}

int xcCmdProcStaSetPSK(char *pcmdStr, BYTE *aBuf, int *aLen)
{
    caStaSetPSK_t *setencryp = (caStaSetPSK_t *) (aBuf+sizeof(wfaTLV));
    char *str;
    caStaSetPSK_t defparams = {"", "", "", "", 0, WFA_INVALID_BOOL, "", "", 0};

    if(aBuf == NULL)
        return WFA_FAILURE;

    memset(aBuf, 0, *aLen);
    memcpy((void *)setencryp, (void *)&defparams, sizeof(caStaSetPSK_t));

    for(;;)
    {
        str = strtok_r(NULL, ",", &pcmdStr);
        if(str == NULL || str[0] == '\0')
            break;

        if(strcasecmp(str, "interface") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            strncpy(setencryp->intf, str, 15);
        }
        else if(strcasecmp(str, "ssid") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            strncpy(setencryp->ssid, str, 64);
            DPRINT_INFO(WFA_OUT, "ssid %s\n", setencryp->ssid);
        }
        else if(strcasecmp(str, "passPhrase") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            strncpy((char *)setencryp->passphrase, str, 63);
        }
        else if(strcasecmp(str, "keyMgmtType") == 0)
        {
            str=strtok_r(NULL, ",", &pcmdStr);
            strncpy(setencryp->keyMgmtType, str, 15);
        }
        else if(strcasecmp(str, "encpType") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);

            if(strcasecmp(str, "tkip") == 0){
                setencryp->encpType = ENCRYPT_TKIP;
            }
            else if(strcasecmp(str, "aes-ccmp") == 0){
                setencryp->encpType = ENCRYPT_AESCCMP;
            }
        }
        else if(strcasecmp(str, "pmf") == 0)
        {
            str = strtok_r (NULL, ",", &pcmdStr);

            if(strcasecmp(str, "Disable") == 0){
                setencryp->pmf = WFA_DISABLED;
            }else if(strcasecmp(str, "optional") == 0){
                setencryp->pmf = WFA_OPTIONAL;
            }else if(strcasecmp(str, "required") == 0){
                setencryp->pmf = WFA_REQUIRED;
            }
        }
        else if (strcasecmp(str, "micAlg") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            if (strcasecmp(str, "SHA-1") != 0){
                strncpy(setencryp->micAlg, str, 15);
            }else{
                strncpy(setencryp->micAlg, "SHA-1", 15);
            }
        }
        else if (strcasecmp(str, "Prog") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            strncpy(setencryp->prog, str, 15);
        }
        else if (strcasecmp(str, "Perfer") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            setencryp->perfer = (atoi(str) == 1)?1:0;
        }
    }

    wfaEncodeTLV(WFA_STA_SET_PSK_TLV, sizeof(caStaSetPSK_t), (BYTE *)setencryp, aBuf);

    *aLen = 4+sizeof(caStaSetPSK_t);

    return WFA_SUCCESS;
}

int xcCmdProcDeviceGetInfo(char *pcmdStr, BYTE *aBuf, int *aLen)
{
    dutCommand_t *dutCmd = (dutCommand_t *) (aBuf+sizeof(wfaTLV));
    caDevInfo_t *dinfo = &(dutCmd->cmdsu.dev);
    char *str;

    if(aBuf == NULL)
        return WFA_FAILURE;

    printf("entering device get info\n");
    memset(aBuf, 0, *aLen);

    dinfo->fw = 0;
    str = strtok_r(NULL, ",", &pcmdStr);
    if(str != NULL && str[0] != '\0')
    {
        DPRINT_INFO(WFA_OUT, "Str is not NULL!\n");
        if(strcasecmp(str, "firmware") == 0)
        {
            dinfo->fw = 1;
        }
    }
    DPRINT_INFO(WFA_OUT, "Ca encode dinfo->fw = %d\n", dinfo->fw);

    wfaEncodeTLV(WFA_DEVICE_GET_INFO_TLV, 0, NULL, aBuf);

    *aLen = 4;

    return WFA_SUCCESS;
}

int xcCmdProcStaGetInfo(char *pcmdStr, BYTE *aBuf, int *aLen)
{
    hi_unref_param(pcmdStr);
    dutCommand_t *getInfo = (dutCommand_t *) (aBuf+sizeof(wfaTLV));

    if(aBuf == NULL)
        return WFA_FAILURE;

    memset(aBuf, 0, *aLen);

    wfaEncodeTLV(WFA_STA_GET_INFO_TLV, sizeof(dutCommand_t), (BYTE *)getInfo, aBuf);

    *aLen = 4 + sizeof(dutCommand_t);

    return WFA_SUCCESS;
}

int xcCmdProcStaAssociate(char *pcmdStr, BYTE *aBuf, int *aLen)
{
    dutCommand_t *setassoc = (dutCommand_t *) (aBuf+sizeof(wfaTLV));
    char *str;
    caStaAssociate_t *assoc = &setassoc->cmdsu.assoc;
    caStaAssociate_t defparams = {"", "", WFA_DISABLED};

    if(aBuf == NULL)
        return WFA_FAILURE;

    memset(aBuf, 0, *aLen);
    memcpy(assoc, &defparams, sizeof(caStaAssociate_t));

    for(;;)
    {
        str = strtok_r(NULL, ",", &pcmdStr);
        if(str == NULL || str[0] == '\0')
            break;

        if(strcasecmp(str, "interface") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            strncpy(setassoc->intf, str, 15);
            DPRINT_INFO(WFA_OUT, "interface %s\n", setassoc->intf);

        }
        else if(strcasecmp(str, "ssid") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            strncpy(setassoc->cmdsu.assoc.ssid, str, 64);
            DPRINT_INFO(WFA_OUT, "ssid %s\n", setassoc->cmdsu.assoc.ssid);
        }
        else if(strcasecmp(str, "bssid") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            strncpy(setassoc->cmdsu.assoc.bssid, str, 17);
            DPRINT_INFO(WFA_OUT, "bssid %s\n", setassoc->cmdsu.assoc.bssid);
        }
        else if(strcasecmp(str, "wps") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            if(strcasecmp(str, "enabled") == 0)
                setassoc->cmdsu.assoc.wps = WFA_ENABLED;
        }
    }

    wfaEncodeTLV(WFA_STA_ASSOCIATE_TLV, sizeof(dutCommand_t), (BYTE *)setassoc, aBuf);

    *aLen = 4+sizeof(dutCommand_t);

    return WFA_SUCCESS;
}

int xcCmdProcStaReAssociate(char *pcmdStr, BYTE *aBuf, int *aLen)
{
    dutCommand_t *setassoc = (dutCommand_t *) (aBuf+sizeof(wfaTLV));
    char *str;
    caStaAssociate_t *assoc = &setassoc->cmdsu.assoc;
    caStaAssociate_t defparams = {"", "", WFA_DISABLED};

    if(aBuf == NULL)
        return WFA_FAILURE;

    memset(aBuf, 0, *aLen);
    memcpy(assoc, &defparams, sizeof(caStaAssociate_t));

    for(;;)
    {
        str = strtok_r(NULL, ",", &pcmdStr);
        if(str == NULL || str[0] == '\0')
            break;

        if(strcasecmp(str, "interface") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            strncpy(setassoc->intf, str, 15);
            DPRINT_INFO(WFA_OUT, "interface %s\n", setassoc->intf);

        }
        else if(strcasecmp(str, "ssid") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            strncpy(setassoc->cmdsu.assoc.ssid, str, 64);
            DPRINT_INFO(WFA_OUT, "ssid %s\n", setassoc->cmdsu.assoc.ssid);
        }
        else if(strcasecmp(str, "bssid") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            strncpy(setassoc->cmdsu.assoc.bssid, str, 17);
            DPRINT_INFO(WFA_OUT, "bssid %s\n", setassoc->cmdsu.assoc.bssid);
        }
    }

    wfaEncodeTLV(WFA_STA_REASSOCIATE_TLV, sizeof(dutCommand_t), (BYTE *)setassoc, aBuf);

    *aLen = 4+sizeof(dutCommand_t);

    return WFA_SUCCESS;
}

int xcCmdProcDeviceListIF(char *pcmdStr, BYTE *aBuf, int *aLen)
{
    dutCommand_t *getdevlist = (dutCommand_t *) (aBuf+sizeof(wfaTLV));
    char *str;

    if(aBuf == NULL)
        return WFA_FAILURE;

    memset(aBuf, 0, *aLen);

    str = strtok_r(NULL, ",", &pcmdStr);
    if(str == NULL || str[0] == '\0')
        return WFA_FAILURE;

    if(strcasecmp(str, "interfaceType") == 0)
    {
        str = strtok_r(NULL, ",", &pcmdStr);
        if(strcmp(str, "802.11") == 0)
            getdevlist->cmdsu.iftype = IF_80211;

        DPRINT_INFO(WFA_OUT, "interface type %i\n", getdevlist->cmdsu.iftype);
    }

    wfaEncodeTLV(WFA_DEVICE_LIST_IF_TLV, sizeof(dutCommand_t), (BYTE *)getdevlist, aBuf);

    *aLen = 4 + sizeof(dutCommand_t);

#if 0
               for(i = 0; i< len; i++)
                 printf("%x ", buf[i]);

               printf("\n");
#endif

    DPRINT_INFO(WFA_OUT, "dutCommand_t len %i\n", sizeof(dutCommand_t));

    return WFA_SUCCESS;
}

int xcCmdProcStaSetMode(char *pcmdStr, BYTE *aBuf, int *aLen)
{
    caStaSetMode_t *setmode = (caStaSetMode_t *) (aBuf+sizeof(wfaTLV));
    char *str;
    caStaSetMode_t defparams = {"", "", 0, 0, 0, {"", "", "", ""}, 0xFF};

    if(aBuf == NULL)
        return WFA_FAILURE;

    memset(aBuf, 0, *aLen);
    memcpy((void *)setmode, (void *)&defparams, sizeof(caStaSetMode_t));

    for(;;)
    {
        str = strtok_r(NULL, ",", &pcmdStr);
        if(str == NULL || str[0] == '\0')
            break;

        if(strcasecmp(str, "interface") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            strncpy(setmode->intf, str, 15);
        }
        else if(strcasecmp(str, "ssid") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            strncpy(setmode->ssid, str, 64);
        }
        else if(strcasecmp(str, "encpType") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            if(strcasecmp(str, "wep") == 0)
                setmode->encpType = ENCRYPT_WEP;
            else
                setmode->encpType = 0;
        }
        else if(strcasecmp(str, "key1") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            strncpy((char *)setmode->keys[0], str, 26);
            DPRINT_INFO(WFA_OUT, "%s\n", setmode->keys[0]);
            setmode->activeKeyIdx = 0;
        }
        else if(strcasecmp(str, "key2") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            strncpy((char *)setmode->keys[1], str, 26);
            DPRINT_INFO(WFA_OUT, "%s\n", setmode->keys[1]);
        }
        else if(strcasecmp(str, "key3") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            strncpy((char *)setmode->keys[2], str, 26);
            DPRINT_INFO(WFA_OUT, "%s\n", setmode->keys[2]);
        }
        else if(strcasecmp(str, "key4") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            strncpy((char *)setmode->keys[3], str, 26);
            DPRINT_INFO(WFA_OUT, "%s\n", setmode->keys[3]);
        }
        else if(strcasecmp(str, "activeKey") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            setmode->activeKeyIdx =  atoi(str);
        }
        else if(strcasecmp(str, "mode") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            printf("\r\n mode is %s\n",str);
            if(strcasecmp(str, "adhoc") == 0)
                setmode->mode = 1;
            else
                setmode->mode = 0;
        }
        else if(strcasecmp(str, "channel") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            setmode->channel = atoi(str);
        }
        else
        {
            DPRINT_INFO(WFA_WNG, "Incorrect Command, check syntax\n");
            printf("\r\n mode is %s\n",str);
        }
    }

    wfaEncodeTLV(WFA_STA_SET_MODE_TLV, sizeof(caStaSetMode_t), (BYTE *)setmode, aBuf);
    *aLen = 4+sizeof(caStaSetMode_t);

    return WFA_SUCCESS;
}

int xcCmdProcStaDisconnect(char *pcmdStr, BYTE *aBuf, int *aLen)
{
    dutCommand_t *disc = (dutCommand_t *) (aBuf+sizeof(wfaTLV));
    char *str;

    for(;;)
    {
        str = strtok_r(NULL, ",", &pcmdStr);
        if(str == NULL || str[0] == '\0')
            break;

        if(strcasecmp(str, "interface") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            strncpy(disc->intf, str,WFA_IF_NAME_LEN-1);
            disc->intf[WFA_IF_NAME_LEN-1]='\0';
        }
    }

    wfaEncodeTLV(WFA_STA_DISCONNECT_TLV, sizeof(dutCommand_t), (BYTE *)disc, aBuf);

    *aLen = 4+sizeof(dutCommand_t);
    return WFA_SUCCESS;

}

/* Check for enable/disable and return WFA_ENABLE/WFA_DISABLE. WFA_INVALID_BOOL if invalid */
int wfaStandardBoolParsing (char *str)
{
    int rc;

    if(strcasecmp(str, "enable") == 0)
        rc=WFA_ENABLED;
    else if(strcasecmp(str, "disable") == 0)
        rc=WFA_DISABLED;
    else
        rc=WFA_INVALID_BOOL;

    return rc;
}

int xcCmdProcStaResetDefault(char *pcmdStr, BYTE *aBuf, int *aLen)
{
    caStaResetDefault_t *reset = (caStaResetDefault_t *) (aBuf+sizeof(wfaTLV));
    char *str;

    if(aBuf == NULL)
       return WFA_FAILURE;

    memset(aBuf, 0, *aLen);

    for(;;)
    {
        str = strtok_r(NULL, ",", &pcmdStr);
        if(str == NULL || str[0] == '\0')
           break;

        if(strcasecmp(str, "interface") == 0)
        {
           str = strtok_r(NULL, ",", &pcmdStr);
           strncpy(reset->intf, str, 15);
        }
        else if(strcasecmp(str, "prog") == 0)
        {
           str = strtok_r(NULL, ",", &pcmdStr);
           strncpy(reset->prog, str, 8);
        }
        else if(strcasecmp(str, "type") == 0)
        {
           str = strtok_r(NULL, ",", &pcmdStr);
           strncpy(reset->type, str, 8);
        }
    }

    wfaEncodeTLV(WFA_STA_RESET_DEFAULT_TLV, sizeof(caStaResetDefault_t), (BYTE *)reset, aBuf);
    *aLen = 4+sizeof(caStaResetDefault_t);

    return WFA_SUCCESS;
}

int xcCmdProcStaSetRadio(char *pcmdStr, BYTE *aBuf, int *aLen)
{
    char *str;
    dutCommand_t *cmd = (dutCommand_t *) (aBuf+sizeof(wfaTLV));
    caStaSetRadio_t *sr = &cmd->cmdsu.sr;

    if(aBuf == NULL)
        return WFA_FAILURE;

    memset(aBuf, 0, *aLen);

    for(;;)
    {
        str = strtok_r(NULL, ",", &pcmdStr);
        if(str == NULL || str[0] == '\0')
            break;

        if(strcasecmp(str, "interface") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            strncpy(cmd->intf, str, 15);
            DPRINT_INFO(WFA_OUT, "interface %s\n", cmd->intf);
        }
        else if (strcasecmp(str, "mode") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            if (strcasecmp(str, "off") == 0)
            {
                sr->mode = WFA_OFF;
            }
            else
            {
                sr->mode = WFA_ON;
            }
        }
    }

    return WFA_SUCCESS;
}

/* If you decide to use CLI, the function is to be disabled */
int xcCmdProcStaSetWireless(char *pcmdStr, BYTE *aBuf, int *aLen)
{

    caStaSetWireless_t *staWirelessParams = (caStaSetWireless_t *) (aBuf+sizeof(wfaTLV));
    char *str;

    DPRINT_INFO(WFA_OUT,"xcCmdProcStaSetWireless Starts...");

    for(;;)
    {
        str = strtok_r(NULL, ",", &pcmdStr);
        if(str == NULL || str[0] == '\0')
                break;

        if(strcasecmp(str, "interface") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            strncpy(staWirelessParams->intf, str, 15);
        }
        if(strcasecmp(str, "program") == 0) // VHT or 11n or Voice
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            strncpy(staWirelessParams->program, str, 15);

            if(strcasecmp(staWirelessParams->program, "VHT") == 0)
            {
            }
        }
    }

    wfaEncodeTLV(WFA_STA_SET_WIRELESS_TLV, sizeof(caStaSetWireless_t), (BYTE *)staWirelessParams, aBuf);
    *aLen = 4+sizeof(caStaSetWireless_t);
    return WFA_SUCCESS;
}

int xcCmdProcStaSendADDBA(char *pcmdStr, BYTE *aBuf, int *aLen)
{
    caStaSetSendADDBA_t *staSendADDBA = (caStaSetSendADDBA_t *) (aBuf+sizeof(wfaTLV));
    caStaSetSendADDBA_t initADDBAParams = {"", 0xFFFF, ""};
    char *str;

    DPRINT_INFO(WFA_OUT,"xcCmdProcStaSendADDBA Starts...");

    memset(aBuf, 0, *aLen);
    memcpy(staSendADDBA, &initADDBAParams, sizeof(caStaSetSendADDBA_t));
    for(;;)
    {
        str = strtok_r(NULL, ",", &pcmdStr);
        if(str == NULL || str[0] == '\0')
            break;

        if(strcasecmp(str, "interface") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            strncpy(staSendADDBA->intf, str, 15);
        }
        else if(strcasecmp(str, "tid") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            staSendADDBA->tid = atoi(str);
            DPRINT_INFO(WFA_OUT, "\n TID -%i- \n", staSendADDBA->tid);
        }
        else if(strcasecmp(str, "Dest_mac") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            strncpy(staSendADDBA->destMac, str, 17);
        }
    }

    wfaEncodeTLV(WFA_STA_SEND_ADDBA_TLV, sizeof(caStaSetSendADDBA_t), (BYTE *)staSendADDBA, aBuf);
    *aLen = 4+sizeof(caStaSetSendADDBA_t);

    return WFA_SUCCESS;
}

int xcCmdProcStaSet11n(char *pcmdStr, BYTE *aBuf, int *aLen)
{


    caSta11n_t *v11nParams = (caSta11n_t *) (aBuf+sizeof(wfaTLV));
    char *str;
    caSta11n_t init11nParams = {"wifi0", 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,0xFFFF, 0xFFFF, "", "", 0xFF, 0xFF, 0xFF, 0xFF};

    DPRINT_INFO(WFA_OUT,"xcCmdProcStaSet11n Starts...");

    if(aBuf == NULL)
        return WFA_FAILURE;

    memset(aBuf, 0, *aLen);
    memcpy(v11nParams, &init11nParams, sizeof(caSta11n_t));

    for(;;)
    {
        str = strtok_r(NULL, ",", &pcmdStr);
        if(str == NULL || str[0] == '\0')
            break;
        if(strcasecmp(str, "interface") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            strncpy(v11nParams->intf, str,WFA_IF_NAME_LEN-1);
            v11nParams->intf[WFA_IF_NAME_LEN-1]='\0';
        }

        if(strcasecmp(str, "ampdu") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            v11nParams->ampdu=wfaStandardBoolParsing(str);
            if (v11nParams->ampdu > 1)
            {
                DPRINT_INFO(WFA_OUT, "Invalid AMPDU Value %s\n",str);
                return WFA_FAILURE;
            }
            DPRINT_INFO(WFA_OUT, "\n AMPDU -%i- \n", v11nParams->ampdu);
        }
        else if(strcasecmp(str, "40_intolerant") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            v11nParams->_40_intolerant=wfaStandardBoolParsing(str);
            if (v11nParams->_40_intolerant > 1)
            {
                DPRINT_INFO(WFA_OUT, "Invalid _40_intolerant Value %s\n",str);
                return WFA_FAILURE;
            }
            DPRINT_INFO(WFA_OUT, "\n _40_intolerant -%i- \n", v11nParams->_40_intolerant);
        }
        else if(strcasecmp(str, "sgi20") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            v11nParams->sgi20=wfaStandardBoolParsing(str);
            if (v11nParams->sgi20 > 1)
            {
                DPRINT_INFO(WFA_OUT, "Invalid sgi20 Value %s\n",str);
                return WFA_FAILURE;
            }
            DPRINT_INFO(WFA_OUT, "\n sgi20 -%i- \n", v11nParams->sgi20);
        }
        else if(strcasecmp(str, "amsdu") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            v11nParams->amsdu=wfaStandardBoolParsing(str);
            if (v11nParams->amsdu > 1)
            {
                DPRINT_INFO(WFA_OUT, "Invalid amsdu Value %s\n",str);
                return WFA_FAILURE;
            }
            DPRINT_INFO(WFA_OUT, "\n amsdu -%i- \n", v11nParams->amsdu);
        }
        else if(strcasecmp(str, "addba_reject") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            v11nParams->addba_reject=wfaStandardBoolParsing(str);
            if (v11nParams->addba_reject > 1)
            {
                DPRINT_INFO(WFA_OUT, "Invalid addba_reject Value %s\n",str);
                return WFA_FAILURE;
            }
            DPRINT_INFO(WFA_OUT, "\n addba_reject -%i- \n", v11nParams->addba_reject);
        }
        else if(strcasecmp(str, "greenfield") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            v11nParams->greenfield=wfaStandardBoolParsing(str);
            if (v11nParams->greenfield > 1)
            {
                DPRINT_INFO(WFA_OUT, "Invalid greenfield Value %s\n",str);
                return WFA_FAILURE;
            }
            DPRINT_INFO(WFA_OUT, "\n greenfield -%i- \n", v11nParams->greenfield);
        }
        else if(strcasecmp(str, "mcs32") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            v11nParams->mcs32=wfaStandardBoolParsing(str);
            if (v11nParams->mcs32 > 1)
            {
                DPRINT_INFO(WFA_OUT, "Invalid mcs32 Value %s\n",str);
                return WFA_FAILURE;
            }
            DPRINT_INFO(WFA_OUT, "\n mcs32 -%i- \n", v11nParams->mcs32);
        }
        else if(strcasecmp(str, "rifs_test") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            v11nParams->rifs_test=wfaStandardBoolParsing(str);
            if (v11nParams->rifs_test > 1)
            {
                DPRINT_INFO(WFA_OUT, "Invalid rifs_test Value %s\n",str);
                return WFA_FAILURE;
            }
            DPRINT_INFO(WFA_OUT, "\n rifs_test -%i- \n", v11nParams->rifs_test);
        }
        else if(strcasecmp(str, "width") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            strncpy(v11nParams->width,str,7);
            DPRINT_INFO(WFA_OUT, "\n width -%s- \n", v11nParams->width);
        }
        else if(strcasecmp(str, "mcs_fixedrate") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            strncpy(v11nParams->mcs_fixedrate, str, strlen(str));
            DPRINT_INFO(WFA_OUT, "\n mcs fixedrate -%s- \n", v11nParams->mcs_fixedrate);
        }
        else if(strcasecmp(str, "stbc_rx") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            v11nParams->stbc_rx = atoi(str);
            DPRINT_INFO(WFA_OUT, "\n stbc rx -%d- \n", v11nParams->stbc_rx);
        }
        else if(strcasecmp(str, "smps") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            if(strcasecmp(str, "dynamic") == 0)
            {
                v11nParams->smps = 0;
            }
            else if(strcasecmp(str, "static")==0)
            {
                v11nParams->smps = 1;
            }
            else if(strcasecmp(str, "nolimit") == 0)
            {
                v11nParams->smps = 2;
            }
            DPRINT_INFO(WFA_OUT, "\n smps  -%d- \n", v11nParams->smps);
        }
        else if(strcasecmp(str, "txsp_stream") == 0 )
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            v11nParams->txsp_stream = atoi(str);
            DPRINT_INFO(WFA_OUT, "\n txsp_stream -%d- \n", v11nParams->txsp_stream);
        }
        else if(strcasecmp(str, "rxsp_stream") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            v11nParams->rxsp_stream = atoi(str);
            DPRINT_INFO(WFA_OUT, "\n rxsp_stream -%d- \n", v11nParams->rxsp_stream);
        }
    }

    wfaEncodeTLV(WFA_STA_SET_11N_TLV, sizeof(caSta11n_t), (BYTE *)v11nParams, aBuf);
    *aLen = 4+sizeof(caSta11n_t);
    return WFA_SUCCESS;
}

int xcCmdProcStaPresetTestParameters(char *pcmdStr, BYTE *aBuf, int *aLen)
{
    caStaPresetParameters_t *presetTestParams = (caStaPresetParameters_t *) (aBuf+sizeof(wfaTLV));
    char *str;
    char *tstr1,*tstr2;

    if(aBuf == NULL){
        return WFA_FAILURE;
    }

    memset(aBuf, 0, *aLen);
    memset(presetTestParams, 0, sizeof(caStaPresetParameters_t));

    for(;;)
    {
        str = strtok_r(pcmdStr, ",", &pcmdStr);
        if(str == NULL || str[0] == '\0'){
            break;
        }

        if(strcasecmp(str, "interface") == 0)
        {
           str = strtok_r(NULL, ",", &pcmdStr);
           strncpy(presetTestParams->intf, str, 15);
        }
        else if(strcasecmp(str, "mode") == 0)
        {
           str = strtok_r(NULL, ",", &pcmdStr);
           printf("modeis %s\n", str);

           if(strcasecmp(str, "11b") == 0 || strcasecmp(str, "b") == 0)
              presetTestParams->wirelessMode = eModeB;
           else if(strcasecmp(str, "11g") == 0 || strcasecmp(str, "g") == 0 || strcasecmp(str, "bg") ==0 )
              presetTestParams->wirelessMode = eModeBG;
           else if(strcasecmp(str, "11a") == 0 || strcasecmp(str, "a") == 0)
              presetTestParams->wirelessMode = eModeA;
           else if(strcasecmp(str, "11abg") == 0 || strcasecmp(str, "abg") == 0)
              presetTestParams->wirelessMode = eModeABG;
           else if(strcasecmp(str, "11na") == 0)
              presetTestParams->wirelessMode = eModeAN;
           else if(strcasecmp(str, "11ng") == 0)
              presetTestParams->wirelessMode = eModeGN;
           else if(strcasecmp(str, "11nl") == 0)
              presetTestParams->wirelessMode = eModeNL;   // n+abg
           else if(strcasecmp(str, "11ac") == 0)
              presetTestParams->wirelessMode = eModeAC;

           presetTestParams->modeFlag = 1;
           printf("\nSetting Mode as %d\n", presetTestParams->wirelessMode);
        }
        else if(strcasecmp(str, "powersave") == 0)
        {
           str = strtok_r(NULL, ",", &pcmdStr);
           printf("powersave is %s\n", str);
           if(strcasecmp(str, "on") == 0 || strcasecmp(str, "pspoll")==0)
              presetTestParams->legacyPowerSave = 1;
           else if (strcasecmp(str, "fast") == 0)
              presetTestParams->legacyPowerSave = 2;
           else if (strcasecmp(str, "psnonpoll") == 0)
              presetTestParams->legacyPowerSave = 3;
           else
              presetTestParams->legacyPowerSave = 0;

           presetTestParams->psFlag = 1;
           printf("\nSetting legacyPowerSave as %d\n", presetTestParams->legacyPowerSave);
        }
        else if(strcasecmp(str, "wmm") == 0)
        {
           presetTestParams->wmmFlag = 1;
           str = strtok_r(NULL, ",", &pcmdStr);
           printf("wmm is %s\n", str);

           if(strcasecmp(str, "on") == 0)
              presetTestParams->wmmState = 1;
           else if(strcasecmp(str, "off") == 0)
              presetTestParams->wmmState = 0;
        }
        else if(strcasecmp(str, "noack") == 0)
        {
            /* uncomment and use it char *ackpol; */
            char *setvalues =strtok_r(NULL, ",", &pcmdStr);
            if(setvalues != NULL)
            {

            }
        }
        else if(strcasecmp(str, "ht") == 0)
        {
           str = strtok_r(NULL, ",", &pcmdStr);
           if(strcasecmp(str, "on") == 0)
           {
              presetTestParams->ht = 1;
           }
           else
           {
              presetTestParams->ht = 0;
           }
        }
        else if(strcasecmp(str, "reset") == 0)
        {
           str = strtok_r(NULL, ",", &pcmdStr);
           if(strcasecmp(str, "11n") == 0)
           {
              presetTestParams->reset = eResetProg11n;
              printf("reset to %s\n", str);
           }
        }
        else if(strcasecmp(str, "ft_oa") == 0)
        {
           str = strtok_r(NULL, ",", &pcmdStr);
           if(strcasecmp(str, "Enable") == 0)
           {
              presetTestParams->ftoa = eEnable;
              printf("ft_oa enabled\n");
           }
           else
           {
              presetTestParams->ftoa = eDisable;
           }
        }
        else if(strcasecmp(str, "ft_ds") == 0)
        {
           str = strtok_r(NULL, ",", &pcmdStr);
           if(strcasecmp(str, "Enable") == 0)
           {
              presetTestParams->ftds = eEnable;
              printf("ft_ds enabled\n");
           }
           else
           {
              presetTestParams->ftds = eDisable;
           }
        }
        else if(strcasecmp(str, "active_scan") == 0)
        {
           str = strtok_r(NULL, ",", &pcmdStr);
           if(strcasecmp(str, "Enable") == 0)
           {
              presetTestParams->activescan = eEnable;
              printf("active scan enabled\n");
           }
           else
           {
              presetTestParams->activescan = eDisable;
           }
        }
        else if(strcasecmp(str, "tdls") == 0)
        {
           presetTestParams->tdlsFlag= 1;
           str = strtok_r(NULL, ",", &pcmdStr);
           if(strcasecmp(str, "Enabled") == 0)
           {
              presetTestParams->tdls = eEnable;
           }
           else
           {
              presetTestParams->tdls = eDisable;
           }
        }
        else if(strcasecmp(str, "tdlsmode") == 0)
        {
           str = strtok_r(NULL, ",", &pcmdStr);
           if(strcasecmp(str, "Default") == 0)
           {
              presetTestParams->tdlsMode = eDef;
           }
           else if(strcasecmp(str, "HiLoMac") == 0)
           {
              presetTestParams->tdlsMode = eHiLoMac;
           }
           else if(strcasecmp(str, "ExistLink") == 0)
           {
              presetTestParams->tdlsMode = eExistLink;
           }
           else if(strcasecmp(str, "APProhibit") == 0)
           {
              presetTestParams->tdlsMode = eAPProhibit;
           }
           else if(strcasecmp(str, "WeakSecurity") == 0)
           {
              presetTestParams->tdlsMode = eWeakSec;
           }
           else if(strcasecmp(str, "IgnoreChswitchProhibit") == 0)
           {
              presetTestParams->tdlsMode = eIgnChnlSWProh;
           }
        }
        else if(strcasecmp(str, "wfddevtype") == 0)
        {
           presetTestParams->wfdDevTypeFlag= 1;
           str = strtok_r(NULL, ",", &pcmdStr);
           if(strcasecmp(str, "source") == 0)
           {
              presetTestParams->wfdDevType= eSource;
           }
           else if(strcasecmp(str, "p-sink") == 0)
           {
              presetTestParams->wfdDevType= ePSink;
           }
           else if(strcasecmp(str, "s-sink") == 0)
           {
              presetTestParams->wfdDevType= eSSink;
           }
           else if(strcasecmp(str, "dual") == 0)
           {
              presetTestParams->wfdDevType= eDual;
           }
        }
        else if(strcasecmp(str, "uibc_gen") == 0)
        {
           presetTestParams->wfdUibcGenFlag= 1;
           str = strtok_r(NULL, ",", &pcmdStr);
           if(strcasecmp(str, "Enable") == 0)
           {
              presetTestParams->wfdUibcGen= eEnable;
           }
           else
           {
              presetTestParams->wfdUibcGen= eDisable;
           }
        }
        else if(strcasecmp(str, "uibc_hid") == 0)
        {
           presetTestParams->wfdUibcHidFlag= 1;
           str = strtok_r(NULL, ",", &pcmdStr);
           if(strcasecmp(str, "Enable") == 0)
           {
              presetTestParams->wfdUibcHid= eEnable;
           }
           else
           {
              presetTestParams->wfdUibcHid= eDisable;
           }
        }
        else if(strcasecmp(str, "ui_input") == 0)
        {
           char *uilist;
           presetTestParams->wfdUiInputFlag= 1;

           uilist = strtok_r(NULL, ",", &pcmdStr);
           presetTestParams->wfdUiInputs=0;
           for(;;)
           {
              str = strtok_r(uilist, " ", &uilist);
              if(str == NULL || str[0] == '\0')
                  break;

              if(strcasecmp(str, "keyboard") == 0)
              {
                  presetTestParams->wfdUiInput[presetTestParams->wfdUiInputs]= eKeyBoard;
              }
              else if(strcasecmp(str, "mouse") == 0)
              {
                  presetTestParams->wfdUiInput[presetTestParams->wfdUiInputs]= eMouse;
              }
              presetTestParams->wfdUiInputs++;
           }
        }
        else if(strcasecmp(str, "hdcp") == 0)
        {
           presetTestParams->wfdHdcpFlag= 1;
           str = strtok_r(NULL, ",", &pcmdStr);
           if(strcasecmp(str, "Enable") == 0)
           {
              presetTestParams->wfdHdcp= eEnable;
           }
           else
           {
              presetTestParams->wfdHdcp= eDisable;
           }
        }
        else if(strcasecmp(str, "frameskip") == 0)
        {
           presetTestParams->wfdFrameSkipFlag= 1;
           str = strtok_r(NULL, ",", &pcmdStr);
           if(strcasecmp(str, "Enable") == 0)
           {
              presetTestParams->wfdFrameSkip= eEnable;
           }
           else
           {
              presetTestParams->wfdFrameSkip= eDisable;
           }
        }
        else if(strcasecmp(str, "avchange") == 0)
        {
           presetTestParams->wfdAvChangeFlag= 1;
           str = strtok_r(NULL, ",", &pcmdStr);
           if(strcasecmp(str, "Enable") == 0)
           {
              presetTestParams->wfdAvChange= eEnable;
           }
           else
           {
              presetTestParams->wfdAvChange= eDisable;
           }
        }
        else if(strcasecmp(str, "standby") == 0)
        {
           presetTestParams->wfdStandByFlag= 1;
           str = strtok_r(NULL, ",", &pcmdStr);
           if(strcasecmp(str, "Enable") == 0)
           {
              presetTestParams->wfdStandBy= eEnable;
           }
           else
           {
              presetTestParams->wfdStandBy= eDisable;
           }
        }
        else if(strcasecmp(str, "inputcontent") == 0)
        {
           presetTestParams->wfdInVideoFlag= 1;
           str = strtok_r(NULL, ",", &pcmdStr);
           if(strcasecmp(str, "Protected") == 0)
           {
              presetTestParams->wfdInVideo= eProtected;
           }
           else if(strcasecmp(str, "Unprotected") == 0)
           {
              presetTestParams->wfdInVideo= eUnprotected;
           }

           else if(strcasecmp(str, "ProtectedVideoOnly") == 0)
           {
              presetTestParams->wfdInVideo= eProtectedVideoOnly;
           }

        }
        else if(strcasecmp(str, "videoformat") == 0)
        {
           int temp1;
           char *videolist;
           presetTestParams->wfdVideoFmatFlag= 1;

           videolist = strtok_r(NULL, ",", &pcmdStr);
           presetTestParams->wfdInputVideoFmats=0;

           for(;;)
           {
               str = strtok_r(videolist, " ", &videolist);
               if(str == NULL || str[0] == '\0')
                   break;

               tstr1 = strtok_r(str, "-", &str);
               tstr2 = strtok_r(str, "-", &str);

               temp1 = atoi(tstr2);
               printf("\n The Video format is : %s****%d*****",tstr1,temp1);


               if(strcasecmp(tstr1, "cea") == 0)
               {
                   presetTestParams->wfdVideoFmt[presetTestParams->wfdInputVideoFmats]= eCEA+1+temp1;
               }
               else if(strcasecmp(tstr1, "vesa") == 0)
               {
                   presetTestParams->wfdVideoFmt[presetTestParams->wfdInputVideoFmats]=  eVesa+1+temp1;
               }
               else
               {
                   presetTestParams->wfdVideoFmt[presetTestParams->wfdInputVideoFmats]=  eHH+1+temp1;
               }
               presetTestParams->wfdInputVideoFmats++;
           }
        }
        else if(strcasecmp(str, "AudioFormat") == 0)
        {
           presetTestParams->wfdAudioFmatFlag= 1;
           str = strtok_r(NULL, ",", &pcmdStr);
           if(strcasecmp(str, "Mandatory") == 0)
           {
              presetTestParams->wfdAudioFmt= eMandatoryAudioMode;
           }
           else
           {
              presetTestParams->wfdAudioFmt= eDefaultAudioMode;
           }
        }

        else if(strcasecmp(str, "i2c") == 0)
        {
           presetTestParams->wfdI2cFlag= 1;
           str = strtok_r(NULL, ",", &pcmdStr);
           if(strcasecmp(str, "Enable") == 0)
           {
              presetTestParams->wfdI2c= eEnable;
           }
           else
           {
              presetTestParams->wfdI2c= eDisable;
           }
        }
        else if(strcasecmp(str, "videorecovery") == 0)
        {
           presetTestParams->wfdVideoRecoveryFlag= 1;
           str = strtok_r(NULL, ",", &pcmdStr);
           if(strcasecmp(str, "Enable") == 0)
           {
              presetTestParams->wfdVideoRecovery= eEnable;
           }
           else
           {
              presetTestParams->wfdVideoRecovery= eDisable;
           }
        }
        else if(strcasecmp(str, "PrefDisplay") == 0)
        {
           presetTestParams->wfdPrefDisplayFlag= 1;
           str = strtok_r(NULL, ",", &pcmdStr);
           if(strcasecmp(str, "Enable") == 0)
           {
              presetTestParams->wfdPrefDisplay= eEnable;
           }
           else
           {
              presetTestParams->wfdPrefDisplay= eDisable;
           }
        }
        else if(strcasecmp(str, "ServiceDiscovery") == 0)
        {
           presetTestParams->wfdServiceDiscoveryFlag= 1;
           str = strtok_r(NULL, ",", &pcmdStr);
           if(strcasecmp(str, "Enable") == 0)
           {
              presetTestParams->wfdServiceDiscovery= eEnable;
           }
           else
           {
              presetTestParams->wfdServiceDiscovery= eDisable;
           }
        }
        else if(strcasecmp(str, "3dVideo") == 0)
        {
           presetTestParams->wfd3dVideoFlag= 1;
           str = strtok_r(NULL, ",", &pcmdStr);
           if(strcasecmp(str, "Enable") == 0)
           {
              presetTestParams->wfd3dVideo= eEnable;
           }
           else
           {
              presetTestParams->wfd3dVideo= eDisable;
           }
        }
        else if(strcasecmp(str, "MultiTxStream") == 0)
        {
           presetTestParams->wfdMultiTxStreamFlag= 1;
           str = strtok_r(NULL, ",", &pcmdStr);
           if(strcasecmp(str, "Enable") == 0)
           {
              presetTestParams->wfdMultiTxStream= eEnable;
           }
           else
           {
              presetTestParams->wfdMultiTxStream= eDisable;
           }
        }
        else if(strcasecmp(str, "TimeSync") == 0)
        {
           presetTestParams->wfdTimeSyncFlag= 1;
           str = strtok_r(NULL, ",", &pcmdStr);
           if(strcasecmp(str, "Enable") == 0)
           {
              presetTestParams->wfdTimeSync= eEnable;
           }
           else
           {
              presetTestParams->wfdTimeSync= eDisable;
           }
        }
        else if(strcasecmp(str, "EDID") == 0)
        {
           presetTestParams->wfdEDIDFlag= 1;
           str = strtok_r(NULL, ",", &pcmdStr);
           if(strcasecmp(str, "Enable") == 0)
           {
              presetTestParams->wfdEDID= eEnable;
           }
           else
           {
              presetTestParams->wfdEDID= eDisable;
           }
        }
        else if(strcasecmp(str, "UIBC_Prepare") == 0)
        {
           presetTestParams->wfdUIBCPrepareFlag= 1;
           str = strtok_r(NULL, ",", &pcmdStr);
           if(strcasecmp(str, "Enable") == 0)
           {
              presetTestParams->wfdUIBCPrepare= eEnable;
           }
           else
           {
              presetTestParams->wfdUIBCPrepare= eDisable;
           }
        }
        else if(strcasecmp(str, "OptionalFeature") == 0)
        {
           str = strtok_r(NULL, ",", &pcmdStr);
           if(strcasecmp(str, "DisableAll") == 0)
           {
              presetTestParams->wfdOptionalFeatureFlag= eEnable;
           }
           else
           {
              presetTestParams->wfdOptionalFeatureFlag= eDisable;
           }
        }
        else if(strcasecmp(str, "SessionAvailability") == 0)
        {
           presetTestParams->wfdSessionAvailFlag= 1;
           str = strtok_r(NULL, ",", &pcmdStr);
           if(strcasecmp(str, "Enable") == 0)
           {
              presetTestParams->wfdSessionAvail= eEnable;
           }
           else
           {
              presetTestParams->wfdSessionAvail= eDisable;
           }
        }
        else if(strcasecmp(str, "DeviceDiscoverability") == 0)
        {
           presetTestParams->wfdDeviceDiscoverabilityFlag= 1;
           str = strtok_r(NULL, ",", &pcmdStr);
           if(strcasecmp(str, "Enable") == 0)
           {
               presetTestParams->wfdDeviceDiscoverability= eEnable;
           }
           else
           {
               presetTestParams->wfdDeviceDiscoverability= eDisable;
           }
        }
        else if(strcasecmp(str, "oper_chn") == 0)
        {
             str = strtok_r(NULL, ",", &pcmdStr);
             presetTestParams->oper_chn= atoi(str);
        }
        else if (strcasecmp(str, "program") == 0)
        {
            presetTestParams->programFlag= 1;
            str = strtok_r(NULL, ",", &pcmdStr);
            if (strcasecmp(str, "PMF") == 0)
            {
                presetTestParams->program=PROG_TYPE_PMF;
            }
            else if (strcasecmp(str, "General") == 0)
            {
                presetTestParams->program=PROG_TYPE_GEN;
            }
            else if (strcasecmp(str, "TDLS") == 0)
            {
                presetTestParams->program=PROG_TYPE_TDLS;
            }
            else if (strcasecmp(str, "VOE") == 0)
            {
                presetTestParams->program=PROG_TYPE_VENT;
            }
            else if (strcasecmp(str, "WFD") == 0)
            {
                presetTestParams->program=PROG_TYPE_WFD;
            }
            else if (strcasecmp(str, "NAN") == 0)
            {
                presetTestParams->program=PROG_TYPE_NAN;
            }
        }
        else if(strcasecmp(str, "CoupledCap") == 0)
        {
            presetTestParams->wfdCoupledCapFlag=1;
            str = strtok_r(NULL, ",", &pcmdStr);
            if(strcasecmp(str, "Enable") == 0)
            {
               presetTestParams->wfdCoupledCap= eEnable;
            }
            else
            {
               presetTestParams->wfdCoupledCap= eDisable;
            }
        }
    else if (strcasecmp(str, "supplicant") == 0)
    {
        str = strtok_r(NULL, ",", &pcmdStr);
        if (strcasecmp(str, "Default") == 0 || strcasecmp(str, "WPA_Supplicant") == 0)
        {
            presetTestParams->supplicant = eWpaSupplicant;
        }
    }
    }

    wfaEncodeTLV(WFA_STA_PRESET_PARAMETERS_TLV, sizeof(caStaPresetParameters_t), (BYTE *)presetTestParams, aBuf);

    *aLen = 4 + sizeof(caStaPresetParameters_t);

    return WFA_SUCCESS;
}

int xcCmdProcApSetWireless(char *pcmdStr, BYTE *aBuf, int *aLen)
{
    caApSetWireless_t *apWirelessParams = (caApSetWireless_t *)(aBuf + sizeof(wfaTLV));
    char *str;

    memset(apWirelessParams, 0, sizeof(caApSetWireless_t));
    memset(aBuf, 0, *aLen);

    DPRINT_INFO(WFA_OUT, "xcCmdProcApSetWireless starts...");

    for(;;){
        str = strtok_r(NULL, ",", &pcmdStr);
        if(str == NULL || str[0] == '\0'){
            break;
        }

        if(strcasecmp(str, "NAME") == 0){
            str = strtok_r(NULL, ",", &pcmdStr);
            strncpy(apWirelessParams->name, str, 16);
            DPRINT_INFO(WFA_OUT, "name %s\n", apWirelessParams->name);
        }else if(strcasecmp(str, "INTERFACE") == 0){
            str = strtok_r(NULL, ",", &pcmdStr);
            strncpy(apWirelessParams->programArgs.args.intf, str, WFA_IF_NAME_LEN);
            apWirelessParams->programArgs.args.intf_flag = 1;
            DPRINT_INFO(WFA_OUT, "interface -%s- \n", apWirelessParams->programArgs.args.intf);
        }else if(strcasecmp(str, "ssid") == 0){
            str = strtok_r(NULL, ",", &pcmdStr);
            strncpy(apWirelessParams->programArgs.args.ssid, str, WFA_SSID_NAME_LEN);
            apWirelessParams->programArgs.args.ssid_flag = 1;
            DPRINT_INFO(WFA_OUT, "ssid -%s- \n", apWirelessParams->programArgs.args.ssid);
        }else if(strcasecmp(str, "channel") == 0){
            str = strtok_r(NULL, ",", &pcmdStr);
            apWirelessParams->programArgs.args.channel = atoi(str);
            apWirelessParams->programArgs.args.channel_flag = 1;
            DPRINT_INFO(WFA_OUT, "channel -%d- \n", apWirelessParams->programArgs.args.channel);
        }else if(strcasecmp(str, "MODE") == 0){
            str = strtok_r(NULL, ",", &pcmdStr);
            strncpy(apWirelessParams->programArgs.args.mode, str, 8);
            apWirelessParams->programArgs.args.mode_flag = 1;
            DPRINT_INFO(WFA_OUT, "MODE -%s- \n", apWirelessParams->programArgs.args.mode);
        }else if(strcasecmp(str, "PWRSAVE") == 0){
            str = strtok_r(NULL, ",", &pcmdStr);
            if (strcasecmp(str, "on") == 0) {
                strncpy(apWirelessParams->programArgs.args.pwrSave, "1", 1);
            } else if (strcasecmp(str, "off") == 0) {
                strncpy(apWirelessParams->programArgs.args.pwrSave, "0", 1);
            } else {
                DPRINT_INFO(WFA_ERR, "mode type error\n");
            }
            apWirelessParams->programArgs.args.pwrSave_flag = 1;
            DPRINT_INFO(WFA_OUT, "PWRSAVE -%s- \n", apWirelessParams->programArgs.args.pwrSave);
        }else if(strcasecmp(str, "WME") == 0){
            str = strtok_r(NULL, ",", &pcmdStr);
            strncpy(apWirelessParams->programArgs.args.wme, str, 8);
            apWirelessParams->programArgs.args.wme_flag = 1;
            DPRINT_INFO(WFA_OUT, "WME -%s- \n", apWirelessParams->programArgs.args.wme);
        }else if(strcasecmp(str, "WMMPS") == 0){
            str = strtok_r(NULL, ",", &pcmdStr);
            strncpy(apWirelessParams->programArgs.args.wmmps, str, 8);
            apWirelessParams->programArgs.args.wmmps_flag = 1;
            DPRINT_INFO(WFA_OUT, "WMMPS -%s- \n", apWirelessParams->programArgs.args.wmmps);
        }else if(strcasecmp(str, "RTS") == 0){
            str = strtok_r(NULL, ",", &pcmdStr);
            apWirelessParams->programArgs.args.rts = atoi(str);
            apWirelessParams->programArgs.args.rts_flag = 1;
            DPRINT_INFO(WFA_OUT, "RTS -%d- \n", apWirelessParams->programArgs.args.rts);
        }else if(strcasecmp(str, "FRGMNT") == 0){
            str = strtok_r(NULL, ",", &pcmdStr);
            apWirelessParams->programArgs.args.frgmnt = atoi(str);
            apWirelessParams->programArgs.args.frgmnt_flag = 1;
            DPRINT_INFO(WFA_OUT, "FRGMNT -%d- \n", apWirelessParams->programArgs.args.frgmnt);

        }else if(strcasecmp(str, "40_INTOLERANT") == 0){
            str = strtok_r(NULL, ",", &pcmdStr);
            apWirelessParams->programArgs.args._40_intolerant = wfaStandardBoolParsing(str);
            if (apWirelessParams->programArgs.args._40_intolerant > 1){
                DPRINT_ERR(WFA_ERR, "Invalid 40_INTOLERANT Value %s\n",str);
                return WFA_FAILURE;
            }
            DPRINT_INFO(WFA_OUT, "40_INTOLERANT -%i- \n", apWirelessParams->programArgs.args._40_intolerant);
        }else if(strcasecmp(str, "GREENFIELD") == 0){
            str = strtok_r(NULL, ",", &pcmdStr);
            apWirelessParams->programArgs.args.greenfield = wfaStandardBoolParsing(str);
            if (apWirelessParams->programArgs.args.greenfield > 1){
                DPRINT_ERR(WFA_ERR, "Invalid GREENFIELD Value %s\n",str);
                return WFA_FAILURE;
            }
            DPRINT_INFO(WFA_OUT, "GREENFIELD -%i- \n", apWirelessParams->programArgs.args.greenfield);
        }else if(strcasecmp(str, "MCS_FIXEDRATE") == 0){
            str = strtok_r(NULL, ",", &pcmdStr);
            apWirelessParams->programArgs.args.mcsFixedRate = atoi(str);
            apWirelessParams->programArgs.args.mcsFixedRate_flag = 1;
            DPRINT_INFO(WFA_OUT, "MCS_FIXEDRATE -%d- \n", apWirelessParams->programArgs.args.mcsFixedRate);
        }else if(strcasecmp(str, "SPATIAL_RX_STREAM") == 0){
            str = strtok_r(NULL, ",", &pcmdStr);
            strncpy(apWirelessParams->programArgs.args.spatialRxStream, str, WFA_SPATIAL_RX_STREAM_LEN);
            DPRINT_INFO(WFA_OUT, "SPATIAL_RX_STREAM -%s- \n", apWirelessParams->programArgs.args.spatialRxStream);
        }else if(strcasecmp(str, "SPATIAL_TX_STREAM") == 0){
            str = strtok_r(NULL, ",", &pcmdStr);
            strncpy(apWirelessParams->programArgs.args.spatialTxStream, str, WFA_SPATIAL_RX_STREAM_LEN);
            DPRINT_INFO(WFA_OUT, "SPATIAL_TX_STREAM -%s- \n", apWirelessParams->programArgs.args.spatialTxStream);
        }else if(strcasecmp(str, "WIDTH") == 0){
            str = strtok_r(NULL, ",", &pcmdStr);
            strncpy(apWirelessParams->programArgs.args.width, str, strlen(str));
            apWirelessParams->programArgs.args.width_flag = 1;
            DPRINT_INFO(WFA_OUT, "WIDTH -%s- \n", apWirelessParams->programArgs.args.width);
        }else if(strcasecmp(str, "ADDBA_REJECT") == 0){
            str = strtok_r(NULL, ",", &pcmdStr);
            apWirelessParams->programArgs.args.addba_reject = wfaStandardBoolParsing(str);
            apWirelessParams->programArgs.args.addba_reject_flag = 1;
            if (apWirelessParams->programArgs.args.addba_reject > 1){
                DPRINT_ERR(WFA_ERR, "Invalid ADDBA_REJECT Value %s\n",str);
                return WFA_FAILURE;
            }
            printf("\n ADDBA_REJECT -%i- \n", apWirelessParams->programArgs.args.addba_reject);
        }else if(strcasecmp(str, "AMPDU") == 0){
            str = strtok_r(NULL, ",", &pcmdStr);
            apWirelessParams->programArgs.args.ampdu = wfaStandardBoolParsing(str);
            apWirelessParams->programArgs.args.ampdu_flag = 1;
            if (apWirelessParams->programArgs.args.ampdu > 1){
                DPRINT_ERR(WFA_ERR, "Invalid AMPDU Value %s\n",str);
                return WFA_FAILURE;
            }
            DPRINT_INFO(WFA_OUT, "AMPDU -%i- \n", apWirelessParams->programArgs.args.ampdu);
        }else if(strcasecmp(str, "AMPDU_EXP") == 0){
            str = strtok_r(NULL, ",", &pcmdStr);
            apWirelessParams->programArgs.args.ampduExp = atoi(str);
            apWirelessParams->programArgs.args.ampduExp_flag = 1;
            DPRINT_INFO(WFA_OUT, "AMPDU_EXP -%d- \n", apWirelessParams->programArgs.args.ampduExp);
        }else if(strcasecmp(str, "AMSDU") == 0){
            str = strtok_r(NULL, ",", &pcmdStr);
            apWirelessParams->programArgs.args.amsdu = wfaStandardBoolParsing(str);
            apWirelessParams->programArgs.args.amsdu_flag = 1;
            if (apWirelessParams->programArgs.args.amsdu > 1){
                DPRINT_ERR(WFA_ERR, "Invalid AMSDU Value %s\n",str);
                return WFA_FAILURE;
            }
            DPRINT_INFO(WFA_OUT, "AMSDU -%i- \n", apWirelessParams->programArgs.args.amsdu);
        }else if(strcasecmp(str, "OFFSET") == 0){
            str = strtok_r(NULL, ",", &pcmdStr);
            apWirelessParams->programArgs.args.offset = wfaStandardBoolParsing(str);
            if (apWirelessParams->programArgs.args.offset > 1){
                DPRINT_ERR(WFA_ERR, "Invalid OFFSET Value %s\n",str);
                return WFA_FAILURE;
            }
            DPRINT_INFO(WFA_OUT, "OFFSET -%i- \n", apWirelessParams->programArgs.args.offset);
        }else if(strcasecmp(str, "MCS_32") == 0){
            str = strtok_r(NULL, ",", &pcmdStr);
            apWirelessParams->programArgs.args.mcs32 = wfaStandardBoolParsing(str);
            if (apWirelessParams->programArgs.args.mcs32 > 1){
                DPRINT_ERR(WFA_ERR, "Invalid MCS_32 Value %s\n",str);
                return WFA_FAILURE;
            }
            DPRINT_INFO(WFA_OUT, "MCS_32 -%i- \n", apWirelessParams->programArgs.args.mcs32);
        }else if(strcasecmp(str, "MPDU_MIN_START_SPACING") == 0){
            str = strtok_r(NULL, ",", &pcmdStr);
            apWirelessParams->programArgs.args.mpduMinStartSpacing= atoi(str);
            apWirelessParams->programArgs.args.mpduMinStartSpacing_flag = 1;
            DPRINT_INFO(WFA_OUT, "MPDU_MIN_START_SPACING -%d- \n", apWirelessParams->programArgs.args.mpduMinStartSpacing);
        }else if(strcasecmp(str, "RIFS_TEST") == 0){
            str = strtok_r(NULL, ",", &pcmdStr);
            apWirelessParams->programArgs.args.rifsTest = wfaStandardBoolParsing(str);
            if (apWirelessParams->programArgs.args.rifsTest > 1){
                DPRINT_ERR(WFA_ERR, "Invalid RIFS_TEST Value %s\n",str);
                return WFA_FAILURE;
            }
            DPRINT_INFO(WFA_OUT, "RIFS_TEST -%i- \n", apWirelessParams->programArgs.args.rifsTest);
        }else if(strcasecmp(str, "SGI20") == 0){
            str = strtok_r(NULL, ",", &pcmdStr);
            apWirelessParams->programArgs.args.sgi20 = wfaStandardBoolParsing(str);
            apWirelessParams->programArgs.args.sgi20_flag = 1;
            if (apWirelessParams->programArgs.args.sgi20 > 1){
                DPRINT_ERR(WFA_ERR, "Invalid SGI20 Value %s\n",str);
                return WFA_FAILURE;
            }
            DPRINT_INFO(WFA_OUT, "SGI20 -%i- \n", apWirelessParams->programArgs.args.sgi20);
        }else if(strcasecmp(str, "STBC_TX") == 0){
            str = strtok_r(NULL, ",", &pcmdStr);
            strncpy(apWirelessParams->programArgs.args.stbcTx, str, WFA_STBC_TX_LEN);
            DPRINT_INFO(WFA_OUT, "STBC_TX -%s- \n", apWirelessParams->programArgs.args.stbcTx);
        }else if(strcasecmp(str, "WIDTH_SCAN") == 0){
            str = strtok_r(NULL, ",", &pcmdStr);
            apWirelessParams->programArgs.args.widthScan = atoi(str);
            apWirelessParams->programArgs.args.widthScan_flag = 1;
            DPRINT_INFO(WFA_OUT, "WIDTH_SCAN -%d- \n", apWirelessParams->programArgs.args.widthScan);
        }else if(strcasecmp(str, "BCNINT") == 0){
            str = strtok_r(NULL, ",", &pcmdStr);
            strncpy(apWirelessParams->programArgs.args.bcnint, str, 16);
            apWirelessParams->programArgs.args.bcnint_flag = 1;
            DPRINT_INFO(WFA_OUT, "BCNINT -%s- \n", apWirelessParams->programArgs.args.bcnint);
        }else if(strcasecmp(str, "RADIO") == 0){
            str = strtok_r(NULL, ",", &pcmdStr);
            apWirelessParams->programArgs.args.radio = atoi(str);
            apWirelessParams->programArgs.args.radio_flag = 1;
            DPRINT_INFO(WFA_OUT, "RADIO -%d- \n", apWirelessParams->programArgs.args.radio);
        }else if(strcasecmp(str, "P2PMgmtBit") == 0){
            str = strtok_r(NULL, ",", &pcmdStr);
            apWirelessParams->programArgs.args.p2pMgmtBit = atoi(str);
            apWirelessParams->programArgs.args.p2pMgmtBit_flag = 1;
            DPRINT_INFO(WFA_OUT, "P2PMgmtBit -%d- \n", apWirelessParams->programArgs.args.p2pMgmtBit);
        }else if(strcasecmp(str, "ChannelUsage") == 0){
            str = strtok_r(NULL, ",", &pcmdStr);
            strncpy(apWirelessParams->programArgs.args.channelUsage, str, strlen(str));
            DPRINT_INFO(WFA_OUT, "ChannelUsage -%s- \n", apWirelessParams->programArgs.args.channelUsage);
        }else if(strcasecmp(str, "TDLSProhibit") == 0){
            str = strtok_r(NULL, ",", &pcmdStr);
            apWirelessParams->programArgs.args.tdlsProhibit = wfaStandardBoolParsing(str);
            apWirelessParams->programArgs.args.tdlsProhibit_flag = 1;
            if (apWirelessParams->programArgs.args.tdlsProhibit > 1){
                DPRINT_ERR(WFA_ERR, "Invalid TDLSProhibit Value %s\n",str);
                return WFA_FAILURE;
            }
            DPRINT_INFO(WFA_OUT, "TDLSProhibit -%i- \n", apWirelessParams->programArgs.args.tdlsProhibit);
        }else if(strcasecmp(str, "TDLSChswitchProhibit") == 0){
            str = strtok_r(NULL, ",", &pcmdStr);
            apWirelessParams->programArgs.args.tdlsChSwitchProhibit = wfaStandardBoolParsing(str);
            apWirelessParams->programArgs.args.tdlsChSwitchProhibit_flag = 1;
            if (apWirelessParams->programArgs.args.tdlsChSwitchProhibit > 1){
                DPRINT_ERR(WFA_ERR, "Invalid TDLSChswitchProhibit Value %s\n",str);
                return WFA_FAILURE;
            }
            DPRINT_INFO(WFA_OUT, "TDLSChswitchProhibit -%i- \n", apWirelessParams->programArgs.args.tdlsChSwitchProhibit);
        }else if(strcasecmp(str, "RRM") == 0){
            str = strtok_r(NULL, ",", &pcmdStr);
            apWirelessParams->programArgs.args.rpm = wfaStandardBoolParsing(str);
            apWirelessParams->programArgs.args.rpm_flag = 1;
            if (apWirelessParams->programArgs.args.rpm > 1){
                DPRINT_ERR(WFA_ERR, "Invalid RRM Value %s\n",str);
                return WFA_FAILURE;
            }
            DPRINT_INFO(WFA_OUT, "RRM -%i- \n", apWirelessParams->programArgs.args.rpm);
        }else if(strcasecmp(str, "NEIBRPT") == 0){
            str = strtok_r(NULL, ",", &pcmdStr);
            apWirelessParams->programArgs.args.neibrpt = wfaStandardBoolParsing(str);
            apWirelessParams->programArgs.args.neibrpt_flag = 1;
            if (apWirelessParams->programArgs.args.neibrpt > 1){
                DPRINT_ERR(WFA_ERR, "Invalid NEIBRPT Value %s\n",str);
                return WFA_FAILURE;
            }
            DPRINT_INFO(WFA_OUT, "NEIBRPT -%i- \n", apWirelessParams->programArgs.args.neibrpt);
        }else if(strcasecmp(str, "FT_OA") == 0){
            str = strtok_r(NULL, ",", &pcmdStr);
            apWirelessParams->programArgs.args.ftOa = wfaStandardBoolParsing(str);
            if (apWirelessParams->programArgs.args.ftOa > 1){
                DPRINT_ERR(WFA_ERR, "Invalid FT_OA Value %s\n",str);
                return WFA_FAILURE;
            }
            DPRINT_INFO(WFA_OUT, "FT_OA -%i- \n", apWirelessParams->programArgs.args.ftOa);
        }else if(strcasecmp(str, "FT_DS") == 0){
            str = strtok_r(NULL, ",", &pcmdStr);
            apWirelessParams->programArgs.args.ftDs = wfaStandardBoolParsing(str);
            if (apWirelessParams->programArgs.args.ftDs > 1){
                DPRINT_ERR(WFA_ERR, "Invalid FT_DS Value %s\n",str);
                return WFA_FAILURE;
            }
            DPRINT_INFO(WFA_OUT, "FT_DS -%i- \n", apWirelessParams->programArgs.args.ftDs);
        }else if(strcasecmp(str, "DOMAIN") == 0){
            str = strtok_r(NULL, ",", &pcmdStr);
            strncpy(apWirelessParams->programArgs.args.domain, str, strlen(str));
            apWirelessParams->programArgs.args.domain_flag = 1;
            DPRINT_INFO(WFA_OUT, "DOMAIN -%s- \n", apWirelessParams->programArgs.args.domain);
        }else if(strcasecmp(str, "PWR_CONST") == 0){
            str = strtok_r(NULL, ",", &pcmdStr);
            apWirelessParams->programArgs.args.pwrConst = atoi(str);
            apWirelessParams->programArgs.args.pwrConst_flag = 1;
            DPRINT_INFO(WFA_OUT, "PWR_CONST -%d- \n", apWirelessParams->programArgs.args.pwrConst);
        }else if(strcasecmp(str, "DTIM") == 0){
            str = strtok_r(NULL, ",", &pcmdStr);
            apWirelessParams->programArgs.args.dtim = atoi(str);
            apWirelessParams->programArgs.args.dtim_flag = 1;
            DPRINT_INFO(WFA_OUT, "DTIM -%d- \n", apWirelessParams->programArgs.args.dtim);
        }else if(strcasecmp(str, "HS2") == 0){
            str = strtok_r(NULL, ",", &pcmdStr);
            apWirelessParams->programArgs.args.hs2 = wfaStandardBoolParsing(str);
            if (apWirelessParams->programArgs.args.hs2 > 1){
                DPRINT_ERR(WFA_ERR, "Invalid HS2 Value %s\n",str);
                return WFA_FAILURE;
            }
            DPRINT_INFO(WFA_OUT, "HS2 -%i- \n", apWirelessParams->programArgs.args.hs2);
        }else if(strcasecmp(str, "P2P_CROSS_CONNECT") == 0){
            str = strtok_r(NULL, ",", &pcmdStr);
            apWirelessParams->programArgs.args.p2pCrossConnect = wfaStandardBoolParsing(str);
            apWirelessParams->programArgs.args.p2pCrossConnect_flag = 1;
            if (apWirelessParams->programArgs.args.p2pCrossConnect > 1){
                DPRINT_ERR(WFA_ERR, "Invalid P2P_CROSS_CONNECT Value %s\n",str);
                return WFA_FAILURE;
            }
            DPRINT_INFO(WFA_OUT, "P2P_CROSS_CONNECT -%i- \n", apWirelessParams->programArgs.args.p2pCrossConnect);
        }else if(strcasecmp(str, "4_FRAME_GAS") == 0){
            str = strtok_r(NULL, ",", &pcmdStr);
            apWirelessParams->programArgs.args._4FramGas = wfaStandardBoolParsing(str);
            apWirelessParams->programArgs.args._4FramGas_flag = 1;
            if (apWirelessParams->programArgs.args._4FramGas > 1){
                DPRINT_ERR(WFA_ERR, "Invalid 4_FRAME_GAS Value %s\n",str);
                return WFA_FAILURE;
            }
            DPRINT_INFO(WFA_OUT, "4_FRAME_GAS -%i- \n", apWirelessParams->programArgs.args._4FramGas);
        }else if(strcasecmp(str, "Regulatory_mode") == 0){
            str = strtok_r(NULL, ",", &pcmdStr);
            strncpy(apWirelessParams->programArgs.args.regularMode, str, strlen(str));
            apWirelessParams->programArgs.args.regularMode_flag = 1;
            DPRINT_INFO(WFA_OUT, "Regulatory_mode -%s- \n", apWirelessParams->programArgs.args.regularMode);
        }else if(strcasecmp(str, "CountryCode") == 0){
            str = strtok_r(NULL, ",", &pcmdStr);
            strncpy(apWirelessParams->programArgs.args.countryCode, str, strlen(str));
            apWirelessParams->programArgs.args.countryCode_flag = 1;
            DPRINT_INFO(WFA_OUT, "CountryCode -%s- \n", apWirelessParams->programArgs.args.countryCode);
        }
    }

    wfaEncodeTLV(WFA_AP_SET_WIRELESS_TLV, sizeof(caApSetWireless_t), (BYTE *)apWirelessParams, aBuf);
    *aLen = 4+sizeof(caApSetWireless_t);
    return WFA_SUCCESS;
}


int xcCmdProcApSetSecurity(char *pcmdStr, BYTE *aBuf, int *aLen)
{
    apSetSetCurity_t *apSecurityParams = (apSetSetCurity_t *)(aBuf + sizeof(wfaTLV));
    char *str;
    memset(aBuf, 0, *aLen);

    for(;;){
        str = strtok_r(NULL, ",", &pcmdStr);

        if(str == NULL || str[0] == '\0')
        break;

        if(strcasecmp(str, "NAME") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            strncpy(apSecurityParams->name, str, 16);
            DPRINT_INFO(WFA_OUT, "name %s\n", apSecurityParams->name);
        }

        if(strcasecmp(str, "KEYMGNT") == 0){
            str = strtok_r(NULL, ",", &pcmdStr);
            strncpy(apSecurityParams->keyMgnt, str, WFA_KEYMGNT_LEN - 1);
            DPRINT_INFO(WFA_OUT, "KEYMGNT -%s- \n", apSecurityParams->keyMgnt);
        }

        if(strcasecmp(str, "INTERFACE") == 0){
            str = strtok_r(NULL, ",", &pcmdStr);
            strncpy(apSecurityParams->interface, str, WFA_HW_INTF_LEN - 1);
            DPRINT_INFO(WFA_OUT, "INTERFACE -%s- \n", apSecurityParams->interface);
        }else if(strcasecmp(str, "PSK") == 0){
            str = strtok_r(NULL, ",", &pcmdStr);
            strncpy(apSecurityParams->pskType, str, WFA_PSK_LEN - 1);
            DPRINT_INFO(WFA_OUT, "PSK -%s- \n", apSecurityParams->pskType);
        }else if(strcasecmp(str, "WEPKEY") == 0){
            str = strtok_r(NULL, ",", &pcmdStr);
            strncpy(apSecurityParams->wepKey, str, WFA_WEPKEY_LEN - 1);
            DPRINT_INFO(WFA_OUT, "WEPKEY -%s- \n", apSecurityParams->wepKey);
        }else if(strcasecmp(str, "SSID") == 0){
            str = strtok_r(NULL, ",", &pcmdStr);
            strncpy(apSecurityParams->ssid, str, WFA_SSID_NAME_LEN - 1);
            DPRINT_INFO(WFA_OUT, "SSID -%s- \n", apSecurityParams->ssid);
        }else if(strcasecmp(str, "PMF") == 0){
            str = strtok_r(NULL, ",", &pcmdStr);
            if(strcasecmp(str, "Required") == 0){
                apSecurityParams->pmfReq = 0;
            }
            else if(strcasecmp(str, "Optional")==0){
                apSecurityParams->pmfReq = 1;
            }
            else if(strcasecmp(str, "Disabled") == 0){
                apSecurityParams->pmfReq = 2;
            }
            DPRINT_INFO(WFA_OUT, "\n PMF  -%d- \n", apSecurityParams->pmfReq);
        }else if(strcasecmp(str, "SHA256AD") == 0){
            str = strtok_r(NULL, ",", &pcmdStr);
            apSecurityParams->sha256ad = wfaStandardBoolParsing(str);
            if (apSecurityParams->sha256ad > 1){
                DPRINT_ERR(WFA_ERR, "Invalid SHA256AD Value %s\n",str);
                return WFA_FAILURE;
            }
            DPRINT_INFO(WFA_OUT, "SHA256AD -%i- \n", apSecurityParams->sha256ad);
        }else if(strcasecmp(str, "ENCRYPT") == 0){
            str = strtok_r(NULL, ",", &pcmdStr);
            strncpy(apSecurityParams->encrypt, str, WFA_ENCRYPT_LEN - 1);
            DPRINT_INFO(WFA_OUT, "ENCRYPT -%s- \n", apSecurityParams->encrypt);
        }
    }

    wfaEncodeTLV(WFA_AP_SET_SECURITY_TLV, sizeof(apSetSetCurity_t), (BYTE *)apSecurityParams, aBuf);
    *aLen = 4+sizeof(apSetSetCurity_t);
    return WFA_SUCCESS;
}

int xcCmdProcApDeauthSta(char *pcmdStr, BYTE *aBuf, int *aLen)
{
    apdeauthsta_t *setencryp = (apdeauthsta_t *) (aBuf+sizeof(wfaTLV));
    char *str;
    apdeauthsta_t defparams = {"", "","", 0};

        if(aBuf == NULL)
            return WFA_FAILURE;

        memset(aBuf, 0, *aLen);
        memcpy((void *)setencryp, (void *)&defparams, sizeof(apdeauthsta_t));

        for(;;)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            if(str == NULL || str[0] == '\0')
                break;

            if(strcasecmp(str, "NAME") == 0)
            {
                str = strtok_r(NULL, ",", &pcmdStr);
                strncpy(setencryp->name, str, 16);
                DPRINT_INFO(WFA_OUT, "name %s\n", setencryp->name);
            }
            else if(strcasecmp(str, "interface") == 0)
            {
                str = strtok_r(NULL, ",", &pcmdStr);
                strncpy(setencryp->intf, str, 16);
                DPRINT_INFO(WFA_OUT, "interface %s\n", setencryp->intf);
            }
            else if(strcasecmp(str, "sta_mac_address") == 0)
            {
                str = strtok_r(NULL, ",", &pcmdStr);
                strncpy((char *)setencryp->stamacaddress, str, 32);
                DPRINT_INFO(WFA_OUT, "stamacaddress %s\n", setencryp->stamacaddress);
            }
            else if(strcasecmp(str, "min orcode") == 0)
            {
                str=strtok_r(NULL, ",", &pcmdStr);
                setencryp->minorcode =  atoi(str);
            }
            else
            {
                DPRINT_INFO(WFA_WNG, "Incorrect Command, check syntax\n");
            }
        }
    wfaEncodeTLV(WFA_AP_DEAUTH_STA_TLV, sizeof(apdeauthsta_t), (BYTE *)setencryp, aBuf);

    *aLen = 4+sizeof(apdeauthsta_t);
    return WFA_SUCCESS;
}

int xcCmdProcApSetPmf(char *pcmdStr, BYTE *aBuf, int *aLen)
{
    apsetpmf_t *setencryp = (apsetpmf_t *) (aBuf+sizeof(wfaTLV));
    char *str;

    memset(aBuf, 0, *aLen);
    if (memset_s((void *)setencryp, sizeof(apsetpmf_t), 0, sizeof(apsetpmf_t)) != EOK) {
        return WFA_ERROR;
    }

    for(;;)
    {
        str = strtok_r(NULL, ",", &pcmdStr);
        if(str == NULL || str[0] == '\0')
            break;

        if(strcasecmp(str, "NAME") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            strncpy(setencryp->name, str, 16);
        }
            else if(strcasecmp(str, "INTERFACE") == 0)
            {
                str = strtok_r(NULL, ",", &pcmdStr);
                strncpy(setencryp->intf, str, 16);
            }
            else if(strcasecmp(str, "pmf") == 0)
            {
                str = strtok_r(NULL, ",", &pcmdStr);
                strncpy((char *)setencryp->pmf, str, 32);
            }
            else
            {
                DPRINT_INFO(WFA_WNG, "Incorrect Command, check syntax\n");
            }
        }

    wfaEncodeTLV(WFA_AP_SET_PMF_TLV, sizeof(apsetpmf_t), (BYTE *)setencryp, aBuf);

    *aLen = 4+sizeof(apsetpmf_t);
    return WFA_SUCCESS;
}

int xcCmdProcStaSetPwrsave(char *pcmdStr, BYTE *aBuf, int *aLen)
{
    stasetpwrsave_t *setencryp = (stasetpwrsave_t *) (aBuf+sizeof(wfaTLV));
    char *str;

    memset(aBuf, 0, *aLen);
    if (memset_s((void *)setencryp, sizeof(stasetpwrsave_t), 0, sizeof(stasetpwrsave_t)) != EOK) {
        return WFA_ERROR;
    }

    for(;;)
    {
        str = strtok_r(NULL, ",", &pcmdStr);
        if(str == NULL || str[0] == '\0')
            break;

        if(strcasecmp(str, "interface") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            strncpy(setencryp->intf, str, 16);
            DPRINT_INFO(WFA_OUT, "----> %s\n",setencryp->intf);
        }
        else if(strcasecmp(str, "mode") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            if (strcasecmp(str, "on") == 0) {
                strncpy(setencryp->mode, "1", 1);
            } else if (strcasecmp(str, "off") == 0) {
                strncpy(setencryp->mode, "0", 1);
            } else {
                DPRINT_INFO(WFA_ERR, "mode type error\n");
            }
            DPRINT_INFO(WFA_OUT, "----> %s\n",setencryp->mode);
        }
        else
        {
            DPRINT_INFO(WFA_WNG, "Incorrect Command, check syntax\n");
        }
    }

    wfaEncodeTLV(WFA_STA_SET_PWRSAVE_TLV, sizeof(stasetpwrsave_t), (BYTE *)setencryp, aBuf);

    *aLen = 4+sizeof(stasetpwrsave_t);
    return WFA_SUCCESS;
}

int xcCmdProcStaSetSecurity(char *pcmdStr, BYTE *aBuf, int *aLen)
{
    caStaSetSecurity_t *setencryp = (caStaSetSecurity_t *) (aBuf+sizeof(wfaTLV));
    char *str;

    memset(aBuf, 0, *aLen);
    if (memset_s((void *)setencryp, sizeof(caStaSetSecurity_t), 0, sizeof(caStaSetSecurity_t)) != EOK) {
        return ERROR;
    }

    for(;;)
    {
        str = strtok_r(NULL, ",", &pcmdStr);
        if(str == NULL || str[0] == '\0')
            break;

        if(strcasecmp(str, "type") == 0)
        {
           /* process the specific type of security */
           str = strtok_r (NULL, ",", &pcmdStr);
           strncpy(setencryp->type, str, 16);
           DPRINT_INFO(WFA_OUT, "-->%s\n",setencryp->type);
        }
        else if(strcasecmp(str, "interface") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            strncpy(setencryp->intf, str, 16);
        }
        else if(strcasecmp(str, "ssid") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            strncpy(setencryp->ssid, str, 64);
            DPRINT_INFO(WFA_OUT, "ssid %s\n", setencryp->ssid);
        }
        else if(strcasecmp(str, "keyMgmtType") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            strncpy(setencryp->keyMgmtType, str, 8);
        }
        else if(strcasecmp(str, "encpType") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            strncpy(setencryp->encpType, str, 9);
        }
        else if(strcasecmp(str, "pmf") == 0)
        {
            str = strtok_r (NULL, ",", &pcmdStr);
            strncpy(setencryp->pmf, str, 16);
        }
        else if(strcasecmp(str, "micAlg") == 0)
        {
           /* process the specific type of security */
           str = strtok_r (NULL, ",", &pcmdStr);
           strncpy(setencryp->micaig, str, 8);
        }
    }
    wfaEncodeTLV(WFA_STA_SET_SECURITY_TLV, sizeof(caStaSetSecurity_t), (BYTE *)setencryp, aBuf);

    *aLen = 4+sizeof(caStaSetSecurity_t);
    return WFA_SUCCESS;
}

int xcCmdProcStaSetUapsd(char *pcmdStr, BYTE *aBuf, int *aLen)
{

    caStaSetUAPSD_t *setuapsd = (caStaSetUAPSD_t *) (aBuf+sizeof(wfaTLV));
    char *str;
    caStaSetUAPSD_t defparams = {"", "", 0, 0, 0, 0, 0};

    DPRINT_INFO(WFA_OUT, "start xcCmdProcAgentConfig ...\n");
    DPRINT_INFO(WFA_OUT, "params::%s\n", pcmdStr);
    if(aBuf == NULL)
        return WFA_FAILURE;

    memset(aBuf, 0, *aLen);
    memcpy((void *)setuapsd, (void *)&defparams, sizeof(caStaSetUAPSD_t));
    setuapsd->maxSPLength= 4;
    setuapsd->acBE = 1;
    setuapsd->acBK = 1;
    setuapsd->acVI = 1;
    setuapsd->acVO = 1;

    for(;;)
    {
        str = strtok_r(NULL, ",", &pcmdStr);
        if(str == NULL || str[0] == '\0')
            break;

        if(strcasecmp(str, "interface") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            strncpy(setuapsd->intf, str, 15);
        }
        else if(strcasecmp(str, "ssid") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            strncpy(setuapsd->ssid, str, WFA_SSID_NAME_LEN - 1);
        }
        else if(strcasecmp(str, "maxSPLength") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            setuapsd->maxSPLength = atoi(str);
        }
        else if(strcasecmp(str, "acBE") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            setuapsd->acBE = atoi(str);

        }
        else if(strcasecmp(str, "acBK") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            setuapsd->acBK = atoi(str);

        }
        else if(strcasecmp(str, "acVI") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            setuapsd->acVI = atoi(str);
        }
        else if(strcasecmp(str, "acVO") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            setuapsd->acVO = atoi(str);
        }
    }

    wfaEncodeTLV(WFA_STA_SET_UAPSD_TLV, sizeof(caStaSetUAPSD_t), (BYTE *)setuapsd, aBuf);

    *aLen = 4+sizeof(caStaSetUAPSD_t);
    return WFA_SUCCESS;
}

int xcCmdApGetMacAddress(char *pcmdStr, BYTE *aBuf, int *aLen)
{
    apgetmacaddress_t *setencryp = (apgetmacaddress_t *) (aBuf+sizeof(wfaTLV));
    char *str;

    memset(aBuf, 0, *aLen);
    if (memset_s((void *)setencryp, sizeof(apgetmacaddress_t), 0, sizeof(apgetmacaddress_t)) != EOK) {
        return WFA_ERROR;
    }

    for(;;)
    {
        str = strtok_r(NULL, ",", &pcmdStr);
        if(str == NULL || str[0] == '\0')
            break;

        if(strcasecmp(str, "interface") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            strncpy(setencryp->interface, str, 16);
            DPRINT_INFO(WFA_OUT, "----> %s\n",setencryp->interface);
        }
        else
        {
            DPRINT_INFO(WFA_WNG, "Incorrect Command, check syntax\n");
        }
    }

    wfaEncodeTLV(WFA_AP_GET_MAC_ADDRESS_TLV, sizeof(apgetmacaddress_t), (BYTE *)setencryp, aBuf);

    *aLen = 4+sizeof(apgetmacaddress_t);
    return WFA_SUCCESS;
}

int xcCmdProcApCaVersion(char *pcmdStr, BYTE *aBuf, int *aLen)
{
    ApCaVersion_t *setencryp = (ApCaVersion_t *) (aBuf+sizeof(wfaTLV));
    char *str;

    memset(aBuf, 0, *aLen);
    if (memset_s((void *)setencryp, sizeof(ApCaVersion_t), 0, sizeof(ApCaVersion_t)) != EOK) {
        return WFA_ERROR;
    }

    for(;;)
    {
        str = strtok_r(NULL, ",", &pcmdStr);
        if(str == NULL || str[0] == '\0')
            break;

        if(strcasecmp(str, "NAME") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            strncpy(setencryp->name, str, 16);
        }
        else
        {
            DPRINT_INFO(WFA_WNG, "Incorrect Command, check syntax\n");
        }
    }

    wfaEncodeTLV(WFA_AP_CA_VERSION_TLV, sizeof(ApCaVersion_t), (BYTE *)setencryp, aBuf);

    *aLen = 4+sizeof(ApCaVersion_t);
    return WFA_SUCCESS;
}

int xcCmdProcApReboot(char *pcmdStr, BYTE *aBuf, int *aLen)
{
    apRoot_t *setencryp = (apRoot_t *) (aBuf+sizeof(wfaTLV));
    char *str;

    memset(aBuf, 0, *aLen);
    if (memset_s((void *)setencryp, sizeof(apRoot_t), 0, sizeof(apRoot_t)) != EOK) {
        return ERROR;
    }

    for(;;)
    {
        str = strtok_r(NULL, ",", &pcmdStr);
        if(str == NULL || str[0] == '\0')
            break;

        if(strcasecmp(str, "NAME") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            strncpy(setencryp->name, str, 16);
        }
        else
        {
            DPRINT_INFO(WFA_WNG, "Incorrect Command, check syntax\n");
        }
    }

    wfaEncodeTLV(WFA_AP_REBOOT_TLV, sizeof(apRoot_t), (BYTE *)setencryp, aBuf);

    *aLen = 4+sizeof(apRoot_t);
    return WFA_SUCCESS;
}

int xcCmdProcApConfigCommit(char *pcmdStr, BYTE *aBuf, int *aLen)
{
    apConfigCommit_t *setencryp = (apConfigCommit_t *) (aBuf+sizeof(wfaTLV));
    char *str;

    memset(aBuf, 0, *aLen);
    if (memset_s((void *)setencryp, sizeof(apConfigCommit_t), 0, sizeof(apConfigCommit_t)) != EOK) {
        return ERROR;
    }

    for(;;)
    {
        str = strtok_r(NULL, ",", &pcmdStr);
        if(str == NULL || str[0] == '\0')
            break;

        if(strcasecmp(str, "NAME") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            strncpy(setencryp->name, str, 16);
        }
        else
        {
            DPRINT_INFO(WFA_WNG, "Incorrect Command, check syntax\n");
        }
    }

    wfaEncodeTLV(WFA_AP_CONFIG_COMMIT_TLV, sizeof(apConfigCommit_t), (BYTE *)setencryp, aBuf);

    *aLen = 4+sizeof(apConfigCommit_t);
    return WFA_SUCCESS;
}

int xcCmdProcApResetDefault(char *pcmdStr, BYTE *aBuf, int *aLen)
{
    apResetDefault_t *setencryp = (apResetDefault_t *) (aBuf+sizeof(wfaTLV));
    char *str;

    memset(aBuf, 0, *aLen);
    if (memset_s((void *)setencryp, sizeof(apResetDefault_t), 0, sizeof(apResetDefault_t)) != EOK) {
        return ERROR;
    }

    for(;;)
    {
        str = strtok_r(NULL, ",", &pcmdStr);
        if(str == NULL || str[0] == '\0')
            break;

        if(strcasecmp(str, "NAME") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            strncpy(setencryp->name, str, 16);
        }
        else if(strcasecmp(str, "program") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            strncpy(setencryp->program, str, 16);
        }
        else if(strcasecmp(str, "interface") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            strncpy(setencryp->interface, str, 16);
        }
        else if(strcasecmp(str, "type") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            strncpy(setencryp->devType, str, 16);
        }
        else
        {
            DPRINT_INFO(WFA_WNG, "Incorrect Command, check syntax\n");
        }
    }

    wfaEncodeTLV(WFA_AP_RESET_DEFAULT_TLV, sizeof(apResetDefault_t), (BYTE *)setencryp, aBuf);

    *aLen = 4+sizeof(apResetDefault_t);
    return WFA_SUCCESS;
}

int xcCmdProcApGetInfo(char *pcmdStr, BYTE *aBuf, int *aLen)
{
    apGetInfo_t *setencryp = (apGetInfo_t *) (aBuf+sizeof(wfaTLV));
    char *str;

    memset(aBuf, 0, *aLen);
    if (memset_s((void *)setencryp, sizeof(apGetInfo_t), 0, sizeof(apGetInfo_t)) != EOK) {
        return ERROR;
    }

    for(;;)
    {
        str = strtok_r(NULL, ",", &pcmdStr);
        if(str == NULL || str[0] == '\0')
            break;

        if(strcasecmp(str, "NAME") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            strncpy(setencryp->name, str, 16);
        }
        else
        {
            DPRINT_INFO(WFA_WNG, "Incorrect Command, check syntax\n");
        }
    }

    wfaEncodeTLV(WFA_AP_GET_INFO_TLV, sizeof(apGetInfo_t), (BYTE *)setencryp, aBuf);
    *aLen = 4+sizeof(apGetInfo_t);
    return WFA_SUCCESS;
}

