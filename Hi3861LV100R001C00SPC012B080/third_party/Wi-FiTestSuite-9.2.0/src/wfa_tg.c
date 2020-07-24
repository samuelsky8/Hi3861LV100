
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
 *    File: wfa_tg.c
 *    Library functions for traffic generator.
 *    They are shared with both TC and DUT agent.
 */

#include "wfa_portall.h"
#include "wfa_debug.h"
#include "wfa_types.h"
#include "wfa_miscs.h"
#include "wfa_ver.h"
#include "wfa_main.h"
#include "wfa_tlv.h"
#include "wfa_tg.h"
#include "wfa_cmds.h"
#include "wfa_sock.h"
#include "wfa_rsp.h"
#include "wfa_wmmps.h"
#include "wfa_dut.h"
#include <hi_sem.h>
#include <errno.h>

/* 存储stream表的数组 */
tgStream_t* gStreams;
extern BOOL gtgRecv;
extern BOOL gtgSend;
extern BOOL gtgTransac;

int adj_latency = 0;

extern tgStream_t *findStreamProfile(int);
extern int wfaTrafficSendTo(int, char *, int, struct sockaddr *);
extern int wfaTrafficRecv(int, char *, struct sockaddr *);
extern void wfaSendPing(tgPingStart_t *staPing, int *interval, int streamid);
extern int wfaStopPing(dutCmdResponse_t *stpResp, int streamid);
extern int gtimeOut;
extern int tgSockfds[];
extern unsigned int power_save_flag;
extern tgWMM_t wmm_thr[];

static int streamId = 0;
static int totalTranPkts = 0, sentTranPkts = 0;
//stream表的索引，值代表当前stream表格内的profile个数
int slotCnt = 0;

extern int usedThread;
extern int runLoop;
extern int sendThrId;

extern dutCmdResponse_t gGenericResp;
extern int is_task_resp;
extern BOOL gtgCaliRTD;
extern double min_rttime;
extern double gtgPktRTDelay;

int psSockfd = -1;
extern int **ac_seq;
int msgsize=256;
extern char gCmdStr[WFA_CMD_STR_SZ];

extern void BUILD_APTS_MSG(int msg, unsigned long *txbuf);
extern void mpx(char *m, void *buf_v, int len);
extern int gtgWmmPS;
extern wfaWmmPS_t wmmps_info;
extern int psSockfd;
extern unsigned int psTxMsg[];
extern unsigned int psRxMsg[];
extern int gtgPsPktRecvd;
extern void wfaSetDUTPwrMgmt(int mode);

/* Some devices may only support UDP ECHO and do not have ICMP level ping */
// #define WFA_PING_UDP_ECHO_ONLY     1

/*
 * findStreamProfile(): search existing stream profile by stream id
 * input: id - stream id;
 * return: matched stream profile
 */
tgStream_t *findStreamProfile(int id)
{
    int i;
    tgStream_t *myStream = gStreams;

    for(i = 0; i< WFA_MAX_TRAFFIC_STREAMS; i++)
    {
       if(myStream->id == id){
           return myStream;
       }
       myStream++;
    }
    printf("findStreamProfile null...\n");
    return NULL;

}

/*
 * wfaTGSendPing(): Instruct Traffic Generator to send ping packets
 *
 */
int wfaTGSendPing(int len, BYTE *caCmdBuf, int *respLen, BYTE *respBuf)
{
    int streamid = ++streamId;
    int interval;      /* it could be subseconds/100s minisecond */
    tgPingStart_t *staPing = (tgPingStart_t *)caCmdBuf;
    dutCmdResponse_t *spresp = &gGenericResp;
    hi_unref_param(len);

    DPRINT_INFO(WFA_OUT, "Entering wfaTSendPing ...\n");
    if(staPing->frameSize == 0){
        staPing->frameSize = 100;
    }
    printf("framerate %d\n", staPing->frameRate);
    if(staPing->frameRate == 0){
        staPing->frameRate = 1;
    }

    interval = (int) (1000 / staPing->frameRate);
    gtimeOut = interval;
    if(interval == 0){
        interval = 1;
    }
    printf("TG: interval %d\n", interval);

    if(staPing->duration == 0){
    }

    printf("The steam ID is:%d \n",streamId);
    wfaSendPing(staPing, &interval, streamId);

    spresp->status = STATUS_COMPLETE;
    spresp->streamId = streamid;


    wfaEncodeTLV(WFA_TRAFFIC_SEND_PING_RESP_TLV, sizeof(dutCmdResponse_t), (BYTE *)spresp, respBuf);
    *respLen = WFA_TLV_HDR_LEN + sizeof(dutCmdResponse_t);

    return WFA_SUCCESS;
}

/*
 * tgStopPing(): Instruct Traffic Generator to stop ping packets
 *
 */
int wfaTGStopPing(int len, BYTE *caCmdBuf, int *respLen, BYTE *respBuf)
{
    unsigned int streamid = *(unsigned int*)(caCmdBuf);
    dutCmdResponse_t *stpResp = &gGenericResp;
    tgStream_t *myStream;
    int i;

    stpResp->status = STATUS_COMPLETE;

    printf("CS: The length %d\n and the command buff is \n",len);

    for (i=0;i<8;i++){
        printf(" %x ",caCmdBuf[i]);
    }
    printf("\nthe stream id is %d",streamid);

    if( gtgTransac == streamid && gtgSend == streamid)
    {
        gtgTransac =0;
        gtgSend = 0;
        gtgRecv = 0;

        myStream = findStreamProfile(streamid);
        if(myStream == NULL)
        {
            stpResp->status = STATUS_INVALID;
        }

        stpResp->cmdru.pingStp.sendCnt = myStream->stats.txFrames;
        stpResp->cmdru.pingStp.repliedCnt = myStream->stats.rxFrames;
    }
    else
    {
        wfaStopPing(stpResp, streamid);
    }

    wfaEncodeTLV(WFA_TRAFFIC_STOP_PING_RESP_TLV, sizeof(dutCmdResponse_t), (BYTE *)stpResp, respBuf);
    *respLen = WFA_TLV_HDR_LEN + sizeof(dutCmdResponse_t);

    return WFA_SUCCESS;
}

/*
 * wfaTGConfig: store the traffic profile setting that will be used to
 *           instruct traffic generation.
 * input: cmd -- not used
 * response: send success back to controller
 * return: success or fail
 * Note: the profile storage is a global space.
 */
int wfaTGConfig(int len, BYTE *caCmdBuf, int *respLen, BYTE *respBuf)
{
    int ret = WFA_FAILURE;
    tgStream_t *myStream = NULL;
    dutCmdResponse_t *confResp = &gGenericResp;

    /* if the stream table over maximum, reset it */
    if(slotCnt == WFA_MAX_TRAFFIC_STREAMS){
        slotCnt = 0;
    }
    if(slotCnt == 0)
    {
        printf("resetting stream table\n");
        wMEMSET(gStreams, 0, WFA_MAX_TRAFFIC_STREAMS*sizeof(tgStream_t));
    }

    DPRINT_INFO(WFA_OUT, "entering tcConfig ...\n");
    myStream = &gStreams[slotCnt++];
    wMEMSET(myStream, 0, sizeof(tgStream_t));
    wMEMCPY(&myStream->profile, caCmdBuf, len);
    myStream->id = ++streamId; /* the id start from 1 */
    myStream->tblidx = slotCnt-1;
    printf("myStream->id = %d\n",myStream->id);
#if 0
    DPRINT_INFO(WFA_OUT, "profile %i direction %i dest ip %s dport %i source %s sport %i rate %i duration %i size %i class %i delay %i\n", myStream->profile.profile, myStream->profile.direction, myStream->profile.dipaddr, myStream->profile.dport, myStream->profile.sipaddr, myStream->profile.sport, myStream->profile.rate, myStream->profile.duration, myStream->profile.pksize, myStream->profile.trafficClass, myStream->profile.startdelay);
#endif

    confResp->status = STATUS_COMPLETE;
    confResp->streamId = myStream->id;
    wfaEncodeTLV(WFA_TRAFFIC_AGENT_CONFIG_RESP_TLV, sizeof(dutCmdResponse_t), (BYTE *)confResp, respBuf);
    *respLen = WFA_TLV_HDR_LEN + sizeof(dutCmdResponse_t);

    return ret;
}

/* RecvStart: instruct traffic generator to start receiving
 *                 based on a profile
 * input:      cmd -- not used
 * response:   inform controller for "running"
 * return:     success or failed
 */
int wfaTGRecvStart(int len, BYTE *parms, int *respLen, BYTE *respBuf)
{
    int status = STATUS_COMPLETE, i;
    int numStreams = len/4;
    int streamid;
    tgProfile_t *theProfile;
    tgStream_t *myStream;

    DPRINT_INFO(WFA_OUT, "entering tgRecvStart\n");

    /*
     * The function wfaSetProcPriority called here is to enhance the real-time
     * performance for packet receiving. It is only for tuning and optional
     * to implement
     */
    //wfaSetProcPriority(60);

    for(i=0; i<numStreams; i++)
    {
        wMEMCPY(&streamid, parms+(4*i), 4); /* changed from 2 to 4, bug reported by n.ojanen */
        myStream = findStreamProfile(streamid);
        if(myStream == NULL)
        {
            DPRINT_INFO(WFA_OUT, "myStream is NULL\n");
            status = STATUS_INVALID;
            wfaEncodeTLV(WFA_TRAFFIC_AGENT_RECV_START_RESP_TLV, 4, (BYTE *)&status, respBuf);
            *respLen = WFA_TLV_HDR_LEN + 4;
            return status;
        }

        theProfile = &myStream->profile;
        if(theProfile == NULL)
        {
           DPRINT_INFO(WFA_OUT, "theProfile is NULL\n");
           status = STATUS_INVALID;
           wfaEncodeTLV(WFA_TRAFFIC_AGENT_RECV_START_RESP_TLV, 4, (BYTE *)&status, respBuf);
           *respLen = WFA_TLV_HDR_LEN + 4;
           return status;
        }

        /* calculate the frame interval which is used to derive its jitter */
        if(theProfile->rate != 0 && theProfile->rate < 5000){
            myStream->fmInterval = 1000000/theProfile->rate; /* in ms */
        }else{
            myStream->fmInterval = 0;
        }

        if(theProfile->direction != DIRECT_RECV)
        {
           DPRINT_INFO(WFA_OUT, "direction is not DIRECT_RECV\n");
           status = STATUS_INVALID;
           wfaEncodeTLV(WFA_TRAFFIC_AGENT_RECV_START_RESP_TLV, 4, (BYTE *)&status, respBuf);
           *respLen = WFA_TLV_HDR_LEN + 4;
           return status;
        }

        wMEMSET(&myStream->stats, 0, sizeof(tgStats_t));

        // mark the stream active
        myStream->state = WFA_STREAM_ACTIVE;

        switch(theProfile->profile)
        {
            case PROF_TRANSC:
                /* fall through */
            case PROF_CALI_RTD:  /* Calibrate roundtrip delay */
                gtgTransac = streamid;
                /* fall through */
            case PROF_MCAST:
                /* fall through */
            case PROF_FILE_TX:
                /* fall through */
            case PROF_IPTV:
              gtgRecv = streamid;
              wmm_thr[usedThread].thr_flag = streamid;
              wPT_MUTEX_LOCK(&wmm_thr[usedThread].thr_flag_mutex);
              wPT_COND_SIGNAL(&wmm_thr[usedThread].thr_flag_semaphore);
              wPT_MUTEX_UNLOCK(&wmm_thr[usedThread].thr_flag_mutex);
              printf("Recv Start in thread %i for streamid %i\n", usedThread, streamid);
              usedThread++;
              break;
           case PROF_UAPSD:
               printf("----> enter wfaTGRecvStart PROF_UAPSD...\n");
               status = STATUS_COMPLETE;
               psSockfd = wfaCreateUDPSock(theProfile->dipaddr, WFA_WMMPS_UDP_PORT);
               printf("----> wfaCreateUDPSock psSockfd = %d...\n",psSockfd);
               power_save_flag = 1;
               wmmps_info.sta_state = 0;
               wmmps_info.wait_state = WFA_WAIT_STAUT_00;

               wMEMSET(&wmmps_info.psToAddr, 0, sizeof(wmmps_info.psToAddr));
               wmmps_info.psToAddr.sin_family = AF_INET;
               wmmps_info.psToAddr.sin_addr.s_addr = inet_addr(theProfile->sipaddr);
               wmmps_info.psToAddr.sin_port = htons(theProfile->sport);
               wmmps_info.reset = 0;

               printf("theProfile->sipaddr---->%s...\n",theProfile->sipaddr);
               printf("theProfile->sport---->%d...\n",theProfile->sport);
               wmm_thr[usedThread].thr_flag = streamid;
               wmmps_info.streamid = streamid;
               wPT_MUTEX_LOCK(&wmm_thr[usedThread].thr_flag_mutex);
               wPT_COND_SIGNAL(&wmm_thr[usedThread].thr_flag_semaphore);
               gtgWmmPS = streamid;
               wPT_MUTEX_UNLOCK(&wmm_thr[usedThread].thr_flag_mutex);
               usedThread++;
               break;
       }
    }

    printf("wfaTGRecvStart......\n");
    /* encode a TLV for response for "complete/error ..." */
    wfaEncodeTLV(WFA_TRAFFIC_AGENT_RECV_START_RESP_TLV, sizeof(int),
                 (BYTE *)&status, respBuf);
    *respLen = WFA_TLV_HDR_LEN + sizeof(int);

    return WFA_SUCCESS;
}

/*
 * tgRecvStop: instruct traffic generator to stop receiving based on a profile
 * input:      cmd -- not used
 * response:   inform controller for "complete"
 * return:     success or failed
 */
int wfaTGRecvStop(int len, BYTE *parms, int *respLen, BYTE *respBuf)
{

    int status = STATUS_COMPLETE, i;
    int numStreams = len/4;
    unsigned int streamid;
    tgProfile_t *theProfile;
    tgStream_t *myStream=NULL;
    dutCmdResponse_t statResp;
    BYTE dutRspBuf[WFA_RESP_BUF_SZ];
    int id_cnt = 0;

    DPRINT_INFO(WFA_OUT, "entering tgRecvStop with length %d\n",len);

    /* in case that send-stream not done yet, an optional delay */
    while(sendThrId != -1){
        DPRINT_INFO(WFA_OUT, "send stream %d is not done yet\n", sendThrId);
        sleep(1);
    }

    /*
     * After finishing the receiving command, it should lower itself back to
     * normal level. It is optional implementation if it is not called
     * while it starts receiving for raising priority level.
     */
    //wfaSetProcPriority(30);
    wMEMSET(dutRspBuf, 0, WFA_RESP_BUF_SZ);
    for(i=0; i<numStreams; i++)
    {
        wMEMCPY(&streamid, parms+(4*i), 4);
        printf(" stop stream id %i\n", streamid);
        myStream = findStreamProfile(streamid);
        if(myStream == NULL)
        {
            status = STATUS_INVALID;
            wfaEncodeTLV(WFA_TRAFFIC_AGENT_RECV_STOP_RESP_TLV, 4, (BYTE *)&status, respBuf);
            *respLen = WFA_TLV_HDR_LEN + 4;
            printf("stream table empty\n");
            continue;
        }
        printf("theProfile ...\n");
        theProfile = &myStream->profile;
        if(theProfile == NULL)
        {
           status = STATUS_INVALID;
           wfaEncodeTLV(WFA_TRAFFIC_AGENT_RECV_STOP_RESP_TLV, 4, (BYTE *)&status, respBuf);
           *respLen = WFA_TLV_HDR_LEN + 4;

           return WFA_SUCCESS;
        }
        printf("theProfile->direction ...\n");
        if(theProfile->direction != DIRECT_RECV)
        {
           status = STATUS_INVALID;
           wfaEncodeTLV(WFA_TRAFFIC_AGENT_RECV_STOP_RESP_TLV, 4, (BYTE *)&status, respBuf);
           *respLen = WFA_TLV_HDR_LEN + 4;

           return WFA_SUCCESS;
        }

        /* reset its flags , close sockets */
        switch(theProfile->profile)
        {
         case PROF_TRANSC:
            /* fall through */
         case PROF_CALI_RTD:
             gtgTransac = 0;
            /* fall through */
         case PROF_MCAST:
            /* fall through */
         case PROF_FILE_TX:
            /* fall through */
         case PROF_IPTV:
             gtgRecv = 0;
             DPRINT_INFO(WFA_OUT, "myStream->tblidx %d\n", myStream->tblidx);
             if(tgSockfds[myStream->tblidx] != -1)
             {
                DPRINT_INFO(WFA_OUT, "close tgSockfds %d \n", tgSockfds[myStream->tblidx]);
                wCLOSE(tgSockfds[myStream->tblidx]);
                tgSockfds[myStream->tblidx] = -1;
             }
             break;

         case PROF_UAPSD:
              printf("PROF_UAPSD ...\n");
              gtgWmmPS = 0;
              gtgPsPktRecvd = 0;
              power_save_flag = 0;
              if(psSockfd != -1)
              {
                  wCLOSE(psSockfd);
                  DPRINT_INFO(WFA_OUT, "wfaTGRecvStop psSockfd...\n");
                  psSockfd = -1;
              }
              wMEMSET(&wmmps_info, 0, sizeof(wfaWmmPS_t));
              wfaSetDUTPwrMgmt(PS_OFF);
              break;

         }

        /* encode a TLV for response for "complete/error ..." */
        statResp.status = STATUS_COMPLETE;
        statResp.streamId = streamid;

#if 1
        DPRINT_INFO(WFA_OUT, "stream Id %u rx %u total %llu\n", streamid, myStream->stats.rxFrames, myStream->stats.rxPayloadBytes);
#endif
        wMEMCPY(&statResp.cmdru.stats, &myStream->stats, sizeof(tgStats_t));
        wMEMCPY((dutRspBuf + i * sizeof(dutCmdResponse_t)), (BYTE *)&statResp, sizeof(dutCmdResponse_t));
        id_cnt++;

        // Not empty it but require to reset the entire table before test starts.
        //wMEMSET(myStream, 0, sizeof(tgStream_t));
    }

    // mark the stream inactive
    myStream->state = WFA_STREAM_INACTIVE;

    sleep(1);
    DPRINT_INFO(WFA_OUT, "id_cnt: %d\n", id_cnt);
    printf("Sending back the statistics at recvstop\n");

    wfaEncodeTLV(WFA_TRAFFIC_AGENT_RECV_STOP_RESP_TLV, id_cnt * sizeof(dutCmdResponse_t), dutRspBuf, respBuf);

    /* done here */
    *respLen = WFA_TLV_HDR_LEN + numStreams * sizeof(dutCmdResponse_t);

    return WFA_SUCCESS;
}

/*
 * wfaTGSendStart: instruct traffic generator to start sending based on a profile
 * input:      cmd -- not used
 * response:   inform controller for "running"
 * return:     success or failed
 */
int wfaTGSendStart(int len, BYTE *parms, int *respLen, BYTE *respBuf)
{
    int i=0, streamid=0;
    int numStreams = len/4;

    tgProfile_t *theProfile;
    tgStream_t *myStream = NULL;

    dutCmdResponse_t staSendResp;

    DPRINT_INFO(WFA_OUT, "Entering tgSendStart for %i streams ...\n", numStreams);
    for(i=0; i<numStreams; i++)
    {
        wMEMCPY(&streamid, parms+(4*i), 4);
        myStream = findStreamProfile(streamid);
        if(myStream == NULL)
        {
           DPRINT_INFO(WFA_OUT, "myStream in send start is NULL\n");
           staSendResp.status = STATUS_INVALID;
           wfaEncodeTLV(WFA_TRAFFIC_AGENT_SEND_RESP_TLV, 4, (BYTE *)&staSendResp, respBuf);
           *respLen = WFA_TLV_HDR_LEN + 4;
           return WFA_SUCCESS;
        }

        theProfile = &myStream->profile;
        if(theProfile == NULL)
        {
           DPRINT_INFO(WFA_OUT, "theProfile in send start is NULL\n");
           staSendResp.status = STATUS_INVALID;
           wfaEncodeTLV(WFA_TRAFFIC_AGENT_SEND_RESP_TLV, 4, (BYTE *)&staSendResp, respBuf);
           *respLen = WFA_TLV_HDR_LEN + 4;

           return WFA_SUCCESS;
        }

        if(theProfile->direction != DIRECT_SEND)
        {
           DPRINT_INFO(WFA_OUT, "direction in send start is not DIRECT_SEND\n");
           staSendResp.status = STATUS_INVALID;
           wfaEncodeTLV(WFA_TRAFFIC_AGENT_SEND_RESP_TLV, 4, (BYTE *)&staSendResp, respBuf);
           *respLen = WFA_TLV_HDR_LEN + 4;

           return WFA_SUCCESS;
        }

        /*
              * need to reset the stats
              */
        wMEMSET(&myStream->stats, 0, sizeof(tgStats_t));

        // mark the stream active;
        myStream->state = WFA_STREAM_ACTIVE;

        switch(theProfile->profile)
        {
            case PROF_FILE_TX:
                /* fall through */
            case PROF_MCAST:
                /* fall through */
            case PROF_TRANSC:
                gtgTransac = streamid;
                gtgSend = streamid;
                /* fall through */
            case PROF_CALI_RTD:
                gtgCaliRTD = streamid;
                /* fall through */
            case PROF_IPTV:
                gtgSend = streamid;

                /*
                        * singal the thread to Sending WMM traffic
                        */
                wmm_thr[usedThread].thr_flag = streamid;
                wPT_MUTEX_LOCK(&wmm_thr[usedThread].thr_flag_mutex);
                wPT_COND_SIGNAL(&wmm_thr[usedThread].thr_flag_semaphore);
                wPT_MUTEX_UNLOCK(&wmm_thr[usedThread].thr_flag_mutex);
                usedThread++;
                //wfaSetProcPriority(90);
                break;
        }
    }

    is_task_resp = 1;
    *respLen = 0;
    return WFA_SUCCESS;

}

int wfaTGReset(int len, BYTE *parms, int *respLen, BYTE *respBuf)
{
    dutCmdResponse_t *resetResp = &gGenericResp;
    int i;
    hi_unref_param(len);
    hi_unref_param(parms);
    /* need to reset all traffic socket fds */
    for(i = 0; i<WFA_MAX_TRAFFIC_STREAMS; i++)
    {
        if(tgSockfds[i] != -1)
        {
            lwip_close(tgSockfds[i]);
            tgSockfds[i] = -1;
        }
    }

    /* just reset the flags for the command */
    gtgRecv = 0;
    gtgSend = 0;
    gtgTransac = 0;

    gtgCaliRTD = 0;
    min_rttime = 0xFFFFFFFF;
    gtgPktRTDelay = 0xFFFFFFFF;

    totalTranPkts = 0;
    //gtimeOut = 0;

    runLoop = 0;

    usedThread = 0;
    gtgWmmPS = 0;
    gtgPsPktRecvd = 0;

    if(psSockfd != -1)
    {
       wCLOSE(psSockfd);
       psSockfd = -1;
    }
    wMEMSET(&wmmps_info, 0, sizeof(wfaWmmPS_t));

    /* Also need to clean up WMM streams NOT DONE YET!*/
    slotCnt = 0;             /* reset stream profile container */
    streamId = 0;
    wMEMSET(gStreams, 0, sizeof(tgStream_t) * WFA_MAX_TRAFFIC_STREAMS);

    /*
     * After be asked to reset, it should lower itself back to
     * normal level. It is optional implementation if it is not called
     * while it starts sending/receiving for raising priority level.
     */
    //wfaSetProcPriority(20);

    /* encode a TLV for response for "complete ..." */
    resetResp->status = STATUS_COMPLETE;
    wfaEncodeTLV(WFA_TRAFFIC_AGENT_RESET_RESP_TLV, 4,
                 (BYTE *)resetResp, respBuf);
    *respLen = WFA_TLV_HDR_LEN + 4;


    return WFA_SUCCESS;
}

/*
 * calculate the sleep time for different frame rate
 * It should be done according the device
 * This is just one way to adjust the packet delivery speed. If you find
 * you device does not meet the test requirements, you MUST re-adjust
 * the method.
 */

/* The HZ value could be found in the build header file */
/* 100 -> 10ms, 1000 -> 1ms , etc                       */
#define WFA_KERNEL_MIN_TIMER_RES   100   /* HZ Value for 10 ms */

void wfaTxSleepTime(int profile, int rate, int *sleepTime, int *throttledRate)
{
    *sleepTime=0;     /* in microseconds */
    /* calculate the sleep time based on frame rate */

    /*
     * Framerate is still required for Multicast traffic
     * Sleep and hold for a timeout.
     *
     * For WMM traffic, the framerate must also need for VO and VI.
     * the framerate 500, OS may not handle it precisely.
     */
    switch(profile)
    {
    /*
     * make it a fix rate
     * according to test plan, it requires ~80kbps which is around 50 frames/s
     * For other cases which may want to run experiments for very high rate,
     * the change should accommodate the requirement.
     */
    case PROF_MCAST:
        if(rate < 500 && rate >= 50)
        {
            *sleepTime = 100000;  /* sleep for 100 ms */
            *throttledRate = WFA_MCAST_FRATE;
        }
        else
        {
            *sleepTime = 100000;
            *throttledRate = rate;
        }
#if 0
        *throttledRate = WFA_MCAST_FRATE;
#endif
        break;

        /*
         * Vendor must find ways to better adjust the speed for their own device
         */
        case PROF_IPTV:
        case PROF_FILE_TX:
        if(rate >50)
        {
        /*
         * this sleepTime indeed is now being used for time period
         * to send packets in the throttled Rate.
         * The idea here is that in each fixed 20 minisecond period,
         * The device will send rate/50 (rate = packets / second),
         * then go sleep for rest of time.
         */
            *sleepTime = 20000; /* fixed 20 miniseconds */
            *throttledRate = (rate?rate:10000)/50;
            printf("Hi Sleep time %i, throttledRate %i\n", *sleepTime, *throttledRate);
        }
        else if(rate == 0)
        {
            *sleepTime = 20000; /* fixed 20 miniseconds */
            *throttledRate = (rate?rate:10000)/50;
            printf("Hi Sleep time %i, throttledRate %i\n", *sleepTime, *throttledRate);
        }
        else if (rate > 0 && rate <= 50) /* typically for voice */
        {
            *throttledRate = 1;
            *sleepTime = 1000*1000/rate;
        }
        break;
        default:
          DPRINT_ERR(WFA_ERR, "Incorrect profile\n");
          break;
    }
}

#define WFA_TIME_DIFF(before, after, rtime, dtime) \
             dtime = rtime + (after.tv_sec*1000000 + after.tv_usec) - (before.tv_sec*1000000 + before.tv_usec);

void buzz_time(int delay)
{
    struct timeval now, stop;
    int diff;
    int remain_time = 0;

    wGETTIMEOFDAY(&stop, 0);

    stop.tv_usec += delay;
    if(stop.tv_usec > 1000000)
    {
        stop.tv_usec -=1000000;
    stop.tv_sec +=1;
    }

    do{
        wGETTIMEOFDAY(&now, 0);
        WFA_TIME_DIFF(now, stop, remain_time, diff);
    } while(diff>0);

}

/**************************************************/
/* the actually functions to send/receive packets */
/**************************************************/

/* This is going to be a blocking SEND till it finishes */
int wfaSendLongFile(int mySockfd, int streamid, BYTE *aRespBuf, int *aRespLen)
{
    tgProfile_t           *theProf = NULL;
    tgStream_t            *myStream = NULL;
    struct sockaddr_in    toAddr;
    char                  *packBuf;
    int  packLen;
    int  bytesSent;
    dutCmdResponse_t sendResp;
    int sleepTime = 0;
    int throttledRate = 0;
    struct timeval before, after,af;
    int difftime = 0, counter = 0;
    struct timeval stime;
//    int throttled_est_cost;
    int act_sleep_time;
    gettimeofday(&af,0);

    DPRINT_INFO(WFA_OUT, "Entering sendLongFile %i\n", streamid);

    /* find the profile */
    myStream = findStreamProfile(streamid);
    if(myStream == NULL)
    {
        DPRINT_ERR(WFA_ERR, "myStream is NULL!\n");
        return WFA_FAILURE;
    }

    theProf = &myStream->profile;

    if(theProf == NULL)
    {
        DPRINT_ERR(WFA_ERR, "theProf is NULL!\n");
        return WFA_FAILURE;
    }

    /* If RATE is 0 which means to send as much as possible, the frame size set to max UDP length */
    if(theProf->rate == 0){
        packLen = MAX_UDP_LEN;
    }else{
        packLen = theProf->pksize;
    }

    /* allocate a buf */
    packBuf = (char *)malloc(packLen+1);
    wMEMSET(packBuf, 0, packLen);

    /* fill in the header */
    wSTRNCPY(packBuf, "1345678", sizeof(tgHeader_t));

    /* initialize the destination address */
    wMEMSET(&toAddr, 0, sizeof(toAddr));
    toAddr.sin_family = AF_INET;
    toAddr.sin_addr.s_addr = inet_addr(theProf->dipaddr);
    toAddr.sin_port = htons(theProf->dport);

    /* if a frame rate and duration are defined, then we know
     * interval for each packet and how many packets it needs to
     * send.
     */
    DPRINT_INFO(WFA_OUT, "theProf->duration = %d\n", theProf->duration);
    if(theProf->duration != 0)
    {
        printf("duration %i\n", theProf->duration);

        /*
         *  use this to decide periodical interval sleep time and frames to send
         *  int the each interval.
         *  Each device should adopt a own algorithm for better performance
         */
        wfaTxSleepTime(theProf->profile, theProf->rate, &sleepTime, &throttledRate);
        /*
             * alright, we need to raise the priority level of the process
             * to improve the real-time performance of packet sending.
             * Since this is for tuning purpose, it is optional implementation.
             */
        //wfaSetProcPriority(60);

        //interval = 1*1000000/theProf->rate ; // in usec;

        // Here assumes it takes 20 usec to send a packet
        //throttled_est_cost = throttledRate * 20;  // MUST estimate the cost per ppk
        act_sleep_time = sleepTime - adj_latency;
        if (act_sleep_time <= 0){
            act_sleep_time = sleepTime;
        }
        printf("sleep time %i act_sleep_time %i\n", sleepTime, act_sleep_time);

        runLoop=1;
        while(runLoop)
        {
            counter++;
            /* fill in the counter */
            int2BuffBigEndian(counter, &((tgHeader_t *)packBuf)->hdr[8]);

           /*
                  * the following code is only used to slow down
                  * over fast traffic flooding the buffer and cause
                  * packet drop or the other end not able to receive due to
                  * some limitations, purely for experiment purpose.
                  * each implementation needs some fine tune to it.
                  */
           if(counter ==1)
           {
               wGETTIMEOFDAY(&before, NULL);

               before.tv_usec += sleepTime;
               if(before.tv_usec > 1000000)
               {
                   before.tv_usec -= 1000000;
                   before.tv_sec +=1;
               }
           }

           if(throttledRate != 0)
           {
               if(counter%throttledRate == 0)
               {
                   wGETTIMEOFDAY(&after, NULL);
                   difftime = wfa_itime_diff(&after, &before);

                   if(difftime > adj_latency)
                   {
                       // too much time left, go sleep
                       wUSLEEP(difftime-adj_latency);

                       wGETTIMEOFDAY(&after, NULL);
                       difftime = wfa_itime_diff(&after, &before);
                   }

                   // burn the rest to absort latency
                   if(difftime >0){
                       buzz_time(difftime);
                   }
                   before.tv_usec += sleepTime;
                   if(before.tv_usec > 1000000)
                   {
                       before.tv_usec -= 1000000;
                       before.tv_sec +=1;
                   }
               }
           } // otherwise, it floods

           /*
                  * Fill the timestamp to the header.
                  */
           wGETTIMEOFDAY(&stime, NULL);

           int2BuffBigEndian(stime.tv_sec, &((tgHeader_t *)packBuf)->hdr[12]);
           int2BuffBigEndian(stime.tv_usec, &((tgHeader_t *)packBuf)->hdr[16]);

           bytesSent = wfaTrafficSendTo(mySockfd, packBuf, packLen,
                            (struct sockaddr *)&toAddr);

           if(bytesSent != -1)
           {
              myStream->stats.txPayloadBytes += bytesSent;
              myStream->stats.txFrames++ ;
           }
           else
           {
               int errsv = errno;
               DPRINT_INFO(WFA_OUT, "errno = %d\n", errsv);
               switch(errsv)
               {
                   case EAGAIN:
                   case ENOBUFS:
                        DPRINT_ERR(WFA_ERR, "send error\n");
                        wUSLEEP(1000);             /* hold for 1 ms */
                        counter-- ;
                        myStream->stats.txFrames--;
                   break;
                   case ECONNRESET:
                        runLoop = 0;
                   break;
                   case EPIPE:
                        runLoop = 0;
                   break;
                   default:
                      //perror("sendto: ");
                      DPRINT_ERR(WFA_ERR, "Packet sent error\n");
                   break;
               }
           }

        }


        /*
              * lower back to an original level if the process is raised previously
              * It is optional.
              */
        //wfaSetProcPriority(30);
    }
    else /* invalid parameters */
    {
        /* encode a TLV for response for "invalid ..." */
        sendResp.status = STATUS_INVALID;
        wfaEncodeTLV(WFA_TRAFFIC_AGENT_SEND_RESP_TLV, 4,
                 (BYTE *)&sendResp, (BYTE *)aRespBuf);

        /* done here */
        *aRespLen = WFA_TLV_HDR_LEN + 4;

        return DONE;
    }

    gtgSend = 0;

    /* free the buffer */
    wFREE(packBuf);

    DPRINT_INFO(WFA_OUT, "done sending long\n");
    /* return statistics */
    sendResp.status = STATUS_COMPLETE;
    sendResp.streamId = myStream->id;
    wMEMCPY(&sendResp.cmdru.stats, &myStream->stats, sizeof(tgStats_t));

#if 0
    DPRINT_INFO(WFA_OUT, "stream Id %u tx %u total %llu\n", myStream->id, myStream->stats.txFrames, myStream->stats.txPayloadBytes);
#endif

    wfaEncodeTLV(WFA_TRAFFIC_AGENT_SEND_RESP_TLV, sizeof(dutCmdResponse_t),
                 (BYTE *)&sendResp, (BYTE *)aRespBuf);

    *aRespLen = WFA_TLV_HDR_LEN + sizeof(dutCmdResponse_t);

    return DONE;
}

/* this only sends one packet a time */
int wfaSendShortFile(int mySockfd, int streamid, BYTE *sendBuf, int pksize, BYTE *aRespBuf, int *aRespLen)
{
    BYTE *packBuf = sendBuf;
    struct sockaddr_in toAddr;
    tgProfile_t *theProf;
    tgStream_t *myStream;
    int packLen, bytesSent=-1;
    dutCmdResponse_t sendResp;

    if(mySockfd == -1)
    {
      /* stop */
      gtgTransac = 0;
      //gtimeOut = 0;
      gtgRecv = 0;
      gtgSend = 0;
      printf("stop short traffic\n");

      myStream = findStreamProfile(streamid);
      if(myStream != NULL)
      {
          sendResp.status = STATUS_COMPLETE;
          sendResp.streamId = streamid;
          wMEMCPY(&sendResp.cmdru.stats, &myStream->stats, sizeof(tgStats_t));

          wfaEncodeTLV(WFA_TRAFFIC_AGENT_SEND_RESP_TLV, sizeof(dutCmdResponse_t), (BYTE *)&sendResp, aRespBuf);

          *aRespLen = WFA_TLV_HDR_LEN + sizeof(dutCmdResponse_t);
      }

      return DONE;
    }

    /* find the profile */
    myStream = findStreamProfile(streamid);
    if(myStream == NULL)
    {
        return WFA_FAILURE;
    }

    theProf = &myStream->profile;
    if(theProf == NULL)
    {
        return WFA_FAILURE;
    }

    if(pksize == 0){
        packLen = theProf->pksize;
    }else{
      packLen = pksize;
    }

    wMEMSET(&toAddr, 0, sizeof(toAddr));
    toAddr.sin_family = AF_INET;
    toAddr.sin_addr.s_addr = inet_addr(theProf->sipaddr);
    toAddr.sin_port = htons(theProf->sport);

    if(gtgRecv && gtgTransac)
    {
    //      printf("mySock %i sipaddr %s sport %i\n", mySockfd, theProf->sipaddr, theProf->sport);
      toAddr.sin_addr.s_addr = inet_addr(theProf->sipaddr);
      toAddr.sin_port = htons(theProf->sport);
    }
    else if(gtgSend && gtgTransac)
    {
    //      printf("mySock %i dipaddr %s dport %i\n", mySockfd, theProf->dipaddr, theProf->dport);
      toAddr.sin_addr.s_addr = inet_addr(theProf->dipaddr);
      toAddr.sin_port = htons(theProf->dport);
    }

    int2BuffBigEndian(myStream->stats.txFrames, &((tgHeader_t *)packBuf)->hdr[8]);

    if(mySockfd != -1)
      bytesSent = wfaTrafficSendTo(mySockfd, (char *)packBuf, packLen, (struct sockaddr *)&toAddr);

    if(bytesSent != -1)
    {
      myStream->stats.txFrames++;
      myStream->stats.txPayloadBytes += bytesSent;
    }
    else
    {
      int errsv = errno;
      switch(errsv)
      {
          case EAGAIN:
          case ENOBUFS:
              DPRINT_ERR(WFA_ERR, "send error\n");
              wUSLEEP(1000);             /* hold for 1 ms */
              myStream->stats.txFrames--;
              break;
          default:
              DPRINT_ERR(WFA_ERR, "Packet sent error\n");
              break;
      }
    }

    sentTranPkts++;

    return WFA_SUCCESS;

}

/* always receive from a specified IP address and Port */
int wfaRecvFile(int mySockfd, int streamid, char *recvBuf)
{
    /* how many packets are received */
    char *packBuf = recvBuf;
    struct sockaddr_in fromAddr;
    tgProfile_t *theProf;
    tgStream_t *myStream;
    int bytesRecvd;
    int lostPkts;

    /* find the profile */
    myStream = findStreamProfile(streamid);
    if(myStream == NULL)
    {
        DPRINT_ERR(WFA_ERR, "myStream %d is NULL!\n", streamid);
        return WFA_ERROR;
    }

    theProf = &myStream->profile;
    if(theProf == NULL)
    {
        DPRINT_ERR(WFA_ERR, "theProf is NULL!\n");
        return WFA_ERROR;
    }

    wMEMSET(packBuf, 0, MAX_UDP_LEN);

    wMEMSET(&fromAddr, 0, sizeof(fromAddr));
    fromAddr.sin_family = AF_INET;
    fromAddr.sin_addr.s_addr = inet_addr(theProf->dipaddr);
    fromAddr.sin_port = htons(theProf->dport);

    if(gtgRecv && gtgTransac)
    {
       //printf("\n1\n");
       fromAddr.sin_addr.s_addr = inet_addr(theProf->sipaddr);
       fromAddr.sin_port = htons(theProf->sport);
    }
    else if(gtgSend && gtgTransac) {
       fromAddr.sin_addr.s_addr = inet_addr(theProf->dipaddr);
       fromAddr.sin_port = htons(theProf->dport);
    }

    /* it is always to receive at least one packet, in case more in the
       queue, just pick them up.
     */
    bytesRecvd = wfaTrafficRecv(mySockfd, packBuf, (struct sockaddr *)&fromAddr);
    if(bytesRecvd != -1) {
        myStream->stats.rxFrames++;
        myStream->stats.rxPayloadBytes +=bytesRecvd;

        /*
             *  Get the lost packet count
             */
        lostPkts = bigEndianBuff2Int(&((tgHeader_t *)packBuf)->hdr[8]) - 1 - myStream->lastPktSN;
        myStream->stats.lostPkts += lostPkts;
        myStream->lastPktSN = bigEndianBuff2Int(&((tgHeader_t *)packBuf)->hdr[8]);
    }
    else
    {
#if 0
       getsockopt(mySockfd, SOL_SOCKET, SO_ERROR, &opt, &optLen);
       DPRINT_ERR(WFA_ERR, "\nerror number: %d\n", opt);
       //DPRINT_ERR(WFA_ERR, "Packet received error\n");
#endif
    }
    return (bytesRecvd);
}
