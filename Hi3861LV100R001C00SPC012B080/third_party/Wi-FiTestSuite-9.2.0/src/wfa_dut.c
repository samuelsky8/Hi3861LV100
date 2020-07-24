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
 * File: wfa_dut.c - The main program for DUT agent.
 *       This is the top level of traffic control. It initializes a local TCP
 *       socket for command and control link and waits for a connect request
 *       from a Control Agent. Once the the connection is established, it
 *       will process the commands from the Control Agent. For details, please
 *       reference the architecture documents.
 *
 */
#include <stdio.h>
#include "malloc.h"
#include "hi_msg.h"
#include "hi_task.h"
#include "hi_sem.h"
#include "hi_mem.h"
#include "hi_config.h"
#include "wfa_portall.h"
#include "wfa_debug.h"
#include "wfa_main.h"
#include "wfa_types.h"
#include "wfa_tlv.h"
#include "wfa_tg.h"
#include "wfa_miscs.h"
#include "wfa_rsp.h"
#include "wfa_agt.h"
#include "wfa_agtctrl.h"
#include "wfa_dut.h"
#include "wfa_wmmps.h"
#include "wfa_sock.h"

#define WMM_TASK_STAK_SIZE (2*1024)
#define WMM_TASK_PRIORITY  20
#define SIGMA_DUT_TASK_STAK_SIZE  (10*1024)
#define SIGMA_DUT_TASK_PRIORITY    25
/* Global flags for synchronizing the TG functions */
BYTE   *trafficBuf, *respBuf;
dutCmdResponse_t gGenericResp;
/* command process functions */
extern xcCommandFuncPtr gWfaCmdFuncTbl[];
extern unsigned int sigma_queue_id;
extern unsigned int sigma_resp_queue_id;
extern BYTE *pcmdBuf;
int        gtimeOut = 0;        /* timeout value for select call in usec */

/* adjust sleep time due to latency */
extern int adj_latency;
tgWMM_t wmm_thr[WFA_THREADS_NUM];
extern dutCommandRespFuncPtr wfaCmdRespProcFuncTbl[];
int is_task_resp = 0;

unsigned int g_wait_sta_associate_sem;
unsigned int g_wait_ping_stop_sem;

extern void wfa_dut_init(BYTE **tBuf,BYTE **rBuf, BYTE **paBuf, BYTE **cBuf);
extern void *wfa_wmm_thread(void *thr_param);
extern int sigma_wmm_resp_sem_create(void);
extern BOOL gtgWmmPS;
extern unsigned long psTxMsg[512];
extern unsigned long psRxMsg[512];
extern wfaWmmPS_t wmmps_info;
extern int  psSockfd;
extern struct apts_msg *apts_msgs;
unsigned int power_save_flag = 0;
extern void BUILD_APTS_MSG(int msg, unsigned long *txbuf);
extern int wfaWmmPowerSaveProcess(int sockfd);
extern void wfaTGSetPrio(int, int);

void wait_sem_create(void)
{
    hi_sem_bcreate(&g_wait_sta_associate_sem, HI_SEM_ZERO);
    hi_sem_bcreate(&g_wait_ping_stop_sem, HI_SEM_ZERO);
}

void *sigma_dut_task(void *param)
{
    int cmdLen = 0, nbytes = 0;
    int respLen;
    BYTE *xcCmdBuf=NULL, *parmsVal=NULL;
    WORD xcCmdTag;
    int i = 0;
    hi_sys_queue_msg sigmaMsg;
    unsigned int ret;
    tgThrData_t tdata[WFA_THREADS_NUM];
    int bytesRcvd;
    hi_sys_queue_msg sigmaRespMsg;
    int ret_status;
    unsigned short tag;
    unsigned char caCmdBuf[WFA_BUFF_2K];
    hi_task_attr wmm_attr = {0};
    hi_unref_param(param);
    unsigned int len;

    adj_latency = wfa_estimate_timer_latency() + 4000; /* four more mini */

    if(adj_latency > 500000)
    {
        printf("****************** WARNING  **********************\n");
        printf("!!!THE SLEEP TIMER LATENCY IS TOO HIGH!!!!!!!!!!!!\n");
        printf("**************************************************\n");

        /* Just set it to  500 mini seconds */
        adj_latency = 500000;
    }

    wfa_dut_init(&trafficBuf, &respBuf, &parmsVal, &xcCmdBuf);
    memset(xcCmdBuf, 0, WFA_BUFF_1K);
    wait_sem_create();
    sigma_wmm_resp_sem_create();
    sigma_traffic_setup_timer();

    wmm_attr.stack_size = WMM_TASK_STAK_SIZE;
    wmm_attr.task_prio = WMM_TASK_PRIORITY;
    wmm_attr.task_name = (hi_char*)"wfa_wmm_task";

    /*
       * Create multiple threads for WMM Stream processing.
       *
       */
    for(i = 0; i < WFA_THREADS_NUM; i++)
    {
         wmm_thr[i].thr = 0;
         tdata[i].tid = i;
         pthread_mutex_init(&wmm_thr[i].thr_flag_mutex, NULL);
         pthread_cond_init(&wmm_thr[i].thr_flag_semaphore, NULL);
         wmm_thr[i].thr_flag = 0;
         wmm_thr[i].stop_flag = 0;

         wmm_thr[i].thr_id = hi_task_create(&(wmm_thr[i].thr), &wmm_attr, wfa_wmm_thread, &(tdata[i]));
    }

    for(;;){
        if (power_save_flag == 1) {
            if (gtgWmmPS != 0 && psSockfd != -1) {
               DPRINT_INFO(WFA_OUT,"enter send udp pack ...\n");
               wfaSetDUTPwrMgmt(0);
               wfaTGSetPrio(psSockfd, 0);
               BUILD_APTS_MSG(APTS_HELLO, (unsigned long*)psTxMsg);
               wfaTrafficSendTo(psSockfd, (char *)psTxMsg, sizeof(psTxMsg), (struct sockaddr *) &wmmps_info.psToAddr);
               wmmps_info.sta_state = 0;
               wmmps_info.wait_state = WFA_WAIT_STAUT_00;
            }
        }

        memset_s(&sigmaMsg, sizeof(hi_sys_queue_msg), 0, sizeof(hi_sys_queue_msg));
        len = sizeof(hi_sys_queue_msg);
        ret = hi_msg_queue_wait(sigma_queue_id, &sigmaMsg, HI_SYS_WAIT_FOREVER, &len);
        if (ret != WFA_SUCCESS) {
            DPRINT_ERR(WFA_ERR, "Failed to recv queue msg\n");
            hi_sleep(10000);
            continue;
        }

        nbytes = (int)(sigmaMsg.param[1]);
        if (memcpy_s(xcCmdBuf, WFA_BUFF_1K, (unsigned char *)sigmaMsg.param[0], nbytes + 1) != EOK) {
            DPRINT_INFO(WFA_OUT, "sigma_dut_task memcpy_s fail\n");
            continue;
        }

        DPRINT_INFO(WFA_OUT, "Dut recv tag: %d\n", ((wfaTLV *)xcCmdBuf)->tag);
        DPRINT_INFO(WFA_OUT, "Dut recv len: %d\n", ((wfaTLV *)xcCmdBuf)->len);
        DPRINT_INFO(WFA_OUT, "Dut recv cmd len : %d\n", nbytes);

        /* decode command  */
        wfaDecodeTLV(xcCmdBuf, nbytes, &xcCmdTag, &cmdLen, parmsVal);

        memset(respBuf, 0, WFA_RESP_BUF_SZ);
        respLen = 0;

        /* reset commond storages used by control functions */
        memset(&gGenericResp, 0, sizeof(dutCmdResponse_t));

        /* command process function defined in wfa_ca.c and wfa_tg.c */
        if(xcCmdTag != 0 && gWfaCmdFuncTbl[xcCmdTag] != NULL)
        {
            /* since the new commands are expanded to new block */
            gWfaCmdFuncTbl[xcCmdTag](cmdLen, parmsVal, &respLen, (BYTE *)respBuf);
            DPRINT_INFO(WFA_OUT, "tag:%d, len:%d, status:%d\n", ((wfaTLV *)respBuf)->tag,
                    ((wfaTLV *)respBuf)->len, ((dutCmdResponse_t *)(respBuf + 4))->status);
        }
        else
        {   /* no command defined */
            gWfaCmdFuncTbl[0](cmdLen, parmsVal, &respLen, (BYTE *)respBuf);
        }

        if (memset_s(caCmdBuf, WFA_BUFF_2K, 0, WFA_BUFF_2K) != EOK) {
            DPRINT_INFO(WFA_OUT, "sigma_dut_task memset_s fail\n");
        }
        if(is_task_resp == 0){
            bytesRcvd = respLen;
            if (memcpy_s(caCmdBuf, WFA_BUFF_2K, respBuf, bytesRcvd) != EOK) {
                DPRINT_INFO(WFA_OUT, "sigma_dut_task memcpy_s fail\n");
            }
        }else{
            memset_s(&sigmaRespMsg, sizeof(hi_sys_queue_msg), 0, sizeof(hi_sys_queue_msg));
            len = sizeof(hi_sys_queue_msg);
            hi_msg_queue_wait(sigma_resp_queue_id, &sigmaRespMsg, HI_SYS_WAIT_FOREVER, &len);

            bytesRcvd = (int)(sigmaRespMsg.param[1]);
            if (memcpy_s(caCmdBuf, WFA_BUFF_2K, (unsigned char *)(sigmaRespMsg.param[0]), bytesRcvd) != EOK) {
                DPRINT_INFO(WFA_OUT, "sigma_dut_task param memcpy_s fail\n");
                continue;
            }
            is_task_resp = 0;
        }
        tag = ((wfaTLV *)caCmdBuf)->tag;

        memcpy(&ret_status, caCmdBuf+4, 4);

        DPRINT_INFO(WFA_OUT, "tag %i \n", tag);
        if(tag != 0 && wfaCmdRespProcFuncTbl[tag] != NULL)
        {
            wfaCmdRespProcFuncTbl[tag](caCmdBuf);
        }else{
            DPRINT_WARNING(WFA_WNG, "function not defined\n");
        }

        if (psSockfd != -1 && power_save_flag == 1) {
            wfaWmmPowerSaveProcess(psSockfd);
            DPRINT_INFO(WFA_OUT, "wfaWmmPowerSaveProcess.....\n");
        }
    }
}

int sigma_dut_init(void)
{
    unsigned int sigma_dut_task_id = 0;
    int ret = WFA_FAILURE;
    hi_task_attr attr = {0};

    attr.stack_size = SIGMA_DUT_TASK_STAK_SIZE;
    attr.task_prio = SIGMA_DUT_TASK_PRIORITY;
    attr.task_name = (hi_char*)"sigma_dut_task";
    ret = hi_task_create(&sigma_dut_task_id, &attr, sigma_dut_task, 0);
    if(ret != WFA_SUCCESS){
        DPRINT_ERR(WFA_ERR, "Failed to create sigma dut task\n");
        return ret;
    }
    return ret;

}

