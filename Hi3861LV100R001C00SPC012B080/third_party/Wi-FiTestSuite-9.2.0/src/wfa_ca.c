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
 * File: wfa_ca.c
 *       This is the main program for Control Agent.
 *
 */
#include <stdio.h>      /* for printf() and fprintf() */
#include "string.h"    /* for memset() */
#include "hi_msg.h"
#include "wfa_debug.h"
#include "wfa_main.h"
#include "wfa_types.h"
#include "wfa_agtctrl.h"
#include "wfa_tlv.h"
#include "wfa_ca.h"
#include "stdlib.h"

unsigned int sigma_queue_id;
unsigned int sigma_resp_queue_id;
BYTE *pcmdBuf;

extern typeNameStr_t nameStr[];
extern dutCommandRespFuncPtr wfaCmdRespProcFuncTbl[];
extern int sigma_uart_send(unsigned char *paData, unsigned int ausDataSize);

int sigmaCaParseCmd(unsigned char command[], int commandLen)
{
    char cmdName[WFA_BUFF_32];
    int i, isFound = 0, slen;
    int cmdLen = WFA_BUFF_1K;
    char respStr[WFA_BUFF_512];
    char *pcmdStr = NULL;
    hi_sys_queue_msg sigmaMsg = { 0 };
    int ret = WFA_FAILURE;

    pcmdBuf = (BYTE *)malloc(WFA_BUFF_1K);
    if(pcmdBuf == NULL){
        DPRINT_ERR(WFA_ERR, "Failed to malloc pcmdBuf\n");
    }
    memset(pcmdBuf, 0, WFA_BUFF_1K);
    memset(respStr, 0, WFA_BUFF_512);

    DPRINT_INFO(WFA_OUT, "message %s %i\n", command, commandLen);
    slen = (int )strlen((char *)command);
    if (slen <= 3) { /* 3:字符数 */
        DPRINT_INFO(WFA_OUT, "slen = %i is error\n", slen);
        free(pcmdBuf);
        return WFA_FAILURE;
    }
    DPRINT_INFO(WFA_OUT, "last %x last-1  %x last-2 %x last-3 %x\n", command[slen],
            command[slen-1], command[slen-2], command[slen-3]);

    command[slen-3] = '\0';

    memcpy(cmdName, strtok_r((char *)command, ",", (char **)&pcmdStr), 32);

    i = 0;
    while(nameStr[i].type != -1)
    {
        if(strcmp(nameStr[i].name, cmdName) == 0)
        {
            isFound = 1;
            break;
        }
        i++;
    }

    DPRINT_INFO(WFA_OUT, "%s\n", cmdName);

    /*
       * isFound = 0: command name is not match
       */
    if(isFound == 0)
    {
        sprintf(respStr, "status,INVALID\r\n");
        //uart2发送CA响应给UCC
        sigma_uart_send((unsigned char *)respStr, strlen(respStr));
        DPRINT_INFO(WFA_OUT, "Command not valid, check the name\n");
        free(pcmdBuf);
        return WFA_FAILURE;
    }

    if(nameStr[i].cmdProcFunc(pcmdStr, pcmdBuf, &cmdLen)==WFA_FAILURE)
    {
        sprintf(respStr, "status,INVALID\r\n");
        sigma_uart_send((unsigned char *)respStr, strlen(respStr));
        DPRINT_INFO(WFA_OUT, "Incorrect command syntax\n");
        free(pcmdBuf);
        return WFA_FAILURE;
    }

    sprintf(respStr, "status,RUNNING\r\n");
    sigma_uart_send((unsigned char *)respStr, strlen(respStr));
    DPRINT_INFO(WFA_OUT, "%s\n", respStr);

    /*
     * send to DUT: TLV编码格式的命令发送给dut
     */
    if (pcmdBuf == NULL) {
        DPRINT_ERR(WFA_ERR, "pcmdBuf is NULL\n");
        return WFA_FAILURE;
    }
    sigmaMsg.param[0] = (uintptr_t)pcmdBuf;
    sigmaMsg.param[1] = (uintptr_t)cmdLen;
    DPRINT_INFO(WFA_OUT, "cmdlen: %d\n", cmdLen);
    ret = hi_msg_queue_send(sigma_queue_id, &sigmaMsg, 0, sizeof(hi_sys_queue_msg));
    if(ret != WFA_SUCCESS){
        DPRINT_ERR(WFA_ERR, "CA failed to send cmd\n");
        DPRINT_INFO(WFA_OUT, "RET: %d\n", ret);
        free(pcmdBuf);
        return WFA_FAILURE;
    }
    DPRINT_INFO(WFA_OUT, "sent to DUT\n");

    free(pcmdBuf);
    return ret;
}

