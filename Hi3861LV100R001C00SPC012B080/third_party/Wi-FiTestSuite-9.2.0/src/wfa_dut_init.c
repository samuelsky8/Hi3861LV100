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
#include <stdio.h>
#include <stdlib.h>
#include "hi_msg.h"
#include "wfa_debug.h"
#include "wfa_main.h"
#include "wfa_types.h"
#include "wfa_dut.h"
#include "wfa_tg.h"
#include "wfa_sock.h"

extern tgStream_t *gStreams;

void wfa_dut_init(BYTE **tBuf, BYTE **rBuf, BYTE **paBuf, BYTE **cBuf)
{
    /* allocate the traffic stream table */
    gStreams = (tgStream_t *) malloc(WFA_MAX_TRAFFIC_STREAMS*sizeof(tgStream_t));
    if(gStreams == NULL)
    {
        DPRINT_ERR(WFA_ERR, "Failed to malloc theStreams\n");
        return;
    }

    /* a buffer used to carry receive and send test traffic */
    *tBuf = (BYTE *) malloc(MAX_UDP_LEN+1); /* alloc a traffic buffer */
    if(*tBuf == NULL)
    {
        DPRINT_ERR(WFA_ERR, "Failed to malloc traffic buffer\n");
        return;
    }

    /* a buffer used for response of control command */
    *rBuf = (BYTE *)malloc(WFA_RESP_BUF_SZ);
    if(*rBuf == NULL)
    {
        DPRINT_ERR(WFA_ERR,"Failed to malloc response buffer\n");
        return;
    }

    /* control command buf */
    *cBuf = malloc(WFA_BUFF_1K);
    if(*cBuf == NULL)
    {
        DPRINT_ERR(WFA_ERR,"Failed to malloc control command buf\n");
        return;
    }

    /* parameters buff */
    *paBuf = malloc(MAX_PARMS_BUFF);
    if(*paBuf == NULL)
    {
        DPRINT_ERR(WFA_ERR,"Failed to malloc parms value buff\n");
        return;
    }
}
