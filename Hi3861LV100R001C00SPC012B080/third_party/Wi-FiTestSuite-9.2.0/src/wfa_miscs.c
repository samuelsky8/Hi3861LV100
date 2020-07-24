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
 * File: wfa_miscs.c - misc functions for agents.
 */

#include "hi_errno.h"
#include "wfa_portall.h"
#include "wfa_debug.h"
#include "wfa_main.h"
#include "wfa_types.h"
#include "wfa_tg.h"
#include "wfa_miscs.h"

unsigned int sigma_timer_handle;
tgStream_t *findStreamProfile(int id);

/*
 * printProfile(): a debugging function to display a profile info based on
 *                 a streamId
 */

void printProfile(tgProfile_t *pf)
{
    printf("profile type %i direction %i Dest ipAddr %s Dest port %i So ipAddr %s So port %i rate %i duration %i pksize %i\n", pf->profile, pf->direction, pf->dipaddr, pf->dport, pf->sipaddr, pf->sport, pf->rate, pf->duration, pf->pksize);
}

int isString(char *str)
{
    if(*str == '\0')
        return WFA_FAILURE;

    if((str[0] >= 'a' && str[0] <= 'z')
            || (str[0] > 'A' && str[0] < 'Z'))
        return WFA_SUCCESS;
    else
        return WFA_FAILURE;

}

int isNumber(char *str)
{
    if(*str == '\0')
        return WFA_FAILURE;

    if (str[0] >= '0' && str[0] <= '9')
        return WFA_SUCCESS;
    else
        return WFA_FAILURE;
}

int isIpV4Addr(char *str)
{
    int dots = 0;
    char *tmpstr = str;

    if(*str == '\0')
        return WFA_FAILURE;

    while(*tmpstr != '\0')
    {
        if(*tmpstr == '.')
        {
            dots++;
        }

        tmpstr++;
    }

    if(dots <3)
        return WFA_FAILURE;
    else
        return WFA_SUCCESS;
}

int wfa_itime_diff(struct timeval *t1, struct timeval *t2)
{
   int dtime;
   int sec = t2->tv_sec - t1->tv_sec;
   int usec = t2->tv_usec - t1->tv_usec;

   if(usec < 0)
   {
       sec -=1;
       usec += 1000000;
   }

   dtime = sec*1000000 + usec;
   return dtime;
}

int wfa_estimate_timer_latency(void)
{
    struct timeval t1, t2, tp2;
    int sleep=20000; /* 20 miniseconds */
    int latency =0;

    gettimeofday(&t1, NULL);
    wUSLEEP(sleep);

    wGETTIMEOFDAY(&t2, NULL);

    tp2.tv_usec = t1.tv_usec + 20000;
    if( tp2.tv_usec >= 1000000)
    {
        tp2.tv_sec = t1.tv_sec +1;
        tp2.tv_usec -= 1000000;
    }
    else
        tp2.tv_sec = t1.tv_sec;

    return latency = (t2.tv_sec - tp2.tv_sec) * 1000000 + (t2.tv_usec - tp2.tv_usec);
}

unsigned int sigma_traffic_setup_timer(void)
{
    unsigned int ret = hi_hrtimer_create(&sigma_timer_handle);
    if (ret != HI_ERR_SUCCESS) {
        DPRINT_ERR(WFA_ERR, "create sigma_traffic timer handle failed!");
        DPRINT_INFO(WFA_OUT, "create timer handle error code = %d\n", ret);
    }

    return ret;
}

void sigma_traffic_start_timer(hi_hrtimer_callback_f traffic_callback_fun,
                                          unsigned int alrm_timeout)
{
    unsigned int ret;
    unsigned int alrm_us = alrm_timeout * 1000000;
    DPRINT_INFO(WFA_OUT, "alrm_us = %d\n", alrm_us);

    ret = hi_hrtimer_start(sigma_timer_handle, alrm_us, traffic_callback_fun, 0);
    if (ret != HI_ERR_SUCCESS) {
        DPRINT_ERR(WFA_ERR, "start sigma_traffic timer failed!");
        DPRINT_INFO(WFA_OUT, "timer error code = %d\n", ret);
    }
}

void sigma_traffic_stop_timer(void)
{
    unsigned int ret;
    ret = hi_hrtimer_stop(sigma_timer_handle);
    if (ret != HI_ERR_SUCCESS) {
        DPRINT_ERR(WFA_ERR, "stop sigma_traffic timer handle failed!");
        DPRINT_INFO(WFA_OUT, "stop timer error code = %d\n", ret);
    }
}

unsigned int sigma_traffic_release_timer(void)
{
    unsigned int ret = WFA_FAILURE;

    ret = hi_hrtimer_delete(sigma_timer_handle);
    if (ret != HI_ERR_SUCCESS) {
        DPRINT_ERR(WFA_ERR, "detele sigma_traffic timer handle failed!");
        DPRINT_INFO(WFA_OUT, "detele timer error code = %d\n", ret);
    }

    return ret;
}

