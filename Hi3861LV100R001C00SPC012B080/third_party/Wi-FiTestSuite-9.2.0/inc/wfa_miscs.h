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


#ifndef _WFA_MISCS_H_
#define _WFA_MISCS_H_

#include "hi_hrtimer.h"
#include "wfa_tg.h"
#include "time.h"

static inline double wfa_timeval2double(struct timeval *tval)
{
    return ((double) tval->tv_sec + (double) tval->tv_usec*1e-6);
}

static inline void wfa_double2timeval(struct timeval *tval, double dval)
{
    tval->tv_sec = (long int) dval;
    tval->tv_usec = (long int) ((dval - tval->tv_sec) * 1000000);
}

static inline double wfa_ftime_diff(struct timeval *t1, struct timeval *t2)
{
   double dtime;

   dtime = wfa_timeval2double(t2) - wfa_timeval2double(t1);
   return dtime ;
}


/*
 * THe following two functions are converting Little Endian to Big Endian.
 * If your machine is already a Big Endian, you may flag it out.
 */
static inline void int2BuffBigEndian(int val, char *buf)
{
   char *littleEn = (char *)&val;

   buf[0] = littleEn[3];
   buf[1] = littleEn[2];
   buf[2] = littleEn[1];
   buf[3] = littleEn[0];
}

static inline int bigEndianBuff2Int(char *buff)
{
   int val;
   char *strval = (char *)&val;

   strval[0] = buff[3];
   strval[1] = buff[2];
   strval[2] = buff[1];
   strval[3] = buff[0];

   return val;
}


extern int isString(char *);
extern int isNumber(char *);
extern int isIpV4Addr(char *);
extern int wfa_itime_diff(struct timeval *t1, struct timeval *t2);
extern int wfa_estimate_timer_latency(void);
extern tgStream_t *findStreamProfile(int id);

unsigned int sigma_traffic_setup_timer(void);
void sigma_traffic_start_timer(hi_hrtimer_callback_f traffic_callback_fun,
                                                 unsigned int alrm_timeout);
void sigma_traffic_stop_timer(void);
unsigned int sigma_traffic_release_timer(void);

#endif
