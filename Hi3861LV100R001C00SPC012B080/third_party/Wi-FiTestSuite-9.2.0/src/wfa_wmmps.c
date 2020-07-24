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



//#ifdef WFA_WMM_PS_EXT
#if 0
#include <netdb.h>
#include <errno.h>
#include <string.h>
#include <signal.h>
#include <pthread.h>
#endif

#include "wfa_portall.h"
#include "wfa_sock.h"
#include "wfa_types.h"
#include "wfa_tg.h"
#include "wfa_ca.h"
#include "wfa_wmmps.h"
#include "wfa_main.h"
#include "wfa_debug.h"
#include "signal.h"

extern int psSockfd;
extern int num_stops;
extern int num_hello;
extern tgWMM_t wmm_thr[];

extern unsigned int psTxMsg[512];
extern unsigned int psRxMsg[512];
extern int msgsize;

char gCmdStr[WFA_CMD_STR_SZ];
int resetsnd = 0;
int reset_recd=0;
int resetrcv=0;
int num_retry=0;
int gtgPsPktRecvd = 0;                    // need to reset
struct timeval time_ap;
struct timeval time_ul;
extern int gtgPsPktRecvd;
extern int resetsnd;
extern wfaWmmPS_t wmmps_info;
extern int gtgWmmPS;
extern void wfaSetDUTPwrMgmt(int mode);
extern int wfaTGSetPrio(int sockfd, int tgClass);

//void wmmps_wait_state_proc();
/* APTS messages*/
struct apts_msg apts_msgs[] ={
    {0, -1, 0, 0, 0, 0},
    {"B.D", B_D, 0, 0, 0, 0},
    {"B.H", B_H, 0, 0, 0, 0},
    {"B.B", B_B, 0, 0, 0, 0},
    {"B.M", B_M, 0, 0, 0, 0},
    {"M.D", M_D, 0, 0, 0, 0},
    {"B.Z", B_Z, 0, 0, 0, 0},
    {"M.Y", M_Y, 0, 0, 0, 0},
    {"L.1", L_1, 0, 0, 0, 0},
    {"A.Y", A_Y, 0, 0, 0, 0},
    {"B.W", B_W, 0, 0, 0, 0},
    {"A.J", A_J, 0, 0, 0, 0},
    {"M.V", M_V, 0, 0, 0, 0},
    {"M.U", M_U, 0, 0, 0, 0},
    {"A.U", A_U, 0, 0, 0, 0},
    {"M.L", M_L, 0, 0, 0, 0},
    {"B.K", B_K, 0, 0, 0, 0},
    {"M.B", M_B, 0, 0, 0, 0},
    {"M.K", M_K, 0, 0, 0, 0},
    {"M.W", M_W, 0, 0, 0, 0},
#ifdef WFA_WMM_AC
    {"422.T02B", WMMAC_422_T02B},
    {"422.T03A", WMMAC_422_T03A},
    {"422.T04A", WMMAC_422_T04B},
    {"422.T05B", WMMAC_422_T05B},
    {"422.T06B", WMMAC_422_T06B},
    {"422.T07B", WMMAC_422_T07B},
    {"422.T08B", WMMAC_422_T08B},
    {"423.T04",  WMMAC_423_T04},
    {"424.T07",  WMMAC_424_T07t14},
    {"425.T04",  WMMAC_425_T04t06},
    {"521.T03", WMMAC_521_T03},
    {"521.T05", WMMAC_521_T05},
    {"522.T04", WMMAC_522_T04},
    {"522.T06", WMMAC_522_T06},
    {"522.T06o", WMMAC_522_T06o},
    {"524.T03", WMMAC_524_T03},
    {"524.T03i", WMMAC_524_T03i},
    {"525.T07", WMMAC_525_T07t10},
#endif
    {"APTS TX         ", APTS_DEFAULT, 0, 0, 0, 0},
    {"APTS Hello      ", APTS_HELLO, 0, 0, 0, 0},
    {"APTS Broadcast  ", APTS_BCST, 0, 0, 0, 0},
    {"APTS Confirm    ", APTS_CONFIRM, 0, 0, 0, 0},
    {"APTS STOP       ", APTS_STOP, 0, 0, 0, 0},
    {"APTS CK BE      ", APTS_CK_BE, 0, 0, 0, 0},
    {"APTS CK BK      ", APTS_CK_BK, 0, 0, 0, 0},
    {"APTS CK VI      ", APTS_CK_VI, 0, 0, 0, 0},
    {"APTS CK VO      ", APTS_CK_VO, 0, 0, 0, 0},
    {"APTS RESET      ", APTS_RESET, 0, 0, 0, 0},
    {"APTS RESET RESP ", APTS_RESET_RESP, 0, 0, 0, 0},
    {"APTS RESET STOP ", APTS_RESET_STOP, 0, 0, 0, 0},
    {0, 0, 0, 0, 0, 0}   /* APTS_LAST */
};

#if 0 /* Since Passing criteria is handled by Sniffer check, checking order of receiving packets not important */
/* The DUT recv table for each of the test cases*/
StationRecvProcStatetbl_t stationRecvProcStatetbl[LAST_TEST+10][6] =
{
    {{WfaRcvStop},{0},{0},{0},{0},{0}},
    /*B.D*/ {{WfaRcvProc},{WfaRcvVO},{WfaRcvStop},{0},{0},{0}},
    /*B.H*/ {{WfaRcvProc},{WfaRcvVO},{WfaRcvVO},{WfaRcvStop},{0},{0}},
    /*B.B*/ {{WfaRcvProc},{WfaRcvStop},{0},{0},{0},{0}},
    /*B.M*/ {{WfaRcvProc},{WfaRcvStop},{0},{0},{0},{0}},
    /*M.D*/ {{WfaRcvProc},{WfaRcvBE},{WfaRcvBK},{WfaRcvVI},{WfaRcvVO},{WfaRcvStop}},
    /*B.Z*/ {{WfaRcvProc},{WfaRcvVI},{WfaRcvBE},{WfaRcvStop},{0},{0}},
    /*M.Y*/ {{WfaRcvProc},{WfaRcvVI},{WfaRcvBE},{WfaRcvBE},{WfaRcvStop},{0}},
    /*L.1*/ {{WfaRcvProc},{WfaRcvVOCyclic},{0},{0},{0},{0}},
    /*A.Y*/ {{WfaRcvProc},{WfaRcvVI},{WfaRcvBE},{WfaRcvBE},{WfaRcvStop},{0}},
    /*B.W*/ {{WfaRcvProc},{WfaRcvBE},{WfaRcvVI},{WfaRcvBE},{WfaRcvVI},{WfaRcvStop}},
    /*A.J*/ {{WfaRcvProc},{WfaRcvVO},{WfaRcvVI},{WfaRcvBE},{WfaRcvBK},{WfaRcvStop}},
    /*M.V*/ {{WfaRcvProc},{WfaRcvBE},{WfaRcvVI},{WfaRcvStop},{0},{0}},
    /*M.U*/ {{WfaRcvProc},{WfaRcvVI},{WfaRcvBE},{WfaRcvVO},{WfaRcvVO},{WfaRcvStop}},
    /*A.U*/ {{WfaRcvProc},{WfaRcvVI},{WfaRcvBE},{WfaRcvVO},{WfaRcvStop},{0}},
    /*M.L*/ {{WfaRcvProc},{WfaRcvBE},{WfaRcvStop},{0},{0},{0}},
    /*B.K*/ {{WfaRcvProc},{WfaRcvVI},{WfaRcvBE},{WfaRcvStop},{0},{0}},
    /*M.B*/ {{WfaRcvProc},{WfaRcvStop},{0},{0},{0},{0}},
    /*M.K*/ {{WfaRcvProc},{WfaRcvBE},{WfaRcvVI},{WfaRcvStop},{0},{0}},
    /*M.W*/ {{WfaRcvProc},{WfaRcvBE},{WfaRcvBE},{WfaRcvBE},{WfaRcvVI},{WfaRcvStop}}
#ifdef WFA_WMM_AC
    /*422_T02B*/ ,{{WfaRcvProc},{WfaRcvVI},{WfaRcvVO},{WfaRcvVO},{WfaRcvBE},{WfaRcvStop}},
    /*422_T03B*/ {{WfaRcvProc},{WfaRcvVO},{WfaRcvVI},{WfaRcvVI},{WfaRcvStop}},
    /*422_T04B*/ {{WfaRcvProc},{WfaRcvVO},{WfaRcvVI},{WfaRcvBE},{WfaRcvBK},{WfaRcvStop}},
    /*422_T05B*/ {{WfaRcvProc},{WfaRcvVO},{WfaRcvVI},{WfaRcvVI},{WfaRcvStop}},
    /*422_T06B*/ {{WfaRcvProc},{WfaRcvVO},{WfaRcvVI},{WfaRcvBE},{WfaRcvBK},{WfaRcvStop}},
    /*422_T07B*/ {{WfaRcvProc},{WfaRcvVO},{WfaRcvVI},{WfaRcvBE},{WfaRcvBK},{WfaRcvStop}},
    /*422_T08B*/ {{WfaRcvProc},{WfaRcvVO},{WfaRcvVO},{WfaRcvVI},{WfaRcvVO},{WfaRcvStop}},
    /*423_T04*/ {{WfaRcvProc},{WfaRcvVO},{WfaRcvStop}},
    /*424_T07t14*/ {{WfaRcvProc},{WfaRcvVI},{WfaRcvVO},{WfaRcvStop}},
    /*425_T04t06*/{{WfaRcvProc},{WfaRcvStop}},
    /*521_T03*/{{WfaRcvProc},{WfaRcvVI},{WfaRcvBE},{WfaRcvStop}},
    /*521_T05*/{{WfaRcvProc},{WfaRcvBE},{WfaRcvVI},{WfaRcvStop}},
    /*522_T04*/ {{WfaRcvProc},{WfaRcvBE},{WfaRcvVI},{WfaRcvStop},{0},{0}},
    /*522_T06*/ {{WfaRcvProc},{WfaRcvBE},{WfaRcvBK},{WfaRcvVI},{WfaRcvVO},{WfaRcvStop}},
    /*522_T06o*/ {{WfaRcvProc},{WfaRcvBE},{WfaRcvBK},{WfaRcvVI},{WfaRcvVO},{WfaRcvStop}},
    /*524_T03*/ {{WfaRcvProc},{WfaRcvVO},{WfaRcvVO},{WfaRcvStop}},
    /*524_T03i*/ {{WfaRcvProc},{WfaRcvVI},{WfaRcvVI},{WfaRcvStop},{0},{0}},
    /*525_T07t10*/ {{WfaRcvProc},{WfaRcvVI},{WfaRcvStop}},
#endif
};

#endif

StationRecvProcStatetbl_t stationRecvProcStatetbl[LAST_TEST+10][6] =
{
    {{WfaRcvStop},{0},{0},{0},{0},{0}},
    /*B.D*/ {{WfaRcvProc},{WfaRcvNotCare},{WfaRcvStop},{0},{0},{0}},
    /*B.H*/ {{WfaRcvProc},{WfaRcvNotCare},{WfaRcvNotCare},{WfaRcvStop},{0},{0}},
    /*B.B*/ {{WfaRcvProc},{WfaRcvStop},{0},{0},{0},{0}},
    /*B.M*/ {{WfaRcvProc},{WfaRcvStop},{0},{0},{0},{0}},
    /*M.D*/ {{WfaRcvProc},{WfaRcvNotCare},{WfaRcvNotCare},{WfaRcvNotCare},{WfaRcvNotCare},{WfaRcvStop}},
    /*B.Z*/ {{WfaRcvProc},{WfaRcvNotCare},{WfaRcvNotCare},{WfaRcvStop},{0},{0}},
    /*M.Y*/ {{WfaRcvProc},{WfaRcvNotCare},{WfaRcvNotCare},{WfaRcvNotCare},{WfaRcvStop},{0}},
    /*L.1*/ {{WfaRcvProc},{WfaRcvVOCyclic},{0},{0},{0},{0}},
    /*A.Y*/ {{WfaRcvProc},{WfaRcvNotCare},{WfaRcvNotCare},{WfaRcvNotCare},{WfaRcvStop},{0}},
    /*B.W*/ {{WfaRcvProc},{WfaRcvNotCare},{WfaRcvNotCare},{WfaRcvNotCare},{WfaRcvNotCare},{WfaRcvStop}},
    /*A.J*/ {{WfaRcvProc},{WfaRcvNotCare},{WfaRcvNotCare},{WfaRcvNotCare},{WfaRcvNotCare},{WfaRcvStop}},
    /*M.V*/ {{WfaRcvProc},{WfaRcvNotCare},{WfaRcvNotCare},{WfaRcvStop},{0},{0}},
    /*M.U*/ {{WfaRcvProc},{WfaRcvNotCare},{WfaRcvNotCare},{WfaRcvNotCare},{WfaRcvNotCare},{WfaRcvStop}},
    /*A.U*/ {{WfaRcvProc},{WfaRcvNotCare},{WfaRcvNotCare},{WfaRcvNotCare},{WfaRcvStop},{0}},
    /*M.L*/ {{WfaRcvProc},{WfaRcvNotCare},{WfaRcvStop},{0},{0},{0}},
    /*B.K*/ {{WfaRcvProc},{WfaRcvNotCare},{WfaRcvNotCare},{WfaRcvStop},{0},{0}},
    /*M.B*/ {{WfaRcvProc},{WfaRcvStop},{0},{0},{0},{0}},
    /*M.K*/ {{WfaRcvProc},{WfaRcvNotCare},{WfaRcvNotCare},{WfaRcvStop},{0},{0}},
    /*M.W*/ {{WfaRcvProc},{WfaRcvNotCare},{WfaRcvNotCare},{WfaRcvNotCare},{WfaRcvNotCare},{WfaRcvStop}}
#ifdef WFA_WMM_AC
    /*422_T02B*/ ,{{WfaRcvProc},{WfaRcvNotCare},{WfaRcvNotCare},{WfaRcvNotCare},{WfaRcvNotCare},{WfaRcvStop}},
    /*422_T03B*/ {{WfaRcvProc},{WfaRcvNotCare},{WfaRcvNotCare},{WfaRcvNotCare},{WfaRcvStop}},
    /*422_T04B*/ {{WfaRcvProc},{WfaRcvNotCare},{WfaRcvNotCare},{WfaRcvNotCare},{WfaRcvNotCare},{WfaRcvStop}},
    /*422_T05B*/ {{WfaRcvProc},{WfaRcvNotCare},{WfaRcvNotCare},{WfaRcvNotCare},{WfaRcvStop}},
    /*422_T06B*/ {{WfaRcvProc},{WfaRcvNotCare},{WfaRcvNotCare},{WfaRcvNotCare},{WfaRcvNotCare},{WfaRcvStop}},
    /*422_T07B*/ {{WfaRcvProc},{WfaRcvNotCare},{WfaRcvNotCare},{WfaRcvNotCare},{WfaRcvNotCare},{WfaRcvStop}},
    /*422_T08B*/ {{WfaRcvProc},{WfaRcvNotCare},{WfaRcvNotCare},{WfaRcvNotCare},{WfaRcvNotCare},{WfaRcvStop}},
    /*423_T04*/ {{WfaRcvProc},{WfaRcvNotCare},{WfaRcvStop}},
    /*424_T07t14*/ {{WfaRcvProc},{WfaRcvNotCare},{WfaRcvNotCare},{WfaRcvStop}},
    /*425_T04t06*/{{WfaRcvProc},{WfaRcvStop}},
    /*521_T03*/{{WfaRcvProc},{WfaRcvNotCare},{WfaRcvNotCare},{WfaRcvStop}},
    /*521_T05*/{{WfaRcvProc},{WfaRcvNotCare},{WfaRcvNotCare},{WfaRcvStop}},
    /*522_T04*/ {{WfaRcvProc},{WfaRcvNotCare},{WfaRcvNotCare},{WfaRcvStop},{0},{0}},
    /*522_T06*/ {{WfaRcvProc},{WfaRcvNotCare},{WfaRcvNotCare},{WfaRcvNotCare},{WfaRcvNotCare},{WfaRcvStop}},
    /*522_T06o*/ {{WfaRcvProc},{WfaRcvNotCare},{WfaRcvNotCare},{WfaRcvNotCare},{WfaRcvNotCare},{WfaRcvStop}},
    /*524_T03*/ {{WfaRcvProc},{WfaRcvNotCare},{WfaRcvNotCare},{WfaRcvStop}},
    /*524_T03i*/ {{WfaRcvProc},{WfaRcvNotCare},{WfaRcvNotCare},{WfaRcvStop},{0},{0}},
    /*525_T07t10*/ {{WfaRcvProc},{WfaRcvNotCare},{WfaRcvStop}},
#endif
};




/* The DUT send table for each of the test cases*/
StationProcStatetbl_t stationProcStatetbl[LAST_TEST+1][11] =
{
    /* Dummy*/{{0},{0},{0},{0},{0},{0},{0},{0},{0},{0},{0}},
    /* B.D*/  {{WfaStaSndHello,P_OFF, 1000000},{WfaStaSndConfirm,P_ON, LII / 2},
        {WfaStaSndVO,P_ON,LII / 2}   ,{WfaStaSndVO,P_ON,LII / 2}        ,{WfaStaWaitStop,P_ON,LII / 2},{0,0,0},{0,0,0},{0,0,0},{0,0,0},{0,0,0}
    },

    /* B.H*/  {{WfaStaSndHello,P_OFF, 1000000},{WfaStaSndConfirm,P_ON, LII / 2},
        {WfaStaSndVO,P_ON,LII / 2}   ,{WfaStaSndVO,P_ON,LII / 2}        ,{WfaStaWaitStop,P_ON,LII / 2},{0,0,0},{0,0,0},{0,0,0},{0,0,0},{0,0,0}
    },

    /* B.B*/  {{WfaStaSndHello,P_OFF, 1000000},{WfaStaSndConfirm,P_ON, LII / 2},
        {WfaStaSndVO,P_ON,LII / 2}   ,{WfaStaSndVI,P_ON,LII / 2}        ,{WfaStaSndBE,P_ON,LII / 2}     ,{WfaStaSndBK,P_ON,LII / 2}    ,{WfaStaWaitStop,P_ON,LII / 2},{0,0,0},{0,0,0},{0,0,0}
    },

    /* B.M*/  {{WfaStaSndHello,P_OFF, 1000000},{WfaStaSndConfirm,P_ON, LII / 2},
        {WfaStaSndVI,P_ON,30000000},{WfaStaWaitStop,P_ON,LII / 2}     ,{0,0,0},{0,0,0},{0,0,0},{0,0,0},{0,0,0},{0,0,0}
    },

    /* M.D*/  {{WfaStaSndHello,P_OFF, 1000000},{WfaStaSndConfirm,P_ON, LII / 2},
        {WfaStaSndVI,P_ON,LII / 2}   ,{WfaStaSndVI,P_ON,LII / 2}        ,{WfaStaSndVI,P_ON,LII / 2}     ,{WfaStaSndVI,P_ON,LII / 2}    ,{WfaStaWaitStop,P_ON,LII / 2},{0,0,0},{0,0,0},{0,0,0}
    },

    /* B.Z*/  {{WfaStaSndHello,P_OFF, 1000000},{WfaStaSndConfirm,P_ON, LII / 2},
        {WfaStaSndVO,P_ON,LII / 2 }  ,{WfaStaWaitStop,P_ON,LII / 2}     ,{0,0,0},{0,0,0},{0,0,0},{0,0,0},{0,0,0},{0,0,0}
    },

    /* M.Y*/  {{WfaStaSndHello,P_OFF, 1000000},{WfaStaSndConfirm,P_ON, LII / 2},
        {WfaStaSndVI,P_ON,LII / 2}   ,{WfaStaSndVO,P_ON,LII / 2}        ,{WfaStaSndBE,P_ON,LII / 2}     ,{WfaStaSndBE,P_ON,LII / 2}    ,{WfaStaWaitStop,P_ON,LII / 2},{0,0,0},{0,0,0},{0,0,0}
    },

    /* L.1*/  {{WfaStaSndHello,P_OFF, 1000000},{WfaStaSndConfirm,P_ON, LII / 2},
        {WfaStaSndVOCyclic,P_ON,20000},{WfaStaWaitStop,P_ON,LII / 2 }
    },

    /* A.Y*/  {{WfaStaSndHello,P_OFF, 1000000},{WfaStaSndConfirm,P_ON, LII / 2},
        {WfaStaSndVI,P_ON,LII / 2}   ,{WfaStaSndVO,P_ON,LII / 2}        ,{WfaStaSndBE,P_ON,LII / 2}     ,{WfaStaSndBE,P_OFF,LII / 2}    ,{WfaStaSndBE,P_ON,LII / 2}   ,{WfaStaWaitStop,P_ON,LII / 2},{0,0,0},{0,0,0}
    },

    /* B.W*/  {{WfaStaSndHello,P_OFF, 1000000},{WfaStaSndConfirm,P_ON, LII / 2},
        {WfaStaSndVI,P_ON,LII / 2}   ,{WfaStaSndVI,P_ON,LII / 2}        ,{WfaStaSndVI,P_ON,LII / 2}    ,{WfaStaWaitStop,P_ON,LII / 2}  ,{0,0,0},{0,0,0},{0,0,0},{0,0,0}
    },

    /* A.J*/  {{WfaStaSndHello,P_OFF, 1000000},{WfaStaSndConfirm,P_ON, LII / 2},
        {WfaStaSndVO,P_ON,LII / 2}   ,{WfaStaSndVO,P_OFF,LII / 2},{WfaStaWaitStop	,P_ON,LII / 2},{0,0,0},{0,0,0},{0,0,0},{0,0,0},{0,0,0}
    },

    /* M.V*/  {{WfaStaSndHello,P_OFF, 1000000},{WfaStaSndConfirm,P_ON, LII / 2},
        {WfaStaSndVI,P_ON,LII / 2}   ,{WfaStaSndBE,P_ON,LII / 2}        ,{WfaStaSndVI,P_ON,LII / 2}    ,{WfaStaWaitStop	,P_ON,LII / 2} ,{0,0,0},{0,0,0},{0,0,0},{0,0,0}
    },

    /* M.U*/  {{WfaStaSndHello,P_OFF, 1000000},{WfaStaSndConfirm,P_ON, LII / 2},
        {WfaStaSndVI,P_ON,LII / 2}   ,{WfaStaSndBE,P_ON,LII / 2}        ,{WfaStaSnd2VO,P_ON,LII / 2}   ,{WfaStaWaitStop	,P_ON,LII / 2} ,{0,0,0},{0,0,0},{0,0,0},{0,0,0}
    },

    /* A.U*/  {{WfaStaSndHello,P_OFF, 1000000},{WfaStaSndConfirm,P_ON, LII / 2},
        {WfaStaSndVI,P_ON,LII / 2}  ,{WfaStaSndBE,P_OFF,LII / 2}      ,{WfaStaSndBE,P_ON,LII / 2}    ,{WfaStaSndBE,P_OFF,LII / 2}   ,{WfaStaSndVO,P_ON,LII / 2}   ,{WfaStaSndVO,P_OFF,LII / 2} ,{WfaStaWaitStop ,P_ON,LII / 2},{0,0,0}
    },

    /* M.L*/  {{WfaStaSndHello,P_OFF, 1000000},{WfaStaSndConfirm,P_ON, LII / 2},
        {WfaStaSndBE,P_ON,LII / 2}   ,{WfaStaWaitStop,P_ON,LII / 2}     ,{0,0,0},{0,0,0},{0,0,0},{0,0,0},{0,0,0},{0,0,0}
    },

    /* B.K*/  {{WfaStaSndHello,P_OFF, 1000000},{WfaStaSndConfirm,P_ON, LII / 2},
        {WfaStaSndVI,P_ON,LII / 2}   ,{WfaStaSndBE,P_ON,LII / 2}        ,{WfaStaSndVI,P_ON,LII / 2}    ,{WfaStaWaitStop,P_ON,LII / 2}  ,{0,0,0},{0,0,0},{0,0,0},{0,0,0}
    },

    /* M.B*/  {{WfaStaSndHello,P_OFF, 1000000},{WfaStaSndConfirm,P_ON, LII / 2},
        {WfaStaSndVO,P_ON,LII / 2}   ,{WfaStaSndVI,P_ON,LII / 2}        ,{WfaStaSndBE,P_ON,LII / 2}     ,{WfaStaSndBK,P_ON,LII / 2}    ,{WfaStaWaitStop,P_ON,LII / 2} ,{0,0,0},{0,0,0},{0,0,0}
    },

    /* M.K*/  {{WfaStaSndHello,P_OFF, 1000000},{WfaStaSndConfirm,P_ON, LII / 2},
        {WfaStaSndVI,P_ON,LII / 2}   ,{WfaStaSndBE,P_ON,LII / 2}        ,{WfaStaSndVI,P_ON,LII / 2}    ,{WfaStaWaitStop,P_ON,LII / 2}  ,{0,0,0},{0,0,0},{0,0,0},{0,0,0}
    },

    /* M.W*/  {{WfaStaSndHello,P_OFF, 1000000},{WfaStaSndConfirm,P_ON, LII / 2},
        {WfaStaSndVI,P_ON,LII / 2}   ,{WfaStaSndBE,P_ON,LII / 2}        ,{WfaStaSndVI,P_ON,LII / 2}    ,{WfaStaWaitStop,P_ON,LII / 2}  ,{0,0,0},{0,0,0},{0,0,0},{0,0,0}
    }
#ifdef WFA_WMM_AC
    /* WMMAC_422_T02B */  ,{{WfaStaSndHello,P_OFF, 1000000},{WfaStaSndConfirm,P_ON, LII / 2}, {WfaStaSndVI,P_ON,1000000}, {WfaStaSndVO,P_ON,1000000}, {WfaStaSndVO,P_ON,1000000}, {WfaStaWaitStop,P_ON,LII / 2}, {0,0,0},{0,0,0},{0,0,0},{0,0,0}},

    /* WMMAC_422_T03B */  {{WfaStaSndHello,P_OFF, 1000000},{WfaStaSndConfirm,P_ON, LII / 2}, {WfaStaSndVI,P_ON,becon_int}   ,{WfaStaSndVO,P_ON,lis_int}        ,{WfaStaSndVI,P_ON,becon_int}  ,{WfaStaSndVO,P_ON,becon_int}  ,{WfaStaWaitStop,P_ON,LII / 2}  ,{0,0,0},{0,0,0},{0,0,0}},

    /* 422_T04B/ATC7 */  {{WfaStaSndHello,P_OFF, 1000000},{WfaStaSndConfirm,P_ON, LII / 2}, {WfaStaSndVI,P_ON,becon_int}   ,{WfaStaSndVO,P_ON,lis_int}        ,{WfaStaSndVI,P_ON,becon_int}  ,{WfaStaSndVO,P_ON,becon_int}  ,{WfaStaWaitStop,P_ON,LII / 2}  ,{0,0,0},{0,0,0},{0,0,0}},

    /* 422_T05B/ATC8 */  {{WfaStaSndHello,P_OFF, 1000000},{WfaStaSndConfirm,P_ON, LII / 2}, {WfaStaSndVO,P_ON,lis_int}   ,{WfaStaSndVI,P_ON,lis_int+2*becon_int} ,{WfaStaSndVI,P_ON,becon_int}  ,{WfaStaWaitStop,P_ON,LII / 2}  ,{0,0,0},{0,0,0},{0,0,0},{0,0,0}},

    /* 422_T06B/ATC9 */  {{WfaStaSndHello,P_OFF, 1000000},{WfaStaSndConfirm,P_ON, LII / 2}, {WfaStaSndBE,P_ON,becon_int}   ,{WfaStaSndVO,P_ON,lis_int}        ,{WfaStaSndBE,P_ON,becon_int}  ,{WfaStaSndVI,P_ON,becon_int}  ,{WfaStaWaitStop,P_ON,LII / 2}  ,{0,0,0},{0,0,0},{0,0,0}},

    /* 422_T07B/ATC10 */  {{WfaStaSndHello,P_OFF, 1000000},{WfaStaSndConfirm,P_ON, LII / 2}, {WfaStaSndVI,P_ON,becon_int}   ,{WfaStaSndBE,P_ON,lis_int}        ,{WfaStaSndVI,P_ON,becon_int}  ,{WfaStaSndBK,P_ON,becon_int}  ,{WfaStaWaitStop,P_ON,LII / 2}  ,{0,0,0},{0,0,0},{0,0,0}},

    /* 422_T08B/ATC11 */  {{WfaStaSndHello,P_OFF, 1000000},{WfaStaSndConfirm,P_ON, LII / 2}, {WfaStaSndBE,P_ON,becon_int}   ,{WfaStaSndVI,P_ON,lis_int}        ,{WfaStaSndBE,P_ON,becon_int}  ,{WfaStaSndVO,P_ON,lis_int}  ,{WfaStaWaitStop,P_ON,LII / 2}  ,{0,0,0},{0,0,0},{0,0,0}},

    /* 423_T04 */  {{WfaStaSndHello,P_OFF, 1000000}, {WfaStaSndConfirm,P_ON, 1}
        ,{WfaStaSndVO,P_ON,1000000}    ,{WfaStaWaitStop,P_ON,LII / 2}  ,{0,0,0},{0,0,0}, {0,0,0},{0,0,0},{0,0,0},{0,0,0}
    },

    /* 424_T07t14 */ {{WfaStaSndHello,P_OFF, 1000000},{WfaStaSndConfirm,P_ON, LII / 2}, {WfaStaSndVI,P_ON,becon_int}   ,{WfaStaSndVO,P_ON,lis_int}        ,{WfaStaSndVO,P_ON,becon_int}  ,{WfaStaWaitStop,P_ON,LII / 2}  ,{0,0,0},{0,0,0},{0,0,0},{0,0,0}},

    /* 425_T04t06 */ {{WfaStaSndHello,P_OFF, 1000000},{WfaStaSndConfirm,P_ON, LII / 2}, {WfaStaSndBE,P_ON,becon_int}   ,{WfaStaWaitStop,P_ON,LII / 2}  ,{0,0,0}, {0,0,0},{0,0,0},{0,0,0},{0,0,0},{0,0,0}},

    /* 521_T03 */  {{WfaStaSndHello,P_OFF, 1000000},{WfaStaSndConfirm,P_ON, LII / 2}, {WfaStaSndVI,P_ON,becon_int}   ,{WfaStaSndBE,P_ON,lis_int}        ,{WfaStaSndVI,P_ON,becon_int}  ,{WfaStaWaitStop,P_ON,LII / 2}  ,{0,0,0},{0,0,0},{0,0,0},{0,0,0}},

    /* 521_T05 */  {{WfaStaSndHello,P_OFF, 1000000},{WfaStaSndConfirm,P_ON, LII / 2}, {WfaStaSndVI,P_ON,becon_int}   ,{WfaStaSndBE,P_ON,lis_int}        ,{WfaStaSndVO,P_ON,becon_int}  ,{WfaStaWaitStop,P_ON,LII / 2}  ,{0,0,0},{0,0,0},{0,0,0},{0,0,0}},

    /* 522_T04 */  {{WfaStaSndHello,P_OFF, 1000000},{WfaStaSndConfirm,P_ON, LII / 2}, {WfaStaSndVI,P_ON,becon_int}   ,{WfaStaSndBE,P_ON,lis_int}        ,{WfaStaSndVO,P_ON,becon_int}  ,{WfaStaWaitStop,P_ON,LII / 2}  ,{0,0,0},{0,0,0},{0,0,0},{0,0,0}},

    /* 522_T06 */  {{WfaStaSndHello,P_OFF, 1000000},{WfaStaSndConfirm,P_ON, LII / 2}, {WfaStaSndVI,P_ON,becon_int}   ,{WfaStaSndVI,P_ON,lis_int}        ,{WfaStaSndVI,P_ON,becon_int}  ,{WfaStaSndVI,P_ON,lis_int}  ,{WfaStaWaitStop,P_ON,LII / 2}  ,{0,0,0},{0,0,0},{0,0,0}},
    /* 522_T06o */  {{WfaStaSndHello,P_OFF, 1000000},{WfaStaSndConfirm,P_ON, LII / 2}, {WfaStaSndVO,P_ON,becon_int}   ,{WfaStaSndVO,P_ON,lis_int}        ,{WfaStaSndVO,P_ON,becon_int}  ,{WfaStaSndVO,P_ON,lis_int}  ,{WfaStaWaitStop,P_ON,LII / 2}  ,{0,0,0},{0,0,0},{0,0,0}},

    /* 524_T03 */  {{WfaStaSndHello,P_OFF, 1000000},{WfaStaSndConfirm,P_ON, LII / 2}, {WfaStaSndVO,P_ON,becon_int}   ,{WfaStaSndVO,P_ON,lis_int}        ,{WfaStaSndVO,P_ON,lis_int} ,{WfaStaWaitStop,P_ON,LII / 2},  {0,0,0},{0,0,0},{0,0,0},{0,0,0}},
    /* 524_T03i */  {{WfaStaSndHello,P_OFF, 1000000},{WfaStaSndConfirm,P_ON, LII / 2}, {WfaStaSndVI,P_ON,becon_int}   ,{WfaStaSndVI,P_ON,lis_int}  ,{WfaStaSndVI,P_ON,lis_int}       ,{WfaStaWaitStop,P_ON,LII / 2}  ,{0,0,0},{0,0,0},{0,0,0},{0,0,0}},

    /* 525_T07t10 */  {{WfaStaSndHello,P_OFF, 1000000},{WfaStaSndConfirm,P_ON, LII / 2}, {WfaStaSndVI,P_ON,becon_int}   ,{WfaStaWaitStop,P_ON,LII / 2}  ,{0,0,0},{0,0,0},{0,0,0},{0,0,0},{0,0,0},{0,0,0}},

#endif

};

int ac_seq[APTS_LAST][6] =
{
    {0,      0,      0,      0,      0},
    {0},
    {0},
    {0},
    {0},
    {0},
    {0},
    {0},
    {0},
    {0},
    {0}, // APTS_TESTS
    {0}, // B.D
    {0}, // B.2
    {0}, // B.H
    {0}, // B.4
    {0}, // B_5
    {0, 0, 0, 0, 0}, // B_6
    {TG_WMM_AC_VO, TG_WMM_AC_VI, TG_WMM_AC_BE, TG_WMM_AC_BK, 0}, // B.B B_B - 4 exchanges: 1 uplink, 0 downlink
    {0}, // B.E
    {0}, // B.G
    {0}, // B.I
    {0}, // M.D
    {0}, // M.G
    {0}, // M.I
    {0}, // B.Z  1, 1, 1, 0},	// 1 special exchange for Broadcast testing
    {TG_WMM_AC_VI, TG_WMM_AC_VO, TG_WMM_AC_BE, TG_WMM_AC_BE, 0}, //  M.Y  M_Y 2 special exchange for Broadcast testing
    {0}, // L.1
    {0}, // DLOAD
    {0}, // ULOAD
    {0}, // "APTS PASS"
    {0}, // "APTS FAIL"
    //{TOS_VI, TOS_VO, TOS_BE, TOS_BE, 0}, //  A.Y A_Y special exchange for Broadcast testing
    {TG_WMM_AC_VI, TG_WMM_AC_VO, TG_WMM_AC_BE, TG_WMM_AC_BE, TG_WMM_AC_BE}, //  A.Y A_Y special exchange for Broadcast testing
    {0}, //  B.W  2 special exchange for Broadcast testing
    {0}, //  A.J
    {TG_WMM_AC_VI, TG_WMM_AC_BE, TG_WMM_AC_VI, TG_WMM_AC_VI, TG_WMM_AC_VI}, //  M.V M_V
    {TG_WMM_AC_VI, TG_WMM_AC_BE, TG_WMM_AC_VO, TG_WMM_AC_VO, TG_WMM_AC_VO}, //  M.U M_U
    {TG_WMM_AC_VI, TG_WMM_AC_BE, TG_WMM_AC_BE, TG_WMM_AC_BE, TG_WMM_AC_VO, TG_WMM_AC_VO},  //  A.U A_U
    {0}, //  M.L M_L
    {TG_WMM_AC_VI, TG_WMM_AC_BE, TG_WMM_AC_VI, TG_WMM_AC_VI, 0}, // B.K B_K
    {TG_WMM_AC_VO, TG_WMM_AC_VI, TG_WMM_AC_BE, TG_WMM_AC_BK, 0}, // M.B M_B - 4 exchanges: 1 uplink, 0 downlink
    {TG_WMM_AC_VI, TG_WMM_AC_BE, TG_WMM_AC_VI, TG_WMM_AC_VI, 0}, // M.K M_K
    {TG_WMM_AC_VI, TG_WMM_AC_BE, TG_WMM_AC_VI, TG_WMM_AC_VI, 0} //  M.W M_W   special exchange for Broadcast testing
};
/* Generic function to create a meassage, it also fills in the AC as part of
** the payload
** */
void create_apts_msg(int msg, unsigned int txbuf[],int id)
{
    struct apts_msg *t;

    t = &apts_msgs[msg];
    txbuf[ 0] = wmmps_info.my_cookie;
    txbuf[ 1] = wmmps_info.dscp;
    txbuf[ 2] = 0;
    txbuf[ 3] = 0;
    txbuf[ 4] = 0;
    txbuf[ 5] = 0;
    //txbuf[ 6] = t->param0;
    //txbuf[ 7] = t->param1;
    //txbuf[ 8] = t->param2;
    txbuf[ 9] = id;
    txbuf[ 10] = t->cmd;
    wSTRCPY((char *)&txbuf[11], t->name);
    PRINTF("create_apts_msg (%s) %d\n", t->name,t->cmd);
}

void print_hex_string(char* buf, int len)
{
    int i;

    if (len==0)
    {
        printf("<empty string>");
        return;
    }

    for (i = 0; i < len; i++)
    {
        printf("%02x ", *((unsigned char *)buf + i));
        if ((i&0xf)==15)
            printf("\n   ");
    }

    if ((i&0xf))
        printf("\n");
}

/* trace print*/
void mpx(char *m, void *buf_v, int len)
{
    char *buf = buf_v;

    printf("%s   MSG: %s\n   ", m, &buf[44] );
    print_hex_string(buf, len);
}

/* function to validate the AC of the payload recd to ensure the correct
** message sequence*/
int receiver(unsigned int *rmsg,int length,int tos,unsigned int type)
{
    int r=1;
   hi_unref_param(length);
#ifndef WFA_WMM_AC
    int new_dscp=rmsg[1];

    if((new_dscp != tos)||(rmsg[10] != type))
    {
        PRINTF("\r\n dscp recd is %d msg type is %d\n",new_dscp,rmsg[10]);
        r=-6;
    }
#else
    if(rmsg[10] != type)
    {
        PRINTF("\r\n dscp recd is %d msg type is %d\n",new_dscp,rmsg[10]);
        r=-6;
    }
#endif

    return r;
}
/* WfaRcvProc: This function receives the test case name
** after sending the initial hello packet, on receiving a
** valid test case it advances onto the next receive state
*/
int WfaRcvProc(unsigned int *rmsg,int length,int *state)
{
    hi_unref_param(length);
    int sta_test;
    int usedThread = wmmps_info.ps_thread;
    num_hello=0;
    sta_test = rmsg[10];
    mpx("STA recv\n", rmsg, 64);
    PRINTF("--->WfaRcvProc--\n");
// For debugging
#if 0
    switch(rmsg[10])
    {
    case APTS_DEFAULT:
        printf("Recvd: APTS_DEFAULT\n");
        break;
    case APTS_HELLO:
        printf("Recvd: APTS_HELLO\n");
        break;
    case APTS_BCST:
        printf("Recvd: APTS_BCST\n");
        break;
    case APTS_CONFIRM:
        printf("Recvd: APTS_CONFIRM\n");
        break;
    case APTS_STOP:
        printf("Recvd: APTS_STOP\n");
        break;
    case APTS_CK_BE:
        printf("Recvd: APTS_CK_BE\n");
        break;
    case APTS_CK_BK:
        printf("Recvd: APTS_CK_BK\n");
        break;
    case APTS_CK_VI:
        printf("Recvd: APTS_CK_VI\n");
        break;
    case APTS_CK_VO:
        printf("Recvd: APTS_CK_VO\n");
        break;
    case APTS_RESET:
        printf("Recvd: APTS_RESET\n");
        break;
    case APTS_RESET_RESP:
        printf("Recvd: APTS_RESET_RESP\n");
        break;
    case APTS_RESET_STOP:
        printf("Recvd: APTS_RESET_STOP\n");
        break;
    }
#endif
    if(!((sta_test >=B_D)&&(sta_test <= LAST_TEST)))
    {
        return -1;
    }

    wmmps_info.sta_test = rmsg[10];
    wmmps_info.my_sta_id = rmsg[9];
    wPT_MUTEX_LOCK(&wmm_thr[usedThread].thr_flag_mutex);
    wmm_thr[usedThread].thr_flag = wmmps_info.streamid;
    wPT_MUTEX_UNLOCK(&wmm_thr[usedThread].thr_flag_mutex);
    (*state)++;

    return 0;
}
/* WfaStaResetAll: This function resets the whole communication with
** the console (in the event of a wrong message received for the test case)
** resulting into resending of all the packets from the scratch, there is an
** upper bound for the resets a max of three*/
void WfaStaResetAll(void)
{
    PRINTF("Entering Reset\n");
    num_retry++;
    if(num_retry > MAXRETRY)
    {
        create_apts_msg(APTS_RESET_STOP, psTxMsg,wmmps_info.my_sta_id);
        wfaTGSetPrio(psSockfd, TG_WMM_AC_BE);
        wSENDTO(psSockfd, psTxMsg, msgsize, 0, (struct sockaddr *)&wmmps_info.psToAddr, sizeof(struct sockaddr));
        mpx("STA msg",psTxMsg,64);
        printf("Too many retries\n");
        //exit(-8);
    }
    if(!reset_recd)
    {
        create_apts_msg(APTS_RESET, psTxMsg,wmmps_info.my_sta_id);
        wfaTGSetPrio(psSockfd, TG_WMM_AC_BE);
        psTxMsg[1] = TOS_BE;
        wSENDTO(psSockfd, psTxMsg, msgsize, 0, (struct sockaddr *)&wmmps_info.psToAddr, sizeof(struct sockaddr));
        mpx("STA msg",psTxMsg,64);
    }
    else
    {
        create_apts_msg(APTS_RESET_RESP, psTxMsg,wmmps_info.my_sta_id);
        wfaTGSetPrio(psSockfd, TG_WMM_AC_BE);
        wSENDTO(psSockfd, psTxMsg, msgsize, 0, (struct sockaddr *)&wmmps_info.psToAddr, sizeof(struct sockaddr));
        mpx("STA msg",psTxMsg,64);
        reset_recd=0;
    }

    resetsnd=1;
    resetrcv=1;
}
/* WfaRcvVO: A function expected to receive a AC_VO packet from
** the console, if does not reeive a valid VO resets the communication wit
** h the console*/

int WfaRcvVO(unsigned int *rmsg,int length,int *state)
{

    int r;

    if ((r=receiver(rmsg,length,TOS_VO,APTS_DEFAULT))>=0)
        (*state)++;
    else
    {
        PRINTF("\nBAD REC in VO%d\n",r);
        WfaStaResetAll();
    }

    return 0;
}
/* WfaRcvVI: A function expected to receive a AC_VI packet from
** the console, if does not reeive a valid VI resets the communication wit
** h the console*/

int WfaRcvVI(unsigned int *rmsg,int length,int *state)
{
    int r;

    if ((r=receiver(rmsg,length,TOS_VI,APTS_DEFAULT))>=0)
        (*state)++;
    else
        PRINTF("\nBAD REC in VI%d\n",r);

    return 0;
}

/* WfaRcvBE: A function expected to receive a AC_BE packet from
** the console, if does not reeive a valid BE resets the communication wit
** h the console*/

int WfaRcvBE(unsigned int *rmsg,int length,int *state)
{

    int r;
    if ((r=receiver(rmsg,length,TOS_BE,APTS_DEFAULT))>=0)
        (*state)++;
    else
    {
        PRINTF("\nBAD REC in BE%d\n",r);
    }

    return 0;
}

/* WfaRcvBK: A function expected to receive a AC_BK packet from
** the console, if does not reeive a valid BK resets the communication wit
** h the console*/

int WfaRcvBK(unsigned int *rmsg,int length,int *state)
{

    int r;

    if ((r=receiver(rmsg,length,TOS_BK,APTS_DEFAULT))>=0)
        (*state)++;
    else
        PRINTF("\nBAD REC in BK%d\n",r);

    return 0;
}
/* WfaRcvVOCyclic: This is meant for the L1 test case. The function
** receives the VO packets from the console */
int WfaRcvVOCyclic(unsigned int *rmsg,int length,int *state)
{
    hi_unref_param(state);
    int r;
    tgWMM_t *my_wmm = &wmm_thr[wmmps_info.ps_thread];

    if(rmsg[10] != APTS_STOP)
    {
        if ((r=receiver(rmsg,length,TOS_VO,APTS_DEFAULT))>=0)
            ;
        else
            PRINTF("\nBAD REC in VO%d\n",r);
    }
    else
    {
        wPT_MUTEX_LOCK(&my_wmm->thr_stop_mutex);
        while(!my_wmm->stop_flag)
        {
            wPT_COND_WAIT(&my_wmm->thr_stop_semaphore, &my_wmm->thr_stop_mutex);
        }
        wPT_MUTEX_UNLOCK(&my_wmm->thr_stop_mutex);
        my_wmm->stop_flag = 0;
        gtgWmmPS = 0;
        wCLOSE(psSockfd);
        psSockfd = -1;
        wSIGNAL(SIGALRM, SIG_IGN);
        //wfaSetDUTPwrMgmt(PS_OFF);
        wSLEEP(1);
    }

    return 0;
}
/* WfaRcvStop: This function receives the stop message from the
** console, it waits for the sending thread to have sent the stop before
** quitting*/
int WfaRcvStop(unsigned int *rmsg,int length,int *state)
{
    hi_unref_param(length);
    hi_unref_param(state);
    tgWMM_t *my_wmm = &wmm_thr[wmmps_info.ps_thread];

    my_wmm->stop_flag = 0;
    PRINTF("\r\nEnterring WfaRcvStop\n");

    if(rmsg[10] != APTS_STOP)
    {
        PRINTF("\nBAD REC in rcvstop\n");
        //WfaStaResetAll();
    }
    else
    {
        pthread_mutex_lock(&my_wmm->thr_stop_mutex);
        while(!my_wmm->stop_flag)
        {
            pthread_cond_wait(&my_wmm->thr_stop_semaphore, &my_wmm->thr_stop_mutex);
        }
        num_stops=0;
        pthread_mutex_unlock(&my_wmm->thr_stop_mutex);
        my_wmm->stop_flag = 0;
        gtgWmmPS = 0;
        wCLOSE(psSockfd);
        psSockfd = -1;
        signal(SIGALRM, SIG_IGN);
        //wfaSetDUTPwrMgmt(PS_OFF);
        sleep(1);
    }
    return 0;
}

int WfaRcvNotCare(unsigned int *rmsg,int length,int *state)
{
    int r;

    if ((r=receiver(rmsg,length,TOS_VO,APTS_DEFAULT))>=0 ||
            (r=receiver(rmsg,length,TOS_VI,APTS_DEFAULT))>=0 ||
            (r=receiver(rmsg,length,TOS_BE,APTS_DEFAULT))>=0 ||
            (r=receiver(rmsg,length,TOS_BK,APTS_DEFAULT))>=0 )
    {
        (*state)++;
    }
    else
    {
        PRINTF("\nBAD Rcv in QoS type r=%d\n",r);
        WfaStaResetAll();
    }

    return 0;
}



void BUILD_APTS_MSG(int msg, unsigned long *txbuf)
{
    struct apts_msg *t;

    t = &apts_msgs[msg];
    txbuf[0] = wmmps_info.msgno++;
    txbuf[1] = 0;
    txbuf[2] = 0;
    txbuf[3] = 0;
    txbuf[4] = 0;
    txbuf[5] = 0;
    txbuf[6] = t->param0;
    txbuf[7] = t->param1;
    txbuf[8] = t->param2;
    txbuf[9] = t->param3;
    txbuf[10] = t->cmd;
    wSTRCPY((char *)&txbuf[11], t->name);
}

void send_txmsg(int new_prio_class)
{
    int new_dscp = 0;

    if(new_prio_class > -1)
        new_dscp = wfaTGSetPrio(psSockfd, new_prio_class);

    psTxMsg[0] = wmmps_info.msgno++;
    psTxMsg[1] = new_dscp;
    psTxMsg[2] = wmmps_info.my_group_cookie;
    psTxMsg[3] = wmmps_info.my_cookie;
    psTxMsg[4] = wmmps_info.my_sta_id;

    if(psTxMsg[10] == APTS_DEFAULT)
    {
        psTxMsg[13] = (wmmps_info.msgno%10) + 0x20202030;
    }

    wfaTrafficSendTo(psSockfd, (char *)psTxMsg, 200+(wmmps_info.msgno%200), (struct sockaddr *) &wmmps_info.psToAddr);

    wmmps_info.nsent++;
}

/*
 * This needs to adopt to the specific platform you port to.
 */
extern void hi_wifi_hipriv(int argc, const unsigned char *argv[]);
void wfaSetDUTPwrMgmt(int mode)
{
    static int curr_mode = -1;
    char iface[32]; /* 32 元素个数 */

    wSTRNCPY(iface, WFA_STAUT_IF, 31); /* 31 拷贝长度 */
    printf("wfaSetDUTPwrMgmt mode: %d curr_mode: %d\n", mode, curr_mode);
    if (curr_mode == mode) {
        printf("curr_mode == mode\n");
        return;
    }

    if (mode == PS_OFF) {
        /* sprintf(gCmdStr, "iwpriv %s set PSMode=CAM", iface); */
        sprintf(gCmdStr, "iwconfig %s power off", iface);
        if (system(gCmdStr) < 0) {
            DPRINT_ERR(WFA_ERR, "Cant Set PS OFF\n");
        } else {
            char* pm_set_switch_cmd_off[] = {"wlan0", "set_sta_pm_on", "0"}; /* 进入到低功耗模式 0为关闭，1为打开 */
            (void)hi_wifi_hipriv(3, (const unsigned char**)pm_set_switch_cmd_off);  /* 3: 入参参数个数 */
            printf("\r\n STA PS OFF \n");
        }
    } else {
        /* sprintf(gCmdStr, "iwpriv %s set PSMode=MAX_PSP", iface); */
        sprintf(gCmdStr, "iwconfig %s power on", iface);
        if (system(gCmdStr) < 0) {
            DPRINT_ERR(WFA_ERR, "Cant Set PS ON\n");
        } else {
            char* pm_set_switch_cmd_on[] = {"wlan0", "set_sta_pm_on", "1"};
            (void)hi_wifi_hipriv(3, (const unsigned char**)pm_set_switch_cmd_on);  /* 3: 入参参数个数 */
            printf("\r\n STA PS ON \n");
        }
    }

    curr_mode = mode;
}

int wfaWmmPowerSaveProcess(int sockfd)
{
    int rbytes = 0;
    int sta_test;
    struct sockaddr from;
    int len;
    StationRecvProcStatetbl_t  *rcvstatarray;
    StationRecvProcStatetbl_t  func;
    int *rcv_state;
    len=sizeof(from);
    PRINTF("enter wfaWmmPowerSaveProcess fun.......\n");
//   rbytes = recvfrom(sockfd, (char *)psRxMsg, MAX_UDP_LEN, MSG_WAITALL, &from, (socklen_t *)&len);
    rbytes = recvfrom(sockfd, (char *)psRxMsg, MAX_UDP_LEN, 0, &from, (socklen_t *)&len);
    if(rbytes < 0)
    {
        PRINTF("recvfrom error...rbytes = %d....\n", rbytes);
        return rbytes;
   }

   PRINTF("recvfrom pass.......\n");
    sta_test = wmmps_info.sta_test;
    if(sta_test != L_1)
        mpx("RX msg",psRxMsg,64);
    if(psRxMsg[10] == APTS_STOP)
        PRINTF("\r\n stop recd\n");

    if(psRxMsg[10] == APTS_RESET)
    {
        PRINTF("psRxMsg[10] == APTS_RESET.......\n");
        reset_recd=1;
        WfaStaResetAll();
        return 0;
    }
    //If reset signal is there for the receiving thread and station has sent the
    //reset message (i.e. !reset_recd) then ignore all the messages till an
    //APTS_RESET_RESP has been received.

    if(resetrcv)
    {
        wmmps_info.rcv_state = 0;
        if((!reset_recd)&&(psRxMsg[10] != APTS_RESET_RESP))
            return 0;
        else
        {
            resetrcv = 0;
            reset_recd = 0;
        }
    }

    if(sta_test > LAST_TEST)
    {
        // unknown case
        return 0;
    }

    sta_test = wmmps_info.sta_test;
    wmmps_info.my_cookie = psRxMsg[0];
    rcv_state = &(wmmps_info.rcv_state);
    rcvstatarray = stationRecvProcStatetbl[sta_test];
    func = rcvstatarray[*(rcv_state)];
    func.statefunc(psRxMsg,rbytes,rcv_state);

    return WFA_SUCCESS;
}
