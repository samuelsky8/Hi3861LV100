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
 * wfa_cmds.h:
 *   definitions of command types.
 */
#ifndef _WFA_CMDS_H
#define _WFA_CMDS_H

typedef struct _tg_ping_start
{
    char dipaddr[IPV6_ADDRESS_STRING_LEN];  /* destination/remote ip address */
    int  frameSize;
    int  frameRate;
    int  duration;
    int  iptype;
} tgPingStart_t;

typedef struct ca_sta_set_ip_config
{
    char intf[WFA_IF_NAME_LEN];
    int isDhcp;
    char ipaddr[WFA_IP_ADDR_STR_LEN];
    char mask[WFA_IP_MASK_STR_LEN];
    char defGateway[WFA_IP_ADDR_STR_LEN];
    char pri_dns[WFA_IP_ADDR_STR_LEN];
    char sec_dns[WFA_IP_ADDR_STR_LEN];
    int type;
} caStaSetIpConfig_t;

typedef struct ca_sta_verify_ip_connection
{
    char dipaddr[WFA_IP_ADDR_STR_LEN];
    int timeout;
} caStaVerifyIpConnect_t;

typedef struct ca_sta_set_encryption
{
    char intf[WFA_IF_NAME_LEN];
    char ssid[WFA_SSID_NAME_LEN];
    int encpType;
    char keys[4][32];  /* 26 hex */
    int activeKeyIdx;
} caStaSetEncryption_t;

typedef enum wfa_enableType
{
    eEnable = 1,
    eDisable
} wfaEnableType;

typedef struct ca_sta_set_mode
{
    char intf[WFA_IF_NAME_LEN];
    char ssid[WFA_SSID_NAME_LEN];
    char mode;
    int encpType;
    int channel;
    char keys[4][32];  /* 26 hex */
    int activeKeyIdx;
} caStaSetMode_t;

typedef struct ca_sta_set_psk
{
   char intf[WFA_IF_NAME_LEN];
   char ssid[WFA_SSID_NAME_LEN];
   char passphrase[64];
   char keyMgmtType[16];  /* WPA-PSK */
   int  encpType;         /* TKIP    */
   BOOL pmf;              /* PMF enable or disable */
   char micAlg[16];
   char prog[16];
   BOOL perfer;
} caStaSetPSK_t;

typedef struct ca_sta_set_eaptls
{
   char username[32];
   char password[16];
   char trustedRootCA[32];
} caStaSetEapTLS_t;

typedef struct ca_sta_set_eapttls
{
   char username[32];
   char password[16];
   char trustedRootCA[32];
} caStaSetEapTTLS_t;

typedef struct ca_sta_set_eapsim
{
    char username[32];
    char password[16];
} caStaSetEapSIM_t;

typedef struct ca_sta_set_eappeap
{
   char username[32];
   char password[16];
   char trustedRootCA[32];
   char innerEAP[16];
   int peapVersion;
} caStaSetEapPEAP_t;

typedef struct ca_sta_set_eapfast
{
   char username[32];
   char password[16];
   char trustedRootCA[32];
   char innerEAP[16];
   char validateServer[8];
   char pacfile[8];
} caStaSetEapFAST_t;

typedef struct ca_sta_set_eapaka
{
   char intf[WFA_IF_NAME_LEN];
   char ssid[WFA_SSID_NAME_LEN];
   char username[32];
   char passwd[96];
   char keyMgmtType[8];
   char encrptype[9];
   char tripletCount;
   char tripletSet[3][96];
   int pmf;               /* PMF enable or disable */
} caStaSetEapAKA_t;


enum sectype {
    SEC_TYPE_PSK = 1,
    SEC_TYPE_EAPTLS,
    SEC_TYPE_EAPTTLS,
    SEC_TYPE_EAPPEAP,
    SEC_TYPE_EAPSIM,
    SEC_TYPE_EAPFAST,
    SEC_TYPE_EAPAKA,
};

typedef struct ca_sta_set_security
{
   char type[16]; /* PSK, EAPx */
   char intf[16];
   char ssid[WFA_SSID_NAME_LEN];
   char keyMgmtType[8];
   char encpType[9];
   char pmf[16];
   char micaig[8];
} caStaSetSecurity_t;

typedef struct ca_sta_set_systime
{
    BYTE month;
    BYTE date;
    WORD year;
    BYTE hours;
    BYTE minutes;
    BYTE seconds;
} caStaSetSystime_t;


/* DEV_SEND_FRAME  related definitions    */
/*  DEV_SEND_FRAME    PMF   */
enum
{
    PMF_TYPE_DISASSOC = 1,
    PMF_TYPE_DEAUTH,
    PMF_TYPE_SAQUERY,
    PMF_TYPE_AUTH,
    PMF_TYPE_ASSOCREQ,
    PMF_TYPE_REASSOCREQ,
};

enum
{
    PMF_PROT_CORRECTKEY = 1,
    PMF_PROT_INCORRECTKEY,
    PMF_PROT_UNPROTECTED,
};

typedef struct pmf_frame
{
    BYTE eFrameName;
    BYTE eProtected;
    char staid[WFA_MAC_ADDR_STR_LEN]; /* sta mac addr */
    /* optional   */
    unsigned char sender_flag;
    char sender[8]; /* ap or sta */

    unsigned char bssid_flag;
    char bssid[WFA_MAC_ADDR_STR_LEN]; /* ap mac addr */


} pmfFrame_t;

/*   DEV_SEND_FRAME     TDLS  */
enum
{
    TDLS_TYPE_DISCOVERY = 1,
    TDLS_TYPE_SETUP,
    TDLS_TYPE_TEARDOWN,
    TDLS_TYPE_CHANNELSWITCH,
    TDLS_TYPE_NULLFRAME,
};

typedef struct tdls_frame
{
    BYTE eFrameName;
    char peer[WFA_MAC_ADDR_STR_LEN];
    /*  optional in the following  */
    unsigned char timeout_flag;
    int timeout;
    unsigned char switchtime_flag;
    int switchtime;
    unsigned char channel_flag;
    int channel;
    unsigned char offset_flag;
    char offset[4]; /* 20 or 40 Mhz */
    unsigned char status_flag;
    int status;     /* status code */
    unsigned char reason_flag;
    int reason;     /* reason code */
    unsigned char bssid_flag;
    char bssid[WFA_MAC_ADDR_STR_LEN];
} tdlsFrame_t;


/*  DEV_SEND_FRAME    VENT, voice ent   */
enum
{
    VENT_TYPE_NEIGREQ = 1,
    VENT_TYPE_TRANSMGMT,
};

typedef struct vent_frame
{
    BYTE type;
    char ssid[WFA_SSID_NAME_LEN];
} ventFrame_t;


/*  DEV_SEND_FRAME    WFD    */
enum
{
    WFD_FRAME_PRBREQ=1,
    WFD_FRAME_RTSP,
    WFD_FRAME_SERVDISC_REQ,
    WFD_FRAME_PRBREQ_TDLS_REQ,
    WFD_FRAME_11V_TIMING_MSR_REQ,
};

enum
{
    WFD_DEV_TYPE_SOURCE=1,
    WFD_DEV_TYPE_PSINK,
    WFD_DEV_TYPE_SSINK,

};

enum
{
    WFD_RTSP_PAUSE=1,
    WFD_RTSP_PLAY,
    WFD_RTSP_TEARDOWN,
    WFD_RTSP_TRIG_PAUSE,
    WFD_RTSP_TRIG_PLAY,
    WFD_RTSP_TRIG_TEARDOWN,
    WFD_RTSP_SET_PARAMETER,

};

enum setParamsTypes
{
    WFD_CAP_UIBC_KEYBOARD=1,
    WFD_CAP_UIBC_MOUSE=1,
    WFD_CAP_RE_NEGO,
    WFD_STANDBY,
    WFD_UIBC_SETTINGS_ENABLE,
    WFD_UIBC_SETTINGS_DISABLE,
    WFD_ROUTE_AUDIO,
    WFD_3D_VIDEOPARAM,
    WFD_2D_VIDEOPARAM,
};


typedef struct wfd_frame
{
    BYTE eframe;
    char sa[WFA_MAC_ADDR_STR_LEN];
    char da[WFA_MAC_ADDR_STR_LEN];
    /*  followings are optional  */
    unsigned char devtype_flag;
    BYTE eDevType;
    unsigned char rtspmsg_flag;
    BYTE eRtspMsgType;
    unsigned char wfdsessionid_flag;
    char wfdSessionID[WFA_WFD_SESSION_ID_LEN];
    unsigned char setparm_flag;
    int	eSetParams;
    unsigned char audioDest_flag;
    int	eAudioDest;
    unsigned char bssid_flag;
    char bssid[WFA_MAC_ADDR_STR_LEN];
    unsigned char msrReqAction_flag;
    int  eMsrAction;
    unsigned char capReNego_flag;
    int  ecapReNego;


} wfdFrame_t;

enum {
    PROG_TYPE_GEN = 1,
    PROG_TYPE_PMF,
    PROG_TYPE_TDLS,
    PROG_TYPE_VENT,
    PROG_TYPE_WFD,
    PROG_TYPE_NAN,
};

typedef struct ca_sta_dev_sendframe
{
   BYTE program;
   union _frametype
   {
       pmfFrame_t pmf;
       tdlsFrame_t tdls;
       ventFrame_t vent;
       wfdFrame_t wfd;
   } frameType;
} caStaDevSendFrame_t;

typedef struct ca_sta_start_wfd_conn
{
    char intf[WFA_IF_NAME_LEN];
    BYTE peer_count;
    char peer[2][WFA_P2P_DEVID_LEN];
    unsigned char init_wfd_flag;
    BYTE init_wfd;
    unsigned char intent_val_flag;
    BYTE intent_val;
    unsigned char oper_chn_flag;
    WORD oper_chn;
    unsigned char coupledSession_flag;
    WORD coupledSession;
} caStaStartWfdConn_t;

typedef struct ca_sta_connect_go_start_wfd
{
    char intf[WFA_IF_NAME_LEN];
    char grpid[WFA_P2P_GRP_ID_LEN];
    char devId[WFA_P2P_DEVID_LEN];
} caStaConnectGoStartWfd_t;

enum
{
    eInvitationSend = 1,
    eInvitationAccept,
};

typedef struct ca_sta_reinvoke_wfd_session
{
    char intf[WFA_IF_NAME_LEN];
    unsigned char grpid_flag;
    char grpid[WFA_P2P_GRP_ID_LEN];
    char peer[WFA_MAC_ADDR_STR_LEN];
    BYTE wfdInvitationAction;
} caStaReinvokeWfdSession_t;

enum {
   eDiscoveredDevList = 1,
   eMasterPref,
};

typedef struct ca_sta_get_parameter
{
   char intf[WFA_IF_NAME_LEN];
   BYTE program;
   BYTE getParamValue;
} caStaGetParameter_t;


enum {
    eUibcGen = 1,
    eUibcHid,
    eFrameSkip,
    eInputContent,
    eI2cRead,
    eI2cWrite,
    eIdrReq,
};

enum {
    eSingleTouchEvent = 1,
    eMultiTouchEvent,
    eKeyBoardEvent,
    eMouseEvent,
    eBtEvent,
};

enum {
    eProtected = 1,
    eUnprotected,
    eProtectedVideoOnly,
};

enum event {
    eDiscoveryResult = 1,
    eReplied,
    ePublishTerminated,
    eSubscribeTerminated,
    eFollowUpReceive,
};

enum method {
    ePublish = 1,
    eSubscribe,
    eFollowUp,
};

enum methodtype {
    eUnsolicited = 1,
    eSolicited,
    eActive,
    ePassive,
    eCancel,
};

typedef struct wfd_generate_event
{
    BYTE type;
    BYTE wfdSessionIdflag;
    char wfdSessionID[WFA_WFD_SESSION_ID_LEN];
    BYTE wfdUibcEventTypeflag;
    BYTE wfdUibcEventType;
    BYTE wfdUibcEventPrepareflag;
    BYTE wfdUibcEventPrepare;
    BYTE wfdFrameSkipRateflag;
    BYTE wfdInputContentTypeflag;
    BYTE wfdInputContentType;
    BYTE wfdI2cDataflag;
    char wfdI2cData[32];

} caWfdStaGenEvent_t;


typedef struct ca_sta_generate_event
{
    char intf[WFA_IF_NAME_LEN];
    BYTE program;
    caWfdStaGenEvent_t wfdEvent;
} caStaGenEvent_t;


//#ifdef WFA_STA_TB
typedef enum wfa_supplicant_names
{
    eWindowsZeroConfig = 1,
    eMarvell,
    eIntelProset,
    eWpaSupplicant,
    eCiscoSecureClient,
    eOpen1x,
    eDefault
} wfaSupplicantName;

typedef struct ca_sta_set_p2p
{
    char intf[WFA_IF_NAME_LEN];

    unsigned char listen_chn_flag;
    WORD listen_chn;

    unsigned char p2p_mode_flag;
    char p2p_mode[16];

    unsigned char presistent_flag;
    int presistent;

    unsigned char intra_bss_flag;
    int intra_bss;

    unsigned char noa_duration_flag;
    int noa_duration;

    unsigned char noa_interval_flag;
    int noa_interval;

    unsigned char noa_count_flag;
    int noa_count;

    unsigned char concurrency_flag;
    int concurrency;

    unsigned char p2p_invitation_flag;
    int p2p_invitation;

    unsigned char bcn_int_flag;
    int bcn_int;

    unsigned char ext_listen_time_int_flag;
    int ext_listen_time_int;

    unsigned char ext_listen_time_period_flag;
    int ext_listen_time_period;

    unsigned char discoverability_flag;
    int discoverability;


    unsigned char service_discovry_flag;
    int service_discovery;

    unsigned char crossconnection_flag;
    int crossconnection;

    unsigned char p2pmanaged_flag;
    int p2pmanaged;

    unsigned char go_apsd_flag;
    int go_apsd;

    unsigned char discover_type_flag;
    int discoverType;

} caStaSetP2p_t;

typedef struct ca_sta_p2p_connect
{
    char intf[WFA_IF_NAME_LEN];

    char grpid[WFA_P2P_GRP_ID_LEN];
    char devId[WFA_P2P_DEVID_LEN];
} caStaP2pConnect_t;

typedef struct ca_sta_start_auto_go
{
    char intf[WFA_IF_NAME_LEN];
    WORD oper_chn;
    unsigned char ssid_flag;
    char ssid[WFA_SSID_NAME_LEN];
    unsigned char rtsp_flag;
    WORD rtsp;

} caStaStartAutoGo_t;


typedef struct ca_sta_p2p_start_grp_formation
{
    char intf[WFA_IF_NAME_LEN];
    char devId[WFA_P2P_DEVID_LEN];
    WORD intent_val;
    WORD init_go_neg;
    unsigned char oper_chn_flag;
    WORD oper_chn;
    unsigned char ssid_flag;
    char ssid[WFA_SSID_NAME_LEN];
} caStaP2pStartGrpForm_t;

typedef struct ca_sta_p2p_dissolve
{
    char intf[WFA_IF_NAME_LEN];
    char grpId[WFA_P2P_GRP_ID_LEN];
} caStaP2pDissolve_t;

typedef struct ca_sta_send_p2p_inv_req
{
    char intf[WFA_IF_NAME_LEN];
    char devId[WFA_P2P_DEVID_LEN];
    char grpId[WFA_P2P_GRP_ID_LEN];
    int reinvoke;
} caStaSendP2pInvReq_t;

typedef struct ca_sta_accept_p2p_inv_req
{
    char intf[WFA_IF_NAME_LEN];
    char devId[WFA_P2P_DEVID_LEN];
    char grpId[WFA_P2P_GRP_ID_LEN];
    int reinvoke;
} caStaAcceptP2pInvReq_t;


typedef struct ca_sta_send_p2p_prov_dis_req
{
    char intf[WFA_IF_NAME_LEN];
    char confMethod[16];
    char devId[WFA_P2P_DEVID_LEN];
} caStaSendP2pProvDisReq_t;

typedef struct ca_sta_set_wps_pbc
{
    char intf[WFA_IF_NAME_LEN];
    unsigned char grpid_flag;
    char grpId[WFA_P2P_GRP_ID_LEN];
} caStaSetWpsPbc_t;

typedef struct ca_sta_wps_read_pin
{
    char intf[WFA_IF_NAME_LEN];
    unsigned char grpid_flag;
    char grpId[WFA_P2P_GRP_ID_LEN];
} caStaWpsReadPin_t;

typedef struct ca_sta_wps_read_label
{
    char intf[WFA_IF_NAME_LEN];
    unsigned char grpid_flag;
    char grpId[WFA_P2P_GRP_ID_LEN];
} caStaWpsReadLabel_t;

typedef struct ca_sta_wps_enter_pin
{
    char intf[WFA_IF_NAME_LEN];
    char wpsPin[WFA_WPS_PIN_LEN];
    unsigned char grpid_flag;
    char grpId[WFA_P2P_GRP_ID_LEN];
} caStaWpsEnterPin_t;

typedef struct ca_sta_get_psk
{
    char intf[WFA_IF_NAME_LEN];
    char grpId[WFA_P2P_GRP_ID_LEN];
} caStaGetPsk_t;

typedef struct ca_sta_get_p2p_ip_config
{
    char intf[WFA_IF_NAME_LEN];
    char grpId[WFA_P2P_GRP_ID_LEN];
} caStaGetP2pIpConfig_t;

typedef struct ca_sta_send_service_discovery_req
{
    char intf[WFA_IF_NAME_LEN];
    char devId[WFA_P2P_DEVID_LEN];
} caStaSendServiceDiscoveryReq_t;

typedef struct ca_sta_send_p2p_presence_req
{
    char intf[WFA_IF_NAME_LEN];
    long long int duration;
    long long int interval;
} caStaSendP2pPresenceReq_t;

typedef struct ca_sta_add_arp_table_entry
{
    char intf[WFA_IF_NAME_LEN];
    char macaddress [WFA_MAC_ADDR_STR_LEN];
    char ipaddress [WFA_MAC_ADDR_STR_LEN];
} caStaAddARPTableEntry_t;

typedef struct ca_sta_block_icmp_reponse
{
    char intf[WFA_IF_NAME_LEN];
    char ipaddress [WFA_MAC_ADDR_STR_LEN];
    char grpId[WFA_P2P_GRP_ID_LEN];
} caStaBlockICMPResponse_t;


typedef struct ca_sta_set_sleep
{
    char intf[WFA_IF_NAME_LEN];
    char grpId[WFA_P2P_GRP_ID_LEN];
} caStaSetSleep_t;

typedef struct ca_sta_set_opportunistic_ps
{
    char intf[WFA_IF_NAME_LEN];
    int ctwindow;
    char grpId[WFA_P2P_GRP_ID_LEN];
} caStaSetOpprPs_t;

/* P2P */

typedef enum wfa_preambleType
{
    eLong = 1,
    eShort
} wfaPreambleType;

typedef enum wfa_WirelessMode
{
    eModeB = 1,
    eModeBG,
    eModeA,
    eModeABG,
    eModeAN,
    eModeGN,
    eModeNL,
    eModeAC,
} wfaWirelessMode;

typedef enum wfa_reset_prog
{
    eResetProg11n =1,
} wfaResetProg;

typedef enum wfa_tdlsMode
{
    eDef = 0,
    eHiLoMac = 1,
    eExistLink,
    eAPProhibit,
    eWeakSec,
    eIgnChnlSWProh,  /* if it is present, ignore channel switch prohibit */
} wfaTDLSMode;

typedef enum wfa_wfdDevType
{
    eSource = 1,
    ePSink,
    eSSink,
    eDual,
} wfaWfdDevType;

typedef enum wfa_UiInput
{
    eKeyBoard = 1,
    eMouse,
    eBt,
    eJoyStick,
    eSingleTouch,
    eMultiTouch,
} wfaUiInput;

typedef enum wfa_AudioModes
{
    eMandatoryAudioMode = 1,
    eDefaultAudioMode,
} wfaAudioModes;




typedef enum wfa_VideoFormats
{
    eCEA = 1,
    e640x480p60,
    e720x480p60,
    e20x480i60,
    e720x576p50,
    e720x576i50,
    e1280x720p30,
    e1280x720p60,
    e1920x1080p30,
    e1920x1080p60,
    e1920x1080i60,
    e1280x720p25,
    e1280x720p50,
    e1920x1080p25,
    e1920x1080p50,
    e1920x1080i50,
    e1280x720p24,
    e1920x1080p24,

    eVesa,
    e800x600p30,
    e800x600p60,
    e1024x768p30,
    e1024x768p60,
    e1152x864p30,
    e1152x864p60,
    e1280x768p30,
    e1280x768p60,
    e1280x800p30,
    e1280x800p60,
    e1360x768p30,
    e1360x768p60,
    e1366x768p30,
    e1366x768p60,
    e1280x1024p30,
    e1280x1024p60,
    e1400x1050p30,
    e1400x1050p60,
    e1440x900p30,
    e1440x900p60,
    e1600x900p30,
    e1600x900p60,
    e1600x1200p30,
    e1600x1200p60,
    e1680x1024p30,
    e1680x1024p60,
    e1680x1050p30,
    e1680x1050p60,
    e1920x1200p30,
    e1920x1200p60,

    eHH,
    e800x480p30,
    e800x480p60,
    e854x480p30,
    e854x480p60,
    e864x480p30,
    e864x480p60,
    e640x360p30,
    e640x360p60,
    e960x540p30,
    e960x540p60,
    e848x480p30,
    e848x480p60,
} wfavideoFormats;



typedef struct ca_sta_preset_parameters
{
    char intf[WFA_IF_NAME_LEN];
    wfaSupplicantName supplicant;

    BYTE programFlag;
    WORD program;


    BYTE rtsFlag;
    WORD rtsThreshold;
    BYTE fragFlag;
    WORD fragThreshold;
    BYTE preambleFlag;
    wfaPreambleType preamble;
    BYTE modeFlag;
    wfaWirelessMode wirelessMode;
    BYTE psFlag;
    BYTE legacyPowerSave;
    BYTE wmmFlag;
    BYTE wmmState;
    BYTE reset;
    BYTE ht;    // temperary for high throughput
    BYTE ftoa;
    BYTE ftds;
    BYTE activescan;
    WORD oper_chn;
    BYTE tdls;
    BYTE tdlsMode;

    BYTE tdlsFlag;

   BYTE wfdDevTypeFlag;
   BYTE wfdDevType ;
   BYTE wfdUibcGenFlag;
   BYTE wfdUibcGen ;
   BYTE wfdUibcHidFlag;
   BYTE wfdUibcHid ;
   BYTE wfdUiInputFlag;
   BYTE wfdUiInputs ;
   BYTE wfdUiInput[3] ;
   BYTE wfdHdcpFlag;
   BYTE wfdHdcp ;
   BYTE wfdFrameSkipFlag;
   BYTE wfdFrameSkip ;
   BYTE wfdAvChangeFlag;
   BYTE wfdAvChange ;
   BYTE wfdStandByFlag;
   BYTE wfdStandBy ;
   BYTE wfdInVideoFlag;
   BYTE wfdInVideo ;
   BYTE wfdVideoFmatFlag;
   BYTE wfdInputVideoFmats;
   BYTE wfdVideoFmt[64];
   BYTE wfdAudioFmatFlag;
   BYTE wfdAudioFmt ;
   BYTE wfdI2cFlag;
   BYTE wfdI2c ;
   BYTE wfdVideoRecoveryFlag;
   BYTE wfdVideoRecovery ;
   BYTE wfdPrefDisplayFlag;
   BYTE wfdPrefDisplay ;
   BYTE wfdServiceDiscoveryFlag;
   BYTE wfdServiceDiscovery ;
   BYTE wfd3dVideoFlag;
   BYTE wfd3dVideo ;
   BYTE wfdMultiTxStreamFlag;
   BYTE wfdMultiTxStream ;
   BYTE wfdTimeSyncFlag;
   BYTE wfdTimeSync ;
   BYTE wfdEDIDFlag;
   BYTE wfdEDID ;
   BYTE wfdUIBCPrepareFlag;
   BYTE wfdUIBCPrepare ;
   BYTE wfdCoupledCapFlag;
   BYTE wfdCoupledCap ;
   BYTE wfdOptionalFeatureFlag;
   BYTE wfdSessionAvail ;
   BYTE wfdSessionAvailFlag;
   BYTE wfdDeviceDiscoverability ;
   BYTE wfdDeviceDiscoverabilityFlag;
} caStaPresetParameters_t;

typedef struct ca_sta_set_11n
{
    char intf[WFA_IF_NAME_LEN];
    BOOL _40_intolerant;
    BOOL addba_reject;
    BOOL ampdu;
    BOOL amsdu;
    BOOL greenfield;
    BOOL sgi20;
    unsigned short stbc_rx;
    unsigned short smps;
    char width[8];
   char mcs_fixedrate[WFA_11N_MCS_FIXEDRATE];
    BOOL mcs32;
    BOOL rifs_test;
    unsigned char txsp_stream;
    unsigned char rxsp_stream;
} caSta11n_t;

typedef struct ca_sta_set_wireless
{
    char intf[WFA_IF_NAME_LEN];
    char program[WFA_PROGNAME_LEN];
    char band [8];
#define NOACK_BE       0
#define NOACK_BK       1
#define NOACK_VI       2
#define NOACK_VO       3
    unsigned char noAck[4];
} caStaSetWireless_t;


typedef struct ca_sta_send_addba
{
    char intf[WFA_IF_NAME_LEN];
    unsigned short tid;
   char destMac[WFA_MAC_ADDR_STR_LEN];
} caStaSetSendADDBA_t;

typedef struct ca_sta_set_rifs
{
    char intf [WFA_IF_NAME_LEN];
    unsigned int action;

} caStaSetRIFS_t;

typedef struct ca_sta_send_coexist_mgmt
{
    char intf[WFA_IF_NAME_LEN];
    char type[16];
    char value[16];
} caStaSendCoExistMGMT_t;
//#endif

typedef struct ca_sta_set_uapsd
{
    char intf[WFA_IF_NAME_LEN];
    char ssid[WFA_SSID_NAME_LEN];
    int maxSPLength;
    BYTE acBE;
    BYTE acBK;
    BYTE acVI;
    BYTE acVO;
//   int  type;
//   char peer[18];
} caStaSetUAPSD_t;

typedef struct ca_sta_set_ibss
{
    char intf[WFA_IF_NAME_LEN];
    char ssid[WFA_SSID_NAME_LEN];
    int channel;
    int encpType;
    char keys[4][32];
    int activeKeyIdx;
} caStaSetIBSS_t;

typedef struct sta_upload
{
    int type;
    int next;     /* sequence number, 0 is the last one */
} caStaUpload_t;

typedef struct sta_debug_set
{
    unsigned short level;
    unsigned short state;
} staDebugSet_t;
typedef struct config
{
    BYTE wmm;
    int  rts_thr ;
    int  frag_thr ;
} wmmconf_t;

typedef struct wmm_tsinfo
{
    unsigned int Reserved1 :1;
    unsigned int TID       :4;
    unsigned int direction :2;
    unsigned int dummy1    :1;
    unsigned int dummy2    :1;
    unsigned int Reserved2 :1;
    unsigned int PSB       :1;
    unsigned int UP        :3;
    unsigned int infoAck   :2;
    unsigned int Reserved4 :1;
    unsigned int Reserved5 :6;
    unsigned int bstSzDef :1;
} wmmtsinfo_t;

typedef struct wmm_tspec
{
    wmmtsinfo_t      tsinfo;
    BOOL Fixed;//The MSDU Fixed Bit
    unsigned short size;//The MSDU Size
    unsigned short maxsize;//Maximum MSDU Size
    unsigned int   min_srvc;//The minimum Service Interval
    unsigned int   max_srvc;//The maximum Service Interval
    unsigned int inactivity;//Inactivity Interval
    unsigned int suspension;//The Suspension Interval
    unsigned int srvc_strt_tim;//The Service Start Time
    unsigned int mindatarate;//The Minimum Data Rate
    unsigned int meandatarate;//The Minimum Data Rate
    unsigned int peakdatarate;//The Minimum Data Rate
    unsigned int burstsize;//The Maximum Burst Size
    unsigned int delaybound;//The Delay Bound
    unsigned int PHYrate;//The minimum PHY Rate
    float sba;//The Surplus Bandwidth Allownce
    unsigned short medium_time;//The medium time
} wmmtspec_t;

typedef struct wmmac_addts
{
    BYTE       dialog_token;
    BYTE       accesscat;
    wmmtspec_t tspec;
} wmmacadd_t;

typedef struct ca_sta_set_wmm
{
    char intf[WFA_IF_NAME_LEN];
    BYTE group;
    BYTE action;
#ifdef WFA_WMM_AC
    BYTE       send_trig;
    char       dipaddr[WFA_IP_ADDR_STR_LEN];
    BYTE       trig_ac;
#endif

    union _action
    {
        wmmconf_t   config;
        wmmacadd_t  addts;
        BYTE        delts;
    } actions;
} caStaSetWMM_t;

typedef struct ca_sta_reset_default
{
    char intf[WFA_IF_NAME_LEN];
    char prog[8];
    char type[8];
} caStaResetDefault_t;

typedef struct ca_dev_info
{
    BYTE fw;
} caDevInfo_t;

typedef struct ca_sta_associate
{
    char ssid[WFA_SSID_NAME_LEN];
    char bssid[18];
    unsigned char wps;
} caStaAssociate_t;

typedef enum wfa_onoffType
{
    WFA_OFF = 0,
    WFA_ON = 1,
} wfaOnOffType;

typedef struct ca_sta_set_radio
{
    wfaOnOffType mode;
} caStaSetRadio_t;

typedef struct ca_sta_rfeature
{
    char prog[8];
    wfaEnableType uapsd;
    char peer[18]; /* peer mac addr */
    wfaEnableType tpktimer;
} caStaRFeat_t;

typedef struct ca_sta_exec_action
{
   char intf[WFA_IF_NAME_LEN];
   BYTE prog;
   char nanOp[8];
   char masterPref[8];
   char randFactor[8];
   char hopCount[8];
   char highTsf[8];
   char methodType[16];
   char furtherAvailInd[8];
   char mac[18];
   char band[8];
   unsigned short fiveGHzOnly;
   char publishType[16];
   char subscribeType[16];
   char serviceName[64];
   unsigned short sdfTxDw;
   unsigned short sdfDelay;
   char rxMatchFilter[64];
   char txMatchFilter[64];
   unsigned short discRangeLtd;
   unsigned short discRangeIgnore;
   unsigned short includeBit;
   unsigned short srfType;
   unsigned int remoteInstanceID;
   unsigned int localInstanceID;   
} caStaExecAction_t;

typedef struct ca_sta_get_events
{
    char intf[WFA_IF_NAME_LEN];
    BYTE program;
    char action[8];
} caStaGetEvents_t;

typedef struct dut_commands
{
    char intf[WFA_IF_NAME_LEN];
    union _cmds
    {
        int streamId;
        int iftype;
        tgProfile_t profile;
        tgPingStart_t startPing;
        char resetProg[16];
        char macaddr[18];
        caStaAssociate_t assoc;
        char ssid[WFA_SSID_NAME_LEN];
        caStaSetIpConfig_t ipconfig;
        caStaVerifyIpConnect_t verifyIp;
        caStaSetEncryption_t wep;
        caStaSetPSK_t        psk;
        caStaSetEapTLS_t     tls;
        caStaSetEapTTLS_t    ttls;
        caStaSetEapSIM_t     sim;
        caStaSetEapPEAP_t    peap;
        caStaSetEapAKA_t     aka;
        caStaSetEapFAST_t    fast;
        caStaSetSecurity_t   setsec;
        caStaSetUAPSD_t      uapsd;
        caStaSetIBSS_t       ibss;
        caStaUpload_t        upload;
        caStaSetWMM_t        setwmm;
        staDebugSet_t        dbg;
        caDevInfo_t          dev;
        caStaDevSendFrame_t     sf;
        caStaSetRadio_t      sr;
        caStaRFeat_t         rfeat;
	   caStaExecAction_t	sact;
	   caStaGetEvents_t		sevts;
    } cmdsu;
} dutCommand_t;

typedef struct general_args
{
    char intf[WFA_IF_NAME_LEN];
    char ssid[WFA_SSID_NAME_LEN];
    unsigned short channel;
    char mode[8];
    char wme[8];
    char wmmps[8];
    unsigned short rts;
    unsigned short frgmnt;
    char pwrSave[8];
    BOOL _40_intolerant;
    BOOL greenfield;
    unsigned short mcsFixedRate;
    char spatialRxStream[WFA_SPATIAL_RX_STREAM_LEN];
    char spatialTxStream[WFA_SPATIAL_TX_STREAM_LEN];
    char width[WFA_WIDTH_LEN];
    BOOL addba_reject;
    BOOL ampdu;
    unsigned short ampduExp;
    BOOL amsdu;
    BOOL offset;
    BOOL mcs32;
    unsigned short mpduMinStartSpacing;
    BOOL rifsTest;
    BOOL sgi20;
    char stbcTx[WFA_STBC_TX_LEN];
    unsigned short widthScan;
    char bcnint[16];
    BOOL radio;
    BOOL p2pMgmtBit;
    char channelUsage[WFA_CHANNEL_USAGE_LEN];
    BOOL tdlsProhibit;
    BOOL tdlsChSwitchProhibit;
    BOOL rpm;
    BOOL neibrpt;
    BOOL ftOa;
    BOOL ftDs;
    char domain[WFA_DOMAIN_LEN];
    int pwrConst;
    int dtim;
    BOOL hs2;
    BOOL p2pCrossConnect;
    BOOL _4FramGas;
    char regularMode[WFA_REGULAR_MODE_LEN];
    char countryCode[WFA_COUNTRY_CODE_LEN];
    BOOL intf_flag;
    BOOL ssid_flag;
    BOOL channel_flag;
    BOOL mode_flag;
    BOOL wme_flag;
    BOOL wmmps_flag;
    BOOL rts_flag;
    BOOL frgmnt_flag;
    BOOL pwrSave_flag;
    BOOL _40_intolerant_flag;
    BOOL greenfield_flag;
    BOOL mcsFixedRate_flag;
    BOOL spatialRxStream_flag;
    BOOL spatialTxStream_flag;
    BOOL width_flag;
    BOOL addba_reject_flag;
    BOOL ampdu_flag;
    BOOL ampduExp_flag;
    BOOL amsdu_flag;
    BOOL offset_flag;
    BOOL mcs32_flag;
    BOOL mpduMinStartSpacing_flag;
    BOOL rifsTest_flag;
    BOOL sgi20_flag;
    BOOL stbcTx_flag;
    BOOL widthScan_flag;
    BOOL bcnint_flag;
    BOOL radio_flag;
    BOOL p2pMgmtBit_flag;
    BOOL channelUsage_flag;
    BOOL tdlsProhibit_flag;
    BOOL tdlsChSwitchProhibit_flag;
    BOOL rpm_flag;
    BOOL neibrpt_flag;
    BOOL ftOa_flag;
    BOOL ftDs_flag;
    BOOL domain_flag;
    BOOL pwrConst_flag;
    BOOL dtim_flag;
    BOOL hs2_flag;
    BOOL p2pCrossConnect_flag;
    BOOL _4FramGas_flag;
    BOOL regularMode_flag;
    BOOL countryCode_flag;
}generalArgs_t;

typedef struct vht_args
{
    char intf[WFA_IF_NAME_LEN];
    char ssid[WFA_SSID_NAME_LEN];
    int channel;
    char mode[8];
    BOOL wme;
    BOOL wmmps;
    unsigned short rts;
    unsigned short frgmnt;
    BOOL pwrSave;
    BOOL bcnint;
    BOOL radio;
    BOOL addba_reject;
    BOOL ampdu;
    unsigned short ampduExp;
    BOOL amsdu;
    BOOL offset;
    unsigned short mcsFixedRate;
    char spatialRxStream[16];
    char spatialTxStream[16];
    unsigned short mpduMinStartSpacing;
    BOOL rifsTest;
    BOOL sgi20;
    char stbcTx[WFA_STBC_TX_LEN];
    char width[8];
    unsigned short widthScan;
    char channelUsage[WFA_CHANNEL_USAGE_LEN];
    int dtim;
    BOOL dynBwSgnl;
    BOOL sgi80;
    BOOL txBf;
    BOOL ldpc;
    char nssMcsCap[WFA_NSS_MCS_CAP_LEN];
    int txLgiRate;
    BOOL spectrumMgt;
    BOOL vhtTkip;
    BOOL vhtWep;
    BOOL bwSgnl;
    BOOL htcVht;
    BOOL zeroCrc;
    char countryCode[WFA_COUNTRY_CODE_LEN];
    BOOL protectMode;
}vhtArgs_t;

typedef struct ca_ap_set_wireless
{
    char name[16];
//    char program[WFA_PROGNAME_LEN];
    union _arg
    {
        generalArgs_t args;
        vhtArgs_t vhtArgs;
    }programArgs;

}caApSetWireless_t;

typedef struct ap_set_security
{
    char name[16];
    char keyMgnt[WFA_KEYMGNT_LEN];
    char interface[WFA_HW_INTF_LEN];
    char pskType[WFA_PSK_LEN];
    char wepKey[WFA_WEPKEY_LEN];
    char ssid[WFA_SSID_NAME_LEN];
    unsigned int pmfReq;
    BOOL sha256ad;
    char encrypt[WFA_ENCRYPT_LEN];
    int lenth;
}apSetSetCurity_t;

typedef struct ap_set_pmf
{
    char interface[WFA_HW_INTF_LEN];
}apSetPmf_t;

typedef struct ap_set_apqos
{
    unsigned short cwmin;
    unsigned short cwmax;
    unsigned short aifs;
    unsigned short txop;
    BOOL acm;
    char interface[WFA_HW_INTF_LEN];
}apSetQos_t;

typedef struct ap_set_staqos
{
    unsigned short cwmin;
    unsigned short cwmax;
    unsigned short aifs;
    unsigned short txop;
    BOOL acm;
    char interface[WFA_HW_INTF_LEN];
}apSetStaqos_t;

typedef struct ap_set_radius
{
    char ipAddr[WFA_IP_ADDR_STR_LEN];
    unsigned short port;
    char password[WFA_PASSWORD_LEN];
    char interface[WFA_HW_INTF_LEN];
}apSetRadius_t;



typedef struct ap_set_rrm
{
    BOOL ece;
    BOOL ce;
    BOOL pce;
    BOOL tre;
    BOOL ble;
    BOOL bae;
    BOOL qte;
}apSetRrm_t;

typedef struct bcnrpt_req
{
    char destMac[WFA_MAC_ADDR_STR_LEN];
    unsigned short regClass;
    unsigned short channel;
    char randint[WFA_RANDINT_LEN];
    unsigned int meadur;
    char meaMode[WFA_MEAMODE_LEN];
    char bssid[WFA_BSSID_LEN];
    unsigned short rptCond;
    char ssid[WFA_SSID_NAME_LEN];
    BOOL rptDet;
    BOOL meaDurMand;
    char apChanRpt[WFA_APCHANRPT_LEN];
    char reqInfo[WFA_REQINFO_LEN];
}bcnrptReq_t;

typedef struct tsmrpt_req
{
    unsigned short repeatition;
    BOOL duration;
    char randint[WFA_RANDINT_LEN];
    char peerAddr[WFA_MAC_ADDR_STR_LEN];
    unsigned int tid;
    unsigned short brang;
    BOOL trigRpt;
    unsigned int avgErrThr;
    unsigned int conErrThr;
    unsigned int delMsduCnt;
    unsigned int trigTimeOut;
    unsigned short repeatitionNum;
    BOOL durationMand;
}tsmrptReq_t;

typedef struct bssTrnsMgmt_req
{
    unsigned int reqMode;
    unsigned int bssTermDur;
    char sessionInfoURL[WFA_INFOURL_LEN];
    char bssTransCandidateList[WFA_CANDIDATE_LIST_LEN];
}bssTrnsMgmtReq_t;

typedef struct ap_send_frame
{
    char frame[WFA_FRAME_LEN];
    char stationId[WFA_MAC_ADDR_STR_LEN];
    char type[WFA_FRAME_TYPE_LEN];
    char destAddr[WFA_MAC_ADDR_STR_LEN];
    unsigned int count;
    unsigned int interval;
    union frame_req
    {
        bcnrptReq_t bcnrpt;
        tsmrptReq_t tsmrpt;
        bssTrnsMgmtReq_t bssTrnsMgmt;
    }frameReq;
}apSendFrame_t;

typedef struct ap_send_addba_req
{
    char staMacAddress[WFA_MAC_ADDR_STR_LEN];
    unsigned int tid;

}apSendAddbaReq_t;

extern int buildCommandProcessTable(void);

typedef struct ap_deauth_sta
{
    char name[16];
    char intf[16];
    char stamacaddress[32];
    int minorcode;
}apdeauthsta_t;

typedef struct ca_ap_set_pmf
{
    char name[16];
    char intf[16];
    char pmf[32];
}apsetpmf_t;

typedef struct ca_sta_set_pwrsave
{
    char intf[16];
    char mode[4];
}stasetpwrsave_t;

typedef struct ca_ap_get_mac_address
{
    char interface[WFA_HW_INTF_LEN];
    char name[16];
    char macAddress[WFA_MAC_ADDR_STR_LEN];
}apgetmacaddress_t;


typedef struct ca_ap_ca_version
{
    char name[16];
    char version[64];
}ApCaVersion_t;

typedef struct ca_ap_reboot
{
    char name[16];
    int length;
}apRoot_t;

typedef struct ca_ap_config_commit
{
    char name[16];
}apConfigCommit_t;

typedef struct ap_reset_default
{
    char name[16];
    char program[WFA_PROGNAME_LEN];
    char interface[WFA_HW_INTF_LEN];
    char devType[WFA_DEVICE_TYPE_LEN];
    int lenth;
}apResetDefault_t;

typedef struct ap_get_info
{
    char name[16];
    char interface[WFA_HW_INTF_LEN];
    char agentVer[WFA_AGENT_VER_LEN];
    char firmwareVer[WFA_FIRMWARE_VER_LEN];
}apGetInfo_t;


#endif
