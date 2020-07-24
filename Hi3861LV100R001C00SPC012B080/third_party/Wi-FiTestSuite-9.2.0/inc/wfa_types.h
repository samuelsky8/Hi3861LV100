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
 * wfa_types.h:
 *   Defines general types and enum
 */
#ifndef _WFA_TYPES_H
#define _WFA_TYPES_H

#include "hi_stdlib.h"
#include "los_typedef.h"

#define WFA_IF_NAME_LEN 16
#define WFA_VERSION_LEN 32
#define WFA_SSID_NAME_LEN 32
#define WFA_IP_ADDR_STR_LEN  40
#define WFA_IP_MASK_STR_LEN  16
#define WFA_MAX_DNS_NUM      2
#define WFA_MAC_ADDR_STR_LEN 6
#define WFA_PROGNAME_LEN 16
#define WFA_PASSWORD_MAX_LEN 64
#define WFA_11N_MCS_FIXEDRATE 16
#define WFA_TRAFFIC_COPY_BUFFER 18

#define WFA_CLI_CMD_RESP_LEN 128
#define WFA_P2P_DEVID_LEN 18
#define WFA_P2P_GRP_ID_LEN 128
#define WFA_WPS_PIN_LEN 256
#define WFA_PSK_PP_LEN  256

#define WFA_WFD_SESSION_ID_LEN 64
#define WFA_EVT_ACTION_LEN 8

#define WFA_SPATIAL_RX_STREAM_LEN 16
#define WFA_SPATIAL_TX_STREAM_LEN 16
#define WFA_WIDTH_LEN 8
#define WFA_STBC_TX_LEN 32
#define WFA_BCNINT_LEN 8
#define WFA_CHANNEL_USAGE_LEN 16
#define WFA_DOMAIN_LEN 8
#define WFA_REGULAR_MODE_LEN 16
#define WFA_COUNTRY_CODE_LEN 16
#define WFA_NSS_MCS_CAP_LEN 16

#define WFA_KEYMGNT_LEN 16
#define WFA_PSK_LEN 16
#define WFA_WEPKEY_LEN 16
#define WFA_ENCRYPT_LEN 8

#define WFA_HW_INTF_LEN 16

#define WFA_PASSWORD_LEN 32
#define WFA_DEVICE_TYPE_LEN 16

#define WFA_AGENT_VER_LEN 32
#define WFA_FIRMWARE_VER_LEN 32

#define WFA_FRAME_LEN 16
#define WFA_FRAME_TYPE_LEN 16

#define WFA_RANDINT_LEN 32
#define WFA_MEAMODE_LEN 8
#define WFA_BSSID_LEN 64
#define WFA_APCHANRPT_LEN 32
#define WFA_REQINFO_LEN 32

#define WFA_INFOURL_LEN 128
#define WFA_CANDIDATE_LIST_LEN 128
#define IF_80211   1
#define IF_ETH     2

//³ÌÐòÔËÐÐ×´Ì¬
#define WFA_OK 0
#define WFA_FAILED 1

/* WMM-AC APSD defines*/
#ifdef WFA_WMM_AC
#define DIR_NONE  0
#define DIR_UP    1
#define DIR_DOWN  2
#define DIR_BIDIR 3
#endif

#ifndef NULL
#define NULL 0
#endif

typedef unsigned short WORD;
typedef unsigned char BYTE;

enum _response_staus
{
    STATUS_RUNNING = 0x0001,
    STATUS_INVALID = 0x0002,
    STATUS_ERROR = 0x0003,
    STATUS_COMPLETE = 0x0004,
};

#ifndef    TRUE
#define    FALSE       -1
#define    TRUE        0
#define    DONE        1
#endif
#define    DONE        1

#define WFA_SUCCESS 0
#define WFA_FAILURE 1
#define WFA_ERROR -1

/*
typedef enum returnTypes
{
   WFA_SUCCESS = 0,
   WFA_FAILURE = 1,
   WFA_ERROR = -1,
} retType_t;
*/

#define WFA_ENABLED 1
enum wfa_state
{
   WFA_DISABLED = 0,
   WFA_OPTIONAL = 1,
   WFA_REQUIRED = 2,
   WFA_F_REQUIRED = 3,            /* forced required */
   WFA_F_DISABLED = 4,            /* forced disabled */
   WFA_INVALID_BOOL = 0xFF
};

#endif
