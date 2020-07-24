/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: WAL layer external API interface implementation.
 * Author: Hisilicon
 * Create: 2019-11-11
 */

/*****************************************************************************
  1 ͷ�ļ�����
*****************************************************************************/
#include "stdio.h"
#include "stdlib.h"
#include "hi_early_debug.h"
#include "hi_stdlib.h"
#include "hi_wifi_api.h"
#ifdef LOSCFG_APP_MESH
#include "hi_wifi_mesh_api.h"
#include "app_mesh_demo.h"
#endif
#include "at_wifi.h"
#include <hi_at.h>
#include "at_general.h"
#include "at.h"
#include "lwip/netifapi.h"
#include "hi_wifi_mfg_test_if.h" /* ���ļ���hi_wifi_mfg_test_if.h��ʹ�� */

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

hi_wifi_bw g_bw_setup_value = HI_WIFI_BW_LEGACY_20M;
#ifdef _PRE_PSK_CALC_USER
unsigned char g_psk_calc[HI_WIFI_STA_PSK_LEN] = {0};
#endif
hi_wifi_sta_psk_config g_set_psk_config = {.ssid = {0}, .key = {0}};

hi_u32 ssid_prefix_scan(hi_s32 argc, const hi_char *argv[], hi_u32 prefix_flag)
{
    hi_s32  ret;
    errno_t rc;
    char   *tmp = HI_NULL;
    size_t  ssid_len = 0;
    hi_wifi_scan_params scan_params = {0};

    if ((argc != 1) || (at_param_null_check(argc, argv) == HI_ERR_FAILURE)) {
        return HI_ERR_FAILURE;
    }

    /* get ssid */
    if (argv[0][0] == 'P') {
        if (strlen(argv[0]) > HI_WIFI_MAX_SSID_LEN * 4 + 3) { /* ssid length should less than 32*4+3 */
            return HI_ERR_FAILURE;
        }
    } else {
        if (strlen(argv[0]) > HI_WIFI_MAX_SSID_LEN + 2) { /* ssid length should less than 32+2 */
            return HI_ERR_FAILURE;
        }
    }
    /* ssid hex to string */
    tmp = at_parse_string(argv[0], &ssid_len);
    scan_params.ssid_len = (unsigned char)ssid_len;
    if (tmp == HI_NULL) {
        return HI_ERR_FAILURE;
    }
    if ((scan_params.ssid_len > HI_WIFI_MAX_SSID_LEN) || (scan_params.ssid_len == 0)) {
        at_free(tmp);
        return HI_ERR_FAILURE;
    }
    rc = memcpy_s(scan_params.ssid, HI_WIFI_MAX_SSID_LEN + 1, tmp, strlen(tmp) + 1);
    at_free(tmp);
    if (rc != EOK) {
        return HI_ERR_FAILURE;
    }

    scan_params.ssid[scan_params.ssid_len] = '\0';

    scan_params.scan_type = (prefix_flag == 1) ? HI_WIFI_SSID_PREFIX_SCAN : HI_WIFI_SSID_SCAN;

    ret = hi_wifi_sta_advance_scan(&scan_params);
    if (ret != HISI_OK) {
        return HI_ERR_FAILURE;
    }

    hi_at_printf("OK\r\n");
    return HI_ERR_SUCCESS;
}


/*****************************************************************************
* Func description: wpa ssid scan
*****************************************************************************/
hi_u32 cmd_wpa_ssid_scan(hi_s32 argc, const hi_char *argv[])
{
    hi_u32 ret = ssid_prefix_scan(argc, argv, 0);
    return ret;
}

/*****************************************************************************
* Func description: wpa  channel scan
*****************************************************************************/
hi_u32 cmd_wpa_channel_scan(hi_s32 argc, const hi_char *argv[])
{
    hi_s32 ret;
    hi_wifi_scan_params scan_params = {0};

    if ((argc != 1) || (integer_check(argv[0]) != HI_ERR_SUCCESS)) {
        return HI_ERR_FAILURE;
    }

    scan_params.channel = (hi_uchar)atoi(argv[0]);
    if ((scan_params.channel < 1) || (scan_params.channel > 14)) { /* �ŵ���Χ1~14 */
        return HI_ERR_FAILURE;
    }
    scan_params.scan_type = HI_WIFI_CHANNEL_SCAN;
    ret = hi_wifi_sta_advance_scan(&scan_params);
    if (ret != HISI_OK) {
        return HI_ERR_FAILURE;
    }

    hi_at_printf("OK\r\n");
    return HI_ERR_SUCCESS;
}

/*****************************************************************************
* Func description: wpa scan
*****************************************************************************/
hi_u32 cmd_wpa_scan(hi_s32 argc, const hi_char *argv[])
{
    hi_s32 ret;

    hi_unref_param(argc);
    hi_unref_param(argv);

    ret = hi_wifi_sta_scan();
    if (ret != HISI_OK) {
        return HI_ERR_FAILURE;
    }

    hi_at_printf("OK\r\n");
    return HI_ERR_SUCCESS;
}

/*****************************************************************************
* Func description: ssid prefix scan
* example: AT+SCANPRSSID="hisi"
*****************************************************************************/
hi_u32 cmd_ssid_prefix_scan(hi_s32 argc, const hi_char *argv[])
{
    hi_u32 ret = ssid_prefix_scan(argc, argv, 1);
    return ret;
}

hi_u32 at_check_ccharacter(const hi_char *tmp)
{
    if (tmp == HI_NULL) {
        return HI_ERR_FAILURE;
    }
    for (; *tmp != '\0'; tmp++) {
        if (*tmp == '\\') {
            if (*(tmp + 1) == '\\') {
                tmp++;
                continue;
            } else if (*(tmp + 1) == 'x') {
                return HI_ERR_SUCCESS;
            }
        }
    }
    return HI_ERR_FAILURE;
}

/*****************************************************************************
* Func description: wpa get scan results
*****************************************************************************/
hi_u32 cmd_wpa_scan_results(hi_s32 argc, const hi_char *argv[])
{
    hi_u32  num = WIFI_SCAN_AP_LIMIT ;
    hi_char ssid_str[HI_WIFI_MAX_SSID_LEN * 4 + 3]; /* ssid length should less 32*4+3 */

    hi_unref_param(argv);
    hi_unref_param(argc);

    hi_wifi_ap_info *results = malloc(sizeof(hi_wifi_ap_info) * WIFI_SCAN_AP_LIMIT);
    if (results == HI_NULL) {
        return HI_ERR_FAILURE;
    }

    /* ��ȫ��̹���6.6���⣨3���Ӷ��з����ڴ�󣬸����ֵ */
    memset_s(results, sizeof(hi_wifi_ap_info) * WIFI_SCAN_AP_LIMIT, 0, sizeof(hi_wifi_ap_info) * WIFI_SCAN_AP_LIMIT);

    hi_s32 ret = hi_wifi_sta_scan_results(results, &num);
    if (ret != HISI_OK) {
        free(results);
        return HI_ERR_FAILURE;
    }

    for (hi_u32 ul_loop = 0; (ul_loop < num) && (ul_loop < WIFI_SCAN_AP_LIMIT); ul_loop++) {
        if ((results[ul_loop].auth < HI_WIFI_SECURITY_OPEN) || (results[ul_loop].auth > HI_WIFI_SECURITY_UNKNOWN)) {
            results[ul_loop].auth = HI_WIFI_SECURITY_UNKNOWN;
        }

        hi_u32 auth_type = results[ul_loop].auth;
        hi_u32 service_flag = 0;
        if (results[ul_loop].wps_flag) {
            service_flag = 1;
        } else if (results[ul_loop].hisi_mesh_flag) {
            service_flag = 2; /* 2:Mesh���� */
        }

        size_t ssid_len = strlen(results[ul_loop].ssid);
        const char* tmp = at_ssid_txt((unsigned char*)results[ul_loop].ssid, ssid_len);
        if (at_check_ccharacter(tmp) == HI_ERR_SUCCESS) {
            ret = sprintf_s(ssid_str, HI_WIFI_MAX_SSID_LEN * 4 + 3, "P\"%s\"", tmp); /* ssid len should less 32*4+3 */
        } else {
            ret = sprintf_s(ssid_str, HI_WIFI_MAX_SSID_LEN * 4 + 3, "%s", results[ul_loop].ssid); /* less 32*4+3 */
        }
        if (ret < 0) {
            free(results);
            return HI_ERR_FAILURE;
        }

        if (service_flag != 0) {
            hi_at_printf("+SCANRESULT:%s,"AT_MACSTR",%d,%d,%d,%d\r\n", ssid_str, at_mac2str(results[ul_loop].bssid),
                results[ul_loop].channel, results[ul_loop].rssi / 100, auth_type, service_flag);
        } else {
            hi_at_printf("+SCANRESULT:%s,"AT_MACSTR",%d,%d,%d\r\n", ssid_str, at_mac2str(results[ul_loop].bssid),
                results[ul_loop].channel, results[ul_loop].rssi / 100, auth_type);
        }
    }

    free(results);

    hi_at_printf("OK\r\n");
    return HI_ERR_SUCCESS;
}

/*****************************************************************************
* Func description: start sta
*****************************************************************************/
hi_u32 cmd_sta_start(hi_s32 argc, const hi_char *argv[])
{
    hi_s32  ret;
    hi_s32  len = 0;
    hi_char ifname[WIFI_IFNAME_MAX_SIZE + 1] = {0};
    hi_char *ifname_point = ifname;

    hi_unref_param(argv);
    hi_unref_param(argc);

    ret = hi_wifi_sta_start(ifname_point, &len);
    if (ret != HISI_OK) {
        return HI_ERR_FAILURE;
    }

    hi_at_printf("OK\r\n");
    return HI_ERR_SUCCESS;
}

hi_u32 sta_start_adv_param(hi_s32 argc, const hi_char *argv[], hi_wifi_bw *bw)
{
    hi_s32  ret, value, i;
    for (i = 0; i < argc; i++) {
        if ((argv[i] != HI_NULL) && (integer_check(argv[i]) != HI_ERR_SUCCESS)) {
            return HI_ERR_FAILURE;
        }
        switch (i) {
            case 0: /* ��0������: Э������ */
                value = (argv[i] != HI_NULL) ? atoi(argv[i]) : HI_WIFI_PHY_MODE_11BGN;
                if ((value == HI_WIFI_PHY_MODE_11B) && (argv[1] != HI_NULL) && (strcmp(argv[1], "20"))) { /* 20:bw */
                    return HI_ERR_FAILURE;
                }
                ret = hi_wifi_sta_set_protocol_mode((hi_wifi_protocol_mode)value);
                break;
            case 1: /* ��1������: ���� */
                if ((argv[i] == HI_NULL) || !(strcmp(argv[i], "20"))) { /* bw 20M */
                    *bw = HI_WIFI_BW_LEGACY_20M;
                } else if (!(strcmp(argv[i], "10"))) { /* bw 10M */
                    *bw = HI_WIFI_BW_HIEX_10M;
                } else if (!(strcmp(argv[i], "5"))) { /* bw 5M */
                    *bw = HI_WIFI_BW_HIEX_5M;
                } else {
                    return HI_ERR_FAILURE;
                }
                ret = HISI_OK;
                break;
            case 2: /* ��2������: pmf */
                value = (argv[i] != HI_NULL) ? atoi(argv[i]) : HI_WIFI_MGMT_FRAME_PROTECTION_OPTIONAL;
                ret = hi_wifi_set_pmf((hi_wifi_pmf_options)value);
                break;
            default:
                return HI_ERR_FAILURE;
        }
        if (ret != HISI_OK) {
            return HI_ERR_FAILURE;
        }
    }
    return HI_ERR_SUCCESS;
}

hi_u32 cmd_sta_start_adv(hi_s32 argc, const hi_char *argv[])
{
    hi_s32  ret;
    hi_s32  len = 0;
    hi_char ifname[WIFI_IFNAME_MAX_SIZE + 1] = {0};
    hi_char *ifname_point = ifname;
    hi_wifi_bw bw = HI_WIFI_BW_LEGACY_20M;

    if (argc != 3) { /* "+STARTSTA"����̶�3��������� */
        return HI_ERR_FAILURE;
    }

    ret = (hi_s32)sta_start_adv_param(argc, argv, &bw);
    if (ret != HI_ERR_SUCCESS) {
        return HI_ERR_FAILURE;
    }

    ret = hi_wifi_sta_start(ifname_point, &len);
    if (ret != HISI_OK) {
        return HI_ERR_FAILURE;
    }

    ret = hi_wifi_set_bandwidth(DEFAULT_IFNAME_STA, strlen(DEFAULT_IFNAME_STA) + 1, bw);
    if (ret != HI_ERR_SUCCESS) {
        hi_wifi_sta_stop();
        return HI_ERR_FAILURE;
    }

    hi_at_printf("OK\r\n");
    return HI_ERR_SUCCESS;
}

/*****************************************************************************
* Func description: stop station
*****************************************************************************/
hi_u32 cmd_sta_stop(hi_s32 argc, const hi_char *argv[])
{
    hi_unref_param(argv);
    hi_unref_param(argc);

    hi_s32 ret = hi_wifi_sta_stop();
    if (ret != HISI_OK) {
        return HI_ERR_FAILURE;
    }

    hi_at_printf("OK\r\n");
    return HI_ERR_SUCCESS;
}

hi_u32 cmd_sta_connect_get_ssid(const hi_char *argv[], hi_wifi_assoc_request *assoc_req,
    hi_wifi_fast_assoc_request *fast_assoc_req, hi_u32 fast_flag)
{
    size_t ssid_len = 0;
    errno_t rc;

    if (argv[0][0] == 'P') {
        if (strlen(argv[0]) > HI_WIFI_MAX_SSID_LEN * 4 + 3) { /* ssid length should less than 32*4+3 */
            return HI_ERR_FAILURE;
        }
    } else {
        if (strlen(argv[0]) > HI_WIFI_MAX_SSID_LEN + 2) { /* ssid length should less than 32+2 */
            return HI_ERR_FAILURE;
        }
    }

    /* ssid hex to string */
    hi_char *tmp = at_parse_string(argv[0], &ssid_len);
    if (tmp == HI_NULL) {
        return HI_ERR_FAILURE;
    }
    if ((ssid_len > HI_WIFI_MAX_SSID_LEN) || (ssid_len == 0)) {
        at_free(tmp);
        return HI_ERR_FAILURE;
    }

    if ((fast_flag == 0) && (assoc_req != HI_NULL)) {
        rc = memcpy_s(assoc_req->ssid, HI_WIFI_MAX_SSID_LEN + 1, tmp, strlen(tmp) + 1);
        at_free(tmp);
        if (rc != EOK) {
            return HI_ERR_FAILURE;
        }
    } else if ((fast_flag == 1) && (fast_assoc_req != HI_NULL)) {
        rc = memcpy_s(fast_assoc_req->req.ssid, HI_WIFI_MAX_SSID_LEN + 1, tmp, strlen(tmp) + 1);
        at_free(tmp);
        if (rc != EOK) {
            return HI_ERR_FAILURE;
        }
    } else {
        at_free(tmp);
    }
    return HI_ERR_SUCCESS;
}

hi_u32 cmd_sta_connect_get_key(hi_s32 argc, const hi_char *argv[], hi_wifi_fast_assoc_request *fast_assoc_req)
{
    if ((fast_assoc_req->req.auth != HI_WIFI_SECURITY_OPEN) && (argc == 5)) { /* 5:����������� */
        if (argv[4] == HI_NULL) { /* 4:key */
            return HI_ERR_FAILURE;
        }
        const hi_char *buf = argv[4]; /* 4:key */

        size_t len = strlen(argv[4]); /* 4:key */
        if ((atoi(argv[3]) == HI_WIFI_SECURITY_WEP) && (len != 9) && (len != 17) && /* 3:���ܷ�ʽ 9:17:���볤�� */
            (len != 12) && (len != 28)) { /* 12:28 ���볤�� */
            return HI_ERR_FAILURE;
        } else if ((atoi(argv[3]) != HI_WIFI_SECURITY_WEP) && ((len > HI_WIFI_AP_KEY_LEN_MAX + 2) || /* 2:���ų���3 */
            (len < HI_WIFI_AP_KEY_LEN_MIN + 2))) { /* 2:���ų��� */
            return HI_ERR_FAILURE;
        }
        if ((buf == HI_NULL) || (*buf != '\"') || (*(buf + strlen(argv[4]) - 1) != '\"') || /* 4 */
            (memcpy_s(fast_assoc_req->req.key, HI_WIFI_MAX_KEY_LEN + 1, buf + 1, strlen(argv[4]) - 2)  /* 4 2 */
            != EOK)) {
            return HI_ERR_FAILURE;
        }
    }
    fast_assoc_req->psk_flag = HI_WIFI_WPA_PSK_NOT_USE;

    return HI_ERR_SUCCESS;
}

/*****************************************************************************
* Func description: station connect network
* example: AT+CONN="hisilicon",,3,"123456789"
*****************************************************************************/
hi_u32 cmd_sta_connect(hi_s32 argc, const hi_char *argv[])
{
    hi_wifi_assoc_request assoc_req = {0};

    if ((argc < 3) || (argc > 4)) { /* "+CONN"����Ĳ��������̶�Ϊ3��4 */
        return HI_ERR_FAILURE;
    }

    /* get ssid */
    if ((argv[0] != HI_NULL) && (cmd_sta_connect_get_ssid(argv, &assoc_req, HI_NULL, 0) != HI_ERR_SUCCESS)) {
        return HI_ERR_FAILURE;
    }

    /* get bssid */
    if (argv[1] == HI_NULL) {
        /* ��ȫ��̹���6.6���⣨2���ṹ�帳���ֵ */
        memset_s(assoc_req.bssid, sizeof(assoc_req.bssid), 0, sizeof(assoc_req.bssid));
    } else if (strlen(argv[1]) == HI_WIFI_TXT_ADDR_LEN) {
        if (cmd_strtoaddr(argv[1], assoc_req.bssid, HI_WIFI_MAC_LEN) != HISI_OK) {
            return HI_ERR_FAILURE;
        }
    } else {
        return HI_ERR_FAILURE;
    }

    /* get auth_type */
    if ((integer_check(argv[2]) != HI_ERR_SUCCESS) || (atoi(argv[2]) < HI_WIFI_SECURITY_OPEN) || /* 2��֤��ʽ */
        (atoi(argv[2]) > HI_WIFI_SECURITY_WPAPSK_WPA2PSK_MIX) || ((atoi(argv[2]) == HI_WIFI_SECURITY_OPEN) && /* 2 */
        (argc != 3)) || ((atoi(argv[2]) != HI_WIFI_SECURITY_OPEN) && (argc != 4))) { /* 2��֤��ʽ34���� */
        return HI_ERR_FAILURE;
    }
    assoc_req.auth = (hi_wifi_auth_mode)atoi(argv[2]); /* 2 */

    /* encipher mode Ĭ������Ϊ0����HI_WIFI_PARIWISE_UNKNOWN */
    assoc_req.pairwise = HI_WIFI_PARIWISE_UNKNOWN;

    /* get key */
    if (argc == 4) { /* 4:����������� */
        const hi_char *buf = argv[3]; /* 3:���һ����������Ϊ�� */
        if (buf == HI_NULL) {
            return HI_ERR_FAILURE;
        }
        size_t len = strlen(argv[3]); /* 3:key */
        if ((atoi(argv[2]) == HI_WIFI_SECURITY_WEP) && (len != 9) && (len != 17) && /* 2:���ܷ�ʽ 9:17:���볤�� */
            (len != 12) && (len != 28)) { /* 12:28 ���볤�� */
            return HI_ERR_FAILURE;
        } else if ((atoi(argv[2]) != HI_WIFI_SECURITY_WEP) && ((len > HI_WIFI_AP_KEY_LEN_MAX + 2) || /* 2:���ų��� */
            (len < HI_WIFI_AP_KEY_LEN_MIN + 2))) { /* 2:���ų��� */
            return HI_ERR_FAILURE;
        }
        if ((*buf != '\"') || (*(buf + strlen(argv[3]) - 1) != '\"') || /* 3:����4 */
            (memcpy_s(assoc_req.key, HI_WIFI_MAX_KEY_LEN + 1, buf + 1, strlen(argv[3]) - 2) != EOK)) { /* 3 2 */
            return HI_ERR_FAILURE;
        }
    }

    if (hi_wifi_sta_connect(&assoc_req) != HISI_OK) {
        return HI_ERR_FAILURE;
    }

    hi_at_printf("OK\r\n");
    return HI_ERR_SUCCESS;
}

/*****************************************************************************
* Func description: station quick connect
* example: AT+FCONN="hisilicon",,6,2,"123456789"
           AT+FCONN=,90:2B:D2:E4:CE:28,6,2,"123456789"
*****************************************************************************/
hi_u32 cmd_sta_quick_connect(hi_s32 argc, const hi_char *argv[])
{
    hi_wifi_fast_assoc_request fast_assoc_req = {0};
    hi_u32 ret;

    if ((argc < 4) || (argc > 5)) { /* "+FCONN"������������̶�Ϊ4��5 */
        return HI_ERR_FAILURE;
    }

    /* get ssid */
    if (argv[0] != HI_NULL) {
        ret = cmd_sta_connect_get_ssid(argv, HI_NULL, &fast_assoc_req, 1);
        if (ret != HI_ERR_SUCCESS) {
            return HI_ERR_FAILURE;
        }
    }

    /* get bssid */
    if (argv[1] == HI_NULL) {
        /* �ṹ�帳��ֵ */
        memset_s(fast_assoc_req.req.bssid, sizeof(fast_assoc_req.req.bssid), 0, sizeof(fast_assoc_req.req.bssid));
    } else if (strlen(argv[1]) == HI_WIFI_TXT_ADDR_LEN) {
        if (cmd_strtoaddr(argv[1], fast_assoc_req.req.bssid, HI_WIFI_MAC_LEN) != HISI_OK) {
            return HI_ERR_FAILURE;
        }
    } else {
        return HI_ERR_FAILURE;
    }

    /* get channel,��Χ1~14 */
    if ((integer_check(argv[2]) != HI_ERR_SUCCESS) || (atoi(argv[2]) <= 0) || (atoi(argv[2]) > 14)) { /* 2 14 */
        return HI_ERR_FAILURE;
    }
    fast_assoc_req.channel = (hi_uchar)atoi(argv[2]); /* 2 */

    /* get auth_type */
    if ((integer_check(argv[3]) != HI_ERR_SUCCESS) || (atoi(argv[3]) < HI_WIFI_SECURITY_OPEN) || /* 3��֤��ʽ */
        (atoi(argv[3]) > HI_WIFI_SECURITY_WPAPSK_WPA2PSK_MIX) || ((atoi(argv[3]) == HI_WIFI_SECURITY_OPEN) && /* 3 */
        (argc != 4)) || ((atoi(argv[3]) != HI_WIFI_SECURITY_OPEN) && (argc != 5))) { /* 3��֤��ʽ45���� */
        return HI_ERR_FAILURE;
    }

    fast_assoc_req.req.auth = (hi_wifi_auth_mode)atoi(argv[3]); /* 3 */

    /* get encipher mode 0����HI_WIFI_PARIWISE_UNKNOWN */
    fast_assoc_req.req.pairwise = HI_WIFI_PARIWISE_UNKNOWN;

    /* get key */
    ret = cmd_sta_connect_get_key(argc, argv, &fast_assoc_req);
    if (ret != HI_ERR_SUCCESS) {
        return HI_ERR_FAILURE;
    }

    if (hi_wifi_sta_fast_connect(&fast_assoc_req) != HISI_OK) {
        return HI_ERR_FAILURE;
    }

    hi_at_printf("OK\r\n");
    return HI_ERR_SUCCESS;
}

/*****************************************************************************
* Func description: sta disconnect network
*****************************************************************************/
hi_u32 cmd_sta_disconnect(hi_s32 argc, const hi_char *argv[])
{
    hi_unref_param(argv);
    hi_unref_param(argc);

    hi_s32 ret = hi_wifi_sta_disconnect();
    if (ret != HISI_OK) {
        return HI_ERR_FAILURE;
    }

    hi_at_printf("OK\r\n");
    return HI_ERR_SUCCESS;
}

/*****************************************************************************
* Func description: get station connection status
*****************************************************************************/
hi_u32 cmd_sta_status(hi_s32 argc, const hi_char *argv[])
{
    hi_s32 ret;
    hi_wifi_status wifi_status;

    hi_unref_param(argv);
    hi_unref_param(argc);

    /* ��ȫ��̹���6.6���⣨2���ṹ�帳���ֵ */
    memset_s(&wifi_status, sizeof(hi_wifi_status), 0, sizeof(hi_wifi_status));

    ret = hi_wifi_sta_get_connect_info(&wifi_status);
    if (ret != HISI_OK) {
        return HI_ERR_FAILURE;
    }
    if (wifi_status.status == HI_WIFI_CONNECTED) {
        const hi_char *tmp = at_ssid_txt((unsigned char*)wifi_status.ssid, strlen(wifi_status.ssid));
        if (at_check_ccharacter(tmp) == HI_ERR_SUCCESS) {
            hi_at_printf("+STASTAT:1,P\"%s\","AT_MACSTR",%d\r\n", tmp, at_mac2str(wifi_status.bssid),
                wifi_status.channel);
        } else {
            hi_at_printf("+STASTAT:1,%s,"AT_MACSTR",%d\r\n", wifi_status.ssid, at_mac2str(wifi_status.bssid),
                wifi_status.channel);
        }
    } else {
        hi_at_printf("+STASTAT:0,0,0,0\r\n");
    }
    hi_at_printf("OK\r\n");
    return HI_ERR_SUCCESS;
}

#ifdef CONFIG_WPS_SUPPORT
/*****************************************************************************
* Func description: using wps pbc to connect network
* example: sta wps_pbc <bssid>
*****************************************************************************/
hi_u32 cmd_wpa_wps_pbc(hi_s32 argc, const hi_char *argv[])
{
    hi_unref_param(argv);
    hi_unref_param(argc);

    hi_s32 ret = hi_wifi_sta_wps_pbc(HI_NULL);
    if (ret != HISI_OK) {
        return HI_ERR_FAILURE;
    }

    hi_at_printf("OK\r\n");
    return HI_ERR_SUCCESS;
}

/*****************************************************************************
* Func description: get wps pin value
*****************************************************************************/
hi_u32 cmd_wpa_wps_pin_get(hi_s32 argc, const hi_char *argv[])
{
    hi_char pin_txt[WIFI_WPS_PIN_LEN + 1] = {0};
    hi_u32  len = WIFI_WPS_PIN_LEN + 1;
    hi_s32  ret;

    hi_unref_param(argv);
    hi_unref_param(argc);

    ret = hi_wifi_sta_wps_pin_get(pin_txt, len);
    if (ret != HISI_OK) {
        return HI_ERR_FAILURE;
    }
    pin_txt[WIFI_WPS_PIN_LEN] = '\0';

    hi_at_printf("+PINSHOW:%s\r\n", pin_txt);
    hi_at_printf("OK\r\n");
    return HI_ERR_SUCCESS;
}

/*****************************************************************************
* Func description: using wps pin to connect network
* example: AT+PIN=03882368
*****************************************************************************/
hi_u32 cmd_wpa_wps_pin(hi_s32 argc, const hi_char *argv[])
{
    hi_char  pin[WIFI_WPS_PIN_LEN + 1] = {0};
    hi_char *ppin = pin;

    if ((argc != 1) || (at_param_null_check(argc, argv) == HI_ERR_FAILURE)) {
        return HI_ERR_FAILURE;
    }

    hi_u32 len = strlen(argv[0]);
    if ((len != WIFI_WPS_PIN_LEN) || (memcpy_s(pin, WIFI_WPS_PIN_LEN + 1, argv[0], len) != EOK)) {
        return HI_ERR_FAILURE;
    }

    if (hi_wifi_sta_wps_pin(ppin, HI_NULL) != HISI_OK) {
        return HI_ERR_FAILURE;
    }

    hi_at_printf("OK\r\n");
    return HI_ERR_SUCCESS;
}
#endif /* LOSCFG_APP_WPS */

hi_u32 cmd_set_reconn(hi_s32 argc, const hi_char *argv[])
{
    hi_s32 enable;
    hi_s32 seconds = RECONN_TIMEOUT_MIN;
    hi_u32 period = RECONN_PERIOD_MIN;
    hi_u32 max_try_count = RECONN_COUNT_MIN;
    if ((argc != 1) && (argc != 4)) { /* 4:�������� */
        return HI_ERR_FAILURE;
    }
    if (argc == 1) {
        if ((integer_check(argv[0]) != HI_ERR_SUCCESS) || (atoi(argv[0]) != 0)) {
            return HI_ERR_FAILURE;
        }
        enable = 0; /* ʹ��λ */
    } else {
        for (hi_s32 i = 0; i < argc - 1; i++) {
            if (integer_check(argv[i]) != HI_ERR_SUCCESS) {
                return HI_ERR_FAILURE;
            }
        }
        enable = atoi(argv[0]); /* ʹ��λ */
        if (enable == 0) {
            return HI_ERR_FAILURE;
        }
        period = (hi_u32)atoi(argv[1]); /* �������� */
        max_try_count = (hi_u32)atoi(argv[2]); /* 2:���������� */
        if (argv[3] != HI_NULL) { /* 3:����������ʱʱ��Ϊ��ѡ����,��������ʹ��Ĭ��ֵ */
            if (integer_check(argv[3]) != HI_ERR_SUCCESS) { /* 3:����������ʱʱ�� */
                return HI_ERR_FAILURE;
            }
            seconds = atoi(argv[3]); /* 3:����������ʱʱ�� */
        }

        if (seconds < RECONN_TIMEOUT_MIN || period < RECONN_PERIOD_MIN || period > RECONN_PERIOD_MAX ||
            max_try_count < RECONN_COUNT_MIN || max_try_count > RECONN_COUNT_MAX) {
            return HI_ERR_FAILURE;
        }
    }
    hi_s32 ret = hi_wifi_sta_set_reconnect_policy(enable, seconds, period, max_try_count);
    if (ret != HISI_OK) {
        return HI_ERR_FAILURE;
    }

    hi_at_printf("OK\r\n");

    return HI_ERR_SUCCESS;
}

const at_cmd_func g_sta_func_tbl[] = {
    {"+STOPSTA", 8, HI_NULL, HI_NULL, HI_NULL, (at_call_back_func)cmd_sta_stop},
    {"+SCAN", 5, HI_NULL, HI_NULL, HI_NULL, (at_call_back_func)cmd_wpa_scan},
    {"+SCANCHN", 8, HI_NULL, HI_NULL, (at_call_back_func)cmd_wpa_channel_scan, HI_NULL},
    {"+SCANSSID", 9, HI_NULL, HI_NULL, (at_call_back_func)cmd_wpa_ssid_scan, HI_NULL},
    {"+SCANPRSSID", 11, HI_NULL, HI_NULL, (at_call_back_func)cmd_ssid_prefix_scan, HI_NULL},
    {"+SCANRESULT", 11, HI_NULL, HI_NULL, HI_NULL, (at_call_back_func)cmd_wpa_scan_results},
    {"+CONN", 5, HI_NULL, HI_NULL, (at_call_back_func)cmd_sta_connect, HI_NULL},
    {"+FCONN", 6, HI_NULL, HI_NULL, (at_call_back_func)cmd_sta_quick_connect, HI_NULL},
    {"+DISCONN", 8, HI_NULL, HI_NULL, HI_NULL, (at_call_back_func)cmd_sta_disconnect},
    {"+STASTAT", 8, HI_NULL, HI_NULL, HI_NULL, (at_call_back_func)cmd_sta_status},
    {"+RECONN", 7, HI_NULL, HI_NULL, (at_call_back_func)cmd_set_reconn, HI_NULL},
#ifdef CONFIG_WPS_SUPPORT
    {"+PBC", 4, HI_NULL, HI_NULL, HI_NULL, (at_call_back_func)cmd_wpa_wps_pbc},
    {"+PIN", 4, HI_NULL, HI_NULL, (at_call_back_func)cmd_wpa_wps_pin, HI_NULL},
    {"+PINSHOW", 8, HI_NULL, HI_NULL, HI_NULL, (at_call_back_func)cmd_wpa_wps_pin_get},
#endif /* LOSCFG_APP_WPS */
};

#define AT_STA_FUNC_NUM (sizeof(g_sta_func_tbl) / sizeof(g_sta_func_tbl[0]))

hi_void hi_at_sta_cmd_register(hi_void)
{
    hi_at_register_cmd(g_sta_func_tbl, AT_STA_FUNC_NUM);
}

const at_cmd_func g_sta_factory_test_func_tbl[] = {
    {"+STARTSTA", 9, HI_NULL, HI_NULL, (at_call_back_func)cmd_sta_start_adv, (at_call_back_func)cmd_sta_start},
};
#define AT_STA_FACTORY_TEST_FUNC_NUM (sizeof(g_sta_factory_test_func_tbl) / sizeof(g_sta_factory_test_func_tbl[0]))

hi_void hi_at_sta_factory_test_cmd_register(hi_void)
{
    hi_at_register_cmd(g_sta_factory_test_func_tbl, AT_STA_FACTORY_TEST_FUNC_NUM);
}

/*****************************************************************************
* Func description: show mesh or softap connected sta information
*****************************************************************************/
hi_u32 cmd_softap_show_sta(hi_s32 argc, const hi_char *argv[])
{
    hi_s32 ret;
    hi_u32 sta_index;
    hi_u32 sta_num = WIFI_DEFAULT_MAX_NUM_STA;
    hi_wifi_ap_sta_info  sta_list[WIFI_DEFAULT_MAX_NUM_STA];
    hi_wifi_ap_sta_info *sta_list_node = HI_NULL;

    hi_unref_param(argc);
    hi_unref_param(argv);

    ret = hi_wifi_softap_get_connected_sta(sta_list, &sta_num);
    if (ret != HISI_OK) {
        return HI_ERR_FAILURE;
    }

    sta_list_node = sta_list;
    for (sta_index = 0; sta_index < sta_num; sta_index++, sta_list_node++) {
        hi_at_printf("+SHOWSTA:" AT_MACSTR, at_mac2str(sta_list_node->mac));
        hi_at_printf("\r\n");
    }

    hi_at_printf("OK\r\n");
    return HI_ERR_SUCCESS;
}

/*****************************************************************************
* Func description: start softap
* example: AT+STARTAP="hisilicon",0,6,1,"123456789"
           AT+STARTAP="hisilicon",0,6,0
*****************************************************************************/
hi_u32 cmd_start_softap(hi_s32 argc, const hi_char *argv[])
{
    hi_wifi_softap_config hapd_conf          = {0};
    hi_char ifname[WIFI_IFNAME_MAX_SIZE + 1] = {0};
    hi_char *ifname_point = ifname;
    hi_s32 len;

    if (((argc != 4) && (argc != 5)) || (at_param_null_check(argc, argv) == HI_ERR_FAILURE)) { /* ��������Ϊ4 �� 5 */
        return HI_ERR_FAILURE;
    }

    /* get ssid */
    if ((argv[0][0] != '\"') || (*(argv[0] + strlen(argv[0]) - 1) != '\"') ||
        (memcpy_s(hapd_conf.ssid, HI_WIFI_MAX_SSID_LEN + 1, argv[0] + 1, strlen(argv[0]) - 2) != EOK)) { /* 2 ��˫���� */
        return HI_ERR_FAILURE;
    }

    /* get ssid_hidden,��Χ0~1 */
    if ((integer_check(argv[1]) != HI_ERR_SUCCESS) || (atoi(argv[1]) < 0) || (atoi(argv[1]) > 1)) {
        return HI_ERR_FAILURE;
    }
    hapd_conf.ssid_hidden = atoi(argv[1]);

    /* get channel,�ŵ��ŷ�Χ1~14 */
    if ((integer_check(argv[2]) != HI_ERR_SUCCESS) || (atoi(argv[2]) <= 0) || (atoi(argv[2]) > 14)) { /* 2 14 */
        return HI_ERR_FAILURE;
    }
    hapd_conf.channel_num = (hi_uchar)atoi(argv[2]); /* 2 */

    /* get ���ܷ�ʽ */
    if ((integer_check(argv[3]) == HI_ERR_FAILURE) || /* 3 */
        ((atoi(argv[3]) != HI_WIFI_SECURITY_OPEN) && (atoi(argv[3]) != HI_WIFI_SECURITY_WPA2PSK) && /* 3 */
        (atoi(argv[3]) != HI_WIFI_SECURITY_WPAPSK_WPA2PSK_MIX)) || /* 3 */
        ((atoi(argv[3]) == HI_WIFI_SECURITY_OPEN) && (argc != 4))) { /* ����3Ϊopen����ʱ��ֻ��4������ */
        return HI_ERR_FAILURE;
    }
    hapd_conf.authmode = (hi_wifi_auth_mode)atoi(argv[3]); /* 3 */

    /* get authmode */
    if ((hapd_conf.authmode != HI_WIFI_SECURITY_OPEN)) {
        if ((argc != 5) || (strlen(argv[4]) > HI_WIFI_AP_KEY_LEN_MAX + 2) || /* 4:�������� ˫����ռ��2�ֽ� 5�������� */
            (strlen(argv[4]) < HI_WIFI_AP_KEY_LEN_MIN + 2)) { /* 4:�������� ˫����ռ��2�ֽ� */
            return HI_ERR_FAILURE;
        }
        const hi_char *buf = argv[4]; /* ����4 */
        len = (int)strlen(argv[4]); /* ����4 */
        if ((*buf != '\"') || (*(buf + len - 1) != '\"') ||
            (memcpy_s((hi_char*)hapd_conf.key, HI_WIFI_AP_KEY_LEN + 1, buf + 1, len - 2) != EOK)) { /* 2ȥ��˫���� */
            return HI_ERR_FAILURE;
        }
    }
    if (hi_wifi_softap_start(&hapd_conf, ifname_point, &len) != HISI_OK) {
        return HI_ERR_FAILURE;
    }

    if (hi_wifi_set_bandwidth(DEFAULT_IFNAME_AP, strlen(DEFAULT_IFNAME_AP) + 1, g_bw_setup_value) != HI_ERR_SUCCESS) {
        hi_wifi_softap_stop();
        return HI_ERR_FAILURE;
    }

    hi_at_printf("OK\r\n");
    return HI_ERR_SUCCESS;
}

/*****************************************************************************
* Func description: start softap
* example: AT+SETAPADV=2,10,100,2,3600,0
*****************************************************************************/
hi_u32 cmd_set_softap_advance(hi_s32 argc, const hi_char *argv[])
{
    hi_s32 ret, value, i;

    if (argc != 6) { /* "+SETAPADV"����̶�6��������� */
        return HI_ERR_FAILURE;
    }
    for (i = 0; i < argc; i++) {
        if ((argv[i] != HI_NULL) && (integer_check(argv[i]) != HI_ERR_SUCCESS)) {
            return HI_ERR_FAILURE;
        }

        if (i == 0) {
            value = (argv[i] != HI_NULL) ? atoi(argv[i]) : HI_WIFI_PHY_MODE_11BGN;
            if ((value == HI_WIFI_PHY_MODE_11B) && (argv[1] != HI_NULL) && (strcmp(argv[1], "20"))) { /* 20:bw */
                return HI_ERR_FAILURE;
            }
            ret = hi_wifi_softap_set_protocol_mode((hi_wifi_protocol_mode)value);
        } else if (i == 1) {
            if ((argv[i] == HI_NULL) || !(strcmp(argv[i], "20"))) { /* 20M */
                g_bw_setup_value = HI_WIFI_BW_LEGACY_20M;
            } else if (!(strcmp(argv[i], "10"))) { /* 10M */
                g_bw_setup_value = HI_WIFI_BW_HIEX_10M;
            } else if (!(strcmp(argv[i], "5"))) { /* 5M */
                g_bw_setup_value = HI_WIFI_BW_HIEX_5M;
            } else {
                return HI_ERR_FAILURE;
            }
            ret = HISI_OK;
        } else if (i == 2) { /* 2:���� */
            ret = (argv[i] != HI_NULL) ? hi_wifi_softap_set_beacon_period(atoi(argv[i])) : HISI_OK; /* ����Ĭ��100ms */
        } else if (i == 3) { /* 3:���� */
            ret = (argv[i] != HI_NULL) ? hi_wifi_softap_set_dtim_period(atoi(argv[i])) : HISI_OK;
        } else if (i == 4) { /* 4:���� */
            ret = (argv[i] != HI_NULL) ? hi_wifi_softap_set_group_rekey(atoi(argv[i])) : HISI_OK;
        } else if (i == 5) { /* 5:���� */
            ret = (argv[i] != HI_NULL) ? hi_wifi_softap_set_shortgi(atoi(argv[i])) : HISI_OK;
        } else {
            return HI_ERR_FAILURE;
        }
        if (ret != HISI_OK) {
            return HI_ERR_FAILURE;
        }
    }

    hi_at_printf("OK\r\n");
    return HI_ERR_SUCCESS;
}

/*****************************************************************************
* Func description: stop softap
*****************************************************************************/
hi_u32 cmd_stop_softap(hi_s32 argc, const hi_char *argv[])
{
    hi_unref_param(argc);
    hi_unref_param(argv);

    if (hi_wifi_softap_stop() != HISI_OK) {
        return HI_ERR_FAILURE;
    }

    hi_at_printf("OK\r\n");
    return HI_ERR_SUCCESS;
}

/*****************************************************************************
* Func description: softap disconnect station
* example: AT+DEAUTHSTA=90:2B:D2:E4:CE:28
*****************************************************************************/
hi_u32 cmd_softap_deauth_sta(hi_s32 argc, const hi_char *argv[])
{
    hi_uchar mac_addr[HI_WIFI_MAC_LEN + 1] = {0};
    hi_s32 ret;

    if ((argc != 1) || (argv[0] == HI_NULL) || (strlen(argv[0]) != HI_WIFI_TXT_ADDR_LEN)) {
        return HI_ERR_FAILURE;
    }

    if (cmd_strtoaddr(argv[0], mac_addr, HI_WIFI_MAC_LEN) != HISI_OK) {
        return HI_ERR_FAILURE;
    }

    ret = hi_wifi_softap_deauth_sta(mac_addr, HI_WIFI_MAC_LEN);
    if (ret != HISI_OK) {
        return HI_ERR_FAILURE;
    }

    hi_at_printf("OK\r\n");
    return HI_ERR_SUCCESS;
}

hi_u32 at_ap_scan(hi_void)
{
    hi_at_printf("ERROR:TBD\r\n");
    return HI_ERR_SUCCESS;
}

const at_cmd_func g_at_ap_func_tbl[] = {
    {"+STARTAP", 8, HI_NULL, HI_NULL, (at_call_back_func)cmd_start_softap, HI_NULL},
    {"+SETAPADV", 9, HI_NULL, HI_NULL, (at_call_back_func)cmd_set_softap_advance, HI_NULL},
    {"+STOPAP", 7, HI_NULL, HI_NULL, HI_NULL, (at_call_back_func)cmd_stop_softap},
    {"+SHOWSTA", 8, HI_NULL, HI_NULL, HI_NULL, (at_call_back_func)cmd_softap_show_sta},
    {"+DEAUTHSTA", 10, HI_NULL, HI_NULL, (at_call_back_func)cmd_softap_deauth_sta, HI_NULL},
    {"+APSCAN", 7, HI_NULL, HI_NULL, HI_NULL, (at_call_back_func)at_ap_scan},
};

#define AT_AP_FUNC_NUM (sizeof(g_at_ap_func_tbl) / sizeof(g_at_ap_func_tbl[0]))

hi_void hi_at_softap_cmd_register(void)
{
    hi_at_register_cmd(g_at_ap_func_tbl, AT_AP_FUNC_NUM);
}

#ifdef LOSCFG_APP_MESH
/*****************************************************************************
* Func description: set mesh sta mode
* example: AT+SETMSTA=1
*****************************************************************************/
hi_s32 cmd_set_mesh_sta_flag(hi_s32 argc, const hi_char *argv[])
{
    hi_s32 flag;
    hi_s32 ret;
    if (argc != 1) {
        return HI_ERR_FAILURE;
    }
    if (integer_check(argv[0]) != HI_ERR_SUCCESS) {
        return HI_ERR_FAILURE;
    }

    flag = atoi(argv[0]);
    if ((flag < 0) || (flag > 1)) {
        return HI_ERR_FAILURE;
    }
    ret = hi_wifi_set_mesh_sta((hi_u16)flag);
    if (ret != HISI_OK) {
        return HI_ERR_FAILURE;
    }
    hi_at_printf("OK\r\n");
    return HI_ERR_SUCCESS;
}

/*****************************************************************************
* Func description: mesh sta scan
*****************************************************************************/
hi_s32 cmd_mesh_sta_scan(hi_s32 argc, const hi_char *argv[])
{
    hi_s32 ret;
    (hi_void)argv;

    if (argc != 0) {
        return HI_ERR_FAILURE;
    }
    ret = hi_wifi_mesh_sta_scan();
    if (ret != HISI_OK) {
        return HI_ERR_FAILURE;
    }
    hi_at_printf("OK\r\n");
    return HI_ERR_SUCCESS;
}

/*****************************************************************************
* Func description: mesh sta ssid scan
*****************************************************************************/
hi_s32 cmd_mesh_sta_ssid_scan(hi_s32 argc, const hi_char *argv[])
{
    hi_s32 ret;
    errno_t rc;
    hi_wifi_scan_params scan_params = {0};
    hi_char* tmp = HI_NULL;
    size_t ssid_len = 0;
    if ((argc != 1) || (at_param_null_check(argc, argv) == HI_ERR_FAILURE)) {
        return HI_ERR_FAILURE;
    }

    /* get ssid */
    if (argv[0][0] == 'P') {
        if (strlen(argv[0]) > HI_WIFI_MAX_SSID_LEN * 4 + 3) { /* ssid length should less than 32*4+3 */
            return HI_ERR_FAILURE;
        }
    } else {
        if (strlen(argv[0]) > HI_WIFI_MAX_SSID_LEN + 2) { /* ssid length should less than 32+2 */
            return HI_ERR_FAILURE;
        }
    }

    /* ssid hex to string */
    tmp = at_parse_string(argv[0], &ssid_len);
    if (tmp == HI_NULL) {
        return HI_ERR_FAILURE;
    }
    rc = memcpy_s(scan_params.ssid, HI_WIFI_MAX_SSID_LEN + 1, tmp, strlen(tmp) + 1);
    at_free(tmp);
    if (rc != EOK) {
        return HI_ERR_FAILURE;
    }
    scan_params.ssid_len = (unsigned char)ssid_len;
    if ((scan_params.ssid_len > HI_WIFI_MAX_SSID_LEN) || (scan_params.ssid_len == 0)) {
        return HI_ERR_FAILURE;
    }
    scan_params.ssid[scan_params.ssid_len] = '\0';
    scan_params.scan_type = HI_WIFI_SSID_SCAN;
    ret = hi_wifi_mesh_sta_advance_scan(&scan_params);
    if (ret != HISI_OK) {
        return HI_ERR_FAILURE;
    }

    hi_at_printf("OK\r\n");
    return HI_ERR_SUCCESS;
}

/*****************************************************************************
* Func description: mesh sta ssid prefix scan
*****************************************************************************/
hi_s32 cmd_mesh_sta_ssid_prefix_scan(hi_s32 argc, const hi_char *argv[])
{
    errno_t rc;
    hi_s32 ret;
    size_t ssid_len;
    hi_wifi_scan_params scan_params = {0};
    hi_char *tmp = HI_NULL;

    if ((argc != 1) || (at_param_null_check(argc, argv) == HI_ERR_FAILURE)) {
        return HI_ERR_FAILURE;
    }

    /* get ssid */
    if (argv[0][0] == 'P') {
        if (strlen(argv[0]) > HI_WIFI_MAX_SSID_LEN * 4 + 3) { /* ssid length should less than 32*4+3 */
            return HI_ERR_FAILURE;
        }
    } else {
        if (strlen(argv[0]) > HI_WIFI_MAX_SSID_LEN + 2) { /* ssid length should less than 32+2 */
            return HI_ERR_FAILURE;
        }
    }

    /* ssid hex to string */
    tmp = at_parse_string(argv[0], &ssid_len);
    if (tmp == HI_NULL) {
        return HI_ERR_FAILURE;
    }
    if ((ssid_len > HI_WIFI_MAX_SSID_LEN) || (ssid_len == 0)) {
        at_free(tmp);
        return HI_ERR_FAILURE;
    }
    scan_params.ssid_len = (unsigned char)ssid_len;
    rc = memcpy_s(scan_params.ssid, HI_WIFI_MAX_SSID_LEN + 1, tmp, ssid_len + 1);
    at_free(tmp);
    if (rc != EOK) {
        return HI_ERR_FAILURE;
    }
    scan_params.ssid[scan_params.ssid_len] = '\0';
    scan_params.scan_type = HI_WIFI_SSID_PREFIX_SCAN;
    ret = hi_wifi_mesh_sta_advance_scan(&scan_params);
    if (ret != HISI_OK) {
        return HI_ERR_FAILURE;
    }

    hi_at_printf("OK\r\n");
    return HI_ERR_SUCCESS;
}

/*****************************************************************************
* Func description: mesh sta channel scan
*****************************************************************************/
hi_s32 cmd_mesh_sta_channel_scan(hi_s32 argc, const hi_char *argv[])
{
    hi_s32 ret;
    hi_wifi_scan_params scan_params = {0};
    if ((argc != 1) || (at_param_null_check(argc, argv) == HI_ERR_FAILURE)) {
        return HI_ERR_FAILURE;
    }

    scan_params.channel = (unsigned char)atoi(argv[0]);
    if ((scan_params.channel < 1) || (scan_params.channel > 14)) { /* �ŵ���Χ1~14 */
        return HI_ERR_FAILURE;
    }
    scan_params.scan_type = HI_WIFI_CHANNEL_SCAN;
    ret = hi_wifi_mesh_sta_advance_scan(&scan_params);
    if (ret != HISI_OK) {
        return HI_ERR_FAILURE;
    }

    hi_at_printf("OK\r\n");
    return HI_ERR_SUCCESS;
}

/*****************************************************************************
* Func description: set mesh accept peer
* example: AT+MGENCONN=1
*****************************************************************************/
hi_s32 cmd_set_mesh_accept_peer(hi_s32 argc, const hi_char *argv[])
{
    hi_uchar enable_accpet_peer;
    hi_s32 ret;

    if (argc != 1) {
        return HI_ERR_FAILURE;
    }
    if (integer_check(argv[0]) != HI_ERR_SUCCESS) {
        return HI_ERR_FAILURE;
    }
    enable_accpet_peer = (hi_uchar)(atoi(argv[0]));
    ret = hi_wifi_mesh_set_accept_peer(enable_accpet_peer);
    if (ret != HISI_OK) {
        return HI_ERR_FAILURE;
    }
    hi_at_printf("OK\r\n");
    return HI_ERR_SUCCESS;
}

/*****************************************************************************
* Func description: set mesh accept sta
* example: AT+MENSTACONN=1
*****************************************************************************/
hi_s32 cmd_set_mesh_accept_sta(hi_s32 argc, const hi_char *argv[])
{
    hi_uchar enable_accept_sta;
    hi_s32 ret;

    if (argc != 1) {
        return HI_ERR_FAILURE;
    }
    if (integer_check(argv[0]) != HI_ERR_SUCCESS) {
        return HI_ERR_FAILURE;
    }
    enable_accept_sta = (hi_uchar)(atoi(argv[0]));
    ret = hi_wifi_mesh_set_accept_sta(enable_accept_sta);
    if (ret != HISI_OK) {
        return HI_ERR_FAILURE;
    }

    hi_at_printf("OK\r\n");
    return HI_ERR_SUCCESS;
}

/*****************************************************************************
* Func description: start mesh ap
* example: AT+MSTART=channle,"ssid",encrypt_type,"key"
*          AT+MSTART=6,"mesh1",0
*          AT+MSTART=6,"mesh1",7,"123456789"
*****************************************************************************/
hi_s32 cmd_wpa_mesh_ap_start(hi_s32 argc, const hi_char *argv[])
{
    hi_wifi_mesh_config wpa_mesh_assoc_req = {0};
    hi_char ifname[WIFI_IFNAME_MAX_SIZE + 1] = {0};
    hi_char *ifname_point = ifname;
    hi_s32 len = 0;

    if ((argc < 3) || (argc > 4)) { /* ��������ֻ��Ϊ3 �� 4 */
        return HI_ERR_FAILURE;
    }

    /* get channel,��Χ1~14 */
    if ((integer_check(argv[0]) != HI_ERR_SUCCESS) || (atoi(argv[0]) <= 0) || (atoi(argv[0]) > 14)) {
        return HI_ERR_FAILURE;
    }
    wpa_mesh_assoc_req.channel = (hi_uchar)atoi(argv[0]);

    /* get ssid */
    const hi_char *buf = argv[1];
    if ((*buf != '\"') || (*(buf + strlen(argv[1]) - 1) != '\"') ||
        (memcpy_s(wpa_mesh_assoc_req.ssid, HI_WIFI_MAX_SSID_LEN + 1, buf + 1, strlen(argv[1]) - 2) != EOK)) { /* 2 */
        return HI_ERR_FAILURE;
    }

    /* get auth_type */ /* 2 ��������֤���� */
    if ((integer_check(argv[2]) == HI_ERR_FAILURE) || /* ����2 */
        ((atoi(argv[2]) != HI_WIFI_SECURITY_OPEN) && (atoi(argv[2]) != HI_WIFI_SECURITY_SAE)) || /* ����2 */
        ((atoi(argv[2]) == HI_WIFI_SECURITY_OPEN) && (argc != 3))) { /* ����2Ϊopen����ʱ���̶�3���������� */
        return HI_ERR_FAILURE;
    }
    wpa_mesh_assoc_req.auth = (hi_wifi_auth_mode)atoi(argv[2]); /* 2 */

    /* get key */
    if (wpa_mesh_assoc_req.auth == HI_WIFI_SECURITY_SAE) {
        buf = argv[3]; /* 3���� */
        if ((argc != 4) || (strlen(buf) > (HI_WIFI_MS_KEY_LEN_MAX + 2)) || /* 4��������  ˫����ռ��2�ֽ� */
            (strlen(buf) < (HI_WIFI_MS_KEY_LEN_MIN + 2))|| /* 2 ���ų��� */
            (*buf != '\"') || (*(buf + strlen(argv[3]) - 1) != '\"') || /* 3���� */
            (memcpy_s((hi_char*)wpa_mesh_assoc_req.key, HI_WIFI_AP_KEY_LEN + 1,
                buf + 1, strlen(argv[3]) - 2) != EOK)) { /* 3����  ˫����ռ��2�ֽ� */
            return HI_ERR_FAILURE;
        }
    }

    if (hi_wifi_mesh_start(&wpa_mesh_assoc_req, ifname_point, &len) != HISI_OK) {
        return HI_ERR_FAILURE;
    }
    /* ����bw */
    if (hi_wifi_set_bandwidth(DEFAULT_IFNAME_MESH, strlen(DEFAULT_IFNAME_MESH) + 1, g_bw_setup_value)
        != HI_ERR_SUCCESS) {
        /* ���������RPL stop�ӿ� */
        if (hi_wifi_mesh_stop() != HISI_OK) {
            return HI_ERR_FAILURE;
        }

        hi_wifi_register_event_callback(HI_NULL);
        return HI_ERR_FAILURE;
    }

    hi_at_printf("OK\r\n");
    return HI_ERR_SUCCESS;
}

/*****************************************************************************
* Func description: set mesh ap parameter
* example: AT+SETMESHADV=5
*****************************************************************************/
hi_u32 cmd_set_mesh_advance(hi_s32 argc, const hi_char *argv[])
{
    if (argc != 1) { /* "+SETMESHADV"����̶�1��������� */
        return HI_ERR_FAILURE;
    }

    if ((argv[0] != HI_NULL) && (integer_check(argv[0]) != HI_ERR_SUCCESS)) { /* 0:��һ������ */
        return HI_ERR_FAILURE;
    }

    if ((argv[0] != HI_NULL) && (atoi(argv[0]) == 5)) {           /* 5M ,0:��һ������ */
        g_bw_setup_value = HI_WIFI_BW_HIEX_5M;
    } else if ((argv[0] != HI_NULL) && (atoi(argv[0]) == 10)) {   /* 10M ,0:��һ������ */
        g_bw_setup_value = HI_WIFI_BW_HIEX_10M;
    } else {
        g_bw_setup_value = HI_WIFI_BW_LEGACY_20M;
    }

    hi_at_printf("OK\r\n");
    return HI_ERR_SUCCESS;
}

/*****************************************************************************
* Func description: connect mesh network
* example: AT+MCONN=11:22:33:44:55:66
*****************************************************************************/
hi_s32 cmd_wpa_mesh_connect(hi_s32 argc, const hi_char *argv[])
{
    hi_s32 ret;
    hi_uchar addr[HI_WIFI_MAC_LEN] = {0};

    if ((argc != 1) || (argv[0] == HI_NULL)) {
        return HI_ERR_FAILURE;
    }
    if (strlen(argv[0]) != HI_WIFI_TXT_ADDR_LEN) {
        return HI_ERR_FAILURE;
    }
    if (cmd_strtoaddr(argv[0], addr, HI_WIFI_MAC_LEN) != HISI_OK) {
        return HI_ERR_FAILURE;
    }

    ret = hi_wifi_mesh_connect(addr, HI_WIFI_MAC_LEN);
    if (ret != HISI_OK) {
        return HI_ERR_FAILURE;
    }

    hi_at_printf("OK\r\n");
    return HI_ERR_SUCCESS;
}

/*****************************************************************************
* Func description: show mesh connected user information
* example: AT+MCONNINFO
*****************************************************************************/
hi_s32 cmd_mesh_conninfo(hi_s32 argc, const hi_char *argv[])
{
    hi_s32 ret;
    hi_u32 sta_index;
    hi_u32 sta_num                  = WIFI_DEFAULT_MAX_NUM_STA;
    hi_wifi_mesh_peer_info* peer_list      = NULL;
    hi_wifi_mesh_peer_info* peer_list_node = NULL;

    if (argc > 1) {
        return HI_ERR_FAILURE;
    }

    if (argc == 1) {
        if (integer_check(argv[0]) != HI_ERR_SUCCESS) {
            return HI_ERR_FAILURE;
        }
        sta_num = (hi_u32)atoi(argv[0]);
        if (sta_num > WIFI_DEFAULT_MAX_NUM_STA) {
            sta_num = WIFI_DEFAULT_MAX_NUM_STA;
        }
    }

    if (sta_num == 0) {
        return HI_ERR_FAILURE;
    }
    peer_list = malloc(sizeof(hi_wifi_mesh_peer_info) * sta_num);
    if (peer_list == NULL) {
        return HI_ERR_FAILURE;
    }
    ret = hi_wifi_mesh_get_connected_peer(peer_list, &sta_num);
    if (ret != HISI_OK) {
        free(peer_list);
        return HI_ERR_FAILURE;
    }

    peer_list_node = peer_list;
    for (sta_index = 0; sta_index < sta_num; sta_index++, peer_list_node++) {
        hi_at_printf("+SHOWPEER:" AT_MACSTR ",%d,%d,%d", at_mac2str(peer_list_node->mac), peer_list_node->mesh_block,
            peer_list_node->mesh_is_mbr, peer_list_node->mesh_role);
        hi_at_printf("\r\n");
    }

    hi_at_printf("OK\r\n");
    free(peer_list);
    return HI_ERR_SUCCESS;
}

/*****************************************************************************
* Func description: mesh scan
* example: AT+MSCAN
*****************************************************************************/
hi_s32 cmd_mesh_scan(hi_s32 argc, const hi_char *argv[])
{
    hi_s32 ret;
    hi_unref_param(argv);
    if (argc != 0) {
        return HI_ERR_FAILURE;
    }

    ret = hi_wifi_mesh_scan();
    if (ret != HISI_OK) {
        return HI_ERR_FAILURE;
    }

    hi_at_printf("OK\r\n");
    return HI_ERR_SUCCESS;
}

/*****************************************************************************
* Func description: mesh channel scan
*****************************************************************************/
hi_s32 cmd_mesh_channel_scan(hi_s32 argc, const hi_char *argv[])
{
    hi_s32 ret;
    hi_wifi_scan_params scan_params = {0};

    if ((argc != 1) || (integer_check(argv[0]) != HI_ERR_SUCCESS)) {
        return HI_ERR_FAILURE;
    }

    scan_params.channel = (hi_uchar)atoi(argv[0]);
    if ((scan_params.channel < 1) || (scan_params.channel > 14)) { /* �ŵ���Χ1~14 */
        return HI_ERR_FAILURE;
    }
    scan_params.scan_type = HI_WIFI_CHANNEL_SCAN;
    ret = hi_wifi_mesh_advance_scan(&scan_params);
    if (ret != HISI_OK) {
        return HI_ERR_FAILURE;
    }

    hi_at_printf("OK\r\n");
    return HI_ERR_SUCCESS;
}

/*****************************************************************************
* Func description: mesh bssid scan
*****************************************************************************/
hi_s32 cmd_mesh_bssid_scan(hi_s32 argc, const hi_char *argv[])
{
    int ret;
    hi_wifi_scan_params scan_params = {0};
    if ((argc != 1) || (argv[0] == HI_NULL)) {
        return HI_ERR_FAILURE;
    }
    if (strlen(argv[0]) != HI_WIFI_TXT_ADDR_LEN) {
        return HI_ERR_FAILURE;
    }
    if (cmd_strtoaddr(argv[0], scan_params.bssid, HI_WIFI_MAC_LEN) != HISI_OK) {
        return HI_ERR_FAILURE;
    }
    scan_params.scan_type = HI_WIFI_BSSID_SCAN;
    ret = hi_wifi_mesh_advance_scan(&scan_params);
    if (ret != HISI_OK) {
        return HI_ERR_FAILURE;
    }

    hi_at_printf("OK\r\n");
    return HI_ERR_SUCCESS;
}

/*****************************************************************************
* Func description: mesh ssid scan
*****************************************************************************/
hi_s32 cmd_mesh_ssid_scan(hi_s32 argc, const hi_char *argv[])
{
    hi_s32 ret;
    errno_t rc;
    hi_wifi_scan_params scan_params = {0};
    hi_char* tmp = HI_NULL;
    size_t ssid_len = 0;

    if ((argc != 1) || (at_param_null_check(argc, argv) == HI_ERR_FAILURE)) {
        return HI_ERR_FAILURE;
    }

    /* get ssid */
    if (argv[0][0] == 'P') {
        if (strlen(argv[0]) > HI_WIFI_MAX_SSID_LEN * 4 + 3) { /* ssid length should less than 32*4+3 */
            return HI_ERR_FAILURE;
        }
    } else {
        if (strlen(argv[0]) > HI_WIFI_MAX_SSID_LEN + 2) { /* ssid length should less than 32+2 */
            return HI_ERR_FAILURE;
        }
    }

    /* ssid hex to string */
    tmp = at_parse_string(argv[0], &ssid_len);
    if (tmp == HI_NULL) {
        return HI_ERR_FAILURE;
    }
    rc = memcpy_s(scan_params.ssid, HI_WIFI_MAX_SSID_LEN + 1, tmp, strlen(tmp) + 1);
    at_free(tmp);
    if (rc != EOK) {
        return HI_ERR_FAILURE;
    }
    scan_params.ssid_len = (unsigned char)ssid_len;
    if ((scan_params.ssid_len > HI_WIFI_MAX_SSID_LEN) || (scan_params.ssid_len == 0)) {
        return HI_ERR_FAILURE;
    }
    scan_params.ssid[scan_params.ssid_len] = '\0';

    scan_params.scan_type = HI_WIFI_SSID_SCAN;
    ret = hi_wifi_mesh_advance_scan(&scan_params);
    if (ret != HISI_OK) {
        return HI_ERR_FAILURE;
    }

    hi_at_printf("OK\r\n");
    return HI_ERR_SUCCESS;
}

/*****************************************************************************
* Func description: mesh ssid prefix scan
*****************************************************************************/
hi_s32 cmd_mesh_ssid_prefix_scan(hi_s32 argc, const hi_char *argv[])
{
    errno_t rc;
    hi_s32 ret;
    size_t ssid_len;
    hi_char *tmp = HI_NULL;
    hi_wifi_scan_params scan_params = {0};
    if ((argc != 1) || (at_param_null_check(argc, argv) == HI_ERR_FAILURE)) {
        return HI_ERR_FAILURE;
    }

    /* get ssid */
    if (argv[0][0] == 'P') {
        if (strlen(argv[0]) > HI_WIFI_MAX_SSID_LEN * 4 + 3) { /* ssid length should less than 32*4+3 */
            return HI_ERR_FAILURE;
        }
    } else {
        if (strlen(argv[0]) > HI_WIFI_MAX_SSID_LEN + 2) { /* ssid length should less than 32+2 */
            return HI_ERR_FAILURE;
        }
    }

    /* ssid hex to string */
    tmp = at_parse_string(argv[0], &ssid_len);
    if (tmp == HI_NULL) {
        return HI_ERR_FAILURE;
    }
    if ((ssid_len > HI_WIFI_MAX_SSID_LEN) || (ssid_len == 0)) {
        at_free(tmp);
        return HI_ERR_FAILURE;
    }
    scan_params.ssid_len = (unsigned char)ssid_len;
    rc = memcpy_s(scan_params.ssid, HI_WIFI_MAX_SSID_LEN + 1, tmp, ssid_len + 1);
    at_free(tmp);
    if (rc != EOK) {
        return HI_ERR_FAILURE;
    }
    scan_params.ssid[scan_params.ssid_len] = '\0';
    scan_params.scan_type = HI_WIFI_SSID_PREFIX_SCAN;

    ret = hi_wifi_mesh_advance_scan(&scan_params);
    if (ret != HISI_OK) {
        return HI_ERR_FAILURE;
    }

    hi_at_printf("OK\r\n");
    return HI_ERR_SUCCESS;
}

/*****************************************************************************
* Func description: mesh AP get scan results
* example: AT+MPEERS
*****************************************************************************/
hi_s32 cmd_mesh_ap_scan_results(hi_s32 argc, const hi_char *argv[])
{
    hi_u32 num = WIFI_SCAN_AP_LIMIT;
    hi_u32 auth_type;
    hi_char ssid_str[HI_WIFI_MAX_SSID_LEN * 4 + 3]; /* ssid length should less 32*4+3 */

    hi_unref_param(argv);

    if (argc != 0) {
        return HI_ERR_FAILURE;
    }

    hi_wifi_mesh_scan_result_info *pst_results = malloc(sizeof(hi_wifi_mesh_scan_result_info) * WIFI_SCAN_AP_LIMIT);
    if (pst_results == HI_NULL) {
        return HI_ERR_FAILURE;
    }

    /* ��ȫ��̹���6.6���⣨3���Ӷ��з����ڴ�󣬸����ֵ */
    memset_s(pst_results, sizeof(hi_wifi_mesh_scan_result_info) * WIFI_SCAN_AP_LIMIT, 0,
        (sizeof(hi_wifi_mesh_scan_result_info) * WIFI_SCAN_AP_LIMIT));
    if (hi_wifi_mesh_scan_results(pst_results, &num) != HISI_OK) {
        free(pst_results);
        return HI_ERR_FAILURE;
    }

    /* ��ӡɨ���� */
    for (hi_u32 ul_loop = 0; (ul_loop < num) && (ul_loop < WIFI_SCAN_AP_LIMIT); ul_loop++) {
        if ((pst_results[ul_loop].auth < HI_WIFI_SECURITY_OPEN) ||
            (pst_results[ul_loop].auth > HI_WIFI_SECURITY_UNKNOWN)) {
            pst_results[ul_loop].auth = HI_WIFI_SECURITY_UNKNOWN;
        }
        auth_type = pst_results[ul_loop].auth;
        size_t ssid_len = strlen(pst_results[ul_loop].ssid);
        const hi_char *tmp = at_ssid_txt((unsigned char*)pst_results[ul_loop].ssid, ssid_len);
        if ((tmp != HI_NULL) && ((tmp + 1) != HI_NULL) && (*tmp == '\\') && (*(tmp + 1) == 'x')) {
            if (sprintf_s(ssid_str, HI_WIFI_MAX_SSID_LEN * 4 + 3, "P\"%s\"", tmp) == -1) { /* 4 3 */
                free(pst_results);
                return HI_ERR_FAILURE;
            }
        } else {
            if (sprintf_s(ssid_str, HI_WIFI_MAX_SSID_LEN * 4 + 3, "%s", pst_results[ul_loop].ssid) == -1) { /* 4 3 */
                free(pst_results);
                return HI_ERR_FAILURE;
            }
        }

        hi_at_printf("+MPEERS:%s,"AT_MACSTR",%d,%d,%d,%d,%d,%d,%d,%d,%d\r\n", ssid_str,
               at_mac2str(pst_results[ul_loop].bssid), pst_results[ul_loop].channel,
               pst_results[ul_loop].rssi / 100, auth_type, pst_results[ul_loop].hisi_mesh_flag,
               pst_results[ul_loop].is_mbr, pst_results[ul_loop].bcn_prio, pst_results[ul_loop].accept_for_sta,
               pst_results[ul_loop].accept_for_peer, pst_results[ul_loop].peering_num);
    }

    free(pst_results);

    hi_at_printf("OK\r\n");
    return HI_ERR_SUCCESS;
}

/*****************************************************************************
* Func description: disconnect mesh point
* example: AT+MDISCONN=11:22:33:44:55:66
*****************************************************************************/
hi_s32 cmd_mesh_disconnect(hi_s32 argc, const hi_char *argv[])
{
    hi_uchar addr[HI_WIFI_MAC_LEN] = {0};
    hi_s32 ret;
    if ((argc != 1) || (argv[0] == HI_NULL)) {
        return HI_ERR_FAILURE;
    }
    if (strlen(argv[0]) != HI_WIFI_TXT_ADDR_LEN) {
        return HI_ERR_FAILURE;
    }
    if (cmd_strtoaddr(argv[0], addr, HI_WIFI_MAC_LEN) != HISI_OK) {
        return HI_ERR_FAILURE;
    }
    ret = hi_wifi_mesh_disconnect(addr, HI_WIFI_MAC_LEN);
    if (ret != HISI_OK) {
        return HI_ERR_FAILURE;
    }
    hi_at_printf("OK\r\n");
    return HI_ERR_SUCCESS;
}

/*****************************************************************************
* Func description: stop mesh
* example: AT+MSTOP
*****************************************************************************/
hi_s32 cmd_stop_mesh(hi_s32 argc, const hi_char *argv[])
{
    hi_unref_param(argv);
    if (argc != 0) {
        return HI_ERR_FAILURE;
    }
    /* ���������RPL stop�ӿ� */
    if (hi_wifi_mesh_stop() != HISI_OK) {
        return HI_ERR_FAILURE;
    }
    hi_wifi_register_event_callback(HI_NULL);

    hi_at_printf("OK\r\n");
    return HI_ERR_SUCCESS;
}

/*****************************************************************************
* Func description: Get mesh node role
* example: AT+MNODEINFO
*****************************************************************************/
hi_s32 cmd_mesh_query_nodeinfo(hi_s32 argc, const hi_char *argv[])
{
    /* �Ȳ�ѯwlan0 */
    (void)hi_wifi_at_start(argc, argv, HISI_AT_GET_WLAN0_MESHINFO);
    /* �ٲ�ѯmesh0 */
    (void)hi_wifi_at_start(argc, argv, HISI_AT_GET_MESH0_MESHINFO);
    hi_at_printf("OK\r\n");
    return HI_ERR_SUCCESS;
}

/*****************************************************************************
* Func description: wpa get scan results
*****************************************************************************/
hi_u32 cmd_mesh_sta_scan_results(hi_s32 argc, const hi_char *argv[])
{
    hi_u32  num = WIFI_SCAN_AP_LIMIT ;
    hi_char ssid_str[HI_WIFI_MAX_SSID_LEN * 4 + 3]; /* ssid length should less 32*4+3 */
    hi_u32 ul_loop;
    hi_u32 auth_type;

    hi_unref_param(argv);
    hi_unref_param(argc);

    hi_wifi_mesh_scan_result_info *pst_results = malloc(sizeof(hi_wifi_mesh_scan_result_info) * WIFI_SCAN_AP_LIMIT);
    if (pst_results == HI_NULL) {
        return HI_ERR_FAILURE;
    }

    /* ��ȫ��̹���6.6���⣨3���Ӷ��з����ڴ�󣬸����ֵ */
    memset_s(pst_results, (sizeof(hi_wifi_mesh_scan_result_info) * WIFI_SCAN_AP_LIMIT), 0,
        (sizeof(hi_wifi_mesh_scan_result_info) * WIFI_SCAN_AP_LIMIT));

    hi_s32 ret = hi_wifi_mesh_sta_scan_results(pst_results, &num);
    if (ret != HISI_OK) {
        free(pst_results);
        return HI_ERR_FAILURE;
    }

    /* ��ӡɨ���� */
    for (ul_loop = 0; (ul_loop < num) && (ul_loop < WIFI_SCAN_AP_LIMIT); ul_loop++) {
        if ((pst_results[ul_loop].auth < HI_WIFI_SECURITY_OPEN) ||
            (pst_results[ul_loop].auth > HI_WIFI_SECURITY_UNKNOWN)) {
            pst_results[ul_loop].auth = HI_WIFI_SECURITY_UNKNOWN;
        }
        auth_type = pst_results[ul_loop].auth;
        size_t ssid_len = strlen(pst_results[ul_loop].ssid);
        const char *tmp = at_ssid_txt((unsigned char*)pst_results[ul_loop].ssid, ssid_len);
        if ((tmp != HI_NULL) && ((tmp + 1) != HI_NULL) && (*tmp == '\\') && (*(tmp + 1) == 'x')) {
            if (sprintf_s(ssid_str, HI_WIFI_MAX_SSID_LEN * 4 + 3, "P\"%s\"", tmp) == -1) { /* 4 3 */
                free(pst_results);
                return HI_ERR_FAILURE;
            }
        } else {
            if (sprintf_s(ssid_str, HI_WIFI_MAX_SSID_LEN * 4 + 3, "%s", pst_results[ul_loop].ssid) == -1) { /* 4 3 */
                free(pst_results);
                return HI_ERR_FAILURE;
            }
        }

        hi_at_printf("+MSCANRESULT:%s,"AT_MACSTR",%d,%d,%d,%d,%d,%d,%d\r\n", ssid_str,
                at_mac2str(pst_results[ul_loop].bssid), pst_results[ul_loop].channel,
                pst_results[ul_loop].rssi / 100, auth_type, pst_results[ul_loop].hisi_mesh_flag,
                pst_results[ul_loop].is_mbr, pst_results[ul_loop].bcn_prio, pst_results[ul_loop].accept_for_sta);
    }

    hi_at_printf("OK\r\n");
    free(pst_results);
    return HI_ERR_SUCCESS;
}

hi_u32 cmd_mesh_auto_get_ssid(const hi_char *argv[], mesh_auto_start_config *mesh_auto_config)
{
    size_t ssid_len = 0;
    errno_t rc;

    /* get ssid */
    if (argv[1][0] == 'P') {
        if (strlen(argv[1]) > HI_WIFI_MAX_SSID_LEN * 4 + 3) { /* ssid length should less than 32*4+3 */
            return HI_ERR_FAILURE;
        }
    } else if (strlen(argv[1]) > HI_WIFI_MAX_SSID_LEN + 2) { /* ssid length should less than 32+2 */
        return HI_ERR_FAILURE;
    }

    /* ssid hex to string */
    hi_char *tmp = at_parse_string(argv[1], &ssid_len);
    if (tmp == HI_NULL) {
        return HI_ERR_FAILURE;
    }
    if ((ssid_len > HI_WIFI_MAX_SSID_LEN) || (ssid_len == 0)) {
        at_free(tmp);
        return HI_ERR_FAILURE;
    }

    rc = memcpy_s(mesh_auto_config->ssid, HI_WIFI_MAX_SSID_LEN + 1, tmp, strlen(tmp) + 1);
    at_free(tmp);
    if (rc != EOK) {
        return HI_ERR_FAILURE;
    }

    return HI_ERR_SUCCESS;
}

/*****************************************************************************
* Func description: start mesh auto join
* example: AT+MAUTOJOIN=1,"router_mesh",0
AT+MAUTOJOIN=1,"router_mesh",1,"123456789"
*****************************************************************************/
hi_s32 cmd_mesh_auto_connect(hi_s32 argc, const hi_char* argv[])
{
    mesh_auto_start_config mesh_auto_config = {0};

    if ((argc < 3) || (argc > 4)) { /* ��������ֻ��Ϊ3 �� 4 */
        return HI_ERR_FAILURE;
    }

    /* get usr config mesh type */
    if ((integer_check(argv[0]) != HI_ERR_SUCCESS) || (atoi(argv[0]) < HI_MESH_MBR) || (atoi(argv[0]) > HI_MESH_AUTO)) {
        return HI_ERR_FAILURE;
    }
    mesh_auto_config.usr_config_role = (hi_mesh_node_type)atoi(argv[0]);

    /* get ssid */
    if (cmd_mesh_auto_get_ssid(argv, &mesh_auto_config) != HI_ERR_SUCCESS) {
        return HI_ERR_FAILURE;
    }

    /* get auth_type */ /* 2 ��������֤���� */
    if ((integer_check(argv[2]) == HI_ERR_FAILURE) || /* ����2 */
        ((atoi(argv[2]) != HI_MESH_OPEN) && (atoi(argv[2]) != HI_MESH_AUTH)) || /* ����2 */
        ((atoi(argv[2]) == HI_MESH_OPEN) && (argc != 3))) { /* ����2Ϊopen����ʱ���̶�3���������� */
        return HI_ERR_FAILURE;
    }
    mesh_auto_config.auth = (hi_mesh_auth_type)atoi(argv[2]); /* 2 */

    /* get key */
    if (mesh_auto_config.auth == HI_MESH_AUTH) {
        if ((argc != 4) || (strlen(argv[3]) > HI_WIFI_MS_KEY_LEN_MAX + 2) || /* 4,3,2 */
            (strlen(argv[3]) < HI_WIFI_MS_KEY_LEN_MIN + 2)) { /* 3,2 */
            return HI_ERR_FAILURE;
        }
        const hi_char *buf = argv[3]; /* 3 */
        size_t len = strlen(argv[3]); /* 3 */
        if ((*buf != '\"') || (*(buf + len - 1) != '\"') ||
            (memcpy_s((hi_char*)mesh_auto_config.key, HI_WIFI_AP_KEY_LEN + 1, buf + 1, len - 2) != EOK)) { /* 2 */
            return HI_ERR_FAILURE;
        }
    }

    if (hi_mesh_auto_join(mesh_auto_config) != HI_ERR_SUCCESS) {
        return HI_ERR_FAILURE;
    }

    hi_at_printf("OK\r\n");
    return HI_ERR_SUCCESS;
}

/*****************************************************************************
* Func description: exit mesh network
* example: AT+MEXIT
* AT+MEXIT
*****************************************************************************/
hi_s32 cmd_mesh_exit_network(hi_s32 argc, const hi_char* argv[])
{
    hi_s32  ret;

    hi_unref_param(argv);
    hi_unref_param(argc);

    ret = hi_mesh_exit_auto_join();
    if (ret != HI_ERR_SUCCESS) {
        return HI_ERR_FAILURE;
    }

    hi_at_printf("OK\r\n");
    return HI_ERR_SUCCESS;
}

/*****************************************************************************
* Func description: set mesh router rssi threshold
* example: AT+MSETRSSI=-50
*****************************************************************************/
hi_s32 cmd_mesh_set_rssi_threshold(hi_s32 argc, const hi_char* argv[])
{
    hi_s32 ret;
    hi_s32 usr_rssi_config;

    if ((argc != 1) || (argv[0] == HI_NULL)) {
        return HI_ERR_FAILURE;
    }

    usr_rssi_config = atoi(argv[0]);
    if ((usr_rssi_config < -127) || (usr_rssi_config > 10)) { /* rssi��Ч��Χ-127-10 */
        return HI_ERR_FAILURE;
    }
    ret = hi_wifi_mesh_set_router_rssi_threshold(usr_rssi_config);
    if (ret != HISI_OK) {
        return HI_ERR_FAILURE;
    }

    hi_at_printf("OK\r\n");
    return HI_ERR_SUCCESS;
}

/*****************************************************************************
* Func description: set mesh autonetwork bw value
* example: AT+MSETBW=5
*****************************************************************************/
hi_s32 cmd_mesh_set_autonetwork_bw(hi_s32 argc, const hi_char* argv[])
{
    hi_wifi_bw bw_value;
    if (argc != 1) { /* "+MSETBW"����̶�1��������� */
        return HI_ERR_FAILURE;
    }

    if ((argv[0] != HI_NULL) && (integer_check(argv[0]) != HI_ERR_SUCCESS)) { /* 0:��һ������ */
        return HI_ERR_FAILURE;
    }

    if ((argv[0] != HI_NULL) && (atoi(argv[0]) == 5)) {           /* 5M ,0:��һ������ */
        bw_value = HI_WIFI_BW_HIEX_5M;
    } else if ((argv[0] != HI_NULL) && (atoi(argv[0]) == 10)) {   /* 10M ,0:��һ������ */
        bw_value = HI_WIFI_BW_HIEX_10M;
    } else {
        bw_value = HI_WIFI_BW_LEGACY_20M;
    }

    hi_mesh_set_mesh_autonetwork_bw_value(bw_value);
    hi_at_printf("OK\r\n");
    return HI_ERR_SUCCESS;
}

const at_cmd_func g_at_mesh_func_tbl[] = {
    {"+MSTART", 7, HI_NULL, HI_NULL, (at_call_back_func)cmd_wpa_mesh_ap_start, HI_NULL},
    {"+SETMESHADV", 11, HI_NULL, HI_NULL, (at_call_back_func)cmd_set_mesh_advance, HI_NULL},
    {"+MSTOP", 6, HI_NULL, HI_NULL, HI_NULL, (at_call_back_func)cmd_stop_mesh},
    {"+MGENCONN", 9, HI_NULL, HI_NULL, (at_call_back_func)cmd_set_mesh_accept_peer, HI_NULL},
    {"+MENSTACONN", 11, HI_NULL, HI_NULL, (at_call_back_func)cmd_set_mesh_accept_sta, HI_NULL},
    {"+MPEERS", 7, HI_NULL, HI_NULL, HI_NULL, (at_call_back_func)cmd_mesh_ap_scan_results},
    {"+MSCAN", 6, HI_NULL, HI_NULL, HI_NULL, (at_call_back_func)cmd_mesh_scan},
    {"+MSCANCHN", 9, HI_NULL, HI_NULL, (at_call_back_func)cmd_mesh_channel_scan, HI_NULL},
    {"+MSCANSSID", 10, HI_NULL, HI_NULL, (at_call_back_func)cmd_mesh_ssid_scan, HI_NULL},
    {"+MSCANBSSID", 11, HI_NULL, HI_NULL, (at_call_back_func)cmd_mesh_bssid_scan, HI_NULL},
    {"+MSCANPRSSID", 12, HI_NULL, HI_NULL, (at_call_back_func)cmd_mesh_ssid_prefix_scan, HI_NULL},
    {"+MCONN", 6, HI_NULL, HI_NULL, (at_call_back_func)cmd_wpa_mesh_connect, HI_NULL},
    {"+MDISCONN", 9, HI_NULL, HI_NULL, (at_call_back_func)cmd_mesh_disconnect, HI_NULL},
    {"+MCONNINFO", 10, HI_NULL, HI_NULL, HI_NULL, (at_call_back_func)cmd_mesh_conninfo},
    {"+SETMSTA", 8, HI_NULL, HI_NULL, (at_call_back_func)cmd_set_mesh_sta_flag, HI_NULL},
    {"+MINFO", 6, HI_NULL, HI_NULL, HI_NULL, (at_call_back_func)cmd_mesh_query_nodeinfo},
    {"+MSCANRESULT", 12, HI_NULL, HI_NULL, HI_NULL, (at_call_back_func)cmd_mesh_sta_scan_results},
    {"+MSTASCAN", 9, HI_NULL, HI_NULL, HI_NULL, (at_call_back_func)cmd_mesh_sta_scan},
    {"+MSTASSIDSCAN", 13, HI_NULL, HI_NULL, (at_call_back_func)cmd_mesh_sta_ssid_scan, HI_NULL},
    {"+MSTASCANPRSSID", 15, HI_NULL, HI_NULL, (at_call_back_func)cmd_mesh_sta_ssid_prefix_scan, HI_NULL},
    {"+MSTASCANCHL", 12, HI_NULL, HI_NULL, (at_call_back_func)cmd_mesh_sta_channel_scan, HI_NULL},
    {"+MAUTOJOIN", 10, HI_NULL, HI_NULL, (at_call_back_func)cmd_mesh_auto_connect, HI_NULL},
    {"+MEXIT", 6, HI_NULL, HI_NULL, HI_NULL, (at_call_back_func)cmd_mesh_exit_network},
    {"+MSETRSSI", 9, HI_NULL, HI_NULL, (at_call_back_func)cmd_mesh_set_rssi_threshold, HI_NULL},
    {"+MSETBW", 7, HI_NULL, HI_NULL, (at_call_back_func)cmd_mesh_set_autonetwork_bw, HI_NULL},
};

#define AT_MESH_FUNC_NUM (sizeof(g_at_mesh_func_tbl) / sizeof(g_at_mesh_func_tbl[0]))

hi_void hi_at_mesh_cmd_register(void)
{
    hi_at_register_cmd(g_at_mesh_func_tbl, AT_MESH_FUNC_NUM);
}
#endif
#ifdef __cplusplus
#if __cplusplus
    }
#endif
#endif
