/*
 * WPA Supplicant / main() function for UNIX like OSes and MinGW
 * Copyright (c) 2003-2013, Jouni Malinen <j@w1.fi>
 * Copyright (c) Huawei Technologies Co., Ltd. 2014-2019. All rights reserved.
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */
/****************************************************************************
 * Notice of Export Control Law
 * ===============================================
 * Huawei LiteOS may be subject to applicable export control laws and regulations,
 * which might include those applicable to Huawei LiteOS of U.S. and the country in
 * which you are located.
 * Import, export and usage of Huawei LiteOS in any manner by you shall be in
 * compliance with such applicable export control laws and regulations.
 ****************************************************************************/

#include "common.h"
#include "wpa_supplicant_i.h"
#include "wpa_supplicant.h"
#include "los_task.h"
#include "wifi_api.h"
#include "eloop.h"
#include "hostapd/hostapd_if.h"
#ifdef CONFIG_P2P
#include "p2p_supplicant.h"
#endif /* CONFIG_P2P */
#include "securec.h"

EVENT_CB_S g_wpa_event;
#ifdef CONFIG_DRIVER_HISILICON
static struct wpa_global *g_wpa_global = NULL;
#endif /* CONFIG_DRIVER_HISILICON */

static int wpa_supplicant_main_int(const char* ifname, struct hisi_wifi_dev **wifi_dev, struct wpa_global **global)
{
	if (ifname == NULL) {
		wpa_error_log0(MSG_ERROR, "wpa_supplicant_main: ifname is null \n");
		(void)LOS_EventWrite(&g_wpa_event, WPA_EVENT_WPA_START_ERROR);
		return HISI_FAIL;
	}
	wpa_debug_level = MSG_DEBUG;
	wpa_printf(MSG_DEBUG, "wpa_supplicant_main: ifname = %s", ifname);
	*wifi_dev = hi_get_wifi_dev_by_name(ifname);
	if (*wifi_dev == NULL) {
		wpa_error_log0(MSG_ERROR, "wpa_supplicant_main: get_wifi_dev_by_name failed \n");
		(void)LOS_EventWrite(&g_wpa_event, WPA_EVENT_WPA_START_ERROR);
		return HISI_FAIL;
	}
	*global = wpa_supplicant_init();
	if (*global == NULL) {
		(void)LOS_EventWrite(&g_wpa_event, WPA_EVENT_WPA_START_ERROR);
		return HISI_FAIL;
	}
	return HISI_OK;
}

int wpa_supplicant_main(const char* ifname)
{
	struct wpa_interface *ifaces     = NULL;
	struct wpa_interface *iface      = NULL;
	struct wpa_global *global        = NULL;
	struct hisi_wifi_dev *wifi_dev   = NULL;
	char driver[MAX_DRIVER_NAME_LEN] = {"hisi"};
	int iface_count;
	int exitcode = HISI_OK;
	int ret;

	ret = wpa_supplicant_main_int(ifname, &wifi_dev, &global);
	if (ret != HISI_OK)
		return HISI_FAIL;

	ifaces = os_zalloc(sizeof(struct wpa_interface));
	if (ifaces == NULL)
		goto OUT;

	iface = ifaces;
	iface_count = 1;
	iface->ifname = ifname;
	iface->driver = driver;

#ifdef CONFIG_DRIVER_HISILICON
	g_wpa_global = global;
#endif /* CONFIG_DRIVER_HISILICON */

	for (int i = 0; (exitcode == HISI_OK) && (i < iface_count); i++) {
		struct wpa_supplicant *wpa_s = wpa_supplicant_add_iface(global, &ifaces[i], NULL);
		if (wpa_s == NULL) {
			exitcode = HISI_FAIL;
			break;
		}
		LOS_TaskLock();
		wifi_dev->priv = wpa_s;
		LOS_TaskUnlock();
		wpa_error_buf(MSG_ERROR, "wpa_supplicant_main: wifi_dev: ifname = %s\n", wifi_dev->ifname, strlen(wifi_dev->ifname));
	}

	if (exitcode == HISI_OK) {
		exitcode = wpa_supplicant_run(global);
		if (exitcode != HISI_FAIL) {
			(void)LOS_EventWrite(&g_wpa_event, WPA_EVENT_WPA_START_OK);
			return HISI_OK;
		}
	}

OUT:
	wpa_supplicant_deinit(global);
#ifdef CONFIG_DRIVER_HISILICON
	g_wpa_global = NULL;
#endif
	LOS_TaskLock();
	if (wifi_dev != NULL)
		wifi_dev->priv = NULL;
	LOS_TaskUnlock();
	os_free(ifaces);
	// send sta start failed event
	(void)LOS_EventWrite(&g_wpa_event, WPA_EVENT_WPA_START_ERROR);
	return HISI_FAIL;
}

void hi_wpa_supplicant_exit(void)
{
	wpa_error_log0(MSG_ERROR, "hi_wpa_supplicant_exit enter\n");
	wpa_supplicant_deinit(g_wpa_global);
	g_wpa_global = NULL;
}

int wpa_supplicant_main_task(UINT32 p0, UINT32 p1,
			UINT32 p2, UINT32 p3)
{
	struct hisi_wifi_dev *wifi_dev = NULL;
	(void)p1;
	(void)p2;
	(void)p3;
	wpa_error_log0(MSG_ERROR, "---> wpa_supplicant_main_task enter.");
	wifi_dev = (struct hisi_wifi_dev *)(uintptr_t)p0;
	if (wifi_dev == NULL) {
		wpa_error_log0(MSG_ERROR, "wpa_supplicant_main: get_wifi_dev_by_name failed \n");
		(void)LOS_EventWrite(&g_wpa_event, WPA_EVENT_WPA_START_ERROR);
		return HISI_FAIL;
	}
	if (wifi_dev->iftype == HI_WIFI_IFTYPE_AP) {
		hostapd_main(wifi_dev->ifname);
		return HISI_OK;
	}
	wpa_supplicant_main(wifi_dev->ifname);
	return HISI_OK;
}

 int wpa_check_reconnect_timeout_match(const struct wpa_supplicant *wpa_s)
{
	int ret;
	if ((g_reconnect_set.enable == WPA_FLAG_OFF) ||
	    (g_reconnect_set.pending_flag == WPA_FLAG_ON) ||
	    (g_reconnect_set.timeout == WIFI_MAX_RECONNECT_TIMEOUT)) {
		return 0;
	}
	ret = ((wpa_s->wpa_state >= WPA_ASSOCIATING) && (wpa_s->wpa_state != WPA_COMPLETED)) ||
	       ((wpa_s->wpa_state == WPA_COMPLETED) && (wpa_s->current_ssid != NULL) &&
	       (g_reconnect_set.current_ssid == wpa_s->current_ssid));
	return ret;
}

void wpa_supplicant_reconnect_restart(void *eloop_ctx, void *timeout_ctx)
{
	(void)timeout_ctx;
	struct wpa_supplicant *wpa_s = eloop_ctx;
	if (wpa_s == NULL) {
		wpa_error_log0(MSG_ERROR, "wpa_supplicant_reconnect_restart input NULL ptr!");
		return;
	}
	if ((g_reconnect_set.enable == WPA_FLAG_OFF) || (g_connecting_ssid == NULL)) {
		wpa_error_log0(MSG_ERROR, "reconnect policy disabled!");
		return;
	}
	if (wpa_s->wpa_state < WPA_AUTHENTICATING) {
		wpa_supplicant_select_network(wpa_s, g_connecting_ssid);
		g_reconnect_set.pending_flag = WPA_FLAG_ON;
		g_connecting_flag = WPA_FLAG_ON;
		wpa_error_log0(MSG_ERROR, "wpa_supplicant_reconnect_restart!");
	}

	if (g_reconnect_set.timeout > 0)
		eloop_register_timeout(g_reconnect_set.timeout, 0, wpa_supplicant_reconnect_timeout, wpa_s, NULL);
}

void wpa_supplicant_reconnect_timeout(void *eloop_ctx, void *timeout_ctx)
{
	(void)timeout_ctx;
	struct wpa_supplicant *wpa_s = eloop_ctx;
	if (wpa_s == NULL) {
		wpa_error_log0(MSG_ERROR, "wpa_supplicant_reconnect_timeout input NULL ptr!");
		return;
	}
	if (g_reconnect_set.enable == WPA_FLAG_OFF) {
		wpa_error_log0(MSG_ERROR, "reconnect policy disabled!");
		return;
	}
	if ((wpa_s->wpa_state != WPA_COMPLETED) &&
		(g_reconnect_set.pending_flag)) {
		wpas_request_disconnection(wpa_s);
		g_connecting_flag = WPA_FLAG_OFF;
		wpa_error_log0(MSG_ERROR, "wpa reconnect timeout, try to connect next period!");
	}
	g_reconnect_set.pending_flag = WPA_FLAG_OFF;
	if (++g_reconnect_set.try_count >= g_reconnect_set.max_try_count) {
		g_reconnect_set.current_ssid = NULL;
		wpa_error_log0(MSG_ERROR, "wpa reconnect timeout, do not try to connect any more !");
		return;
	}
	if (g_reconnect_set.period > 0)
		eloop_register_timeout(g_reconnect_set.period, 0, wpa_supplicant_reconnect_restart, wpa_s, NULL);
}
