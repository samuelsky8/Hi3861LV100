/*
 * hostapd / Station table
 * Copyright (c) 2002-2017, Jouni Malinen <j@w1.fi>
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#include "utils/includes.h"

#include "utils/common.h"
#include "utils/eloop.h"
#include "common/ieee802_11_defs.h"
#include "common/wpa_ctrl.h"
#include "common/sae.h"
#ifndef HISI_CODE_CROP
#include "radius/radius.h"
#include "radius/radius_client.h"
#endif /* HISI_CODE_CROP */
#include "p2p/p2p.h"
#include "fst/fst.h"
#include "crypto/crypto.h"
#include "hostapd.h"
#include "accounting.h"
#include "ieee802_1x.h"
#include "ieee802_11.h"
#ifndef HISI_CODE_CROP
#include "ieee802_11_auth.h"
#endif /* HISI_CODE_CROP */
#include "wpa_auth.h"
#include "preauth_auth.h"
#include "ap_config.h"
#include "beacon.h"
#include "ap_mlme.h"
#include "vlan_init.h"
#include "p2p_hostapd.h"
#include "ap_drv_ops.h"
#include "gas_serv.h"
#include "wnm_ap.h"
#include "mbo_ap.h"
#include "ndisc_snoop.h"
#include "sta_info.h"
#ifndef LOS_CONFIG_NO_VLAN
#include "vlan.h"
#endif
#include "wifi_api.h"
#include "wps_hostapd.h"
#include "wpa_supplicant/hi_mesh.h"
#include "hi_at.h"

static void ap_sta_remove_in_other_bss(struct hostapd_data *hapd,
				       struct sta_info *sta);
static void ap_handle_session_timer(void *eloop_ctx, void *timeout_ctx);
static void ap_handle_session_warning_timer(void *eloop_ctx, void *timeout_ctx);
static void ap_sta_deauth_cb_timeout(void *eloop_ctx, void *timeout_ctx);
static void ap_sta_disassoc_cb_timeout(void *eloop_ctx, void *timeout_ctx);
#ifdef CONFIG_IEEE80211W_AP
static void ap_sa_query_timer(void *eloop_ctx, void *timeout_ctx);
#endif /* CONFIG_IEEE80211W_AP */
static int ap_sta_remove(struct hostapd_data *hapd, struct sta_info *sta);
static void ap_sta_delayed_1x_auth_fail_cb(void *eloop_ctx, void *timeout_ctx);

int ap_for_each_sta(struct hostapd_data *hapd,
		    int (*cb)(struct hostapd_data *hapd, struct sta_info *sta,
			      void *ctx),
		    void *ctx)
{
	struct sta_info *sta;

	for (sta = hapd->sta_list; sta; sta = sta->next) {
		if (cb(hapd, sta, ctx))
			return 1;
	}

	return 0;
}


struct sta_info * ap_get_sta(struct hostapd_data *hapd, const u8 *sta)
{
	struct sta_info *s;

#ifndef HISI_CODE_CROP
	s = hapd->sta_hash[STA_HASH(sta)];
	while (s != NULL && os_memcmp(s->addr, sta, 6) != 0)
		s = s->hnext;
	return s;
#else
	for (s = hapd->sta_list; s; s = s->next) {
		if (os_memcmp(s->addr, sta, ETH_ALEN) == 0)
			return s;
}
	return NULL;
#endif /* HISI_CODE_CROP */
}

#ifdef CONFIG_P2P
struct sta_info * ap_get_sta_p2p(struct hostapd_data *hapd, const u8 *addr)
{
	struct sta_info *sta;

	for (sta = hapd->sta_list; sta; sta = sta->next) {
		const u8 *p2p_dev_addr;

		if (sta->p2p_ie == NULL)
			continue;

		p2p_dev_addr = p2p_get_go_dev_addr(sta->p2p_ie);
		if (p2p_dev_addr == NULL)
			continue;

		if (os_memcmp(p2p_dev_addr, addr, ETH_ALEN) == 0)
			return sta;
	}

	return NULL;
}
#endif /* CONFIG_P2P */


static void ap_sta_list_del(struct hostapd_data *hapd, struct sta_info *sta)
{
	struct sta_info *tmp;

	if (hapd->sta_list == sta) {
		hapd->sta_list = sta->next;
		return;
	}

	tmp = hapd->sta_list;
	while (tmp != NULL && tmp->next != sta)
		tmp = tmp->next;
	if (tmp == NULL) {
		wpa_warning_log4(MSG_DEBUG, "Could not remove STA " "%02x:xx:xx:%02x:%02x:%02x" " from "
			   "list.", (sta->addr)[0], (sta->addr)[3], (sta->addr)[4], (sta->addr)[5]);
	} else
		tmp->next = sta->next;
}

#ifndef HISI_CODE_CROP
void ap_sta_hash_add(struct hostapd_data *hapd, struct sta_info *sta)
{
	sta->hnext = hapd->sta_hash[STA_HASH(sta->addr)];
	hapd->sta_hash[STA_HASH(sta->addr)] = sta;
}


static void ap_sta_hash_del(struct hostapd_data *hapd, struct sta_info *sta)
{
	struct sta_info *s;

	s = hapd->sta_hash[STA_HASH(sta->addr)];
	if (s == NULL) return;
	if (os_memcmp(s->addr, sta->addr, 6) == 0) {
		hapd->sta_hash[STA_HASH(sta->addr)] = s->hnext;
		return;
	}

	while (s->hnext != NULL &&
	       os_memcmp(s->hnext->addr, sta->addr, ETH_ALEN) != 0)
		s = s->hnext;
	if (s->hnext != NULL) {
		s->hnext = s->hnext->hnext;
	}
	else {
		wpa_warning_log4(MSG_DEBUG, "AP: could not remove STA " "%02x:xx:xx:%02x:%02x:%02x"
			   " from hash table", (sta->addr)[0], (sta->addr)[3], (sta->addr)[4], (sta->addr)[5]);
	}
}

void sta_ip6addr_del(struct hostapd_data *hapd,
				   struct sta_info *sta)
{
	(void)hapd;
	(void)sta;
}
void ap_sta_ip6addr_del(struct hostapd_data *hapd, struct sta_info *sta)
{
	sta_ip6addr_del(hapd, sta);
}
#endif /* HISI_CODE_CROP */

void ap_free_sta(struct hostapd_data *hapd, struct sta_info *sta)
{
	int set_beacon = 0;

	accounting_sta_stop(hapd, sta);

	/* just in case */
	ap_sta_set_authorized(hapd, sta, 0);
#ifndef HISI_CODE_CROP
	if (sta->flags & WLAN_STA_WDS)
		(void)hostapd_set_wds_sta(hapd, NULL, sta->addr, sta->aid, 0);
#endif /* HISI_CODE_CROP */
#ifndef LOS_CONFIG_HISI_DRIVER_NOT_SUPPORT
	if (sta->ipaddr)
		(void)hostapd_drv_br_delete_ip_neigh(hapd, 4, (u8 *) &sta->ipaddr);
#endif /* LOS_CONFIG_HISI_DRIVER_NOT_SUPPORT */
#ifndef HISI_CODE_CROP
	ap_sta_ip6addr_del(hapd, sta);

	wpa_warning_log2(MSG_DEBUG, "ap_free_sta: hapd->iface->driver_ap_teardown = %d,sta->flags = %d",
						hapd->iface->driver_ap_teardown, sta->flags);
	if (!hapd->iface->driver_ap_teardown &&
	    !(sta->flags & WLAN_STA_PREAUTH)) {
#endif /* HISI_CODE_CROP */
		(void)hostapd_drv_sta_remove(hapd, sta->addr);
		sta->added_unassoc = 0;
#ifndef HISI_CODE_CROP
	}
#endif /* HISI_CODE_CROP */

#ifndef HISI_CODE_CROP
	ap_sta_hash_del(hapd, sta);
#endif /* HISI_CODE_CROP */
	ap_sta_list_del(hapd, sta);

#ifndef HISI_CODE_CROP
	if (sta->aid > 0)
		hapd->sta_aid[(sta->aid - 1) / 32] &=
			~(BIT((sta->aid - 1) % 32));
#else
	if (sta->aid > 0)
		hapd->sta_aid &= ~(BIT(sta->aid - 1));
#endif /* HISI_CODE_CROP */

	hapd->num_sta--;
#ifndef HISI_CODE_CROP
	if (sta->nonerp_set) {
		sta->nonerp_set = 0;
		hapd->iface->num_sta_non_erp--;
		if (hapd->iface->num_sta_non_erp == 0)
			set_beacon++;
	}

	if (sta->no_short_slot_time_set) {
		sta->no_short_slot_time_set = 0;
		hapd->iface->num_sta_no_short_slot_time--;
		if (hapd->iface->current_mode &&
		    hapd->iface->current_mode->mode == HOSTAPD_MODE_IEEE80211G
		    && hapd->iface->num_sta_no_short_slot_time == 0)
			set_beacon++;
	}

	if (sta->no_short_preamble_set) {
		sta->no_short_preamble_set = 0;
		hapd->iface->num_sta_no_short_preamble--;
		if (hapd->iface->current_mode &&
		    hapd->iface->current_mode->mode == HOSTAPD_MODE_IEEE80211G
		    && hapd->iface->num_sta_no_short_preamble == 0)
			set_beacon++;
	}

	if (sta->no_ht_gf_set) {
		sta->no_ht_gf_set = 0;
		hapd->iface->num_sta_ht_no_gf--;
	}

	if (sta->no_ht_set) {
		sta->no_ht_set = 0;
		hapd->iface->num_sta_no_ht--;
	}

	if (sta->ht_20mhz_set) {
		sta->ht_20mhz_set = 0;
		hapd->iface->num_sta_ht_20mhz--;
	}
#endif /* HISI_CODE_CROP */

#ifdef CONFIG_TAXONOMY
	wpabuf_free(sta->probe_ie_taxonomy);
	sta->probe_ie_taxonomy = NULL;
	wpabuf_free(sta->assoc_ie_taxonomy);
	sta->assoc_ie_taxonomy = NULL;
#endif /* CONFIG_TAXONOMY */

#ifndef HISI_CODE_CROP
#ifdef CONFIG_IEEE80211N
	ht40_intolerant_remove(hapd->iface, sta);
#endif /* CONFIG_IEEE80211N */
#endif /* HISI_CODE_CROP */

#ifdef CONFIG_P2P
	if (sta->no_p2p_set) {
		sta->no_p2p_set = 0;
		hapd->num_sta_no_p2p--;
		if (hapd->num_sta_no_p2p == 0)
			hostapd_p2p_non_p2p_sta_disconnected(hapd);
	}
#endif /* CONFIG_P2P */

#ifndef HISI_CODE_CROP
#if defined(NEED_AP_MLME) && defined(CONFIG_IEEE80211N)
	if (hostapd_ht_operation_update(hapd->iface) > 0)
		set_beacon++;
#endif /* NEED_AP_MLME && CONFIG_IEEE80211N */
#endif /* HISI_CODE_CROP */

#ifdef CONFIG_MESH
	if (hapd->mesh_sta_free_cb)
		hapd->mesh_sta_free_cb(hapd, sta);
#endif /* CONFIG_MESH */

	if (set_beacon)
		(void)ieee802_11_set_beacons(hapd->iface);

	wpa_warning_log4(MSG_DEBUG, "ap_free_sta: cancel ap_handle_timer for " "%02x:xx:xx:%02x:%02x:%02x",
		   (sta->addr)[0], (sta->addr)[3], (sta->addr)[4], (sta->addr)[5]);
	(void)eloop_cancel_timeout(ap_handle_timer, hapd, sta);
	(void)eloop_cancel_timeout(ap_handle_session_timer, hapd, sta);
	(void)eloop_cancel_timeout(ap_handle_session_warning_timer, hapd, sta);
	ap_sta_clear_disconnect_timeouts(hapd, sta);
	sae_clear_retransmit_timer(hapd, sta);

	ieee802_1x_free_station(hapd, sta);
	wpa_auth_sta_deinit(sta->wpa_sm);
	rsn_preauth_free_station(hapd, sta);
#ifndef CONFIG_NO_RADIUS
	if (hapd->radius)
		radius_client_flush_auth(hapd->radius, sta->addr);
#endif /* CONFIG_NO_RADIUS */

#ifndef CONFIG_NO_VLAN
	/*
	 * sta->wpa_sm->group needs to be released before so that
	 * vlan_remove_dynamic() can check that no stations are left on the
	 * AP_VLAN netdev.
	 */
	if (sta->vlan_id)
		vlan_remove_dynamic(hapd, sta->vlan_id);
	if (sta->vlan_id_bound) {
		/*
		 * Need to remove the STA entry before potentially removing the
		 * VLAN.
		 */
		if (hapd->iface->driver_ap_teardown &&
		    !(sta->flags & WLAN_STA_PREAUTH)) {
			hostapd_drv_sta_remove(hapd, sta->addr);
			sta->added_unassoc = 0;
		}
		vlan_remove_dynamic(hapd, sta->vlan_id_bound);
	}
#endif /* CONFIG_NO_VLAN */

	os_free(sta->challenge);

#ifdef CONFIG_IEEE80211W_AP
	os_free(sta->sa_query_trans_id);
	(void)eloop_cancel_timeout(ap_sa_query_timer, hapd, sta);
#endif /* CONFIG_IEEE80211W_AP */

#ifdef CONFIG_P2P
	p2p_group_notif_disassoc(hapd->p2p_group, sta->addr);
#endif /* CONFIG_P2P */
#ifndef HISI_CODE_CROP
#ifdef CONFIG_INTERWORKING
	if (sta->gas_dialog) {
		int i;
		for (i = 0; i < GAS_DIALOG_MAX; i++)
			gas_serv_dialog_clear(&sta->gas_dialog[i]);
		os_free(sta->gas_dialog);
	}
#endif /* CONFIG_INTERWORKING */
#endif
	wpabuf_free(sta->wps_ie);
#ifdef CONFIG_P2P
	wpabuf_free(sta->p2p_ie);
#endif /* CONFIG_P2P */
#ifndef HISI_CODE_CROP
	wpabuf_free(sta->hs20_ie);
	wpabuf_free(sta->roaming_consortium);
#endif /* HISI_CODE_CROP */
#ifdef CONFIG_FST
	wpabuf_free(sta->mb_ies);
#endif /* CONFIG_FST */

#ifndef HISI_CODE_CROP
	os_free(sta->ht_capabilities);
	os_free(sta->vht_capabilities);
	hostapd_free_psk_list(sta->psk);
#endif /* HISI_CODE_CROP */
	os_free(sta->identity);
#ifndef HISI_CODE_CROP
	os_free(sta->radius_cui);
	os_free(sta->remediation_url);
	os_free(sta->t_c_url);
	wpabuf_free(sta->hs20_deauth_req);
	os_free(sta->hs20_session_info_url);
#endif /* HISI_CODE_CROP */

#ifdef CONFIG_SAE
	sae_clear_data(sta->sae);
	os_free(sta->sae);
#endif /* CONFIG_SAE */

	mbo_ap_sta_free(sta);
#ifndef HISI_CODE_CROP
	os_free(sta->supp_op_classes);

#ifdef CONFIG_FILS
	os_free(sta->fils_pending_assoc_req);
	wpabuf_free(sta->fils_hlp_resp);
	wpabuf_free(sta->hlp_dhcp_discover);
	eloop_cancel_timeout(fils_hlp_timeout, hapd, sta);
#ifdef CONFIG_FILS_SK_PFS
	crypto_ecdh_deinit(sta->fils_ecdh);
	wpabuf_clear_free(sta->fils_dh_ss);
	wpabuf_free(sta->fils_g_sta);
#endif /* CONFIG_FILS_SK_PFS */
#endif /* CONFIG_FILS */

#ifdef CONFIG_OWE
	bin_clear_free(sta->owe_pmk, sta->owe_pmk_len);
	crypto_ecdh_deinit(sta->owe_ecdh);
#endif /* CONFIG_OWE */
#endif /* HISI_CODE_CROP */
	os_free(sta->ext_capability);

#ifdef CONFIG_WNM_AP
	eloop_cancel_timeout(ap_sta_reset_steer_flag_timer, hapd, sta);
#endif /* CONFIG_WNM_AP */

#ifndef HISI_CODE_CROP
	os_free(sta->ifname_wds);
#endif /* HISI_CODE_CROP */
	os_free(sta);
}


void hostapd_free_stas(struct hostapd_data *hapd)
{
	struct sta_info *sta, *prev;

	sta = hapd->sta_list;

	while (sta) {
		prev = sta;
		if (sta->flags & WLAN_STA_AUTH) {
			mlme_deauthenticate_indication(
				hapd, sta, WLAN_REASON_UNSPECIFIED);
		}
		sta = sta->next;
		wpa_warning_log4(MSG_DEBUG, "Removing station " "%02x:xx:xx:%02x:%02x:%02x",
			   (prev->addr)[0], (prev->addr)[3], (prev->addr)[4], (prev->addr)[5]);
		ap_free_sta(hapd, prev);
	}
}


/**
 * ap_handle_timer - Per STA timer handler
 * @eloop_ctx: struct hostapd_data *
 * @timeout_ctx: struct sta_info *
 *
 * This function is called to check station activity and to remove inactive
 * stations.
 */
void ap_handle_timer(void *eloop_ctx, void *timeout_ctx)
{
	struct hostapd_data *hapd = eloop_ctx;
	struct sta_info *sta = timeout_ctx;
	unsigned long next_time = 0;
	int reason;

	wpa_warning_buf(MSG_DEBUG, "%s: ap_handle_timer: ",
		   hapd->conf->iface, strlen(hapd->conf->iface));
	wpa_warning_log4(MSG_DEBUG, "%02x:xx:xx:%02x:%02x:%02x",
		   (sta->addr)[0], (sta->addr)[3], (sta->addr)[4], (sta->addr)[5]);
	wpa_warning_log2(MSG_DEBUG, " flags=0x%x timeout_next=%d",
		   sta->flags, sta->timeout_next);
	if (sta->timeout_next == STA_REMOVE) {
		hostapd_logger(hapd, sta->addr, HOSTAPD_MODULE_IEEE80211,
			       HOSTAPD_LEVEL_INFO, "deauthenticated due to "
			       "local deauth request");
		ap_free_sta(hapd, sta);
		return;
	}

	if ((sta->flags & WLAN_STA_ASSOC) &&
	    (sta->timeout_next == STA_NULLFUNC ||
	     sta->timeout_next == STA_DISASSOC)) {
#ifndef LOS_CONFIG_HISI_DRIVER_NOT_SUPPORT
		int inactive_sec;
		/*
		 * Add random value to timeout so that we don't end up bouncing
		 * all stations at the same time if we have lots of associated
		 * stations that are idle (but keep re-associating).
		 */
		int fuzz = os_random() % 20;
		inactive_sec = hostapd_drv_get_inact_sec(hapd, sta->addr);
		if (inactive_sec == -1) {
			wpa_msg(hapd->msg_ctx, MSG_DEBUG,
				"Check inactivity: Could not "
				"get station info from kernel driver for "
				MACSTR, MAC2STR(sta->addr));
			/*
			 * The driver may not support this functionality.
			 * Anyway, try again after the next inactivity timeout,
			 * but do not disconnect the station now.
			 */
			next_time = hapd->conf->ap_max_inactivity + fuzz;
		} else if (inactive_sec == -ENOENT) {
			wpa_msg(hapd->msg_ctx, MSG_DEBUG,
				"Station " MACSTR " has lost its driver entry",
				MAC2STR(sta->addr));

			/* Avoid sending client probe on removed client */
			sta->timeout_next = STA_DISASSOC;
			goto skip_poll;
		} else if (inactive_sec < hapd->conf->ap_max_inactivity) {
			/* station activity detected; reset timeout state */
#ifndef HISI_CODE_CROP
			wpa_msg(hapd->msg_ctx, MSG_DEBUG,
				"Station " MACSTR " has been active %is ago",
				MAC2STR(sta->addr), inactive_sec);
#endif
			sta->timeout_next = STA_NULLFUNC;
			next_time = hapd->conf->ap_max_inactivity + fuzz -
				inactive_sec;
		} else {
			wpa_msg(hapd->msg_ctx, MSG_DEBUG,
				"Station " MACSTR " has been "
				"inactive too long: %d sec, max allowed: %d",
				MAC2STR(sta->addr), inactive_sec,
				hapd->conf->ap_max_inactivity);

			if (hapd->conf->skip_inactivity_poll)
				sta->timeout_next = STA_DISASSOC;
		}
#else
	int fuzz = os_random() % 20;
	sta->timeout_next = STA_NULLFUNC;
	next_time = hapd->conf->ap_max_inactivity + fuzz;
#endif /* LOS_CONFIG_HISI_DRIVER_NOT_SUPPORT */
	}

#ifndef HISI_CODE_CROP
	if ((sta->flags & WLAN_STA_ASSOC) &&
	    sta->timeout_next == STA_DISASSOC &&
	    !(sta->flags & WLAN_STA_PENDING_POLL) &&
	    !hapd->conf->skip_inactivity_poll) {
#else
	if ((sta->flags & WLAN_STA_ASSOC) &&
		sta->timeout_next == STA_DISASSOC &&
		!(sta->flags & WLAN_STA_PENDING_POLL)) {
#endif /* HISI_CODE_CROP */
		wpa_msg(hapd->msg_ctx, MSG_DEBUG, "Station " MACSTR
			" has ACKed data poll", MAC2STR(sta->addr));
		/* data nullfunc frame poll did not produce TX errors; assume
		 * station ACKed it */
		sta->timeout_next = STA_NULLFUNC;
		next_time = hapd->conf->ap_max_inactivity;
	}

#ifndef LOS_CONFIG_HISI_DRIVER_NOT_SUPPORT
skip_poll:
#endif /* LOS_CONFIG_HISI_DRIVER_NOT_SUPPORT */
	if (next_time) {
		wpa_warning_log4(MSG_DEBUG, "ap_handle_timer: register ap_handle_timer timeout "
			   "for " "%02x:xx:xx:%02x:%02x:%02x",
			   (sta->addr)[0], (sta->addr)[3], (sta->addr)[4], (sta->addr)[5]);
		wpa_warning_log1(MSG_DEBUG, " (%lu seconds)",
				next_time);
		(void)eloop_register_timeout(next_time, 0, ap_handle_timer, hapd,
				       sta);
		return;
	}

	if (sta->timeout_next == STA_NULLFUNC &&
	    (sta->flags & WLAN_STA_ASSOC)) {
		wpa_warning_log0(MSG_DEBUG, "  Polling STA");
		sta->flags |= WLAN_STA_PENDING_POLL;
#ifndef LOS_CONFIG_HISI_DRIVER_NOT_SUPPORT
		hostapd_drv_poll_client(hapd, hapd->own_addr, sta->addr,
					sta->flags & WLAN_STA_WMM);
#endif /* LOS_CONFIG_HISI_DRIVER_NOT_SUPPORT */
	}
#ifndef HISI_CODE_CROP
	else if (sta->timeout_next != STA_REMOVE) {
		int deauth = sta->timeout_next == STA_DEAUTH;

		wpa_dbg(hapd->msg_ctx, MSG_DEBUG,
			"Timeout, sending %s info to STA " MACSTR,
			deauth ? "deauthentication" : "disassociation",
			MAC2STR(sta->addr));

		if (deauth) {
			(void)hostapd_drv_sta_deauth(
				hapd, sta->addr,
				WLAN_REASON_PREV_AUTH_NOT_VALID);
		} else {
			reason = (sta->timeout_next == STA_DISASSOC) ?
				WLAN_REASON_DISASSOC_DUE_TO_INACTIVITY :
				WLAN_REASON_PREV_AUTH_NOT_VALID;

			(void)hostapd_drv_sta_disassoc(hapd, sta->addr, reason);
		}
	}
#endif
	switch (sta->timeout_next) {
	case STA_NULLFUNC:
		sta->timeout_next = STA_DISASSOC;
		wpa_warning_log4(MSG_DEBUG, "ap_handle_timer: register ap_handle_timer timeout "
			   "for " "%02x:xx:xx:%02x:%02x:%02x",
			   (sta->addr)[0], (sta->addr)[3], (sta->addr)[4], (sta->addr)[5]);
		wpa_warning_log1(MSG_DEBUG, " (%d seconds - AP_DISASSOC_DELAY)",
			   AP_DISASSOC_DELAY);
		(void)eloop_register_timeout(AP_DISASSOC_DELAY, 0, ap_handle_timer,
				       hapd, sta);
		break;
	case STA_DISASSOC:
	case STA_DISASSOC_FROM_CLI:
		ap_sta_set_authorized(hapd, sta, 0);
		sta->flags &= ~WLAN_STA_ASSOC;
		ieee802_1x_notify_port_enabled(sta->eapol_sm, 0);
#ifndef HISI_CODE_CROP
		if (!sta->acct_terminate_cause)
			sta->acct_terminate_cause =
				RADIUS_ACCT_TERMINATE_CAUSE_IDLE_TIMEOUT;
#endif
		accounting_sta_stop(hapd, sta);
		ieee802_1x_free_station(hapd, sta);
		hostapd_logger(hapd, sta->addr, HOSTAPD_MODULE_IEEE80211,
			       HOSTAPD_LEVEL_INFO, "disassociated due to "
			       "inactivity");
		reason = (sta->timeout_next == STA_DISASSOC) ?
			WLAN_REASON_DISASSOC_DUE_TO_INACTIVITY :
			WLAN_REASON_PREV_AUTH_NOT_VALID;
		sta->timeout_next = STA_DEAUTH;
		wpa_warning_log4(MSG_DEBUG, "ap_handle_timer: register ap_handle_timer timeout "
			   "for " "%02x:xx:xx:%02x:%02x:%02x",
			   (sta->addr)[0], (sta->addr)[3], (sta->addr)[4], (sta->addr)[5]);
		wpa_warning_log1(MSG_DEBUG, " (%d seconds - AP_DEAUTH_DELAY)", AP_DEAUTH_DELAY);
		(void)eloop_register_timeout(AP_DEAUTH_DELAY, 0, ap_handle_timer,
				       hapd, sta);
		mlme_disassociate_indication(hapd, sta, reason);
		break;
	case STA_DEAUTH:
	case STA_REMOVE:
#ifndef HISI_CODE_CROP
		hostapd_logger(hapd, sta->addr, HOSTAPD_MODULE_IEEE80211,
			       HOSTAPD_LEVEL_INFO, "deauthenticated due to "
			       "inactivity (timer DEAUTH/REMOVE)");
		if (!sta->acct_terminate_cause)
			sta->acct_terminate_cause =
				RADIUS_ACCT_TERMINATE_CAUSE_IDLE_TIMEOUT;
#endif
		mlme_deauthenticate_indication(
			hapd, sta,
			WLAN_REASON_PREV_AUTH_NOT_VALID);
		ap_free_sta(hapd, sta);
		break;
	}
}


static void ap_handle_session_timer(void *eloop_ctx, void *timeout_ctx)
{
	struct hostapd_data *hapd = eloop_ctx;
	struct sta_info *sta = timeout_ctx;

#ifndef CONFIG_PRINT_NOUSE
	wpa_printf(MSG_DEBUG, "%s: Session timer for STA " MACSTR,
		   hapd->conf->iface, MAC2STR(sta->addr));
#endif /* CONFIG_PRINT_NOUSE */
	if (!(sta->flags & WLAN_STA_AUTH)) {
		if (sta->flags & WLAN_STA_GAS) {
#ifndef CONFIG_PRINT_NOUSE
			wpa_printf(MSG_DEBUG, "GAS: Remove temporary STA "
				   "entry " MACSTR, MAC2STR(sta->addr));
#endif /* CONFIG_PRINT_NOUSE */
			ap_free_sta(hapd, sta);
		}
		return;
	}
#ifndef HISI_CODE_CROP
	(void)hostapd_drv_sta_deauth(hapd, sta->addr,
			       WLAN_REASON_PREV_AUTH_NOT_VALID);
#endif
	mlme_deauthenticate_indication(hapd, sta,
				       WLAN_REASON_PREV_AUTH_NOT_VALID);
#ifndef HISI_CODE_CROP
	hostapd_logger(hapd, sta->addr, HOSTAPD_MODULE_IEEE80211,
		       HOSTAPD_LEVEL_INFO, "deauthenticated due to "
		       "session timeout");
	sta->acct_terminate_cause =
		RADIUS_ACCT_TERMINATE_CAUSE_SESSION_TIMEOUT;
#endif
	ap_free_sta(hapd, sta);
}


void ap_sta_replenish_timeout(struct hostapd_data *hapd, struct sta_info *sta,
			      u32 session_timeout)
{
	if (eloop_replenish_timeout(session_timeout, 0,
				    ap_handle_session_timer, hapd, sta) == 1) {
		hostapd_logger(hapd, sta->addr, HOSTAPD_MODULE_IEEE80211,
			       HOSTAPD_LEVEL_DEBUG, "setting session timeout "
			       "to %d seconds", session_timeout);
	}
}


void ap_sta_session_timeout(struct hostapd_data *hapd, struct sta_info *sta,
			    u32 session_timeout)
{
	hostapd_logger(hapd, sta->addr, HOSTAPD_MODULE_IEEE80211,
		       HOSTAPD_LEVEL_DEBUG, "setting session timeout to %d "
		       "seconds", session_timeout);
	(void)eloop_cancel_timeout(ap_handle_session_timer, hapd, sta);
	(void)eloop_register_timeout(session_timeout, 0, ap_handle_session_timer,
			       hapd, sta);
}


void ap_sta_no_session_timeout(struct hostapd_data *hapd, struct sta_info *sta)
{
	(void)eloop_cancel_timeout(ap_handle_session_timer, hapd, sta);
}


static void ap_handle_session_warning_timer(void *eloop_ctx, void *timeout_ctx)
{
#ifdef CONFIG_WNM_AP
	struct hostapd_data *hapd = eloop_ctx;
	struct sta_info *sta = timeout_ctx;

	wpa_printf(MSG_DEBUG, "%s: WNM: Session warning time reached for "
		   MACSTR, hapd->conf->iface, MAC2STR(sta->addr));
	if (sta->hs20_session_info_url == NULL)
		return;

	wnm_send_ess_disassoc_imminent(hapd, sta, sta->hs20_session_info_url,
				       sta->hs20_disassoc_timer);
#else
	(void)eloop_ctx;
	(void)timeout_ctx;
#endif /* CONFIG_WNM_AP */
}


void ap_sta_session_warning_timeout(struct hostapd_data *hapd,
				    struct sta_info *sta, int warning_time)
{
	(void)eloop_cancel_timeout(ap_handle_session_warning_timer, hapd, sta);
	(void)eloop_register_timeout(warning_time, 0, ap_handle_session_warning_timer,
			       hapd, sta);
}


struct sta_info * ap_sta_add(struct hostapd_data *hapd, const u8 *addr)
{
	struct sta_info *sta;

	sta = ap_get_sta(hapd, addr);
	if (sta)
		return sta;

	wpa_warning_log0(MSG_DEBUG, "  New STA");
	if (hapd->num_sta >= hapd->conf->max_num_sta) {
		/* FIX: might try to remove some old STAs first? */
		wpa_warning_log2(MSG_DEBUG, "no more room for new STAs (%d/%d)",
			   hapd->num_sta, hapd->conf->max_num_sta);
		return NULL;
	}

	sta = os_zalloc(sizeof(struct sta_info));
	if (sta == NULL) {
		wpa_error_log0(MSG_ERROR, "malloc failed");
		return NULL;
	}
#ifndef CONFIG_PRINT_NOUSE
	sta->acct_interim_interval = hapd->conf->acct_interim_interval;
#endif /* CONFIG_PRINT_NOUSE */
	if (accounting_sta_get_id(hapd, sta) < 0) {
		os_free(sta);
		return NULL;
	}

	if (!(hapd->iface->drv_flags & WPA_DRIVER_FLAGS_INACTIVITY_TIMER)) {
		wpa_warning_log4(MSG_DEBUG, "ap_sta_add: register ap_handle_timer timeout "
			   "for " "%02x:xx:xx:%02x:%02x:%02x",
			   addr[0], addr[3], addr[4], addr[5]);
		wpa_warning_log1(MSG_DEBUG," (%d seconds - ap_max_inactivity)",
			   hapd->conf->ap_max_inactivity);
		(void)eloop_register_timeout(hapd->conf->ap_max_inactivity, 0,
				       ap_handle_timer, hapd, sta);
	}

	/* initialize STA info data */
	(void)os_memcpy(sta->addr, addr, ETH_ALEN);
	sta->next = hapd->sta_list;
	hapd->sta_list = sta;
	hapd->num_sta++;
#ifndef HISI_CODE_CROP
	ap_sta_hash_add(hapd, sta);
#endif /* HISI_CODE_CROP */
	ap_sta_remove_in_other_bss(hapd, sta);
	sta->last_seq_ctrl = WLAN_INVALID_MGMT_SEQ;
#ifndef HISI_CODE_CROP
	dl_list_init(&sta->ip6addr);
#endif /* HISI_CODE_CROP */

#ifdef CONFIG_TAXONOMY
	sta_track_claim_taxonomy_info(hapd->iface, addr,
				      &sta->probe_ie_taxonomy);
#endif /* CONFIG_TAXONOMY */

	return sta;
}


static int ap_sta_remove(struct hostapd_data *hapd, struct sta_info *sta)
{
	ieee802_1x_notify_port_enabled(sta->eapol_sm, 0);

#ifndef LOS_CONFIG_HISI_DRIVER_NOT_SUPPORT
	if (sta->ipaddr)
		(void)hostapd_drv_br_delete_ip_neigh(hapd, 4, (u8 *) &sta->ipaddr);
#endif /* LOS_CONFIG_HISI_DRIVER_NOT_SUPPORT */
#ifndef HISI_CODE_CROP
	ap_sta_ip6addr_del(hapd, sta);
#endif /* HISI_CODE_CROP */

	wpa_error_buf(MSG_DEBUG, "%s: Removing STA ",
		   hapd->conf->iface, strlen(hapd->conf->iface));
	wpa_error_log4(MSG_DEBUG, "%02x:xx:xx:%02x:%02x:%02x" " from kernel driver",
		   (sta->addr)[0], (sta->addr)[3], (sta->addr)[4], (sta->addr)[5]);
	if (hostapd_drv_sta_remove(hapd, sta->addr) &&
	    sta->flags & WLAN_STA_ASSOC) {
		wpa_warning_buf(MSG_DEBUG, "%s: Could not remove station ",
			   hapd->conf->iface, strlen(hapd->conf->iface));
		wpa_warning_log4(MSG_DEBUG, "%02x:xx:xx:%02x:%02x:%02x"
			   " from kernel driver",
			   (sta->addr)[0], (sta->addr)[3], (sta->addr)[4], (sta->addr)[5]);
		return -1;
	}
	sta->added_unassoc = 0;
	return 0;
}


static void ap_sta_remove_in_other_bss(struct hostapd_data *hapd,
				       struct sta_info *sta)
{
	struct hostapd_iface *iface = hapd->iface;
	size_t i;

	for (i = 0; i < iface->num_bss; i++) {
		struct hostapd_data *bss = iface->bss[i];
		struct sta_info *sta2;
		/* bss should always be set during operation, but it may be
		 * NULL during reconfiguration. Assume the STA is not
		 * associated to another BSS in that case to avoid NULL pointer
		 * dereferences. */
		if (bss == hapd || bss == NULL)
			continue;
		sta2 = ap_get_sta(bss, sta->addr);
		if (!sta2)
			continue;

		wpa_warning_two_buf(MSG_DEBUG, "%s: disconnect old STA "
			   " association from another BSS %s",
			   hapd->conf->iface, strlen(hapd->conf->iface),
			   bss->conf->iface, strlen(bss->conf->iface));
		wpa_warning_log4(MSG_DEBUG, "%02x:xx:xx:%02x:%02x:%02x",
			   (sta2->addr)[0], (sta2->addr)[3], (sta2->addr)[4], (sta2->addr)[5]);
		ap_sta_disconnect(bss, sta2, sta2->addr,
				  WLAN_REASON_PREV_AUTH_NOT_VALID);
	}
}


static void ap_sta_disassoc_cb_timeout(void *eloop_ctx, void *timeout_ctx)
{
	struct hostapd_data *hapd = eloop_ctx;
	struct sta_info *sta = timeout_ctx;

	wpa_warning_buf(MSG_DEBUG, "%s: Disassociation callback for STA ",
		   hapd->conf->iface, strlen(hapd->conf->iface));
	wpa_warning_log4(MSG_DEBUG, "%02x:xx:xx:%02x:%02x:%02x",
		   (sta->addr)[0], (sta->addr)[3], (sta->addr)[4], (sta->addr)[5]);
	(void)ap_sta_remove(hapd, sta);
	mlme_disassociate_indication(hapd, sta, sta->disassoc_reason);
}


void ap_sta_disassociate(struct hostapd_data *hapd, struct sta_info *sta,
			 u16 reason)
{
	wpa_warning_buf(MSG_DEBUG, "%s: disassociate STA ",
		   hapd->conf->iface, strlen(hapd->conf->iface));
	wpa_warning_log4(MSG_DEBUG, "%02x:xx:xx:%02x:%02x:%02x",
			   (sta->addr)[0], (sta->addr)[3], (sta->addr)[4], (sta->addr)[5]);
	sta->last_seq_ctrl = WLAN_INVALID_MGMT_SEQ;
#ifndef HISI_CODE_CROP
	if (hapd->iface->current_mode &&
	    hapd->iface->current_mode->mode == HOSTAPD_MODE_IEEE80211AD) {
		/* Skip deauthentication in DMG/IEEE 802.11ad */
		sta->flags &= ~(WLAN_STA_AUTH | WLAN_STA_ASSOC |
				WLAN_STA_ASSOC_REQ_OK);
		sta->timeout_next = STA_REMOVE;
	} else {
		sta->flags &= ~(WLAN_STA_ASSOC | WLAN_STA_ASSOC_REQ_OK);
		sta->timeout_next = STA_DEAUTH;
	}
#else
	sta->flags &= ~(WLAN_STA_ASSOC | WLAN_STA_ASSOC_REQ_OK);
		sta->timeout_next = STA_DEAUTH;
#endif
	ap_sta_set_authorized(hapd, sta, 0);
	wpa_warning_log4(MSG_DEBUG, "ap_sta_disassociate: reschedule ap_handle_timer timeout "
		   "for " "%02x:xx:xx:%02x:%02x:%02x",
		   (sta->addr)[0], (sta->addr)[3], (sta->addr)[4], (sta->addr)[5]);
	wpa_warning_log1(MSG_DEBUG, " (%d seconds - "
		   "AP_MAX_INACTIVITY_AFTER_DISASSOC)",
		   AP_MAX_INACTIVITY_AFTER_DISASSOC);
	(void)eloop_cancel_timeout(ap_handle_timer, hapd, sta);
	(void)eloop_register_timeout(AP_MAX_INACTIVITY_AFTER_DISASSOC, 0,
			       ap_handle_timer, hapd, sta);
	accounting_sta_stop(hapd, sta);
	ieee802_1x_free_station(hapd, sta);

	sta->disassoc_reason = reason;
	sta->flags |= WLAN_STA_PENDING_DISASSOC_CB;
	(void)eloop_cancel_timeout(ap_sta_disassoc_cb_timeout, hapd, sta);
	(void)eloop_register_timeout(hapd->iface->drv_flags &
			       WPA_DRIVER_FLAGS_DEAUTH_TX_STATUS ? 2 : 0, 0,
			       ap_sta_disassoc_cb_timeout, hapd, sta);
}


static void ap_sta_deauth_cb_timeout(void *eloop_ctx, void *timeout_ctx)
{
	struct hostapd_data *hapd = eloop_ctx;
	struct sta_info *sta = timeout_ctx;

	wpa_warning_buf(MSG_DEBUG, "%s: Deauthentication callback for STA ",
		   hapd->conf->iface, strlen(hapd->conf->iface));
	wpa_warning_log4(MSG_DEBUG, "%02x:xx:xx:%02x:%02x:%02x",
		   (sta->addr)[0], (sta->addr)[3], (sta->addr)[4], (sta->addr)[5]);
	(void)ap_sta_remove(hapd, sta);
	mlme_deauthenticate_indication(hapd, sta, sta->deauth_reason);
}


void ap_sta_deauthenticate(struct hostapd_data *hapd, struct sta_info *sta,
			   u16 reason)
{
#ifndef HISI_CODE_CROP
	if (hapd->iface->current_mode &&
	    hapd->iface->current_mode->mode == HOSTAPD_MODE_IEEE80211AD) {
		/* Deauthentication is not used in DMG/IEEE 802.11ad;
		 * disassociate the STA instead. */
		ap_sta_disassociate(hapd, sta, reason);
		return;
	}
#endif
	wpa_warning_buf(MSG_DEBUG, "%s: deauthenticate STA ",
		   hapd->conf->iface, strlen(hapd->conf->iface));
	wpa_warning_log4(MSG_DEBUG, "%02x:xx:xx:%02x:%02x:%02x",
		   (sta->addr)[0], (sta->addr)[3], (sta->addr)[4], (sta->addr)[5]);
	sta->last_seq_ctrl = WLAN_INVALID_MGMT_SEQ;
	sta->flags &= ~(WLAN_STA_AUTH | WLAN_STA_ASSOC | WLAN_STA_ASSOC_REQ_OK);
	ap_sta_set_authorized(hapd, sta, 0);
	sta->timeout_next = STA_REMOVE;
	wpa_warning_log4(MSG_DEBUG, "ap_sta_deauthenticate: reschedule ap_handle_timer timeout "
		   "for " "%02x:xx:xx:%02x:%02x:%02x",
		   (sta->addr)[0], (sta->addr)[3], (sta->addr)[4], (sta->addr)[5]);
	wpa_warning_log1(MSG_DEBUG, " (%d seconds - "
		   "AP_MAX_INACTIVITY_AFTER_DEAUTH)",
		   AP_MAX_INACTIVITY_AFTER_DEAUTH);
	(void)eloop_cancel_timeout(ap_handle_timer, hapd, sta);
	(void)eloop_register_timeout(AP_MAX_INACTIVITY_AFTER_DEAUTH, 0,
			       ap_handle_timer, hapd, sta);
	accounting_sta_stop(hapd, sta);
	ieee802_1x_free_station(hapd, sta);

	sta->deauth_reason = reason;
	sta->flags |= WLAN_STA_PENDING_DEAUTH_CB;
	(void)eloop_cancel_timeout(ap_sta_deauth_cb_timeout, hapd, sta);
	(void)eloop_register_timeout(hapd->iface->drv_flags &
			       WPA_DRIVER_FLAGS_DEAUTH_TX_STATUS ? 2 : 0, 0,
			       ap_sta_deauth_cb_timeout, hapd, sta);
}


#ifdef CONFIG_WPS
int ap_sta_wps_cancel(struct hostapd_data *hapd,
		      struct sta_info *sta, void *ctx)
{
	(void)ctx;
	if (sta && (sta->flags & WLAN_STA_WPS)) {
		ap_sta_deauthenticate(hapd, sta,
				      WLAN_REASON_PREV_AUTH_NOT_VALID);
		wpa_warning_log4(MSG_DEBUG, "WPS: ap_sta_wps_cancel: Deauth sta=" "%02x:xx:xx:%02x:%02x:%02x",
			   (sta->addr)[0], (sta->addr)[3], (sta->addr)[4], (sta->addr)[5]);
		return 1;
	}

	return 0;
}
#endif /* CONFIG_WPS */
#ifndef LOS_CONFIG_NO_VLAN

static int ap_sta_get_free_vlan_id(struct hostapd_data *hapd)
{
	struct hostapd_vlan *vlan;
	int vlan_id = MAX_VLAN_ID + 2;

retry:
	for (vlan = hapd->conf->vlan; vlan; vlan = vlan->next) {
		if (vlan->vlan_id == vlan_id) {
			vlan_id++;
			goto retry;
		}
	}
	return vlan_id;
}


int ap_sta_set_vlan(struct hostapd_data *hapd, struct sta_info *sta,
		    struct vlan_description *vlan_desc)
{
	struct hostapd_vlan *vlan = NULL, *wildcard_vlan = NULL;
	int old_vlan_id, vlan_id = 0, ret = 0;

	if (hapd->conf->ssid.dynamic_vlan == DYNAMIC_VLAN_DISABLED)
		vlan_desc = NULL;

	/* Check if there is something to do */
	if (hapd->conf->ssid.per_sta_vif && !sta->vlan_id) {
		/* This sta is lacking its own vif */
	} else if (hapd->conf->ssid.dynamic_vlan == DYNAMIC_VLAN_DISABLED &&
		   !hapd->conf->ssid.per_sta_vif && sta->vlan_id) {
		/* sta->vlan_id needs to be reset */
	} else if (!vlan_compare(vlan_desc, sta->vlan_desc)) {
		return 0; /* nothing to change */
	}

	/* Now the real VLAN changed or the STA just needs its own vif */
	if (hapd->conf->ssid.per_sta_vif) {
		/* Assign a new vif, always */
		/* find a free vlan_id sufficiently big */
		vlan_id = ap_sta_get_free_vlan_id(hapd);
		/* Get wildcard VLAN */
		for (vlan = hapd->conf->vlan; vlan; vlan = vlan->next) {
			if (vlan->vlan_id == VLAN_ID_WILDCARD)
				break;
		}
		if (!vlan) {
			hostapd_logger(hapd, sta->addr,
				       HOSTAPD_MODULE_IEEE80211,
				       HOSTAPD_LEVEL_DEBUG,
				       "per_sta_vif missing wildcard");
			vlan_id = 0;
			ret = -1;
			goto done;
		}
	} else if (vlan_desc && vlan_desc->notempty) {
		for (vlan = hapd->conf->vlan; vlan; vlan = vlan->next) {
			if (!vlan_compare(&vlan->vlan_desc, vlan_desc))
				break;
			if (vlan->vlan_id == VLAN_ID_WILDCARD)
				wildcard_vlan = vlan;
		}
		if (vlan) {
			vlan_id = vlan->vlan_id;
		} else if (wildcard_vlan) {
			vlan = wildcard_vlan;
			vlan_id = vlan_desc->untagged;
			if (vlan_desc->tagged[0]) {
				/* Tagged VLAN configuration */
				vlan_id = ap_sta_get_free_vlan_id(hapd);
			}
		} else {
			hostapd_logger(hapd, sta->addr,
				       HOSTAPD_MODULE_IEEE80211,
				       HOSTAPD_LEVEL_DEBUG,
				       "missing vlan and wildcard for vlan=%d%s",
				       vlan_desc->untagged,
				       vlan_desc->tagged[0] ? "+" : "");
			vlan_id = 0;
			ret = -1;
			goto done;
		}
	}

	if (vlan && vlan->vlan_id == VLAN_ID_WILDCARD) {
		vlan = vlan_add_dynamic(hapd, vlan, vlan_id, vlan_desc);
		if (vlan == NULL) {
			hostapd_logger(hapd, sta->addr,
				       HOSTAPD_MODULE_IEEE80211,
				       HOSTAPD_LEVEL_DEBUG,
				       "could not add dynamic VLAN interface for vlan=%d%s",
				       vlan_desc ? vlan_desc->untagged : -1,
				       (vlan_desc && vlan_desc->tagged[0]) ?
				       "+" : "");
			vlan_id = 0;
			ret = -1;
			goto done;
		}

		hostapd_logger(hapd, sta->addr, HOSTAPD_MODULE_IEEE80211,
			       HOSTAPD_LEVEL_DEBUG,
			       "added new dynamic VLAN interface '%s'",
			       vlan->ifname);
	} else if (vlan && vlan->dynamic_vlan > 0) {
		vlan->dynamic_vlan++;
		hostapd_logger(hapd, sta->addr,
			       HOSTAPD_MODULE_IEEE80211,
			       HOSTAPD_LEVEL_DEBUG,
			       "updated existing dynamic VLAN interface '%s'",
			       vlan->ifname);
	}
done:
	old_vlan_id = sta->vlan_id;
	sta->vlan_id = vlan_id;
	sta->vlan_desc = vlan ? &vlan->vlan_desc : NULL;

	if (vlan_id != old_vlan_id && old_vlan_id)
		(void)vlan_remove_dynamic(hapd, old_vlan_id);

	return ret;
}


int ap_sta_bind_vlan(struct hostapd_data *hapd, struct sta_info *sta)
{
#ifndef CONFIG_NO_VLAN
	const char *iface;
	struct hostapd_vlan *vlan = NULL;
	int ret;
	int old_vlanid = sta->vlan_id_bound;

	iface = hapd->conf->iface;
	if (hapd->conf->ssid.vlan[0])
		iface = hapd->conf->ssid.vlan;

	if (sta->vlan_id > 0) {
		for (vlan = hapd->conf->vlan; vlan; vlan = vlan->next) {
			if (vlan->vlan_id == sta->vlan_id)
				break;
		}
		if (vlan)
			iface = vlan->ifname;
	}

	/*
	 * Do not increment ref counters if the VLAN ID remains same, but do
	 * not skip hostapd_drv_set_sta_vlan() as hostapd_drv_sta_remove() might
	 * have been called before.
	 */
	if (sta->vlan_id == old_vlanid)
		goto skip_counting;

	if (sta->vlan_id > 0 && vlan == NULL) {
		hostapd_logger(hapd, sta->addr, HOSTAPD_MODULE_IEEE80211,
			       HOSTAPD_LEVEL_DEBUG, "could not find VLAN for "
			       "binding station to (vlan_id=%d)",
			       sta->vlan_id);
		ret = -1;
		goto done;
	} else if (vlan && vlan->dynamic_vlan > 0) {
		vlan->dynamic_vlan++;
		hostapd_logger(hapd, sta->addr,
			       HOSTAPD_MODULE_IEEE80211,
			       HOSTAPD_LEVEL_DEBUG,
			       "updated existing dynamic VLAN interface '%s'",
			       iface);
	}

	/* ref counters have been increased, so mark the station */
	sta->vlan_id_bound = sta->vlan_id;

skip_counting:
	hostapd_logger(hapd, sta->addr, HOSTAPD_MODULE_IEEE80211,
		       HOSTAPD_LEVEL_DEBUG, "binding station to interface "
		       "'%s'", iface);

	if (wpa_auth_sta_set_vlan(sta->wpa_sm, sta->vlan_id) < 0)
		wpa_warning_log0(MSG_INFO, "Failed to update VLAN-ID for WPA");

	ret = hostapd_drv_set_sta_vlan(iface, hapd, sta->addr, sta->vlan_id);
	if (ret < 0) {
		hostapd_logger(hapd, sta->addr, HOSTAPD_MODULE_IEEE80211,
			       HOSTAPD_LEVEL_DEBUG, "could not bind the STA "
			       "entry to vlan_id=%d", sta->vlan_id);
	}

	/* During 1x reauth, if the vlan id changes, then remove the old id. */
	if (old_vlanid > 0 && old_vlanid != sta->vlan_id)
		vlan_remove_dynamic(hapd, old_vlanid);
done:

	return ret;
#else /* CONFIG_NO_VLAN */
	(void)hapd;
	(void)sta;
	return 0;
#endif /* CONFIG_NO_VLAN */
}
#endif

#ifdef CONFIG_IEEE80211W_AP

int ap_check_sa_query_timeout(struct hostapd_data *hapd, struct sta_info *sta)
{
	u32 tu;
	struct os_reltime now, passed;
	os_get_reltime(&now);
	os_reltime_sub(&now, &sta->sa_query_start, &passed);
	tu = (passed.sec * 1000000 + passed.usec) / 1024;
	if (hapd->conf->assoc_sa_query_max_timeout < tu) {
		hostapd_logger(hapd, sta->addr,
			       HOSTAPD_MODULE_IEEE80211,
			       HOSTAPD_LEVEL_DEBUG,
			       "association SA Query timed out");
		sta->sa_query_timed_out = 1;
		os_free(sta->sa_query_trans_id);
		sta->sa_query_trans_id = NULL;
		sta->sa_query_count = 0;
		eloop_cancel_timeout(ap_sa_query_timer, hapd, sta);
		return 1;
	}

	return 0;
}


static void ap_sa_query_timer(void *eloop_ctx, void *timeout_ctx)
{
	struct hostapd_data *hapd = eloop_ctx;
	struct sta_info *sta = timeout_ctx;
	unsigned int timeout, sec, usec;
	u8 *trans_id, *nbuf;

	wpa_warning_buf(MSG_DEBUG, "%s: SA Query timer for STA ",
		   hapd->conf->iface, strlen(hapd->conf->iface));
	wpa_warning_log4(MSG_DEBUG, "%02x:xx:xx:%02x:%02x:%02x",
		   (sta->addr)[0], (sta->addr)[3], (sta->addr)[4], (sta->addr)[5]);
	wpa_warning_log1(MSG_DEBUG, " (count=%d)", sta->sa_query_count);
	if (sta->sa_query_count > 0 &&
	    ap_check_sa_query_timeout(hapd, sta))
		return;

	nbuf = os_realloc_array(sta->sa_query_trans_id,
				sta->sa_query_count + 1,
				WLAN_SA_QUERY_TR_ID_LEN);
	if (nbuf == NULL)
		return;
	if (sta->sa_query_count == 0) {
		/* Starting a new SA Query procedure */
		os_get_reltime(&sta->sa_query_start);
	}
	trans_id = nbuf + sta->sa_query_count * WLAN_SA_QUERY_TR_ID_LEN;
	sta->sa_query_trans_id = nbuf;
	sta->sa_query_count++;

	if (os_get_random(trans_id, WLAN_SA_QUERY_TR_ID_LEN) < 0) {
		/*
		 * We don't really care which ID is used here, so simply
		 * hardcode this if the mostly theoretical os_get_random()
		 * failure happens.
		 */
		trans_id[0] = 0x12;
		trans_id[1] = 0x34;
	}

	timeout = hapd->conf->assoc_sa_query_retry_timeout;
	sec = ((timeout / 1000) * 1024) / 1000;
	usec = (timeout % 1000) * 1024;
	eloop_register_timeout(sec, usec, ap_sa_query_timer, hapd, sta);

	hostapd_logger(hapd, sta->addr, HOSTAPD_MODULE_IEEE80211,
		       HOSTAPD_LEVEL_DEBUG,
		       "association SA Query attempt %d", sta->sa_query_count);

	ieee802_11_send_sa_query_req(hapd, sta->addr, trans_id);
}


void ap_sta_start_sa_query(struct hostapd_data *hapd, struct sta_info *sta)
{
	ap_sa_query_timer(hapd, sta);
}


void ap_sta_stop_sa_query(struct hostapd_data *hapd, struct sta_info *sta)
{
	eloop_cancel_timeout(ap_sa_query_timer, hapd, sta);
	os_free(sta->sa_query_trans_id);
	sta->sa_query_trans_id = NULL;
	sta->sa_query_count = 0;
}

#endif /* CONFIG_IEEE80211W_AP */


void ap_sta_set_authorized(struct hostapd_data *hapd, struct sta_info *sta,
			   int authorized)
{
	char buf[100];
	hi_wifi_event wpa_events = {0};
#ifdef CONFIG_P2P
	const u8 *dev_addr = NULL;
	u8 addr[ETH_ALEN];
#ifndef CONFIG_NO_WPA_MSG
	u8 ip_addr_buf[4];
#endif /* CONFIG_NO_WPA_MSG */
#endif /* CONFIG_P2P */
#ifdef CONFIG_NO_WPA_MSG
	(void)hapd;
#endif /* CONFIG_NO_WPA_MSG */

	if (!!authorized == !!(sta->flags & WLAN_STA_AUTHORIZED))
		return;

	if (authorized)
		sta->flags |= WLAN_STA_AUTHORIZED;
	else
		sta->flags &= ~WLAN_STA_AUTHORIZED;

#ifdef CONFIG_P2P
	if (hapd->p2p_group == NULL) {
		if (sta->p2p_ie != NULL &&
		    p2p_parse_dev_addr_in_p2p_ie(sta->p2p_ie, addr) == 0)
			dev_addr = addr;
	} else
		dev_addr = p2p_group_get_dev_addr(hapd->p2p_group, sta->addr);

	if (dev_addr)
		(void)os_snprintf(buf, sizeof(buf), MACSTR " p2p_dev_addr=" MACSTR,
			    MAC2STR(sta->addr), MAC2STR(dev_addr));
	else
#endif /* CONFIG_P2P */
	(void)os_snprintf(buf, sizeof(buf), MACSTR, MAC2STR(sta->addr));

#ifdef CONFIG_P2P
	if (hapd->sta_authorized_cb)
		hapd->sta_authorized_cb(hapd->sta_authorized_cb_ctx,
					sta->addr, authorized, dev_addr);
#endif /* CONFIG_P2P */
	if (authorized) {
#ifndef CONFIG_NO_WPA_MSG
		char ip_addr[100];
		ip_addr[0] = '\0';
#ifdef CONFIG_P2P
		if (wpa_auth_get_ip_addr(sta->wpa_sm, ip_addr_buf) == 0) {
			os_snprintf(ip_addr, sizeof(ip_addr),
				    " ip_addr=%u.%u.%u.%u",
				    ip_addr_buf[0], ip_addr_buf[1],
				    ip_addr_buf[2], ip_addr_buf[3]);
		}
#endif /* CONFIG_P2P */

		wpa_msg(hapd->msg_ctx, MSG_INFO, AP_STA_CONNECTED "%s%s",
			buf, ip_addr);
#endif /* CONFIG_NO_WPA_MSG */
			(void)os_memcpy(wpa_events.info.ap_sta_connected.addr, sta->addr, ETH_ALEN);
			hi_at_printf("+NOTICE:STA CONNECTED\r\n");
			wpa_events.event = HI_WIFI_EVT_STA_CONNECTED;
			if (g_wpa_event_cb != NULL)
				wifi_new_task_event_cb(&wpa_events);
#ifndef HISI_CODE_CROP
		if (hapd->msg_ctx_parent &&
		    hapd->msg_ctx_parent != hapd->msg_ctx)
			wpa_msg_no_global(hapd->msg_ctx_parent, MSG_INFO,
					  AP_STA_CONNECTED "%s%s",
					  buf, ip_addr);
#endif /* HISI_CODE_CROP */
	} else {
		wpa_msg(hapd->msg_ctx, MSG_INFO, AP_STA_DISCONNECTED "%s", buf);
			(void)os_memcpy(wpa_events.info.ap_sta_disconnected.addr, sta->addr, ETH_ALEN);
			hi_at_printf("+NOTICE:STA DISCONNECTED\r\n");
			wpa_events.event = HI_WIFI_EVT_STA_DISCONNECTED;
			if (g_wpa_event_cb != NULL)
				wifi_new_task_event_cb(&wpa_events);
#ifndef HISI_CODE_CROP
		if (hapd->msg_ctx_parent &&
		    hapd->msg_ctx_parent != hapd->msg_ctx)
			wpa_msg_no_global(hapd->msg_ctx_parent, MSG_INFO,
					  AP_STA_DISCONNECTED "%s", buf);
#endif /* HISI_CODE_CROP */
	}

#ifdef CONFIG_FST
	if (hapd->iface->fst) {
		if (authorized)
			fst_notify_peer_connected(hapd->iface->fst, sta->addr);
		else
			fst_notify_peer_disconnected(hapd->iface->fst,
						     sta->addr);
	}
#endif /* CONFIG_FST */
}


void ap_sta_disconnect(struct hostapd_data *hapd, struct sta_info *sta,
		       const u8 *addr, u16 reason)
{
	if (sta) {
		wpa_warning_buf(MSG_DEBUG, "ap_sta_disconnect: %s STA ",
			   hapd->conf->iface, strlen(hapd->conf->iface));
		wpa_warning_log4(MSG_DEBUG, "%02x:xx:xx:%02x:%02x:%02x",
			   addr[0], addr[3], addr[4], addr[5]);
		wpa_warning_log1(MSG_DEBUG, " reason=%u", reason);
	}
	else if (addr) {
		wpa_warning_buf(MSG_DEBUG, "ap_sta_disconnect: %s addr ",
			   hapd->conf->iface, strlen(hapd->conf->iface));
		wpa_warning_log4(MSG_DEBUG, "%02x:xx:xx:%02x:%02x:%02x",
			   addr[0], addr[3], addr[4], addr[5]);
		wpa_warning_log1(MSG_DEBUG, " reason=%u", reason);
	}

	if (sta == NULL && addr)
		sta = ap_get_sta(hapd, addr);
#ifndef HISI_CODE_CROP
	if (addr)
		(void)hostapd_drv_sta_deauth(hapd, addr, reason);
#endif
	if (sta == NULL)
		return;
	ap_sta_set_authorized(hapd, sta, 0);
	(void)wpa_auth_sm_event(sta->wpa_sm, WPA_DEAUTH);
	ieee802_1x_notify_port_enabled(sta->eapol_sm, 0);
	sta->flags &= ~(WLAN_STA_AUTH | WLAN_STA_ASSOC);
	wpa_warning_buf(MSG_DEBUG, "ap_sta_disconnect: %s: reschedule ap_handle_timer timeout ",
		   hapd->conf->iface, strlen(hapd->conf->iface));
	wpa_warning_log4(MSG_DEBUG,
		   "for " "%02x:xx:xx:%02x:%02x:%02x",
			(sta->addr)[0], (sta->addr)[3], (sta->addr)[4], (sta->addr)[5]);
	wpa_warning_log1(MSG_DEBUG, " (%d seconds - "
		   "AP_MAX_INACTIVITY_AFTER_DEAUTH)", AP_MAX_INACTIVITY_AFTER_DEAUTH);
	(void)eloop_cancel_timeout(ap_handle_timer, hapd, sta);
	(void)eloop_register_timeout(AP_MAX_INACTIVITY_AFTER_DEAUTH, 0,
			       ap_handle_timer, hapd, sta);
	sta->timeout_next = STA_REMOVE;

#ifndef HISI_CODE_CROP
	if (hapd->iface->current_mode &&
	    hapd->iface->current_mode->mode == HOSTAPD_MODE_IEEE80211AD) {
		/* Deauthentication is not used in DMG/IEEE 802.11ad;
		 * disassociate the STA instead. */
		sta->disassoc_reason = reason;
		sta->flags |= WLAN_STA_PENDING_DISASSOC_CB;
		eloop_cancel_timeout(ap_sta_disassoc_cb_timeout, hapd, sta);
		eloop_register_timeout(hapd->iface->drv_flags &
				       WPA_DRIVER_FLAGS_DEAUTH_TX_STATUS ?
				       2 : 0, 0, ap_sta_disassoc_cb_timeout,
				       hapd, sta);
		return;
	}
#endif
	sta->deauth_reason = reason;
	sta->flags |= WLAN_STA_PENDING_DEAUTH_CB;
	(void)eloop_cancel_timeout(ap_sta_deauth_cb_timeout, hapd, sta);
	(void)eloop_register_timeout(hapd->iface->drv_flags &
			       WPA_DRIVER_FLAGS_DEAUTH_TX_STATUS ? 2 : 0, 0,
			       ap_sta_deauth_cb_timeout, hapd, sta);
}


void ap_sta_deauth_cb(struct hostapd_data *hapd, struct sta_info *sta)
{
	if (!(sta->flags & WLAN_STA_PENDING_DEAUTH_CB)) {
		wpa_warning_log0(MSG_DEBUG, "Ignore deauth cb for test frame");
		return;
	}
	sta->flags &= ~WLAN_STA_PENDING_DEAUTH_CB;
	(void)eloop_cancel_timeout(ap_sta_deauth_cb_timeout, hapd, sta);
	ap_sta_deauth_cb_timeout(hapd, sta);
}


void ap_sta_disassoc_cb(struct hostapd_data *hapd, struct sta_info *sta)
{
	if (!(sta->flags & WLAN_STA_PENDING_DISASSOC_CB)) {
		wpa_warning_log0(MSG_DEBUG, "Ignore disassoc cb for test frame");
		return;
	}
	sta->flags &= ~WLAN_STA_PENDING_DISASSOC_CB;
	(void)eloop_cancel_timeout(ap_sta_disassoc_cb_timeout, hapd, sta);
	ap_sta_disassoc_cb_timeout(hapd, sta);
}


void ap_sta_clear_disconnect_timeouts(struct hostapd_data *hapd,
				      struct sta_info *sta)
{
	if (eloop_cancel_timeout(ap_sta_deauth_cb_timeout, hapd, sta) > 0) {
		wpa_warning_buf(MSG_DEBUG,
			   "%s: Removed ap_sta_deauth_cb_timeout timeout for ",
			   hapd->conf->iface, strlen(hapd->conf->iface));
		wpa_warning_log4(MSG_DEBUG,
			   "%02x:xx:xx:%02x:%02x:%02x",
			   (sta->addr)[0], (sta->addr)[3], (sta->addr)[4], (sta->addr)[5]);
	}
	if (eloop_cancel_timeout(ap_sta_disassoc_cb_timeout, hapd, sta) > 0) {
		wpa_warning_buf(MSG_DEBUG,
			   "%s: Removed ap_sta_disassoc_cb_timeout timeout for ",
			   hapd->conf->iface, strlen(hapd->conf->iface));
		wpa_warning_log4(MSG_DEBUG,
			   "%02x:xx:xx:%02x:%02x:%02x",
			   (sta->addr)[0], (sta->addr)[3], (sta->addr)[4], (sta->addr)[5]);
	}
	if (eloop_cancel_timeout(ap_sta_delayed_1x_auth_fail_cb, hapd, sta) > 0)
	{
		wpa_warning_buf(MSG_DEBUG,
			   "%s: Removed ap_sta_delayed_1x_auth_fail_cb timeout for ",
			   hapd->conf->iface, strlen(hapd->conf->iface));
		wpa_warning_log4(MSG_DEBUG,
			   "%02x:xx:xx:%02x:%02x:%02x",
			   (sta->addr)[0], (sta->addr)[3], (sta->addr)[4], (sta->addr)[5]);
#ifdef CONFIG_WPS_AP
		if (sta->flags & WLAN_STA_WPS)
			hostapd_wps_eap_completed(hapd);
#endif /* CONFIG_WPS_AP */
	}
}


int ap_sta_flags_txt(u32 flags, char *buf, size_t buflen)
{
	int res;

	buf[0] = '\0';
	res = os_snprintf(buf, buflen, "%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s",
			  (flags & WLAN_STA_AUTH ? "[AUTH]" : ""),
			  (flags & WLAN_STA_ASSOC ? "[ASSOC]" : ""),
			  (flags & WLAN_STA_AUTHORIZED ? "[AUTHORIZED]" : ""),
			  (flags & WLAN_STA_PENDING_POLL ? "[PENDING_POLL" :
			   ""),
			  (flags & WLAN_STA_SHORT_PREAMBLE ?
			   "[SHORT_PREAMBLE]" : ""),
			  (flags & WLAN_STA_PREAUTH ? "[PREAUTH]" : ""),
			  (flags & WLAN_STA_WMM ? "[WMM]" : ""),
			  (flags & WLAN_STA_MFP ? "[MFP]" : ""),
			  (flags & WLAN_STA_WPS ? "[WPS]" : ""),
			  (flags & WLAN_STA_MAYBE_WPS ? "[MAYBE_WPS]" : ""),
			  (flags & WLAN_STA_WDS ? "[WDS]" : ""),
			  (flags & WLAN_STA_NONERP ? "[NonERP]" : ""),
			  (flags & WLAN_STA_WPS2 ? "[WPS2]" : ""),
			  (flags & WLAN_STA_GAS ? "[GAS]" : ""),
			  (flags & WLAN_STA_HT ? "[HT]" : ""),
#ifndef HISI_CODE_CROP
			  (flags & WLAN_STA_VHT ? "[VHT]" : ""),
			  (flags & WLAN_STA_VENDOR_VHT ? "[VENDOR_VHT]" : ""),
#endif /* HISI_CODE_CROP */
			  (flags & WLAN_STA_WNM_SLEEP_MODE ?
			   "[WNM_SLEEP_MODE]" : ""));
	if (os_snprintf_error(buflen, res))
		res = -1;

	return res;
}


static void ap_sta_delayed_1x_auth_fail_cb(void *eloop_ctx, void *timeout_ctx)
{
	struct hostapd_data *hapd = eloop_ctx;
	struct sta_info *sta = timeout_ctx;

	wpa_dbg(hapd->msg_ctx, MSG_DEBUG,
		"IEEE 802.1X: Scheduled disconnection of " MACSTR
		" after EAP-Failure", MAC2STR(sta->addr));

	ap_sta_disconnect(hapd, sta, sta->addr,
			  WLAN_REASON_IEEE_802_1X_AUTH_FAILED);
#ifdef CONFIG_WPS_AP
	if (sta->flags & WLAN_STA_WPS)
		hostapd_wps_eap_completed(hapd);
#endif /* CONFIG_WPS_AP */
}


void ap_sta_delayed_1x_auth_fail_disconnect(struct hostapd_data *hapd,
					    struct sta_info *sta)
{
	wpa_dbg(hapd->msg_ctx, MSG_DEBUG,
		"IEEE 802.1X: Force disconnection of " MACSTR
		" after EAP-Failure in 10 ms", MAC2STR(sta->addr));

	/*
	 * Add a small sleep to increase likelihood of previously requested
	 * EAP-Failure TX getting out before this should the driver reorder
	 * operations.
	 */
	eloop_cancel_timeout(ap_sta_delayed_1x_auth_fail_cb, hapd, sta);
	eloop_register_timeout(0, 10000, ap_sta_delayed_1x_auth_fail_cb,
			       hapd, sta);
}


int ap_sta_pending_delayed_1x_auth_fail_disconnect(struct hostapd_data *hapd,
						   struct sta_info *sta)
{
	return eloop_is_timeout_registered(ap_sta_delayed_1x_auth_fail_cb,
					   hapd, sta);
}
