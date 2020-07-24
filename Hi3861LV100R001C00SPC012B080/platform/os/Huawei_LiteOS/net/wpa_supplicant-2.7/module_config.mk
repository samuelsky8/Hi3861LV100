wpa_srcs := wpa_supplicant src hostapd
CCFLAGS += 
CCFLAGS += -DINCLUDE_UNUSED -DWLAN_HEADERS -DWIRELESS_EXT=0 -DBT_SETUP=0 -DREGCODE_REMAPPING=0 -DSOFTAP_MODE -DSOFTMAC_FILE_USED -DWPA_SUPPLICANT -DHOSTAPD -DCONFIG_NO_CONFIG_WRITE -DCONFIG_WPA -DCONFIG_SHA256 -DOS_NO_C_LIB_DEFINES -DOPENSSL_DISABLE_OLD_DES_SUPPORT -DTHIRTY_TWO_BIT -DOPENSSL_NO_SOCK -DCONFIG_IEEE80211N -DNEED_AP_MLME -DCONFIG_INTERNAL_LIBTOMMATH -DLTM_FAST -DCONFIG_NO_RADIUS -DCONFIG_NO_ACCOUNTING -DCONFIG_NO_VLAN -DCONFIG_NO_CONFIG_BLOBS -DCONFIG_CTRL_IFACE -DCONFIG_AP -DIEEE8021X_EAPOL -DCONFIG_TI_COMPILER -DCONFIG_CRYPTO_INTERNAL -DCONFIG_LITEOS_WPA -DLOS_WPA_EVENT_CALLBAK -DLOS_CONFIG_NO_VLAN -DLOS_CONFIG_MESH_TRIM -DLOS_CONFIG_HOSTAPD_QOS -DHISI_WPA_MINI -DLOS_CONFIG_HOSTAPD_SECURITY -DLOS_CONFIG_HISI_DRIVER_NOT_SUPPORT -DLOS_CONFIG_HOSTAPD_EAP_CIPHERS -DHISI_WPA_KEY_MGMT_CROP -DLOS_CONFIG_HOSTAPD_TKIP_MIC -DLOS_CONFIG_HOSTAPD_RRM -DHISI_EAP_TRIM -DCONFIG_NO_HOSTAPD_LOGGER -DLOS_CONFIG_80211_IES_CROP -DLOS_CONFIG_NO_PMKSA -DCONFIG_NO_RANDOM_POOL -DCONFIG_NO_STDOUT_DEBUG -DCONFIG_IEEE80211W -DHISI_CODE_CROP -DCONFIG_NO_WPA_MSG -DCONFIG_PRINT_NOUSE -DHISI_SCAN_SIZE_CROP -DCONFIG_SAE_NO_FFC -DCONFIG_DRIVER_HISILICON -DWITH_LWIP -DTEST3516CV300 -DCONFIG_STRERROR -D__LITEOS__ -DLWIP_ENABLE_DIAG_CMD=0
CCFLAGS += -I$(MAIN_TOPDIR)/third_party/mbedtls-2.16.2/include \
	-I$(MAIN_TOPDIR)/platform/drivers/cipher \
	-I$(MAIN_TOPDIR)/components/wifi/include \
	-I$(MAIN_TOPDIR)/components/lwip_sack/include \
	-I$(MAIN_TOPDIR)/platform/os/Huawei_LiteOS/net/wpa_supplicant-2.7 \
	-I$(MAIN_TOPDIR)/platform/os/Huawei_LiteOS/net/wpa_supplicant-2.7/src \
	-I$(MAIN_TOPDIR)/platform/os/Huawei_LiteOS/net/wpa_supplicant-2.7/src/utils \
	-I$(MAIN_TOPDIR)/platform/os/Huawei_LiteOS/net/wpa_supplicant-2.7/src/drivers \
	-I$(MAIN_TOPDIR)/platform/os/Huawei_LiteOS/net/wpa_supplicant-2.7/wpa_supplicant \
	-I$(MAIN_TOPDIR)/platform/os/Huawei_LiteOS/net/wpa_supplicant-2.7/src/wps \
	-I$(MAIN_TOPDIR)/platform/os/Huawei_LiteOS/net/wpa_supplicant-2.7/src/p2p \
	-I$(MAIN_TOPDIR)/platform/os/Huawei_LiteOS/net/wpa_supplicant-2.7/src/ap \
	-I$(MAIN_TOPDIR)/platform/os/Huawei_LiteOS/net/wpa_supplicant-2.7/src/eap_peer \
	-I$(MAIN_TOPDIR)/platform/os/Huawei_LiteOS/net/wpa_supplicant-2.7/src/eap_server \
	-I$(MAIN_TOPDIR)/platform/os/Huawei_LiteOS/net/wpa_supplicant-2.7/src/eap_common \
	-I$(MAIN_TOPDIR)/platform/os/Huawei_LiteOS/net/wpa_supplicant-2.7/src/common \
	-I$(MAIN_TOPDIR)/platform/os/Huawei_LiteOS/net/wpa_supplicant-2.7/hostapd \
	-I$(MAIN_TOPDIR)/platform/os/Huawei_LiteOS/net/wpa_supplicant-2.7/src/crypto \
	-I$(MAIN_TOPDIR)/platform/os/Huawei_LiteOS/net/wpa_supplicant-2.7/src/eapol_supp \
	-I$(MAIN_TOPDIR)/platform/os/Huawei_LiteOS/net/wpa_supplicant-2.7/src/l2_packet \
	-I$(MAIN_TOPDIR)/platform/os/Huawei_LiteOS/net/wpa_supplicant-2.7/src/rsn_supp \
	-I$(MAIN_TOPDIR)/platform/os/Huawei_LiteOS/net/wpa_supplicant-2.7/src/tls
