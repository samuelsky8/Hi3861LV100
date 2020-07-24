at_srcs := src
CCFLAGS += -DCONFIG_IPERF_SUPPORT
CCFLAGS += -I$(MAIN_TOPDIR)/platform/drivers/uart \
	-I$(MAIN_TOPDIR)/platform/system/cpup \
	-I$(MAIN_TOPDIR)/platform/at \
	-I$(MAIN_TOPDIR)/components/at/src \
	-I$(MAIN_TOPDIR)/components/wifi/include \
	-I$(MAIN_TOPDIR)/components/lwip_sack/include/lwip \
	-I$(MAIN_TOPDIR)/components/iperf2/include \
	-I$(MAIN_TOPDIR)/config/diag \
	-I$(MAIN_TOPDIR)/third_party/Wi-FiTestSuite-9.2.0/inc \
	-I$(MAIN_TOPDIR)/platform/os/Huawei_LiteOS/targets/hi3861v100/commons
ifeq ($(CONFIG_IPERF), y)
	DEFIENES += -DCONFIG_IPERF_SUPPORT
endif
ifeq ($(CONFIG_SIGMA_SUPPORT), y)
	DEFIENES += -DCONFIG_SIGMA_SUPPORT -DCONFIG_LWIP_FOR_WIFI_SIGMA
endif
