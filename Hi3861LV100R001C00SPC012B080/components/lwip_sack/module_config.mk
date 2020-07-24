lwip_srcs := src/arch src/api src/core src/core/ipv4 src/core/ipv6 src/netif src/core/nat64
CCFLAGS += 
CCFLAGS += -DWITH_LWIP -DLWIP_NOASSERT -D__LITEOS__ -DLIB_CONFIGURABLE -DLWIP_NETIF_DEFAULT_LINK_DOWN=1 -DLWIP_HI3861_THREAD_SLEEP=1 -DLWIP_ENABLE_DIAG_CMD=0 -DMEMP_USE_CUSTOM_POOLS=1 -DLWIP_LIBCOAP=1
CCFLAGS += -I$(MAIN_TOPDIR)/components/mcast6/include \
	-I$(MAIN_TOPDIR)/components/ripple/include \
	-I$(MAIN_TOPDIR)/components/ripple/exports \
	-I$(MAIN_TOPDIR)/components/ripple/src/platform/lwip \
	-I$(MAIN_TOPDIR)/third_party/libcoap/include/coap2 \
	-I$(MAIN_TOPDIR)/third_party/libcoap
ifeq ($(LOSCFG_TEST_NET), y)
	DEFIENES += -DLWIP_TESTBED
endif
ifeq ($(LOSCFG_NET_LIBCOAP), y)
	DEFIENES += -DMEMP_USE_CUSTOM_POOLS=1 -DLWIP_LIBCOAP=1
endif
