coap_srcs := src
CCFLAGS += 
CCFLAGS += -DWITH_LWIP -DMEMP_USE_CUSTOM_POOLS=1
CCFLAGS += -I$(MAIN_TOPDIR)/third_party/libcoap \
	-I$(MAIN_TOPDIR)/third_party/libcoap/include/coap2
ifeq ($(CONFIG_LIBCOAP), y)
	DEFIENES += -DLOSCFG_NET_LIBCOAP
endif
