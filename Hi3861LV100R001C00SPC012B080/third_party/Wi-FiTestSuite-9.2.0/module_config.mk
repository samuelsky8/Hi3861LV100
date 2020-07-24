sigma_srcs := src
CCFLAGS += 
CCFLAGS += -I$(MAIN_TOPDIR)/third_party/Wi-FiTestSuite-9.2.0/inc \
	-I$(MAIN_TOPDIR)/components/lwip_sack/include/ipv4/lwip \
	-I$(MAIN_TOPDIR)/components/lwip_sack/include \
	-I$(MAIN_TOPDIR)/components/lwip_sack/include/lwip \
	-I$(MAIN_TOPDIR)/platform/os/Huawei_LiteOS/targets/hi3861v100/commons
