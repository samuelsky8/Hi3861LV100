cfg_srcs := cfg
cpup_srcs := cpup
parttab_srcs := partition_table
upg_srcs := upg
CCFLAGS += -Werror
CCFLAGS += -I$(MAIN_TOPDIR)/platform/system/include \
	-I$(MAIN_TOPDIR)/platform/system/upg \
	-I$(MAIN_TOPDIR)/platform/os/Huawei_LiteOS/kernel/extended/include
