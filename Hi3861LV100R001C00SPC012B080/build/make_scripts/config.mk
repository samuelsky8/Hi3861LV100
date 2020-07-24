include $(MAIN_TOPDIR)/build/make_scripts/usr.mk
include $(MAIN_TOPDIR)/build/config/sdk.mk
include $(MAIN_TOPDIR)/build/config/usr_config.mk

COMPILE_MODULE += drv sys os wpa mbedtls lwip at
drv_dir := platform/drivers
drv_libs := flash uart adc
sys_dir := platform/system
sys_libs := cfg cpup parttab upg
os_dir := platform/os/Huawei_LiteOS
os_libs := res_cfg
wpa_dir := platform/os/Huawei_LiteOS/net/wpa_supplicant-2.7
wpa_libs := wpa
mbedtls_dir := third_party/mbedtls-2.16.2
mbedtls_libs := mbedtls
lwip_dir := components/lwip_sack
lwip_libs := lwip
at_dir := components/at
at_libs := at
iperf_dir := components/iperf2
iperf_libs := iperf
mqtt_dir := third_party/paho.mqtt.c-1.3.0
mqtt_libs := mqtt
coap_dir := third_party/libcoap
coap_libs := coap
cjson_dir := third_party/cjson
cjson_libs := cjson cjson_utils
sigma_dir := third_party/Wi-FiTestSuite-9.2.0
sigma_libs := sigma

ifeq ($(USR_APP_ON), n)
COMPILE_MODULE += demo
LIBS += -ldemo
demo_dir := app/demo
demo_libs := demo
else
LIBS += $(USR_LIBS)
endif
RM := rm -rf
MAKE := make
MV := mv
MAKE_DIR := mkdir -p
CC := $(TOOLS_PREFIX)gcc
AR := $(TOOLS_PREFIX)ar
AS := $(TOOLS_PREFIX)as
CXX := $(TOOLS_PREFIX)cpp
LINK := $(TOOLS_PREFIX)ld
RANLIB := $(TOOLS_PREFIX)ranlib
OBJCOPY := $(TOOLS_PREFIX)objcopy
OBJDUMP := $(TOOLS_PREFIX)objdump
LIBPATH += -Lbuild/scripts -Lbuild/libs -Lbuild/build_tmp/libs -Lbuild/build_tmp/scripts
LIBS += $(patsubst lib%.a, -l%, $(notdir $(wildcard $(MAIN_TOPDIR)/build/libs/*.a)))
LIBS += -lwifi -lwifi_flash
LIBS += -lflash -luart -ladc -lcfg -lcpup -lparttab -lres_cfg -lwpa -lmbedtls -llwip -lat -lupg -lgcc
BASE_NUM := d11133fff0d435d699e27817e165cf1d10c1a951452bd07d40da5bcfc41ef773
NV_CFG_NAME := mss_nvi_db.xml
ifdef PYTHON_SCRIPTS
NV_TOOL := python3 $(MAIN_TOPDIR)/tools/nvtool/build_nv.py
OTA_TOOL := python3 $(MAIN_TOPDIR)/build/scripts/pkt_builder.py
else
NV_TOOL := cd $(MAIN_TOPDIR)/tools/nvtool;\
    $(MAIN_TOPDIR)/tools/nvtool/nv_builder
OTA_TOOL := cd $(MAIN_TOPDIR)/build/scripts;\
    $(MAIN_TOPDIR)/build/scripts/ota_builder
endif

ARFLAGS := cr
CCFLAGS := -mabi=ilp32 -march=rv32imc -falign-functions=2 -msave-restore -fno-optimize-strlen -freorder-blocks-algorithm=simple -fno-schedule-insns -fno-inline-small-functions -fno-inline-functions-called-once -Wa,-enable-c-lbu-sb -mtune=size -fno-strict-aliasing -msmall-data-limit=0 -nostdinc -fno-aggressive-loop-optimizations -fno-builtin -std=c99 -Os -femit-lli -ffunction-sections -fdata-sections -fno-exceptions -fno-short-enums -fno-common -Wall -Wundef -fldm-stm-optimize -fstack-protector-strong -freg-struct-return -fvisibility=hidden -pipe -funsigned-char -DLOS_COMPILE_LDM
ASLAGS :=
DEFINES := -DCYGPKG_POSIX_SIGNALS \
	-D__ECOS__ \
	-D__RTOS_ \
	-DPRODUCT_CFG_HAVE_FEATURE_SYS_ERR_INFO \
	-D__LITEOS__ \
	-DLIB_CONFIGURABLE \
	-DLOSCFG_SHELL \
	-DLOSCFG_CACHE_STATICS \
	-DCUSTOM_AT_COMMAND \
	-DLOS_COMPILE_LDM \
	-DLOS_CONFIG_IPERF3 \
	-DPRODUCT_USR_SOFT_VER_STR=\"None\" \
	-DSECUREC_ENABLE_SCANF_FILE=0
INCLUDE := -I$(MAIN_TOPDIR)/include \
	-I$(MAIN_TOPDIR)/platform/include \
	-I$(MAIN_TOPDIR)/config \
	-I$(MAIN_TOPDIR)/config/nv \
	-I$(MAIN_TOPDIR)/components/lwip_sack/include \
	-I$(MAIN_TOPDIR)/platform/os/Huawei_LiteOS/kernel/base/include \
	-I$(MAIN_TOPDIR)/platform/os/Huawei_LiteOS/targets/hi3861v100/include \
	-I$(MAIN_TOPDIR)/platform/os/Huawei_LiteOS/targets/hi3861v100/plat/riscv
LINKFLAGS := -nostartfiles -nostdlib -static --gc-sections
LINK_SCRIPTS_FLAG := -Iplatform/os/Huawei_LiteOS/kernel/include -Iconfig




ifeq ($(CONFIG_MQTT), y)
	COMPILE_MODULE += mqtt
	LIBS += -lmqtt
endif
ifeq ($(CONFIG_CJSON), y)
	COMPILE_MODULE += cjson
	LIBS += -lcjson
	LIBS += -lcjson_utils
endif
# currently not support in makefile.
#ifeq ($(CONFIG_LIBCOAP), y)
#	COMPILE_MODULE += coap
#	LIBS += -lcoap
#endif
ifeq ($(CONFIG_SIGMA_SUPPORT), y)
	COMPILE_MODULE += sigma
	LIBS += -lsigma
endif
ifeq ($(CONFIG_IPERF), y)
	COMPILE_MODULE += iperf
    LIBS += -liperf
endif
ifeq ($(CONFIG_I2C_SUPPORT), y)
	drv_libs += i2c
endif
ifeq ($(CONFIG_SPI_SUPPORT), y)
	drv_libs += spi
endif
ifeq ($(CONFIG_PWM_SUPPORT), y)
	drv_libs += pwm
endif
ifeq ($(CONFIG_I2C_SUPPORT), y)
	DEFINES += -DCONFIG_I2C_SUPPORT
endif
ifeq ($(CONFIG_DMA_SUPPORT), y)
	DEFINES += -DCONFIG_DMA_SUPPORT
endif
ifeq ($(CONFIG_SPI_SUPPORT), y)
	DEFINES += -DCONFIG_SPI_SUPPORT
endif
ifeq ($(CONFIG_PWM_SUPPORT), y)
	DEFINES += -DCONFIG_PWM_SUPPORT
endif
ifeq ($(CONFIG_I2S_SUPPORT), y)
	DEFINES += -DCONFIG_I2S_SUPPORT
endif
ifeq ($(CONFIG_COMPRESSION_OTA_SUPPORT), y)
	DEFINES += -DCONFIG_COMPRESSION_OTA_SUPPORT
endif
ifeq ($(CONFIG_DUAL_PARTITION_OTA_SUPPORT), y)
	DEFINES += -DCONFIG_DUAL_PARTITION_OTA_SUPPORT
endif
ifeq ($(CONFIG_AT_SUPPORT), y)
	DEFINES += -DCONFIG_AT_COMMAND
endif
ifeq ($(LOSCFG_DAQ), y)
	DEFINES += -DFEATURE_DAQ
endif
ifeq ($(LOSCFG_BACKTRACE), y)
	DEFINES += -DLOS_BACKTRACE
endif
ifeq ($(LOSCFG_COMPILER_CHIP_VER), Hi3861L)
	DEFINES += -DCHIP_VER_Hi3861L -DPRODUCT_CFG_CHIP_VER_STR=\"Hi3861LV100\" -DCONFIG_CHIP_PRODUCT_NAME=\"Hi3861L\"
else ifeq ($(LOSCFG_COMPILER_CHIP_VER), Hi3861)
	DEFINES += -DCHIP_VER_Hi3861 -DPRODUCT_CFG_CHIP_VER_STR=\"Hi3861V100\" -DCONFIG_CHIP_PRODUCT_NAME=\"Hi3861\"
else ifeq ($(LOSCFG_COMPILER_CHIP_VER), Hi3881)
	DEFINES += -DCHIP_VER_Hi3881 -DPRODUCT_CFG_CHIP_VER_STR=\"Hi3881V100\" -DCONFIG_CHIP_PRODUCT_NAME=\"Hi3881\"
else
	DEFINES += -DPRODUCT_CFG_CHIP_VER_STR=\"Unknown\"
endif
ifeq ($(LOSCFG_COMPILER_HI3861_ASIC), y)
	DEFINES += -DHI_BOARD_ASIC
else
	DEFINES += -DHI_BOARD_FPGA
endif
ifeq ($(LOSCFG_COMPILER_HI3861_FLASH), y)
	DEFINES += -DHI_ON_FLASH
else
	DEFINES += -DHI_ON_RAM
endif
ifeq ($(LOSCFG_NET_MQTT), y)
	DEFINES += -DLOSCFG_CONFIG_MQTT
endif
ifeq ($(CONFIG_LWIP_SMALL_SIZE), y)
	DEFINES += -DCONFIG_LWIP_SMALL_SIZE
endif
ifeq ($(CONFIG_LWIP_SMALL_SIZE_MESH), y)
	DEFINES += -DCONFIG_LWIP_SMALL_SIZE_MESH
endif
ifeq ($(CONFIG_NETIF_HOSTNAME), y)
	DEFINES += -DCONFIG_NETIF_HOSTNAME
endif
ifeq ($(CONFIG_DHCP_VENDOR_CLASS_IDENTIFIER), y)
	DEFINES += -DCONFIG_DHCP_VENDOR_CLASS_IDENTIFIER
endif
ifeq ($(CONFIG_DHCPS_GW), y)
	DEFINES += -DCONFIG_DHCPS_GW
endif
ifeq ($(CONFIG_UART_DMA_SUPPORT), y)
	DEFINES += -DCONFIG_UART_DMA_SUPPORT
endif
ifeq ($(CONFIG_SDIO_SUPPORT), y)
	DEFINES += -DCONFIG_SDIO_SUPPORT
endif
ifeq ($(CONFIG_SPI_DMA_SUPPORT), y)
	DEFINES += -DCONFIG_SPI_DMA_SUPPORT
endif
ifeq ($(CONFIG_MESH_SUPPORT), y)
	DEFINES += -DCONFIG_MESH_SUPPORT -DLOS_CONFIG_MESH -DLOS_CONFIG_MESH_GTK -DCONFIG_MESH -DCONFIG_SAE -DCONFIG_ECC -DLOS_CONFIG_HOSTAPD_MGMT -DLOSCFG_APP_MESH -DLWIP_DEBUG_OPEN -DLWIP_SMALL_SIZE_MESH=1
else
    DEFINES += -DLWIP_SMALL_SIZE_MESH=0
endif
ifeq ($(CONFIG_TEE_HUKS_SUPPORT), y)
	DEFINES += -DCONFIG_TEE_HUKS_SUPPORT
endif
ifeq ($(CONFIG_FLASH_ENCRYPT_SUPPORT), y)
	DEFINES += -DCONFIG_FLASH_ENCRYPT_SUPPORT
endif
ifeq ($(CONFIG_WPS_SUPPORT), y)
	DEFINES += -DCONFIG_WPS_SUPPORT -DCONFIG_WPS -DEAP_WSC
endif
ifeq ($(CONFIG_FILE_SYSTEM_SUPPORT), y)
	DEFINES += -DCONFIG_FILE_SYSTEM_SUPPORT
endif
ifeq ($(CONFIG_DIAG_SUPPORT), y)
	DEFINES += -DCONFIG_DIAG_SUPPORT
endif
ifeq ($(LOSCFG_KASAN)_$(LOSCFG_KASAN_EXAMPLES_DEMO), y_y)
	DEFINES += -DLOSCFG_DEBUG_KASAN
endif
ifeq ($(LOSCFG_KASAN)_$(LOSCFG_KASAN_LITEOS_NET_COAP), y_y)
	DEFINES += -DLOSCFG_DEBUG_KASAN
endif
ifeq ($(LOSCFG_BACKTRACE), y)
	ASLAGS += -fno-omit-frame-pointer
endif
ifeq ($(HB_LITEOS_COMPILE_TESTCASE), y)
	LINK_SCRIPTS_FLAG += -DHI1131TEST
endif
ifeq ($(LOSCFG_KASAN), y)
	LINK_SCRIPTS_FLAG += -DLOSCFG_DEBUG_KASAN
endif
ifeq ($(CONFIG_FLASH_ENCRYPT_SUPPORT), y)
	LINK_SCRIPTS_FLAG += -DCONFIG_FLASH_ENCRYPT_SUPPORT
endif
ifeq ($(CONFIG_TEE_HUKS_SUPPORT), y)
	LINK_SCRIPTS_FLAG += -DCONFIG_TEE_HUKS_SUPPORT
endif
ifeq ($(LOSCFG_COMPILER_HI3861_ASIC), y)
	LINK_SCRIPTS_FLAG += -DHI_BOARD_ASIC
else
	LINK_SCRIPTS_FLAG += -DHI_BOARD_FPGA
endif
ifeq ($(LOSCFG_COMPILER_HI3861_FLASH), y)
	LINK_SCRIPTS_FLAG += -DHI_ON_FLASH
else
	LINK_SCRIPTS_FLAG += -DHI_ON_RAM
endif
ifeq ($(LOSCFG_KERNEL_LITEKERNEL), y)
	INCLUDE += -I$(MAIN_TOPDIR)/platform/os/Huawei_LiteOS/kernel/include
endif
ifeq ($(LOSCFG_KERNEL_RUNSTOP), y)
	INCLUDE += -I$(MAIN_TOPDIR)/platform/os/Huawei_LiteOS/kernel/extended/runstop
endif
ifeq ($(LOSCFG_COMPAT_POSIX), y)
	INCLUDE += -I$(MAIN_TOPDIR)/platform/os/Huawei_LiteOS/components/posix/include
endif
ifeq ($(LOSCFG_COMPAT_LINUX), y)
	INCLUDE += -I$(MAIN_TOPDIR)/platform/os/Huawei_LiteOS/components/linux/include
endif
ifeq ($(LOSCFG_LIB_LIBM), y)
	INCLUDE += -I$(MAIN_TOPDIR)/platform/os/Huawei_LiteOS/components/lib/libc/bionic/libm
endif
ifeq ($(LOSCFG_SHELL), y)
	INCLUDE += -I$(MAIN_TOPDIR)/platform/os/Huawei_LiteOS/shell/include
endif
ifeq ($(LOSCFG_NET_TELNET), y)
	INCLUDE += -I$(MAIN_TOPDIR)/platform/os/Huawei_LiteOS/net/telnet/include
endif
ifeq ($(LOSCFG_LIB_LIBC), y)
	INCLUDE += -I$(MAIN_TOPDIR)/platform/os/Huawei_LiteOS/components/lib/libc/musl-1.1.22/include \
        -I$(MAIN_TOPDIR)/platform/os/Huawei_LiteOS/components/lib/libc/musl-1.1.22/arch/generic \
        -I$(MAIN_TOPDIR)/platform/os/Huawei_LiteOS/components/lib/libc/musl-1.1.22/arch/riscv32 \
        -I$(MAIN_TOPDIR)/platform/os/Huawei_LiteOS/components/lib/libc/musl-1.1.22/obj/include \
        -I$(MAIN_TOPDIR)/platform/os/Huawei_LiteOS/components/lib/libc/nuttx/include \
        -I$(MAIN_TOPDIR)/platform/os/Huawei_LiteOS/components/lib/libsec/include \
        -I$(MAIN_TOPDIR)/platform/os/Huawei_LiteOS/targets/hi3861v100/config \
        -I$(MAIN_TOPDIR)/platform/os/Huawei_LiteOS/targets/hi3861v100/user \
        -I$(MAIN_TOPDIR)/platform/os/Huawei_LiteOS/targets/hi3861v100/plat \
        -I$(MAIN_TOPDIR)/platform/os/Huawei_LiteOS/targets/hi3861v100/extend/include \
        -I$(MAIN_TOPDIR)/platform/os/Huawei_LiteOS/arch
endif
ifeq ($(LOSCFG_COMPAT_CJSON), y)
	INCLUDE += -Ithird_party/cjson
endif
ifeq ($(LOSCFG_BACKTRACE), y)
	CCFLAGS += -fno-omit-frame-pointer
endif
ifeq ($(LOSCFG_KASAN)_$(LOSCFG_KASAN_EXAMPLES_DEMO), y_y)
	CCFLAGS += -fsanitize=kernel-address -fasan-shadow-offset=1835008 --param asan-stack=1 -fsanitize=bounds-strict
endif
ifeq ($(LOSCFG_KASAN)_$(LOSCFG_KASAN_LITEOS_NET_COAP), y_y)
	CCFLAGS += -fsanitize=kernel-address -fasan-shadow-offset=1835008 --param asan-stack=1 -fsanitize=bounds-strict
endif

ifdef LOSCFG_COMPILER_CHIP_VER
DEFINES += -DPRODUCT_CFG_SOFT_VER_STR=\"$(LOSCFG_COMPILER_CHIP_VER)\"
endif
ifeq ($(CONFIG_MESH_SUPPORT), y)
    LIBPATH += -Lbuild/libs/mesh
else
    LIBPATH += -Lbuild/libs/no_mesh
endif

CCFLAGS += $(DEFINES) $(INCLUDE)
