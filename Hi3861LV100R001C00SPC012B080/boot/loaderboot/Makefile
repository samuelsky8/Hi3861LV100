include $(MAIN_TOPDIR)/build/config/usr_config.mk
include $(MAIN_TOPDIR)/build/make_scripts/config.mk
-include $(MAIN_TOPDIR)/$(MODULE_DIR)/srcs.mk
include $(MAIN_TOPDIR)/$(MODULE_DIR)/module_config.mk

override CCFLAGS = $(BOOT_CCFLAGS) $(BOOT_DEFINE) $(BOOT_INC)
override ASFLAGS = $(BOOT_ASFLAGS) $(BOOT_DEFINE) $(BOOT_INC)

LIBDIR = $(MAIN_TOPDIR)/$(LIB_PATH)/$(MODULE_DIR)
OBJDIR = $(MAIN_TOPDIR)/$(OBJ_PATH)/$(MODULE_DIR)
ID_CFG_FILE = $(MAIN_TOPDIR)/$(MODULE_DIR)/file_id.cfg

LIB_NAME = lib$(LIB).a
SRCS = $($(LIB)_srcs)
LIBOUT = $(LIBDIR)/$(LIB_NAME)

ifdef SRC_FILES
OBJ_SRCS = $(filter %.c, $(SRC_FILES))
ASM_SRCS = $(filter %.S, $(SRC_FILES))
else
OBJ_SRCS = $(foreach dir, $(SRCS), $(wildcard $(dir)/*.c))
ASM_SRCS = $(foreach dir, $(SRCS), $(wildcard $(dir)/*.S ))
endif

OBJS = $(patsubst %.c, $(OBJDIR)/%.o, $(OBJ_SRCS))
ASM_OBJS = $(patsubst %.S, $(OBJDIR)/%.o, $(ASM_SRCS))


SIGN_TOOL = $(MAIN_TOPDIR)/tools/sign_tool/sign_tool
ENCRYPT_KEY_PATH = $(MAIN_TOPDIR)/tools/sign_tool/aes_key.txt
ifeq ($(CONFIG_TARGET_SIG_SHA256), y)
    LINK_FILE = $(MAIN_TOPDIR)/build/scripts/loaderboot_sha256.lds
else ifeq ($(CONFIG_TARGET_SIG_ECC), y)
    LINK_FILE = $(MAIN_TOPDIR)/build/scripts/loaderboot_ecc.lds
    ROOT_KEY_PATH = $(MAIN_TOPDIR)/tools/sign_tool/root_ecc.pem
    SUB_KEY_PATH = $(MAIN_TOPDIR)/tools/sign_tool/sub_ecc.pem
    SIGN_TYPE = 2
else
    LINK_FILE = $(MAIN_TOPDIR)/build/scripts/loaderboot_rsa.lds
    ROOT_KEY_PATH = $(MAIN_TOPDIR)/tools/sign_tool/root_rsa.pem
    SUB_KEY_PATH = $(MAIN_TOPDIR)/tools/sign_tool/sub_rsa.pem
    ifeq ($(CONFIG_TARGET_SIG_RSA_V15), y)
        SIGN_TYPE = 0
    else ifeq ($(CONFIG_TARGET_SIG_RSA_PSS), y)
        SIGN_TYPE = 1
    endif
endif

CONFIG_TARGET_BIN_NAME = Hi3861
BOOT_ELF = $(MAIN_TOPDIR)/$(CACHE_PATH)/loader_boot.elf
BOOT_BIN = $(MAIN_TOPDIR)/$(CACHE_PATH)/hi_loader_boot.bin
BOOT_SIGNED_BIN = $(MAIN_TOPDIR)/$(BIN_PATH)/$(CONFIG_TARGET_BIN_NAME)_loader_signed.bin

all: $(OBJS) $(ASM_OBJS)
	$(CC) $(BOOT_CCFLAGS) $(BOOT_DEFINE) $(BOOT_LINK_FLAGS) -L$(MAIN_TOPDIR)/build/libs -T $(LINK_FILE)  $(sort $^) -o $(BOOT_ELF)
	$(OBJCOPY) -Obinary -R .rom.text -R .rom.code.text -R .u_boot_cmd  -R .rom.data -R .rom.code.data -R .rom.bss -R .rom.code.bss -S $(BOOT_ELF) $(BOOT_BIN)
ifeq ($(CONFIG_TARGET_SIG_SHA256), y)
	$(SIGN_TOOL) -i $(BOOT_BIN) -o $(BOOT_SIGNED_BIN) -n
else ifeq ($(CONFIG_BOOT_ENCRYPT), y)
	$(SIGN_TOOL) -i $(BOOT_BIN) -o $(BOOT_SIGNED_BIN) -r$(ROOT_KEY_PATH) -s$(SUB_KEY_PATH) -v $(CONFIG_TARGET_BOOT_VER) -a $(SIGN_TYPE) -e$(ENCRYPT_KEY_PATH)
else
	$(SIGN_TOOL) -i $(BOOT_BIN) -o $(BOOT_SIGNED_BIN) -r$(ROOT_KEY_PATH) -s$(SUB_KEY_PATH) -v $(CONFIG_TARGET_BOOT_VER) -a $(SIGN_TYPE) -e$(ENCRYPT_KEY_PATH)
endif
	$(Q)echo [LOADER_BOOT] SUCCESS
	$(RM) $(BOOT_ELF) $(BOOT_BIN)


include $(MAIN_TOPDIR)/build/make_scripts/lib.mk
