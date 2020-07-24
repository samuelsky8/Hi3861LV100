/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2012-2019. All rights reserved.
 * Description: Flash encryption and decryption feature head file.
 * Author: wangjian
 * Create: 2019-05-12
 */
#ifndef __CRYPTO_H__
#define __CRYPTO_H__
#ifdef CONFIG_FLASH_ENCRYPT_SUPPORT
#include <hi_flashboot.h>
#include <hi_types.h>

#define crypto_mem_free(sz)               \
    do {                                  \
        if ((sz) != HI_NULL) {            \
            boot_free(sz);                \
        }                                 \
        (sz) = HI_NULL;                   \
    } while (0)

#define IV_BYTE_LENGTH          16
#define ROOTKEY_IV_BYTE_LENGTH  32

#define DIE_ID_BYTE_LENGTH      24

#define KEY_BYTE_LENGTH         32

#define SHA_256_LENGTH          32

#define CRYPTO_CNT_NUM          6

#define CRYPTO_KERNEL_LENGTH  4096

#define KERNEL_RAM_ADDR       0xD8200

#define KDF_ITERATION_CNT       1000

#define MIN_CRYPTO_BLOCK_SIZE   16

#define HI_NV_FTM_KERNELA_WORK_ID         0x4
#define HI_NV_FTM_BACKUP_KERNELA_WORK_ID  0x5
#define HI_NV_FTM_KERNELB_WORK_ID         0x6
#define HI_NV_FTM_BACKUP_KERNELB_WORK_ID  0x7

#ifdef CONFIG_FLASH_ENCRYPT_NOT_USE_EFUSE
#define HI_NV_FLASH_CRYPT_CNT_ID      0x8
#endif

#define ENCRYPT_DATA 0
#define DECRYPT_DATA 1

typedef enum {
    CRYPTO_WORKKEY_KERNEL_A = 0x1,
    CRYPTO_WORKKEY_KERNEL_A_BACKUP = 0x2,
    CRYPTO_WORKKEY_KERNEL_A_BOTH = 0x3,
    CRYPTO_WORKKEY_KERNEL_B = 0x4,
    CRYPTO_WORKKEY_KERNEL_B_BACKUP = 0x8,
    CRYPTO_WORKKEY_KERNEL_B_BOTH = 0xC,
} crypto_workkey_partition;

typedef struct {
    hi_u8 iv_nv[IV_BYTE_LENGTH];         /* 加密后段，存到工厂区NV */
    hi_u8 iv_content[IV_BYTE_LENGTH];    /* 工作密钥加密加flash的盐值 */
    hi_u8 work_text[KEY_BYTE_LENGTH];    /* 工作密钥 */
    hi_u8 content_sh256[SHA_256_LENGTH]; /* 以上三个数据哈希的结果 */
} hi_flash_crypto_content;

typedef enum {
    BURN_KERNEL_ENCRYPT = 0x0,
    UPG_KERNEL_ENCRYPT = 0x1,
} flash_encrypt_mode;

typedef enum {
    CURRENT_KERNEL,
    OLD_KERNEL,
} kernel_mode_type;

#ifdef CONFIG_FLASH_ENCRYPT_NOT_USE_EFUSE
typedef struct {
    hi_u32 flash_crypt_cnt;
} hi_flash_crypto_cnt;
#endif

#define KERNEL_ENCRYPT_SIZE 4096

typedef struct {
    uintptr_t kernel_addr;
    uintptr_t encrypt_start_addr;
    uintptr_t encrypt_end_addr;
    hi_u16 encrypt_total_size;
    hi_u16 encrypted_size;
    hi_bool is_encrypt_section;
    hi_bool para_is_init;
    hi_u8 *buf;
} encrypt_ctx;

encrypt_ctx *encrypt_get_ctx(hi_void);

hi_u32 encrypt_upg_data(encrypt_ctx *para);

#ifdef CONFIG_FLASH_ENCRYPT_NOT_USE_EFUSE
hi_flash_crypto_cnt *boot_crypto_get_cfg(hi_void);
hi_u32 boot_set_crypto_finish_flag(hi_void);
#endif

hi_u32 crypto_decrypt(hi_u32 ram_addr, hi_u32 ram_size);
hi_u32 crypto_burn_encrypt(hi_void);
hi_u32 upg_crypto_encrypt(hi_void);
hi_bool is_burn_need_crypto(hi_void);
hi_bool is_upg_need_crypto(hi_void);

hi_u32 crypto_load_flash_raw(uintptr_t ram_addr, hi_u32 ram_size);

hi_void crypto_check_decrypt(hi_void);
hi_u32 crypto_kernel_write(hi_u32 start, hi_u32 offset, hi_u8 *buffer, hi_u32 size);

#endif
#endif
