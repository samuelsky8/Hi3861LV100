/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2012-2019. All rights reserved.
 * Description: Flash encryption and decryption feature header file.
 * Author: hisilicon
 * Create: 2020-03-16
 */

#ifndef __ENCRYPT_UPG_DUAL_PARTITION_H__
#define __ENCRYPT_UPG_DUAL_PARTITION_H__

#if defined(CONFIG_FLASH_ENCRYPT_SUPPORT)
#include <hi_config.h>
#include <hi_mem.h>

#define crypto_mem_free(sz)                  \
    do {                                     \
        if ((sz) != HI_NULL) {               \
            hi_free(HI_MOD_ID_CRYPTO, (sz)); \
        }                                    \
        (sz) = HI_NULL;                      \
    } while (0)

#define IV_BYTE_LENGTH          16
#define ROOTKEY_IV_BYTE_LENGTH  32

#define DIE_ID_BYTE_LENGTH      24

#define KEY_BYTE_LENGTH         32

#define SHA_256_LENGTH          32

#define CRYPTO_CNT_NUM          6

#define CRYPTO_FIRMWARE_LENGTH  4096

#define ENCRYPT_KDF_ITERATION_CNT       1000

#define MIN_CRYPTO_BLOCK_SIZE   16

#define HI_NV_FTM_KERNELA_WORK_ID         0x4
#define HI_NV_FTM_BACKUP_KERNELA_WORK_ID  0x5
#define HI_NV_FTM_KERNELB_WORK_ID         0x6
#define HI_NV_FTM_BACKUP_KERNELB_WORK_ID  0x7

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
    hi_u8 *raw_buf;
} encrypt_ctx;

encrypt_ctx *encrypt_get_ctx(hi_void);

hi_u32 crypto_decrypt(encrypt_ctx *para);

hi_u32 encrypt_upg_data(encrypt_ctx *para);

#endif

#endif
