/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2012-2019. All rights reserved.
 * Description: Flash encryption and decryption feature src file.
 * Author: hisilicon
 * Create: 2020-03-16
 */

#ifdef CONFIG_FLASH_ENCRYPT_SUPPORT
#include <hi_stdlib.h>
#include <hi_mem.h>
#include <hi_cipher.h>
#include <hi_efuse.h>
#include <hi_flash.h>
#include <hi_nv.h>
#include <hi_partition_table.h>
#include "kernel_crypto.h"

#define SFC_BUFFER_BASE_ADDRESS             0x400000

/* 和die_id的哈希异或生成rootkry盐值，工作密钥的随机数调接口随机生成 */
static hi_u8 g_rootkey_magic_num[ROOTKEY_IV_BYTE_LENGTH] = { 0x97, 0x0B, 0x79, 0x13, 0x26, 0x79, 0x47, 0xEE,
                                                             0xBD, 0x9C, 0x9D, 0xD3, 0x96, 0xEF, 0xE7, 0xDD,
                                                             0xE4, 0xEE, 0x10, 0x0E, 0x43, 0x4D, 0x94, 0x24,
                                                             0xC7, 0x54, 0x6D, 0xFB, 0x15, 0xA1, 0x46, 0x97 };

encrypt_ctx g_encrypt_param = {0};

encrypt_ctx *encrypt_get_ctx(hi_void)
{
    return &g_encrypt_param;
}

hi_u32 crypto_content_id(encrypt_ctx *cfg, crypto_workkey_partition *content, crypto_workkey_partition *content_bak)
{
    hi_flash_partition_table *partition = hi_get_partition_table();
    hi_u32 kernel_a = partition->table[HI_FLASH_PARTITON_KERNEL_A].addr;
    hi_u32 kernel_b = partition->table[HI_FLASH_PARTITON_KERNEL_B].addr;
    if (cfg->kernel_addr == kernel_a) {
        *content = CRYPTO_WORKKEY_KERNEL_A;
        *content_bak = CRYPTO_WORKKEY_KERNEL_A_BACKUP;
    } else if (cfg->kernel_addr == kernel_b) {
        *content = CRYPTO_WORKKEY_KERNEL_B;
        *content_bak = CRYPTO_WORKKEY_KERNEL_B_BACKUP;
    } else {
        return HI_ERR_FLASH_CRYPTO_KERNEL_ADDR_ERR;
    }

    return HI_ERR_SUCCESS;
}

static hi_u32 crypto_prepare(hi_void)
{
    hi_u32 ret;
    hi_u8 hash[SHA_256_LENGTH];
    hi_u8 die_id[DIE_ID_BYTE_LENGTH];
    hi_u8 rootkey_iv[ROOTKEY_IV_BYTE_LENGTH];
    hi_cipher_kdf_ctrl ctrl;
    hi_u32 i;

    ret = hi_efuse_read(HI_EFUSE_DIE_RW_ID, die_id, DIE_ID_BYTE_LENGTH);
    if (ret != HI_ERR_SUCCESS) {
        return ret;
    }
    ret = hi_cipher_hash_sha256((uintptr_t)die_id, DIE_ID_BYTE_LENGTH, hash, SHA_256_LENGTH);
    if (ret != HI_ERR_SUCCESS) {
        return ret;
    }
    for (i = 0; i < ROOTKEY_IV_BYTE_LENGTH; i++) {
        rootkey_iv[i] = g_rootkey_magic_num[i] ^ hash[i];
    }
    ctrl.salt = rootkey_iv;
    ctrl.salt_len = sizeof(rootkey_iv);
    ctrl.kdf_cnt = ENCRYPT_KDF_ITERATION_CNT;
    ctrl.kdf_mode = HI_CIPHER_SSS_KDF_KEY_STORAGE; /* 自动生成HUK值的方式，硬件直接从EFUSE中获取HUK，生成根密钥固定 */
    return hi_cipher_kdf_key_derive(&ctrl);
}

static hi_void crpto_set_aes_ctrl_default_value(hi_cipher_aes_ctrl *aes_ctrl)
{
    if (aes_ctrl == HI_NULL) {
        return;
    }
    aes_ctrl->random_en = HI_FALSE;
    aes_ctrl->key_from = HI_CIPHER_AES_KEY_FROM_CPU;
    aes_ctrl->work_mode = HI_CIPHER_AES_WORK_MODE_CBC;
    aes_ctrl->key_len = HI_CIPHER_AES_KEY_LENGTH_256BIT;
}

static hi_u32 crypto_load_root_data(hi_cipher_kdf_ctrl *ctrl)
{
    hi_u32 ret;
    hi_u32 i;
    hi_u8 hash[SHA_256_LENGTH];
    hi_u8 die_id[DIE_ID_BYTE_LENGTH];
    hi_u8 rootkey_iv[ROOTKEY_IV_BYTE_LENGTH];

    ret = hi_efuse_read(HI_EFUSE_DIE_RW_ID, die_id, DIE_ID_BYTE_LENGTH);
    if (ret != HI_ERR_SUCCESS) {
        return ret;
    }
    ret = hi_cipher_hash_sha256((uintptr_t)die_id, DIE_ID_BYTE_LENGTH, hash, SHA_256_LENGTH);
    if (ret != HI_ERR_SUCCESS) {
        return ret;
    }
    for (i = 0; i < ROOTKEY_IV_BYTE_LENGTH; i++) {
        rootkey_iv[i] = g_rootkey_magic_num[i] ^ hash[i];
    }
    ctrl->salt = rootkey_iv;
    ctrl->salt_len = sizeof(rootkey_iv);
    ctrl->kdf_cnt = ENCRYPT_KDF_ITERATION_CNT;
    ctrl->kdf_mode = HI_CIPHER_SSS_KDF_KEY_STORAGE;
    ret = hi_cipher_kdf_key_derive(ctrl);
    if (ret != HI_ERR_SUCCESS) {
        return ret;
    }

    return HI_ERR_SUCCESS;
}

static hi_u32 crypto_decrypt_hash(hi_flash_crypto_content *key_content)
{
    hi_u32 ret;
    hi_u32 content_size = (hi_u32)sizeof(hi_flash_crypto_content);

    hi_flash_crypto_content *content_tmp = (hi_flash_crypto_content *)hi_malloc(HI_MOD_ID_CRYPTO, content_size);
    if (content_tmp == HI_NULL) {
        return HI_ERR_FLASH_CRYPTO_MALLOC_FAIL;
    }

    ret = (hi_u32)memcpy_s(content_tmp, content_size, key_content, content_size);
    if (ret != EOK) {
        goto fail;
    }

    hi_cipher_aes_ctrl aes_ctrl = {
        .random_en = HI_FALSE,
        .key_from = HI_CIPHER_AES_KEY_FROM_KDF,
        .work_mode = HI_CIPHER_AES_WORK_MODE_CBC,
        .key_len = HI_CIPHER_AES_KEY_LENGTH_256BIT,
    };

    ret = (hi_u32)memcpy_s(aes_ctrl.iv, sizeof(aes_ctrl.iv), content_tmp->iv_nv, IV_BYTE_LENGTH);
    if (ret != EOK) {
        goto fail;
    }
    ret = hi_cipher_aes_config(&aes_ctrl);
    if (ret != HI_ERR_SUCCESS) {
        goto crypto_fail;
    }
    ret = hi_cipher_aes_crypto((uintptr_t)content_tmp->iv_content, (uintptr_t)key_content->iv_content,
        content_size - IV_BYTE_LENGTH, HI_FALSE);
    if (ret != HI_ERR_SUCCESS) {
        goto crypto_fail;
    }

crypto_fail:
    (hi_void) hi_cipher_aes_destroy_config();
fail:
    crypto_mem_free(content_tmp);
    return ret;
}

static hi_u32 crypto_encrypt_hash(hi_flash_crypto_content *key_content)
{
    hi_cipher_kdf_ctrl ctrl;
    hi_cipher_aes_ctrl aes_ctrl;
    hi_u32 content_size = (hi_u32)sizeof(hi_flash_crypto_content);

    hi_flash_crypto_content *data_tmp = (hi_flash_crypto_content *)hi_malloc(HI_MOD_ID_CRYPTO, content_size);
    if (data_tmp == HI_NULL) {
        return HI_ERR_FLASH_CRYPTO_MALLOC_FAIL;
    }

    hi_u32 ret = crypto_load_root_data(&ctrl);
    if (ret != HI_ERR_SUCCESS) {
        goto fail;
    }

    ret = (hi_u32)memcpy_s(aes_ctrl.key, sizeof(aes_ctrl.key), ctrl.result, sizeof(ctrl.result));
    if (ret != EOK) {
        goto fail;
    }

    ret = (hi_u32)memcpy_s(aes_ctrl.iv, sizeof(aes_ctrl.iv), key_content->iv_nv, IV_BYTE_LENGTH);
    if (ret != EOK) {
        goto fail;
    }

    aes_ctrl.random_en = HI_FALSE;
    aes_ctrl.key_from = HI_CIPHER_AES_KEY_FROM_KDF;
    aes_ctrl.work_mode = HI_CIPHER_AES_WORK_MODE_CBC;
    aes_ctrl.key_len = HI_CIPHER_AES_KEY_LENGTH_256BIT;
    ret = hi_cipher_aes_config(&aes_ctrl);
    if (ret != HI_ERR_SUCCESS) {
        goto crypto_fail;
    }
    ret = hi_cipher_aes_crypto((hi_u32)(uintptr_t)key_content->iv_content, (hi_u32)(uintptr_t)(data_tmp->iv_content),
        content_size - IV_BYTE_LENGTH, HI_TRUE);
    if (ret != HI_ERR_SUCCESS) {
        goto crypto_fail;
    }

    ret = (hi_u32)memcpy_s(key_content->iv_content, content_size - IV_BYTE_LENGTH, data_tmp->iv_content,
        content_size - IV_BYTE_LENGTH);

crypto_fail:
    (hi_void) hi_cipher_aes_destroy_config();
fail:
    crypto_mem_free(data_tmp);
    return ret;
}

static hi_u32 crypto_load_key_content(crypto_workkey_partition part, hi_flash_crypto_content *key_content)
{
    hi_u32 ret = HI_ERR_SUCCESS;
    hi_u8 hash[SHA_256_LENGTH];
    hi_u8 key_e[KEY_BYTE_LENGTH] = { 0 };

    (hi_void) memset_s(key_e, sizeof(key_e), 0x0, KEY_BYTE_LENGTH);
    if (part == CRYPTO_WORKKEY_KERNEL_A) {
        ret = hi_factory_nv_read(HI_NV_FTM_KERNELA_WORK_ID, key_content, sizeof(hi_flash_crypto_content), 0);
        if (ret != HI_ERR_SUCCESS) {
            goto fail;
        }
    } else if (part == CRYPTO_WORKKEY_KERNEL_A_BACKUP) {
        ret = hi_factory_nv_read(HI_NV_FTM_BACKUP_KERNELA_WORK_ID, key_content, sizeof(hi_flash_crypto_content), 0);
        if (ret != HI_ERR_SUCCESS) {
            goto fail;
        }
    } else if (part == CRYPTO_WORKKEY_KERNEL_B) {
        ret = hi_factory_nv_read(HI_NV_FTM_KERNELB_WORK_ID, key_content, sizeof(hi_flash_crypto_content), 0);
        if (ret != HI_ERR_SUCCESS) {
            goto fail;
        }
    } else if (part == CRYPTO_WORKKEY_KERNEL_B_BACKUP) {
        ret = hi_factory_nv_read(HI_NV_FTM_BACKUP_KERNELB_WORK_ID, key_content, sizeof(hi_flash_crypto_content), 0);
        if (ret != HI_ERR_SUCCESS) {
            goto fail;
        }
    }

    if (memcmp(key_content->work_text, key_e, KEY_BYTE_LENGTH) == HI_ERR_SUCCESS) {
        ret = HI_ERR_FLASH_CRYPTO_KEY_EMPTY_ERR;
        goto fail;
    }

    ret = crypto_decrypt_hash(key_content);
    if (ret != HI_ERR_SUCCESS) {
        goto fail;
    }

    ret = hi_cipher_hash_sha256((uintptr_t)(key_content->iv_nv), sizeof(hi_flash_crypto_content) - SHA_256_LENGTH,
                                hash, SHA_256_LENGTH);
    if (ret != HI_ERR_SUCCESS) {
        goto fail;
    }
    if (memcmp(key_content->content_sh256, hash, SHA_256_LENGTH) != HI_ERR_SUCCESS) {
        ret = HI_ERR_FLASH_CRYPTO_KEY_INVALID_ERR;
        goto fail;
    }
fail:
    return ret;
}

static hi_u32 crypto_save_work_key(crypto_workkey_partition part, hi_flash_crypto_content *key_content)
{
    hi_u32 ret;
    hi_u32 content_size = (hi_u32)sizeof(hi_flash_crypto_content);
    hi_flash_crypto_content *content_tmp = (hi_flash_crypto_content *)hi_malloc(HI_MOD_ID_CRYPTO, content_size);
    if (content_tmp == HI_NULL) {
        return HI_ERR_FLASH_CRYPTO_MALLOC_FAIL;
    }

    ret = (hi_u32)memcpy_s(content_tmp, content_size, key_content, content_size);
    if (ret != EOK) {
        goto fail;
    }

    /* 先加密，再存到工厂区NV中 */
    ret = crypto_encrypt_hash(content_tmp);
    if (ret != HI_ERR_SUCCESS) {
        goto fail;
    }

    if ((hi_u32)part & CRYPTO_WORKKEY_KERNEL_A) {
        ret = hi_factory_nv_write(HI_NV_FTM_KERNELA_WORK_ID, content_tmp, content_size, 0);
        if (ret != HI_ERR_SUCCESS) {
            ret = HI_ERR_FLASH_CRYPTO_KEY_SAVE_ERR;
            goto fail;
        }
    }
    if ((hi_u32)part & CRYPTO_WORKKEY_KERNEL_A_BACKUP) {
        ret = hi_factory_nv_write(HI_NV_FTM_BACKUP_KERNELA_WORK_ID, content_tmp, content_size, 0);
        if (ret != HI_ERR_SUCCESS) {
            ret =  HI_ERR_FLASH_CRYPTO_KEY_SAVE_ERR;
            goto fail;
        }
    }

    if ((hi_u32)part & CRYPTO_WORKKEY_KERNEL_B) {
        ret = hi_factory_nv_write(HI_NV_FTM_KERNELB_WORK_ID, content_tmp, content_size, 0);
        if (ret != HI_ERR_SUCCESS) {
            ret = HI_ERR_FLASH_CRYPTO_KEY_SAVE_ERR;
            goto fail;
        }
    }
    if ((hi_u32)part & CRYPTO_WORKKEY_KERNEL_B_BACKUP) {
        ret = hi_factory_nv_write(HI_NV_FTM_BACKUP_KERNELB_WORK_ID, content_tmp, content_size, 0);
        if (ret != HI_ERR_SUCCESS) {
            ret =  HI_ERR_FLASH_CRYPTO_KEY_SAVE_ERR;
            goto fail;
        }
    }

fail:
    crypto_mem_free(content_tmp);
    return ret;
}

static hi_u32 crypto_gen_key_content(hi_flash_crypto_content *key_content)
{
    hi_u8 salt[IV_BYTE_LENGTH];
    hi_u8 kdf_key[KEY_BYTE_LENGTH];
    hi_cipher_kdf_ctrl ctrl;

    (hi_void)hi_cipher_trng_get_random_bytes(salt, IV_BYTE_LENGTH);
    (hi_void)hi_cipher_trng_get_random_bytes(kdf_key, KEY_BYTE_LENGTH);
    (hi_void)hi_cipher_trng_get_random_bytes(key_content->iv_nv, IV_BYTE_LENGTH);
    (hi_void)hi_cipher_trng_get_random_bytes(key_content->iv_content, IV_BYTE_LENGTH);

    if ((hi_u32)memcpy_s(ctrl.key, sizeof(ctrl.key), kdf_key, sizeof(kdf_key)) != EOK) {
        return HI_ERR_FAILURE;
    }
    ctrl.salt = salt;
    ctrl.salt_len = sizeof(salt);
    ctrl.kdf_cnt = ENCRYPT_KDF_ITERATION_CNT;
    ctrl.kdf_mode = HI_CIPHER_SSS_KDF_KEY_DEVICE; /* 用户提供HUK值的方式 */
    if (hi_cipher_kdf_key_derive(&ctrl) != HI_ERR_SUCCESS) {
        return HI_ERR_FAILURE;
    }

    if (memcpy_s(key_content->work_text, KEY_BYTE_LENGTH, ctrl.result, sizeof(ctrl.result)) != EOK) {
        return HI_ERR_FAILURE;
    }

    if (hi_cipher_hash_sha256((uintptr_t)(key_content->iv_nv), sizeof(hi_flash_crypto_content) - SHA_256_LENGTH,
                              key_content->content_sh256, SHA_256_LENGTH) != HI_ERR_SUCCESS) {
        return HI_ERR_FAILURE;
    }

    return HI_ERR_SUCCESS;
}

static hi_u32 crypto_decrypt_kernel(hi_flash_crypto_content *content, encrypt_ctx *para)
{
    hi_u32 ret;
    hi_cipher_aes_ctrl aes_ctrl;
    hi_u8 *fw_raw_data = para->raw_buf;

    ret = (hi_u32)memcpy_s(aes_ctrl.key, sizeof(aes_ctrl.key), content->work_text, KEY_BYTE_LENGTH);
    if (ret != HI_ERR_SUCCESS) {
        goto fail;
    }

    ret = (hi_u32)memcpy_s(aes_ctrl.iv, sizeof(aes_ctrl.iv), content->iv_content, IV_BYTE_LENGTH);
    if (ret != HI_ERR_SUCCESS) {
        goto fail;
    }

    crpto_set_aes_ctrl_default_value(&aes_ctrl);
    ret = hi_cipher_aes_config(&aes_ctrl);
    if (ret != HI_ERR_SUCCESS) {
        goto fail;
    }

    ret = hi_cipher_aes_crypto(para->kernel_addr + para->encrypt_start_addr + SFC_BUFFER_BASE_ADDRESS,
        (uintptr_t)fw_raw_data, para->encrypt_total_size, HI_FALSE);
    if (ret != HI_ERR_SUCCESS) {
        goto crypto_fail;
    }

crypto_fail:
    (hi_void) hi_cipher_aes_destroy_config();
fail:
    return ret;
}

hi_u32 crypto_decrypt(encrypt_ctx *para)
{
    hi_u32 ret;
    hi_bool is_backup_content = HI_FALSE;
    crypto_workkey_partition werk_content;
    crypto_workkey_partition werk_content_bak;
    ret = crypto_content_id(para, &werk_content, &werk_content_bak);
    if (ret != HI_ERR_SUCCESS) {
        return ret;
    }

    hi_flash_crypto_content *key_content = (hi_flash_crypto_content *)hi_malloc(HI_MOD_ID_CRYPTO,
        sizeof(hi_flash_crypto_content));
    if (key_content == HI_NULL) {
        return HI_ERR_FLASH_CRYPTO_PREPARE_ERR;
    }

    ret = crypto_prepare();
    if (ret != HI_ERR_SUCCESS) {
        crypto_mem_free(key_content);
        return HI_ERR_FLASH_CRYPTO_PREPARE_ERR;
    }

    ret = crypto_load_key_content(werk_content, key_content);
    if (ret != HI_ERR_SUCCESS) {
        ret = crypto_load_key_content(werk_content_bak, key_content);
        if (ret != HI_ERR_SUCCESS) {
            goto fail;
        } else {
            ret = crypto_save_work_key(werk_content, key_content);
            if (ret != HI_ERR_SUCCESS) {
                goto fail;
            }
            is_backup_content = HI_TRUE;
        }
    }

    ret = crypto_decrypt_kernel(key_content, para);
    if ((ret != HI_ERR_SUCCESS) && (is_backup_content == HI_FALSE)) {
        ret = crypto_load_key_content(werk_content_bak, key_content);
        if (ret != HI_ERR_SUCCESS) {
            goto fail;
        }
        ret = crypto_decrypt_kernel(key_content, para);
        if (ret != HI_ERR_SUCCESS) {
            ret = HI_ERR_FLASH_CRYPTO_DATA_DECRYPT_ERR;
            goto fail;
        }
    }
fail:
    crypto_mem_free(key_content);
    return ret;
}

static hi_u32 crypto_encrypt_data(hi_flash_crypto_content *new_content, encrypt_ctx *para)
{
    hi_u32 ret = HI_ERR_FAILURE;
    hi_cipher_aes_ctrl aes_ctrl;

    hi_u8 *fw_cyp_data = hi_malloc(HI_MOD_ID_CRYPTO, para->encrypt_total_size);
    if (fw_cyp_data == HI_NULL) {
        return HI_ERR_FLASH_CRYPTO_PREPARE_ERR;
    }

    if (memcpy_s(aes_ctrl.key, sizeof(aes_ctrl.key), new_content->work_text, KEY_BYTE_LENGTH) != EOK) {
        goto fail;
    }

    if (memcpy_s(aes_ctrl.iv, sizeof(aes_ctrl.iv), new_content->iv_content, IV_BYTE_LENGTH) != EOK) {
        goto fail;
    }

    crpto_set_aes_ctrl_default_value(&aes_ctrl);
    ret = hi_cipher_aes_config(&aes_ctrl);
    if (ret != HI_ERR_SUCCESS) {
        goto fail;
    }

    ret = hi_cipher_aes_crypto((uintptr_t)(para->buf), (uintptr_t)fw_cyp_data, para->encrypt_total_size, HI_TRUE);
    if (ret != HI_ERR_SUCCESS) {
        goto crypto_fail;
    }

    ret = hi_flash_write(para->kernel_addr + para->encrypt_start_addr, para->encrypt_total_size, fw_cyp_data, HI_TRUE);
    if (ret != HI_ERR_SUCCESS) {
        goto crypto_fail;
    }

crypto_fail:
    (hi_void) hi_cipher_aes_destroy_config();
fail:
    crypto_mem_free(fw_cyp_data);
    return ret;
}

hi_u32 encrypt_check_start_addr(hi_u32 offset_addr)
{
    hi_flash_partition_table *partition = hi_get_partition_table();
    hi_u32 kernel_a = partition->table[HI_FLASH_PARTITON_KERNEL_A].addr;
    hi_u32 kernel_b = partition->table[HI_FLASH_PARTITON_KERNEL_B].addr;

    if ((offset_addr != kernel_a) && (offset_addr != kernel_b)) {
        return HI_ERR_FLASH_CRYPTO_INVALID_PARAM;
    }

    return HI_ERR_SUCCESS;
}

hi_u32 encrypt_upg_data(encrypt_ctx *para)
{
    hi_u32 ret;
    crypto_workkey_partition werk_content;
    crypto_workkey_partition werk_content_bak;
    ret = crypto_content_id(para, &werk_content, &werk_content_bak);
    if (ret != HI_ERR_SUCCESS) {
        return ret;
    }

    hi_flash_crypto_content *new_content = (hi_flash_crypto_content *)hi_malloc(HI_MOD_ID_CRYPTO,
        sizeof(hi_flash_crypto_content));
    if (new_content == HI_NULL) {
        return HI_ERR_FLASH_CRYPTO_PREPARE_ERR;
    }

    ret = crypto_prepare();
    if (ret != HI_ERR_SUCCESS) {
        crypto_mem_free(new_content);
        return HI_ERR_FLASH_CRYPTO_PREPARE_ERR;
    }

    /* 生成新密钥存放到密钥分区 */
    ret = crypto_gen_key_content(new_content);
    if (ret != HI_ERR_SUCCESS) {
        goto fail;
    }

    /* 更新密钥流程中，密钥备份区暂不更新，待旧kernel解密成功后再更新密钥备份区 */
    ret = crypto_save_work_key(werk_content, new_content);
    if (ret != HI_ERR_SUCCESS) {
        goto fail;
    }

    ret = crypto_encrypt_data(new_content, para);
    if (ret != HI_ERR_SUCCESS) {
        goto fail;
    }

    /* 更新密钥流程中，密钥备份区暂不更新，待旧kernel解密成功后再更新密钥备份区 */
    ret = crypto_save_work_key(werk_content_bak, new_content);
    if (ret != HI_ERR_SUCCESS) {
    }

fail:
    crypto_mem_free(new_content);
    return ret;
}

#endif
