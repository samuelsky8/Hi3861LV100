/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: Flash encryption and decryption feature src file.
 * Author: hisilicon
 * Create: 2020-03-16
 */
#ifdef CONFIG_FLASH_ENCRYPT_SUPPORT
#include <hi_nvm.h>
#include <load_partition_table.h>

#include "load_crypto.h"
#include "burn_file.h"

#define ENCPT_CFG_FLAG 1

/* 和die_id的哈希异或生成rootkry盐值，工作密钥的随机数调接口随机生成 */
static hi_u8 g_rootkey_magic_num[ROOTKEY_IV_BYTE_LENGTH] = { 0x97, 0x0B, 0x79, 0x13, 0x26, 0x79, 0x47, 0xEE,
                                                             0xBD, 0x9C, 0x9D, 0xD3, 0x96, 0xEF, 0xE7, 0xDD,
                                                             0xE4, 0xEE, 0x10, 0x0E, 0x43, 0x4D, 0x94, 0x24,
                                                             0xC7, 0x54, 0x6D, 0xFB, 0x15, 0xA1, 0x46, 0x97 };

static hi_efuse_idx g_efuse_id[CRYPTO_CNT_NUM] = {
    HI_EFUSE_FLASH_ENCPY_CNT0_RW_ID,
    HI_EFUSE_FLASH_ENCPY_CNT1_RW_ID,
    HI_EFUSE_FLASH_ENCPY_CNT2_RW_ID,
    HI_EFUSE_FLASH_ENCPY_CNT3_RW_ID,
    HI_EFUSE_FLASH_ENCPY_CNT4_RW_ID,
    HI_EFUSE_FLASH_ENCPY_CNT5_RW_ID
};

static hi_efuse_idx g_writeable_efuse = HI_EFUSE_IDX_MAX;

#ifdef CONFIG_FLASH_ENCRYPT_NOT_USE_EFUSE
hi_flash_crypto_cnt g_crypto_nv_cfg;

hi_flash_crypto_cnt *boot_crypto_get_cfg(hi_void)
{
    return &g_crypto_nv_cfg;
}

hi_u32 boot_crypto_save_cfg_to_nv(hi_void)
{
    hi_flash_crypto_cnt *cfg = boot_crypto_get_cfg();
    hi_u32 ret = hi_factory_nv_write(HI_NV_FLASH_CRYPT_CNT_ID, cfg, sizeof(hi_flash_crypto_cnt), 0);
    if (ret != HI_ERR_SUCCESS) {
        boot_msg1("[boot crypto save nv]nv write fail,ret ", ret);
        return ret;
    }
    return ret;
}

hi_void boot_crypto_load_cfg_from_nv(hi_void)
{
    hi_u32 cs;
    hi_flash_crypto_cnt nv_cfg = { 0 };
    hi_flash_crypto_cnt *cfg = boot_crypto_get_cfg();
    hi_u32 ret = hi_factory_nv_read(HI_NV_FLASH_CRYPT_CNT_ID, &nv_cfg, sizeof(hi_flash_crypto_cnt), 0);
    if ((ret != HI_ERR_SUCCESS) ||
        ((nv_cfg.flash_crypt_cnt != 0) && (nv_cfg.flash_crypt_cnt != 1))) {
        cfg->flash_crypt_cnt = 0;
        ret = boot_crypto_save_cfg_to_nv();
        if (ret != HI_ERR_SUCCESS) {
            return;
        }
    } else {
        cs = (uintptr_t)cfg ^ sizeof(hi_flash_crypto_cnt) ^ ((uintptr_t)&nv_cfg) ^ sizeof(hi_flash_crypto_cnt);
        memcpy_s(cfg, sizeof(hi_flash_crypto_cnt), &nv_cfg, sizeof(hi_flash_crypto_cnt), cs);
    }
}

hi_u32 boot_set_crypto_finish_flag(hi_void)
{
    hi_u32 ret;
    hi_flash_crypto_cnt *cfg = boot_crypto_get_cfg();
    cfg->flash_crypt_cnt = 0x1;
    ret = boot_crypto_save_cfg_to_nv();
    if (ret != HI_ERR_SUCCESS) {
        return ret;
    }

    return HI_ERR_SUCCESS;
}

#endif

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

static hi_u32 crypto_destory(hi_void)
{
    return hi_cipher_deinit();
}

static hi_u32 crypto_prepare(hi_void)
{
    hi_u32 ret;
    hi_u8 hash[SHA_256_LENGTH];
    hi_u8 die_id[DIE_ID_BYTE_LENGTH];
    hi_u8 rootkey_iv[ROOTKEY_IV_BYTE_LENGTH];
    hi_cipher_kdf_ctrl ctrl;
    hi_u32 i;

    ret = hi_cipher_init();
    if (ret != HI_ERR_SUCCESS) {
        return ret;
    }
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
    ctrl.kdf_cnt = KDF_ITERATION_CNT;
    ctrl.kdf_mode = HI_CIPHER_SSS_KDF_KEY_STORAGE; /* 自动生成HUK值的方式，硬件直接从EFUSE中获取HUK，生成根密钥固定 */
    return hi_cipher_kdf_key_derive(&ctrl);
}

hi_u8 get_flash_crypto_cfg(hi_void)
{
    hi_u8 flash_encpt_cfg;
    if (hi_efuse_read(HI_EFUSE_FLASH_ENCPY_CFG_RW_ID, &flash_encpt_cfg, (hi_u8)sizeof(hi_u8)) != HI_ERR_SUCCESS) {
        flash_encpt_cfg = ENCPT_CFG_FLAG;
    }

    return flash_encpt_cfg;
}

hi_bool is_burn_need_crypto(hi_void)
{
    hi_u8 flash_encpt_cfg = get_flash_crypto_cfg();
    if ((flash_encpt_cfg & 0x1) == ENCPT_CFG_FLAG) {
        hi_u8 flash_encpt_cnt = 0;
        hi_u32 i = 0;

        for (i = 0; i < CRYPTO_CNT_NUM; i++) {
            (hi_void)hi_efuse_read(g_efuse_id[i], &flash_encpt_cnt, (hi_u8)sizeof(hi_u8));
            if ((flash_encpt_cnt & 0x3) == 1) {
                g_writeable_efuse = g_efuse_id[i];
                return HI_TRUE;
            } else if ((flash_encpt_cnt & 0x3) == 0) {
                break;
            }
        }
    } else {
#ifdef CONFIG_FLASH_ENCRYPT_NOT_USE_EFUSE
        boot_crypto_load_cfg_from_nv();
        hi_flash_crypto_cnt *cfg = boot_crypto_get_cfg();
        if (cfg->flash_crypt_cnt == 0) {
            return HI_TRUE;
        }
#endif
    }
    return HI_FALSE;
}

hi_u32 boot_get_crypto_firmware_start(hi_void)
{
    hi_u32 flash_offset = 0;
    hi_flash_partition_table *partition = hi_get_partition_table();
    uintptr_t kernel_a_addr = partition->table[HI_FLASH_PARTITON_KERNEL_A].addr;

    loaderboot_get_start_addr_offset(kernel_a_addr, &flash_offset);

    return flash_offset;
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
    ctrl->kdf_cnt = KDF_ITERATION_CNT;
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
    hi_u32 cs;
    hi_u32 content_size = (hi_u32)sizeof(hi_flash_crypto_content);

    hi_flash_crypto_content *content_tmp = (hi_flash_crypto_content *)boot_malloc(content_size);
    if (content_tmp == HI_NULL) {
        return HI_PRINT_ERRNO_MALLOC_EXAUST_ERR;
    }

    cs = (uintptr_t)(content_tmp) ^ content_size ^ (uintptr_t)(key_content) ^ content_size;
    ret = (hi_u32)memcpy_s(content_tmp, content_size, key_content, content_size, cs);
    if (ret != EOK) {
        goto fail;
    }

    hi_cipher_aes_ctrl aes_ctrl = {
        .random_en = HI_FALSE,
        .key_from = HI_CIPHER_AES_KEY_FROM_KDF,
        .work_mode = HI_CIPHER_AES_WORK_MODE_CBC,
        .key_len = HI_CIPHER_AES_KEY_LENGTH_256BIT,
    };
    cs = (uintptr_t)(aes_ctrl.iv) ^ (hi_u32)sizeof(aes_ctrl.iv) ^ (uintptr_t)(content_tmp->iv_nv) ^ IV_BYTE_LENGTH;
    ret = (hi_u32)memcpy_s(aes_ctrl.iv, sizeof(aes_ctrl.iv), content_tmp->iv_nv, IV_BYTE_LENGTH, cs);
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

    hi_flash_crypto_content *data_tmp = (hi_flash_crypto_content *)boot_malloc(content_size);
    if (data_tmp == HI_NULL) {
        return HI_PRINT_ERRNO_MALLOC_EXAUST_ERR;
    }

    hi_u32 ret = crypto_load_root_data(&ctrl);
    if (ret != HI_ERR_SUCCESS) {
        goto fail;
    }

    hi_u32 cs = (uintptr_t)(aes_ctrl.key) ^ (hi_u32)sizeof(aes_ctrl.key) ^
        (uintptr_t)ctrl.result ^ (hi_u32)sizeof(ctrl.result);
    ret = (hi_u32)memcpy_s(aes_ctrl.key, sizeof(aes_ctrl.key), ctrl.result, sizeof(ctrl.result), cs);
    if (ret != EOK) {
        goto fail;
    }

    cs = (uintptr_t)(aes_ctrl.iv) ^ (hi_u32)sizeof(aes_ctrl.iv) ^ (uintptr_t)(key_content->iv_nv) ^
        IV_BYTE_LENGTH;
    ret = (hi_u32)memcpy_s(aes_ctrl.iv, sizeof(aes_ctrl.iv), key_content->iv_nv, IV_BYTE_LENGTH, cs);
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
    ret = hi_cipher_aes_crypto((uintptr_t)key_content->iv_content, (uintptr_t)(data_tmp->iv_content),
        content_size - IV_BYTE_LENGTH, HI_TRUE);
    if (ret != HI_ERR_SUCCESS) {
        goto crypto_fail;
    }

    cs = (uintptr_t)(key_content->iv_content) ^ (content_size - IV_BYTE_LENGTH) ^ (uintptr_t)(data_tmp->iv_content) ^
        (content_size - IV_BYTE_LENGTH);
    ret = (hi_u32)memcpy_s(key_content->iv_content, content_size - IV_BYTE_LENGTH, data_tmp->iv_content,
        content_size - IV_BYTE_LENGTH, cs);

crypto_fail:
    (hi_void) hi_cipher_aes_destroy_config();
fail:
    boot_free(data_tmp);
    return ret;
}

static hi_u32 crypto_load_key_content(crypto_workkey_partition part, hi_flash_crypto_content *key_content)
{
    hi_u32 ret = HI_ERR_SUCCESS;
    hi_u8 hash[SHA_256_LENGTH];
    hi_u8 key_e[KEY_BYTE_LENGTH] = { 0 };

    hi_u32 cs = (uintptr_t)key_e ^ (hi_u32)sizeof(key_e) ^ 0x0 ^ KEY_BYTE_LENGTH;
    (hi_void) memset_s(key_e, sizeof(key_e), 0x0, KEY_BYTE_LENGTH, cs);
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
    }

    if (memcmp(key_content->work_text, key_e, KEY_BYTE_LENGTH) == HI_ERR_SUCCESS) {
        ret = HI_PRINT_ERRNO_CRYPTO_KEY_EMPTY_ERR;
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
        ret = HI_PRINT_ERRNO_CRYPTO_KEY_INVALID_ERR;
        goto fail;
    }
fail:
    return ret;
}

static hi_u32 crypto_save_work_key(crypto_workkey_partition part, hi_flash_crypto_content *key_content)
{
    hi_u32 ret;
    hi_u32 cs;
    hi_u32 content_size = (hi_u32)sizeof(hi_flash_crypto_content);
    hi_flash_crypto_content *content_tmp = (hi_flash_crypto_content *)boot_malloc(content_size);
    if (content_tmp == HI_NULL) {
        return HI_PRINT_ERRNO_MALLOC_EXAUST_ERR;
    }

    cs = (uintptr_t)(content_tmp) ^ content_size ^ (uintptr_t)(key_content) ^ content_size;
    ret = (hi_u32)memcpy_s(content_tmp, content_size, key_content, content_size, cs);
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
            ret = HI_PRINT_ERRNO_CRYPTO_KEY_SAVE_ERR;
            goto fail;
        }
    }
    if ((hi_u32)part & CRYPTO_WORKKEY_KERNEL_A_BACKUP) {
        ret = hi_factory_nv_write(HI_NV_FTM_BACKUP_KERNELA_WORK_ID, content_tmp, content_size, 0);
        if (ret != HI_ERR_SUCCESS) {
            ret =  HI_PRINT_ERRNO_CRYPTO_KEY_SAVE_ERR;
            goto fail;
        }
    }

fail:
    crypto_mem_free(content_tmp);
    return ret;
}

static hi_u32 crypto_is_need_gen_key(hi_flash_crypto_content *key_content, hi_u8 *need_gen_key)
{
    hi_u32 ret = crypto_load_key_content(CRYPTO_WORKKEY_KERNEL_A, key_content);
    if (ret == HI_PRINT_ERRNO_CRYPTO_KEY_EMPTY_ERR || ret == HI_PRINT_ERRNO_CRYPTO_KEY_INVALID_ERR) {
        ret = crypto_load_key_content(CRYPTO_WORKKEY_KERNEL_A_BACKUP, key_content);
        if (ret == HI_PRINT_ERRNO_CRYPTO_KEY_EMPTY_ERR || ret == HI_PRINT_ERRNO_CRYPTO_KEY_INVALID_ERR) {
            *need_gen_key = 1;
            return HI_ERR_SUCCESS;
        } else if (ret != HI_ERR_SUCCESS) {
            goto fail;
        } else {
            ret = crypto_save_work_key(CRYPTO_WORKKEY_KERNEL_A, key_content);
        }
    }
fail:
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

    hi_u32 cs = (uintptr_t)(ctrl.key) ^ (hi_u32)sizeof(ctrl.key) ^ (uintptr_t)kdf_key ^ (hi_u32)sizeof(kdf_key);
    if ((hi_u32)memcpy_s(ctrl.key, sizeof(ctrl.key), kdf_key, sizeof(kdf_key), cs) != EOK) {
        return HI_ERR_FAILURE;
    }
    ctrl.salt = salt;
    ctrl.salt_len = sizeof(salt);
    ctrl.kdf_cnt = KDF_ITERATION_CNT;
    ctrl.kdf_mode = HI_CIPHER_SSS_KDF_KEY_DEVICE; /* 用户提供HUK值的方式 */
    if (hi_cipher_kdf_key_derive(&ctrl) != HI_ERR_SUCCESS) {
        return HI_ERR_FAILURE;
    }

    cs = (uintptr_t)(key_content->work_text) ^ KEY_BYTE_LENGTH ^ (uintptr_t)(ctrl.result) ^
        (hi_u32)sizeof(ctrl.result);
    if (memcpy_s(key_content->work_text, KEY_BYTE_LENGTH, ctrl.result, sizeof(ctrl.result), cs) != EOK) {
        return HI_ERR_FAILURE;
    }

    if (hi_cipher_hash_sha256((uintptr_t)(key_content->iv_nv), sizeof(hi_flash_crypto_content) - SHA_256_LENGTH,
                              key_content->content_sh256, SHA_256_LENGTH) != HI_ERR_SUCCESS) {
        return HI_ERR_FAILURE;
    }

    return HI_ERR_SUCCESS;
}

static hi_u32 crypto_encrypt_data(hi_flash_crypto_content *content, hi_u32 flash_addr, hi_u32 len)
{
    hi_u32 ret = HI_ERR_FAILURE;
    hi_cipher_aes_ctrl aes_ctrl;

    hi_u8 *fw_cyp_data = boot_malloc(len);
    if (fw_cyp_data == HI_NULL) {
        return HI_PRINT_ERRNO_CRYPTO_PREPARE_ERR;
    }

    hi_u32 cs = (uintptr_t)(aes_ctrl.key) ^ (hi_u32)sizeof(aes_ctrl.key) ^
        (uintptr_t)(content->work_text) ^ KEY_BYTE_LENGTH;
    if (memcpy_s(aes_ctrl.key, sizeof(aes_ctrl.key), content->work_text, KEY_BYTE_LENGTH, cs) != EOK) {
        goto fail;
    }

    cs = (uintptr_t)(aes_ctrl.iv) ^ (hi_u32)sizeof(aes_ctrl.iv) ^ (uintptr_t)(content->iv_content) ^ IV_BYTE_LENGTH;
    if (memcpy_s(aes_ctrl.iv, sizeof(aes_ctrl.iv), content->iv_content, IV_BYTE_LENGTH, cs) != EOK) {
        goto fail;
    }

    crpto_set_aes_ctrl_default_value(&aes_ctrl);
    ret = hi_cipher_aes_config(&aes_ctrl);
    if (ret != HI_ERR_SUCCESS) {
        goto fail;
    }

    ret = hi_cipher_aes_crypto(flash_addr + SFC_BUFFER_BASE_ADDRESS, (uintptr_t)fw_cyp_data, len, HI_TRUE);
    if (ret != HI_ERR_SUCCESS) {
        goto crypto_fail;
    }

    ret = g_flash_cmd_funcs.write(flash_addr, len, (hi_u8 *)fw_cyp_data, HI_TRUE);
    if (ret != HI_ERR_SUCCESS) {
        goto crypto_fail;
    }

crypto_fail:
    (hi_void) hi_cipher_aes_destroy_config();
fail:
    crypto_mem_free(fw_cyp_data);
    return ret;
}

hi_u32 crypto_save_encrypt_status(hi_void)
{
    hi_u32 ret;
    hi_u8 flash_encpt_cfg = get_flash_crypto_cfg();
    if ((flash_encpt_cfg & 0x1) == ENCPT_CFG_FLAG) {
        hi_u8 efuse_val = 0x3;
        ret = hi_efuse_write(g_writeable_efuse, &efuse_val);
        if (ret != HI_ERR_SUCCESS) {
            return ret;
        }
    } else {
#ifdef CONFIG_FLASH_ENCRYPT_NOT_USE_EFUSE
        ret = boot_set_crypto_finish_flag();
        if (ret != HI_ERR_SUCCESS) {
            return ret;
        }
#endif
    }

    return HI_ERR_SUCCESS;
}

hi_u32 crypto_burn_encrypt(hi_void)
{
    hi_u8 need_gen_key = 0;
    hi_u32 crypto_frmware_addr = boot_get_crypto_firmware_start();

    hi_flash_crypto_content *key_content = (hi_flash_crypto_content *)boot_malloc(sizeof(hi_flash_crypto_content));
    if (key_content == HI_NULL) {
        return HI_PRINT_ERRNO_CRYPTO_PREPARE_ERR;
    }

    hi_u32 ret = crypto_prepare();
    if (ret != HI_ERR_SUCCESS) {
        crypto_mem_free(key_content);
        return HI_PRINT_ERRNO_CRYPTO_PREPARE_ERR;
    }

    ret = crypto_is_need_gen_key(key_content, &need_gen_key);
    if (ret != HI_ERR_SUCCESS) {
        goto fail;
    }

    if (need_gen_key == 1) {
        ret = crypto_gen_key_content(key_content);
        if (ret != HI_ERR_SUCCESS) {
            goto fail;
        }

        if (crypto_save_work_key(CRYPTO_WORKKEY_KERNEL_A_BOTH, key_content) != HI_ERR_SUCCESS) {
            goto fail;
        }
    }

    ret = crypto_encrypt_data(key_content, crypto_frmware_addr, CRYPTO_KERNEL_LENGTH);
    if (ret != HI_ERR_SUCCESS) {
        ret = HI_PRINT_ERRNO_CRYPTO_FW_ENCRYPT_ERR;
        goto fail;
    }

    ret = crypto_save_encrypt_status();
    if (ret != HI_ERR_SUCCESS) {
        goto fail;
    }
fail:
    crypto_mem_free(key_content);
    crypto_destory();
    return ret;
}

hi_u32 crypto_check_encrypt(hi_void)
{
    hi_u32 ret;

    ret = hi_factory_nv_init(HI_FNV_DEFAULT_ADDR, HI_NV_DEFAULT_TOTAL_SIZE, HI_NV_DEFAULT_BLOCK_SIZE); /* NV初始化 */
    if (ret != HI_ERR_SUCCESS) {
        return ret;
    }

    ret = hi_flash_partition_init();
    if (ret != HI_ERR_SUCCESS) { /* use flash table */
        return ret;
    }

    hi_bool burn_encrypt_flag = is_burn_need_crypto();
    if (burn_encrypt_flag == HI_TRUE) {
        /* 烧写flash加密流程 */
        ret = crypto_burn_encrypt();
        if (ret != HI_ERR_SUCCESS) {
            boot_put_errno(ret);
            return ret;
        }
    }

    return HI_ERR_SUCCESS;
}

#endif
