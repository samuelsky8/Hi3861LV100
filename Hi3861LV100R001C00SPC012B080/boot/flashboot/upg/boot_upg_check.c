/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: boot upg check.
 * Author: Hisilicon
 * Create: 2019-12-10
 */

#include <boot_upg_check.h>
#include <boot_upg_check_secure.h>
#include <boot_upg_start_up.h>

hi_u32 boot_upg_check_image_id(hi_u32 image_id)
{
    if (image_id != PRODUCT_UPG_FILE_IMAGE_ID) {
        boot_msg1("[bootupg check image id]fail,image id:", image_id);
        return HI_ERR_UPG_IMAGE_ID;
    }
    return HI_ERR_SUCCESS;
}

hi_u32 boot_upg_check_file_type(hi_u8 file_type)
{
    if (file_type != HI_UPG_FILE_KERNEL) {
        boot_msg1("[bootupg check file type]fail,file type:", file_type);
        return HI_ERR_UPG_FILE_TYPE;
    }
    return HI_ERR_SUCCESS;
}

hi_u32 boot_upg_get_efuse_code_ver(hi_u8 *version)
{
    hi_u8 pos;
    hi_u8 efuse_data[KERNEL_VER_LEN];
    hi_u32 ret;
    hi_u32 check_sum = (uintptr_t)efuse_data ^ KERNEL_VER_LEN ^ 0xFF ^ KERNEL_VER_LEN;
    (hi_void) memset_s(efuse_data, KERNEL_VER_LEN, 0xFF, KERNEL_VER_LEN, check_sum);
    ret = hi_efuse_read(HI_EFUSE_TEE_KERNEL_VER_RW_ID, efuse_data, sizeof(efuse_data));
    if (ret != HI_ERR_SUCCESS) {
        boot_msg1("[bootupg get code efuse ver]fail,ret:", ret);
        return ret;
    }

    for (pos = 0; pos < KERELN_VER_MAX; pos++) {
        if (boot_upg_tool_bit_test(efuse_data, pos) == HI_FALSE) {
            break;
        }
    }
    if (pos >= KERELN_VER_MAX) {
        *version = KERELN_VER_MAX;
    } else {
        *version = pos;
    }
    return ret;
}

hi_u32 boot_upg_check_code_ver(hi_u8 ver)
{
    hi_u8 current_ver;
    hi_u32 ret = boot_upg_get_efuse_code_ver(&current_ver);
    if (ret != HI_ERR_SUCCESS) {
        boot_msg1("[bootupg check code ver]get ver ret:", ret);
        return ret;
    }
    if (ver < current_ver) {
        ret = HI_ERR_UPG_KERNEL_VER;
        boot_msg2("[bootupg check code ver]currentver-filever:", current_ver, ver);
    }
    return ret;
}

hi_u32 boot_upg_get_max_file_len(hi_u32 *file_len)
{
    hi_flash_partition_table *partition = hi_get_partition_table();
    hi_u32 kernel_a_size = partition->table[HI_FLASH_PARTITON_KERNEL_A].size;
    hi_u32 kernel_b_size = partition->table[HI_FLASH_PARTITON_KERNEL_B].size;
#if defined(CONFIG_COMPRESSION_OTA_SUPPORT)
    *file_len = kernel_a_size + kernel_b_size;
#else
    hi_nv_ftm_startup_cfg *cfg = boot_upg_get_cfg();

    if (cfg->addr_start == partition->table[HI_FLASH_PARTITON_KERNEL_A].addr) {
        *file_len = kernel_a_size;
    } else if (cfg->addr_start == partition->table[HI_FLASH_PARTITON_KERNEL_B].addr) {
        *file_len = kernel_b_size;
    } else {
        *file_len = hi_max(kernel_a_size, kernel_b_size);
        boot_msg1("[bootupg get file len]addr_start error", cfg->addr_start);
    }
#endif
    return HI_ERR_SUCCESS;
}

hi_u32 boot_upg_check_code_file_len(hi_u32 file_len)
{
    hi_u32 max_len;
    hi_u32 ret = boot_upg_get_max_file_len(&max_len);
    if (ret != HI_ERR_SUCCESS) {
        boot_msg1("[bootupg check file len]get file len ret: ", ret);
        return ret;
    }

    if (file_len > max_len) {
        boot_msg2("[bootupg check file len]filelen>maxlen: ", file_len, max_len);
        return HI_ERR_UPG_FILE_LEN_OVER;
    }
    return HI_ERR_SUCCESS;
}

hi_u32 boot_upg_get_common_head(hi_u32 addr, hi_upg_common_head *head)
{
    hi_u32 ret = hi_flash_read(addr, sizeof(hi_upg_common_head), (hi_u8 *)head);
    if (ret != HI_ERR_SUCCESS) {
        boot_msg2("[bootupg]get common head addr-ret:", addr, ret);
        return ret;
    }

    return ret;
}

hi_u32 boot_upg_get_section_head(hi_u32 addr, hi_upg_section_head *section_head)
{
    hi_upg_common_head head = { 0 };
    hi_u32 ret;

    if (section_head == HI_NULL) {
        return HI_ERR_UPG_NULL_POINTER;
    }
    ret = hi_flash_read(addr, sizeof(hi_upg_common_head), (hi_u8 *)(&head));
    if (ret != HI_ERR_SUCCESS) {
        boot_msg1("[bootupg get section head]flash read ret:", ret);
        return ret;
    }
    ret = hi_flash_read(addr + head.section_offset, sizeof(hi_upg_section_head), (hi_u8 *)section_head);
    if (ret != HI_ERR_SUCCESS) {
        boot_msg1("[bootupg get section head]flash read ret:", ret);
        return ret;
    }

    return ret;
}

hi_u32 boot_upg_check_alg_param(const hi_upg_common_head *head)
{
    sign_alg_param alg_param;
    hi_u32 cs = (uintptr_t)(&alg_param) ^ sizeof(sign_alg_param) ^
                (uintptr_t)(&(head->param)) ^ sizeof(sign_alg_param);
    if (memcpy_s(&alg_param, sizeof(sign_alg_param), &(head->param), sizeof(sign_alg_param), cs) != EOK) {
        return HI_ERR_FAILURE;
    }
    if ((alg_param.sign_alg != HI_MODE_PKCS_V15) && (alg_param.sign_alg != HI_MODE_PKCS_PSS) &&
        (alg_param.sign_alg != HI_MODE_ECC)) {
        return HI_ERR_UPG_SIGN_ALG;
    }
    if (alg_param.sign_alg < HI_MODE_ECC) {
        if (head->key_len != sizeof(upg_rsa_key)) {
            return HI_ERR_UPG_RSA_KEY_LEN;
        }
        if (head->section_offset != (sizeof(hi_upg_common_head) + head->key_len + sizeof(upg_rsa_sign))) {
            return HI_ERR_UPG_RSA_HEAD_SIGN;
        }
        return HI_ERR_SUCCESS;
    }
    if (head->key_len != sizeof(upg_ecc_key)) {
        return HI_ERR_UPG_ECC_KEY_LEN;
    }
    if (head->section_offset != (sizeof(hi_upg_common_head) + head->key_len + sizeof(upg_ecc_sign))) {
        return HI_ERR_UPG_ECC_HEAD_SIGN;
    }
    return HI_ERR_SUCCESS;
}

hi_u32 boot_upg_check_common_head(const hi_upg_common_head *head, hi_u32 head_size)
{
    hi_u32 ret = boot_upg_check_image_id(head->image_id);
    if (ret != HI_ERR_SUCCESS) {
        return ret;
    }
    ret = boot_upg_check_file_type(head->file_type);
    if (ret != HI_ERR_SUCCESS) {
        return ret;
    }
    ret = boot_upg_check_code_file_len(head->file_len);
    if (ret != HI_ERR_SUCCESS) {
        return ret;
    }
    if ((head->file_len != (head->section_offset + head->section_len)) ||
        (head->section_offset != (sizeof(hi_upg_common_head) + sizeof(hi_upg_key) + sizeof(hi_upg_sign))) ||
        (head->section_len < (sizeof(hi_upg_section_head) + sizeof(upg_rsa_sign)))) {
        return HI_ERR_UPG_FILE_LEN;
    }
    if (boot_upg_is_secure_efuse() != HI_TRUE) {
        return HI_ERR_SUCCESS;
    }
    ret = boot_upg_check_code_ver(head->file_version);
    if (ret != HI_ERR_SUCCESS) {
        return ret;
    }
    return boot_upg_check_alg_param(head);
}

hi_u32 boot_upg_check_file(hi_u32 flash_addr)
{
    hi_u32 ret = HI_ERR_UPG_MALLOC_FAIL;
    hi_upg_head *upg_head = (hi_upg_head *)boot_malloc(sizeof(hi_upg_head));

    if (upg_head == HI_NULL) {
        goto end;
    }
    ret = hi_flash_read(flash_addr, sizeof(hi_upg_head), (hi_u8 *)upg_head);
    if (ret != HI_ERR_SUCCESS) {
        boot_msg2("[boot check file]flash read err, addr-ret:", flash_addr, ret);
        goto end;
    }
    hi_upg_common_head *common_head = &(upg_head->common);
    ret = boot_upg_check_common_head(common_head, sizeof(hi_upg_common_head));
    if (ret != HI_ERR_SUCCESS) {
        goto end;
    }

    ret = hi_cipher_init();
    if (ret != HI_ERR_SUCCESS) {
        goto end;
    }
    if (boot_upg_is_secure_efuse() == HI_TRUE) {
        ret = boot_upg_check_secure_info(flash_addr, upg_head);
    } else {
        ret = boot_upg_check_unsecure_info(flash_addr, upg_head);
    }
    hi_u32 ck = hi_cipher_deinit();
    if (ret == HI_ERR_SUCCESS) {
        ret = ck;
    }
end:
    boot_upg_mem_free(upg_head);
    return ret;
}

hi_void boot_get_start_addr_offset(hi_u32 addr, hi_u32 *offset)
{
    hi_upg_section_head section_head = { 0 };
    hi_u32 ret = boot_upg_get_section_head(addr, &section_head);
    if (ret == HI_ERR_SUCCESS) {
        *offset = addr + section_head.section0_offset;
    } else {
        boot_msg1("[boot get start addr offset]fail.", ret);
        *offset = addr;
    }
}

