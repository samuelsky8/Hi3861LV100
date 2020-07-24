/**
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: Interface of upgrade Kernel
 * Author: Hisilicon
 * Create: 2020-2-27
 */

#include "boot_upg_kernel.h"
#include "boot_upg_check.h"
#include "boot_upg_tool.h"

hi_u32 boot_upg_lzma_detect(hi_u32 addr_write, hi_u32 *uncompress_size, const hi_upg_section_head *section_head)
{
    hi_u8 lzma_head[13] = { 0 }; /* head 13B */
    hi_u32 dic_size = 0;

    /* get LZMA head. get uncompressed size */
    hi_u32 ret = hi_flash_read(addr_write + section_head->section0_offset, 13, lzma_head); /* 13 Bytes:head length */
    if (ret != HI_ERR_SUCCESS) {
        boot_msg1("[bootupg lzma detect]flash read ret", ret);
        return ret;
    }
    ret = hi_lzma_get_uncompress_len(lzma_head, sizeof(lzma_head), uncompress_size, &dic_size);
    if (ret != HI_ERR_SUCCESS) {
        boot_msg1("[bootupg lzma detect]get uncompress len", ret);
        return ret;
    }

    /* RAM usage detect for  LAMA uncompressing.
        * Avoid can't uncompress after erasing file, it'll cause unable to start */
    ret = hi_lzma_mem_detect(lzma_head, sizeof(lzma_head));
    if (ret != HI_ERR_SUCCESS) {
        boot_msg1("[bootupg kernel lzma detect]mem detect", ret);
    } else {
        if ((*uncompress_size) == 0) {
            ret = HI_ERR_UPG_FILE_LEN_ZERO;
            boot_msg0("[bootupg lzma detect]uncompress size.");
        }
    }
    return ret;
}

hi_u32 boot_upg_lzma_verify(hi_u32 addr_write, hi_u32 *uncompress_size, const hi_upg_section_head *section_head,
                            const hi_upg_file_head *file_head)
{
    hi_u32 ret = boot_upg_lzma_detect(addr_write, uncompress_size, section_head);
    if (ret != HI_ERR_SUCCESS) {
        boot_msg2("[bootupg kernel process]detect1 writeaddr-uncompress_size:", addr_write, *uncompress_size);
        return ret;
    }
    ret = hi_cipher_init();
    if (ret != HI_ERR_SUCCESS) {
        boot_msg1("[bootupg lzma verify]cipher init:", ret);
        return ret;
    }
    ret = boot_upg_check_before_decompress(addr_write, section_head, file_head);
    if (ret != HI_ERR_SUCCESS) {
        boot_msg1("[bootupg lzma verify]check before decompress:", ret);
    }
    (hi_void)hi_cipher_deinit();
    return ret;
}

hi_u32 boot_upg_kernel_process(hi_u32 addr_start, hi_u32 addr_write)
{
    hi_u32 erase_size;
    hi_u32 uncompress_size;
    hi_upg_file_head *file_head = HI_NULL;
    hi_upg_section_head section_head = { 0 };
    hi_u32 ret = hi_flash_read(addr_write + sizeof(hi_upg_head), sizeof(hi_upg_section_head), (hi_u8 *)(&section_head));
    if (ret != HI_ERR_SUCCESS) {
        boot_msg1("[bootupg kernel process]flash read:", ret);
        return ret;
    }
    if (section_head.section0_compress == HI_FALSE) {
        boot_msg0("[bootupg kernel process]Not support uncompressed file.");
        return HI_ERR_UPG_PARAMETER;
    }
    file_head = boot_malloc(sizeof(hi_upg_file_head));
    if (file_head == HI_NULL) {
        return HI_ERR_UPG_MALLOC_FAIL;
    }

    ret = boot_upg_lzma_verify(addr_write, &uncompress_size, &section_head, file_head);
    if (ret != HI_ERR_SUCCESS) {
        boot_msg1("[bootupg kernel process]lzma verify:", ret);
        goto end;
    }

    ret = boot_upg_lzma_detect(addr_write, &uncompress_size, &section_head);
    if (ret != HI_ERR_SUCCESS) {
        boot_msg1("[bootupg kernel process]detect2:", ret);
        goto end;
    }

    /* make 4K allignment for kernal and NV before compression. Erasing target space */
    erase_size = uncompress_size;
    erase_size = align_length(erase_size, ALIGNTYPE_4K);
    ret = hi_flash_erase(addr_start, erase_size);
    boot_msg4("[bootupg kernel process]info start-erasesize-write-uncompresssize:", addr_start, erase_size,
              addr_write, uncompress_size);
    /* uncompress kernel and nv file to target space */
    ret = boot_upg_copy_flash_2_flash(addr_write + section_head.section0_offset, section_head.section0_len,
                                      addr_start, uncompress_size, section_head.section0_compress);
    if (ret == HI_ERR_SUCCESS) {
        boot_msg0("[bootupg kernel process]decompress success.");
    }
end:
    boot_upg_mem_free(file_head);
    return ret;
}


