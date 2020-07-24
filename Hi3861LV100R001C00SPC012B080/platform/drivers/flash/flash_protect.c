/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: flash protect process implementatioin.
 * Author: Hisilicon
 * Create: 2019-12-27
 */
#include "flash_prv.h"
#ifdef HI_FLASH_SUPPORT_FLASH_PROTECT
#include <hi_timer.h>
#include <hi_stdlib.h>
#endif
#include "flash_protect.h"
#include <hi_errno.h>

support_flash_protect g_support_flash_protect = {0};

#ifdef HI_FLASH_SUPPORT_FLASH_PROTECT

hi_flash_protect_ctrl g_protect_ctrl = {
    0,
};
hi_spi_flash_ctrl *g_flash_ctrl = HI_NULL;
hi_u8  *g_flash_protect_op_during_flash = HI_NULL;

/*
  * 1.��ͬоƬ���ò�ͬ������flashоƬ�������ȷ�ϱ��
  * 2.bit���òμ�Flash �ֲ�memory protection�½ڣ������ο�W25Q16JL/W25Q16JW/GD25LE16/GD25WQ16/EN25S16
  * 3.����ʵ�ʿռ���Ծ����ϸ����
 */
HI_CONST hi_flash_protect_size g_flash_protect_size_lower[] = {
    /* bit[5]:cmp
     * bit[4:0]:bp[4:0]:  �������ֲ�
     */
    { 0b000000, 0x0,  0 },  /* ������ */
    { 0b011100, 0x8,  0 },  /* ����32KB */
    { 0b001001, 0x10, 0 }, /* ����64KB */
    { 0b001100, 0x80, 0 }, /* ����512KB */
    { 0b001101, 0x100, 0 }, /* ����1024KB */
};
HI_CONST hi_flash_protect_size g_flash_protect_size_upper[] = { /* kernel A */
    { 0b000101, 0x100, 0 }, /* �ߵ�ַ����1024KB */
    { 0b000100, 0x180, 0 }, /* �ߵ�ַ����512KB */
    { 0b000001, 0x1F0, 0 }, /* �ߵ�ַ����64KB */
    { 0b010100, 0x1F8,  0 },  /* �ߵ�ַ����32KB */
    { 0b000000, 0x200,  0 },  /* ������ */
};

#define flash_lock()                                                            \
    do {                                                                        \
        if ((!hi_is_int_context()) && (*g_flash_protect_op_during_flash != HI_TRUE)) {  \
            hi_mux_pend(g_flash_ctrl->mutex_handle, HI_SYS_WAIT_FOREVER);    \
        }                                                                       \
    } while (0)
#define flash_unlock()                                                          \
    do {                                                                        \
        if ((!hi_is_int_context()) && (*g_flash_protect_op_during_flash != HI_TRUE)) {  \
            hi_mux_post(g_flash_ctrl->mutex_handle);                         \
        }                                                                       \
    } while (0)

BSP_RAM_TEXT_SECTION hi_u32 spi_flash_write_sr_reg(hi_u8 cmd, hi_u8* p_data, hi_u8 data_len, hi_bool is_volatile)
{
    hi_u32 temp_data = 0;
    hi_u32 ret;
    if (data_len > 0) {
        ret = (hi_u32)memcpy_s(&temp_data, sizeof(temp_data), p_data, data_len); /* 4 */
        if (ret != EOK) {
            return ret;
        }
    }
    if (is_volatile) {
        hisfc_write(SFC_REG_CMD_INS, SPI_CMD_VSR_WREN);
        hisfc_write(SFC_REG_CMD_CONFIG, (hi_u32)(SFC_CMD_CONFIG_SEL_CS | SFC_CMD_CONFIG_START));
        spif_wait_config_start();
    } else {
        ret = spif_write_enable(HI_TRUE);
        if (ret != HI_ERR_SUCCESS) {
            return ret;
        }
    }
    hisfc_write(SFC_REG_CMD_INS, cmd);
    hisfc_write(SFC_REG_CMD_DATABUF1, temp_data);
    hisfc_write(SFC_REG_CMD_CONFIG,
                SFC_CMD_CONFIG_SEL_CS
                | SFC_CMD_CONFIG_DATA_EN
                | sfc_cmd_config_data_cnt(data_len)
                | SFC_CMD_CONFIG_START);
    spif_wait_config_start();
    return HI_ERR_SUCCESS;
}

BSP_RAM_TEXT_SECTION hi_u32 flash_protect_set_protect(hi_u8 cmp_bp, hi_bool is_volatile)
{
    hi_u32 ret;
    hi_u8 p_data[2] = {0}; /* 2 */
    hi_u8 cmp = (cmp_bp >> 5) & 0x1; /* 5 */
    hi_u8 bp = cmp_bp & 0x1F;
    hi_flash_protect_ctrl *p_ctrl = &g_protect_ctrl;
    if (p_ctrl->enable == HI_FALSE) {
        return HI_ERR_SUCCESS; /* δʹ��Ҳ���سɹ� */
    }
    ret = spif_wait_ready(HI_TRUE, SPI_CMD_SR_WIPN, SPI_SR_BIT_WIP);
    if (ret != HI_ERR_SUCCESS) {
        return ret;
    }
    ret = spi_flash_read_reg(SPI_CMD_RDSR, &p_data[0], 1);
    if (ret != HI_ERR_SUCCESS) {
        return ret;
    }
    ret = spi_flash_read_reg(SPI_CMD_RDSR2, &p_data[1], 1);
    if (ret != HI_ERR_SUCCESS) {
        return ret;
    }
    if (((p_data[0] & (0x1F << 2)) == (bp << 2)) && ((p_data[1] & (0x1 << 6)) == (cmp << 6))) { /* 2 6 */
        return HI_ERR_SUCCESS;
    }
    p_data[0] &= ~(0x1f<<2);      /* 2 */
    p_data[0] |= (hi_u8)(bp<<2);  /* 2 */
    p_data[1] &= ~(0x1<<6);       /* 6 */
    p_data[1] |= (hi_u8)(cmp<<6); /* 6 */
    ret = spi_flash_write_sr_reg(SPI_CMD_WRSR1, p_data, 2, is_volatile); /* 2 : p_data len */
    if (ret != HI_ERR_SUCCESS) {
        return ret;
    }
    ret = spif_wait_ready(HI_TRUE, SPI_CMD_SR_WIPN, SPI_SR_BIT_WIP); /* wait flash WIP is zero */
    if (ret != HI_ERR_SUCCESS) {
        return ret;
    }
    ret = spi_flash_read_reg(SPI_CMD_RDSR, &p_data[0], 1);
    if (ret != HI_ERR_SUCCESS) {
        return ret;
    }
    ret = spi_flash_read_reg(SPI_CMD_RDSR2, &p_data[1], 1);
    if (ret != HI_ERR_SUCCESS) {
        return ret;
    }
    if (((p_data[0] & (0x1F<<2)) == (bp<<2)) && ((p_data[1] & (0x1<<6)) == (cmp<<6))) { /* 2 6 */
        return HI_ERR_SUCCESS;
    } else {
        return p_data[0] | (p_data[1] << 8); /* 8 */
    }
}

static hi_u32 get_timer_val(hi_flash_protect_type type)
{
    if (type == HI_FLASH_PROTECT_TYPE_1) {
        return PROTECT_TIMEOUT_1;
    } else if (type == HI_FLASH_PROTECT_TYPE_2) {
        return PROTECT_TIMEOUT_2;
    } else {
        return 0;
    }
}

hi_void flash_protect_timeout(hi_u32 is_volatile)
{
    hi_flash_protect_ctrl *p_ctrl = &g_protect_ctrl;
    support_flash_protect *fp = &g_support_flash_protect;
    hi_u32 int_value = hi_int_lock();
    p_ctrl->is_volatile = (hi_bool)is_volatile;
    fp->protect_all = HI_TRUE;
    hi_int_restore(int_value);
}

hi_u32 flash_protect_all_area(hi_void)
{
    hi_u32 ret = HI_ERR_SUCCESS;
    hi_flash_protect_ctrl *p_ctrl = &g_protect_ctrl;
    support_flash_protect *fp = &g_support_flash_protect;
    if ((!hi_is_int_context()) && (*g_flash_protect_op_during_flash != HI_TRUE)) {
        ret = hi_mux_pend(g_flash_ctrl->mutex_handle, 0);
    }
    if (ret != HI_ERR_SUCCESS) {
        hi_timer_start(p_ctrl->timer_handle, HI_TIMER_TYPE_ONCE, p_ctrl->timer_timeout, flash_protect_timeout,
            (hi_u32)p_ctrl->is_volatile);
        fp->protect_all = HI_FALSE;
        return ret;
    }
    if (p_ctrl->run_kernel_a) {    /* �����ߵ�ַ */
        p_ctrl->current_block = 0;
    } else {                       /* �����͵�ַ */
        p_ctrl->current_block = g_flash_ctrl->chip_size / PRODUCT_CFG_FLASH_BLOCK_SIZE;
    }
    /* ���ȫ����ʧ�ܣ� p_ctrl->current_block�Ѿ�����Ϊȫ����״̬��ַ����Ӱ���´β�д���� */
    ret = flash_protect_set_protect(PROTECT_FLASH_ALL, p_ctrl->is_volatile);
    if (ret != HI_ERR_SUCCESS) {
        hi_timer_start(p_ctrl->timer_handle, HI_TIMER_TYPE_ONCE, p_ctrl->timer_timeout, flash_protect_timeout,
            (hi_u32)p_ctrl->is_volatile);
    }
    fp->protect_all = HI_FALSE;
    flash_unlock();
    return ret;
}
hi_u32 flash_protect_prv(hi_u32 flash_offset, hi_u32 size, hi_bool is_volatile)
{
    hi_u32 ret;
    hi_s8 i;
    hi_flash_protect_ctrl *p_ctrl = &g_protect_ctrl;
    hi_u32 block = (flash_offset / PRODUCT_CFG_FLASH_BLOCK_SIZE);
    if (p_ctrl->run_kernel_a) {                        /* Kernel A �����ߵ�ַ */
        block = (flash_offset + size - 1) / PRODUCT_CFG_FLASH_BLOCK_SIZE; /* unlock protect areas */
        if (block < p_ctrl->current_block) {
         /* Ҫ��/д��ַ�Ѿ��⿪���� */
            return HI_ERR_SUCCESS;
        }
        for (i = 0; i < (hi_s8)(sizeof(g_flash_protect_size_upper) / sizeof(hi_flash_protect_size)); i++) {
            if (block < g_flash_protect_size_upper[i].block) {
                break;
            }
        }
        if (i < (hi_s8)(sizeof(g_flash_protect_size_upper) / sizeof(hi_flash_protect_size))) {
            ret = flash_protect_set_protect(g_flash_protect_size_upper[i].cmp_bp, is_volatile);
        } else {
            ret = flash_protect_set_protect(0, is_volatile);
        }
        if (ret != HI_ERR_SUCCESS) {
            return ret;
        }
        if (i < (hi_s8)(sizeof(g_flash_protect_size_upper) / sizeof(hi_flash_protect_size))) {
            p_ctrl->current_block = g_flash_protect_size_upper[i].block;
        } else {
            p_ctrl->current_block = block;
        }
    } else {                                   /* Kernel B �͵�ַ����  */
        if (block > p_ctrl->current_block) {
         /* Ҫ��/д��ַ�Ѿ��⿪���� */
            return HI_ERR_SUCCESS;
        }
        for (i = (sizeof(g_flash_protect_size_lower) / sizeof(hi_flash_protect_size)) - 1; i >= 0; i--) {
            if (block >= g_flash_protect_size_lower[i].block) {
                break;
            }
        }
        if (i >= 0) {
            ret = flash_protect_set_protect(g_flash_protect_size_lower[i].cmp_bp, is_volatile);
        } else {
            ret = flash_protect_set_protect(0, is_volatile);
        }
        if (ret != HI_ERR_SUCCESS) {
            return ret;
        }
        p_ctrl->current_block = (i >= 0) ? g_flash_protect_size_lower[i].block : block;
    }
    return ret;
}

hi_u32 flash_protect(hi_u32 flash_offset, hi_u32 size, hi_u32 timeout, hi_bool is_volatile)
{
    hi_u32 ret;
    hi_flash_protect_ctrl *p_ctrl = &g_protect_ctrl;
    if (p_ctrl->enable == HI_FALSE) {
        return HI_ERR_SUCCESS; /* δʹ��Ҳ���سɹ� */
    }
    ret = flash_protect_prv(flash_offset, size, is_volatile);
    if (ret != HI_ERR_SUCCESS) {
        return ret;
    }
    if (timeout) {
        if (timeout == PROTECT_TIMEOUT_AUTO) {
            p_ctrl->timer_timeout = get_timer_val((hi_flash_protect_type)(p_ctrl->default_type));
        } else {
            p_ctrl->timer_timeout = timeout;
        }
        ret = hi_timer_start(p_ctrl->timer_handle, HI_TIMER_TYPE_ONCE, p_ctrl->timer_timeout, flash_protect_timeout,
            (hi_u32)is_volatile);
        if (ret != HI_ERR_SUCCESS) {
            return ret;
        }
    } else {
        /* ����5.1 �Ժ����Ĵ��󷵻���Ҫȫ�洦�� */
        ret = hi_timer_stop(p_ctrl->timer_handle);
    }
    return HI_ERR_SUCCESS;
}
#endif

support_flash_protect *flash_get_support_flash_protect_info(hi_void)
{
    return &g_support_flash_protect;
}
/* hi_flash_protect_init �ڲ�ʹ�ú��� */
hi_u32 flash_protect_init_cfg(hi_flash_protect_type type)
{
#ifdef HI_FLASH_SUPPORT_FLASH_PROTECT
    hi_flash_protect_ctrl *p_ctrl = &g_protect_ctrl;
    support_flash_protect *fp = &g_support_flash_protect;
    hi_u32 ret;
    hi_u16 reg_val;
    flash_lock();
    p_ctrl->default_type = type;
    hi_reg_read16(CLDO_CTL_GEN_REG0, reg_val);
    if (reg_val >> 15) { /* 15 */
        p_ctrl->run_kernel_a = HI_TRUE;
    } else {
        p_ctrl->run_kernel_a = HI_FALSE;
    }
    p_ctrl->init = HI_TRUE;
    p_ctrl->enable = HI_TRUE;

    ret = flash_protect_set_protect(PROTECT_FLASH_ALL, HI_FALSE); /* protect all flash chip */
    if (ret != HI_ERR_SUCCESS) {
        flash_unlock();
        return ret;
    }

    fp->protect_all = HI_FALSE;
    fp->protect_all_area = flash_protect_all_area;
    fp->support_flash_protect = HI_TRUE;
    if (p_ctrl->run_kernel_a) { /* �����ߵ�ַ */
        p_ctrl->current_block = 0;
    } else {                    /* �����͵�ַ */
        p_ctrl->current_block = g_flash_ctrl->chip_size / PRODUCT_CFG_FLASH_BLOCK_SIZE;
    }
    flash_unlock();
    return ret;
#else
    hi_unref_param(type);
    return HI_ERR_SUCCESS;
#endif
}

const hi_u8 g_unknown_chip[] = "UNKNOWN";
hi_u32 hi_flash_protect_init(hi_flash_protect_type type)
{
    support_flash_protect *fp = &g_support_flash_protect;
#ifdef HI_FLASH_SUPPORT_FLASH_PROTECT
    hi_u32 ret;
    hi_flash_protect_ctrl *p_ctrl = &g_protect_ctrl;
    g_flash_ctrl = flash_get_spi_flash_ctrl_info();
    g_flash_protect_op_during_flash = flash_get_flash_op_during_flash_info();
    if (p_ctrl->init == HI_TRUE) {
        return HI_ERR_FLASH_PROTECT_RE_INIT;
    }
    if (type >= HI_FLASH_PROTECT_TYPE_MAX) {
        return HI_ERR_FLASH_INVALID_PARAM;
    }
    if (type == HI_FLASH_PROTECT_NONE) {
        return HI_ERR_FLASH_PROTECT_NOT_SUPPORT;
    }
    if (g_flash_ctrl->basic_info.chip_name == HI_NULL) {
        return HI_ERR_FLASH_NOT_INIT;
    }
    if (memcmp(g_flash_ctrl->basic_info.chip_name, g_unknown_chip, sizeof(g_unknown_chip)) == 0) {
        return HI_ERR_FLASH_PROTECT_NOT_FIND_CHIP;
    }
    ret = hi_timer_create(&(p_ctrl->timer_handle));
    if (ret != HI_ERR_SUCCESS) {
        return ret;
    }
    ret = flash_protect_init_cfg(type);
    if (ret != HI_ERR_SUCCESS) {
        goto end;
    }
    return ret;
end:
    hi_timer_delete(p_ctrl->timer_handle);
    fp->protect_all_area = HI_NULL;
    p_ctrl->enable = HI_FALSE;
    return ret;
#else
    hi_unref_param(type);
    fp->protect_all_area = HI_NULL;
    return HI_ERR_SUCCESS;
#endif
}

hi_u32 hi_flash_protect_deinit(hi_void)
{
    hi_u32 ret = HI_ERR_SUCCESS;

#ifdef HI_FLASH_SUPPORT_FLASH_PROTECT
    /* full-chip volatile protection, resources are not released */
    ret = flash_protect_set_protect(PROTECT_FLASH_ALL, HI_TRUE);
    hi_flash_protect_ctrl *p_ctrl = &g_protect_ctrl;
    support_flash_protect *fp = &g_support_flash_protect;
    if (fp->protect_all) {
        fp->protect_all = HI_FALSE;
    }
    if (p_ctrl->run_kernel_a) { /* �����ߵ�ַ */
        p_ctrl->current_block = 0;
    } else {                    /* �����͵�ַ */
        p_ctrl->current_block = g_flash_ctrl->chip_size / PRODUCT_CFG_FLASH_BLOCK_SIZE;
    }
#endif

    return ret;
}
