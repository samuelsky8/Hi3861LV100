/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: flash soft process implementatioin.
 * Author: wuxianfeng
 * Create: 2019-05-30
 */

#include <hi3861_platform.h>
#include "flash_prv.h"
#include <hi_flash.h>
#include <hi_stdlib.h>
#include <hi_isr.h>
#include <hi_mux.h>
#include <los_hwi.h>
#include <los_pmp.h>
#include <hi_io.h>
#include <hi_adc.h>
#ifdef HI_FLASH_SUPPORT_UPDATE_SFC_FREQ
#include <hi_timer.h>
#endif
#include <hi_time.h>
#ifdef HI_BOARD_ASIC
#include <hi_efuse.h>
#endif

/* if suppot suspend:#define HI_FLASH_SUPPORT_SUSPEND */
#define HI_FLASH_SUSPEND_TIMEOUT_US 5000
#define HI_FLASH_RESUME_TIMEOUT_US  5000
#define OFFSET_8_BITS      8

hi_spi_flash_ctrl g_flash_drv_ctrl = {
    0,
};

hi_u32 g_back_buffer[1024] = { 0 };   /* size 1024 */
hi_u32 g_dma_buffer[256] = { 0 };     /* size 256 */
hi_u8  g_flash_op_during_flash = HI_FALSE;
hi_u16 g_sfc_lp_freq_reg = 0;  /* ��˯ǰsfcʱ��Ƶ�ʼĴ������� */
#ifdef HI_FLASH_SUPPORT_REF_VBAT
flash_vlt_sfc_info g_flash_vlt_sfc_info_tbl[HI_FLASH_DEFAULT_TYPE_NUM] = {
    /* 0-->96 1-->80 2-->60 3-->48 */
    {{0,              }, 0x1, 0x1, 0x3, 0x1}, /*  unknown ����1.8V �Լ�3.3V */
    {{0xef, 0x60, 0x15}, 0x1, 0x1, 0x1, 0x0}, /*  w25q16jw 1.8v */
    /* {{0xef, 0x40, 0x15}, 0x1d}, 0x1d:00,01,11,01, w25q16jl 3.3v */
    {{0xef, 0x40, 0x15}, 0x0, 0x1, 0x1, 0x1}, /*  w25q16jl 3.3v */
    {{0xc8, 0x60, 0x15}, 0x1, 0x1, 0x1, 0x0}, /*  gd25le16 1.8v */
    {{0xc8, 0x65, 0x15}, 0x0, 0x1, 0x1, 0x1}, /*  gd25wq16 1.65~3.6v use 2.3~3.6v */
    {{0x1c, 0x38, 0x15}, 0x1, 0x1, 0x1, 0x0}, /*  en25s16 1.8v */
    {{0x1C, 0x70, 0x15}, 0x0, 0x1, 0x1, 0x1}, /*  en25qh16 3.3v */
    {{0x85, 0x60, 0x15}, 0x0, 0x1, 0x1, 0x1}, /*  p25q16 1.65~3.6v use 2.3~3.6V */
};


flash_vlt_sfc_info g_flash_vlt_sfc_info = {
    {0,              }, 0x1, 0x1, 0x3, 0x1
};
hi_u16 g_voltage_old = 0;
hi_u16 g_voltage = 0;
hi_u32 g_sfc_update_timer_handle;
hi_u32 g_sfc_update_time_ms = 20000; /* default 20000 ms */
hi_u8  g_vlt_threshold_delt = 3; /* default 3*0.01V */
#endif

#define flash_lock()                                                            \
    do {                                                                        \
        if ((!hi_is_int_context()) && (g_flash_op_during_flash != HI_TRUE)) {  \
            hi_mux_pend(g_flash_drv_ctrl.mutex_handle, HI_SYS_WAIT_FOREVER);    \
        }                                                                       \
    } while (0)
#define flash_unlock()                                                          \
    do {                                                                        \
        if ((!hi_is_int_context()) && (g_flash_op_during_flash != HI_TRUE)) {  \
            hi_mux_post(g_flash_drv_ctrl.mutex_handle);                         \
        }                                                                       \
    } while (0)

BSP_RAM_TEXT_SECTION hi_void flash_set_crash_flag(hi_void)
{
    g_flash_op_during_flash = HI_TRUE;
}

hi_spi_flash_ctrl *flash_get_spi_flash_ctrl_info(hi_void)
{
    return &g_flash_drv_ctrl;
}

hi_u8 *flash_get_flash_op_during_flash_info(hi_void)
{
    return &g_flash_op_during_flash;
}

#ifdef HI_FLASH_SUPPORT_REF_VBAT
hi_u32 flash_get_ref_voltage(hi_u16 *voltage)
{
    hi_u32 ret;
    hi_u16 data = 0;
    ret = hi_adc_read(HI_ADC_CHANNEL_7, &data, HI_ADC_EQU_MODEL_4, HI_ADC_CUR_BAIS_DEFAULT, 0);
    /* bypass:�������ѹ��ϵ����flashLDO��Ҫ����ѹ��ϵ��0.95 */
    if (ret == HI_ERR_SUCCESS) {
        *voltage = (hi_u16)(((hi_u32)data * 180) >> 10);   /* bypass:180, flashLDO:180*0.95, 10:ϵ��  ��λ0.01V */
    }

    return ret;
}
/* ��ȡflash�ο���ѹ */
hi_u32 flash_get_average_ref_vlt(hi_u16 *voltage)
{
    hi_u32 ret;
    hi_u16 vlt;
    hi_u32 vlt_total = 0;
    ret = flash_get_ref_voltage(&vlt);
    if (ret != HI_ERR_SUCCESS) {
        return ret;
    }
    vlt_total += vlt;
    ret = flash_get_ref_voltage(&vlt);
    if (ret != HI_ERR_SUCCESS) {
        *voltage = (hi_u16) vlt_total;
        return HI_ERR_SUCCESS;
    }
    vlt_total += vlt;
    ret = flash_get_ref_voltage(&vlt);
    if (ret != HI_ERR_SUCCESS) {
        *voltage = (hi_u16) (vlt_total>>1);
        return HI_ERR_SUCCESS;
    }
    vlt_total += vlt;
    *voltage = (hi_u16) ((vlt_total) / 3); /* 3: ��ƽ�� */
    return HI_ERR_SUCCESS;
}

hi_void sfc_config_set_experience(const hi_u8 *chip_id, flash_vlt_sfc_info *flash_info,
    flash_vlt_sfc_info *flash_info_tbl, hi_u32 tbl_size)
{
    flash_vlt_sfc_info *info = HI_NULL;
    hi_u32 i;
    hi_u8 cur_chip_idx = 0xFF;

    for (i = 1; i < tbl_size; i++) {
        info = &flash_info_tbl[i];
        if (chip_id != HI_NULL &&
            memcmp(info->chip_id, chip_id, HI_FLASH_CHIP_ID_NUM) == 0) {
            cur_chip_idx = i;
        }
    }
    info = (cur_chip_idx == 0xFF) ? &flash_info_tbl[0] : &flash_info_tbl[cur_chip_idx];
    if (memcpy_s(flash_info, sizeof(flash_vlt_sfc_info), info, sizeof(flash_vlt_sfc_info)) != EOK) {
        return;
    }
}
/* ���flash�Ƿ����ڱ����� */
hi_u32 sfc_config_can_modify_freq(hi_u32 time_out_us)
{
    hi_u16 dma_start;
    hi_u16 cmd_start;
    do {
        cmd_start = hisfc_read(SFC_REG_CMD_CONFIG) & 0x1;
        dma_start = hisfc_read(SFC_REG_BUS_DMA_CTRL) & 0x1;
        if ((dma_start == 0) && (cmd_start == 0)) {
            return HI_ERR_SUCCESS;
        }
        hi_udelay(1);
        time_out_us--;
    } while (time_out_us);
    return HI_ERR_FAILURE;
}
/* ͨ����ѹֵ�ıȽϣ���ȡSFCӦ�����õ�Ƶ��ֵ */
hi_u32 sfc_config_get_freq(hi_u16 *reg_val)
{
    hi_u8 delt = g_vlt_threshold_delt;
    hi_u16 vlt = g_voltage;
    hi_u16 vlt_old = g_voltage_old;
    flash_vlt_sfc_info *flash_info = &g_flash_vlt_sfc_info;
    hi_u16 vlt_th01 = HI_FLASH_VOLTAGE_TH0 + delt;
    hi_u16 vlt_th02 = HI_FLASH_VOLTAGE_TH0 + (delt << 1);
    hi_u16 vlt_th11 = HI_FLASH_VOLTAGE_TH1 + delt;
    hi_u16 vlt_th12 = HI_FLASH_VOLTAGE_TH1 + (delt << 1);
    if (reg_val == HI_NULL) {
        return HI_ERR_FAILURE;
    }
    if (vlt > vlt_old) { /* ��ѹ */
        if (vlt < vlt_old + delt) {
            return HI_ERR_FAILURE;
        }
        if ((vlt >= vlt_th12)) {
            *reg_val = flash_info->freq_high;
        } else if ((vlt >= vlt_th02)) {
            *reg_val = flash_info->freq_midle;
        } else {
            *reg_val = flash_info->freq_low;
        }
    } else { /* ��ѹ */
        if (vlt + delt > vlt_old) {
            return HI_ERR_FAILURE;
        }
        if ((vlt < vlt_th01)) {
            *reg_val = flash_info->freq_low;
        } else if ((vlt < vlt_th11)) {
            *reg_val = flash_info->freq_midle;
        } else {
            *reg_val = flash_info->freq_high;
        }
    }
    return HI_ERR_SUCCESS;
}
/* ����SFC ����flash�����߼Ĵ���������Ĵ��� */
BSP_RAM_TEXT_SECTION hi_void sfc_config_bus_config(const flash_vlt_sfc_info *flash_info, hi_u16 voltage)
{
    if (flash_info == HI_NULL) {
        return;
    }
    hi_u8 delt = g_vlt_threshold_delt;
    hi_u16 vlt_th01 = HI_FLASH_VOLTAGE_TH0 + delt;
    hi_u16 vlt_th02 = HI_FLASH_VOLTAGE_TH0 + (delt << 1);
    hi_spi_flash_ctrl *p_spif_ctrl = &g_flash_drv_ctrl;
    /* wb 2.7v �л�������ָ�� */
    if (memcmp(flash_info->chip_id, g_flash_vlt_sfc_info_tbl[2].chip_id, HI_FLASH_CHIP_ID_NUM) == 0) { /* 2 */
        /* ����ж�cmd != 0xeb������Ҫ�ж��Ƿ�֧�����߶� */
        if ((voltage > vlt_th02) && (p_spif_ctrl->opt_read.cmd == 0x6b)) {
            if (memcpy_s(&p_spif_ctrl->opt_read, sizeof(spi_flash_operation), &g_spi_opt_fast_quad_eb_out_read,
                sizeof(spi_flash_operation)) != EOK) {
                return ;
            }
            spif_bus_config(&(p_spif_ctrl->opt_read), p_spif_ctrl->opt_read.cmd, HI_TRUE);
        }
        /* ����ж�cmd != 0x6b������Ҫ�ж��Ƿ�֧�����߶� */
        if ((voltage <= vlt_th01) && (p_spif_ctrl->opt_read.cmd == 0xeb)) {
            if (memcpy_s(&p_spif_ctrl->opt_read, sizeof(spi_flash_operation), &g_spi_opt_fast_quad_out_read,
                sizeof(spi_flash_operation)) != EOK) {
                return ;
            }
            spif_bus_config(&(p_spif_ctrl->opt_read), p_spif_ctrl->opt_read.cmd, HI_TRUE);
        }
    }
}

/* ����<<hi1131H_QFN32_Flash��Ƶ���������Ƽ�_1220A.xlsx>>����IO�������� */
hi_void sfc_set_driver_strength(hi_void)
{
   /* only 3881 use external flash */
#ifdef CHIP_VER_Hi3881
    hi_u32 ret;
    hi_io_driver_strength drv_str_old;
    hi_io_driver_strength drv_str_new;
    ret = hi_io_get_driver_strength(HI_IO_NAME_SFC_CLK, &drv_str_old);
    if (ret != HI_ERR_SUCCESS) {
        return;
    }
    /* according to the manual setting and the actual flash ID */
    if (g_voltage >= HI_FLASH_VOLTAGE_TH1) { /* 2.97v */
        drv_str_new = HI_IO_DRIVER_STRENGTH_7;
    } else {
        drv_str_new = HI_IO_DRIVER_STRENGTH_6;
    }
    if (drv_str_new == drv_str_old) {
        return;
    }
    hi_io_set_driver_strength(HI_IO_NAME_SFC_CLK, drv_str_new);
#endif
}

/* ���flash�ο���ѹ������SFC Ƶ�� */
BSP_RAM_TEXT_SECTION hi_void sfc_config_update_freq(hi_u32 addr)
{
    hi_u32 ret;
    hi_u16 val = 0xFF;
    hi_u16 reg_val;
    hi_u32 int_value;
    flash_vlt_sfc_info *flash_info = (flash_vlt_sfc_info *)(uintptr_t)addr;
    int_value = hi_int_lock();
    ret = sfc_config_can_modify_freq(100); /* wait 100us */
    if (ret == HI_ERR_FAILURE) {
        goto end;
    }
    hi_reg_read16(PMU_CMU_CTL_CMU_CLK_SEL_REG, reg_val);
    if (flash_info->voltage == 0) { /* 1.8V flash */
        reg_val &= ~(PLL2DBB_192M_MASK << OFFSET_8_BITS);
        val = flash_info->freq_high; /* high freq */
        reg_val |= val << OFFSET_8_BITS;
        hi_reg_write16(PMU_CMU_CTL_CMU_CLK_SEL_REG, reg_val);
        /* ������������ */
        hi_io_set_driver_strength(HI_IO_NAME_SFC_CLK, HI_IO_DRIVER_STRENGTH_5);
        goto end;
    }
    ret = flash_get_average_ref_vlt(&g_voltage);
    if (ret != HI_ERR_SUCCESS) { /* �˳�,Ƶ�ʵò������� */
        goto end;
    }
    sfc_config_bus_config(flash_info, g_voltage); /* wb 2.3-2.7V ��ָ���л� */
    ret = sfc_config_get_freq(&val);
    if (ret == HI_ERR_FAILURE) {
        goto end;
    }
    sfc_set_driver_strength();
    if (val == ((reg_val >> OFFSET_8_BITS) & PLL2DBB_192M_MASK)) {
        goto end;
    }
    reg_val &= ~(PLL2DBB_192M_MASK << OFFSET_8_BITS);
    reg_val |= val << OFFSET_8_BITS;
    Mb();
    hi_reg_write16(PMU_CMU_CTL_CMU_CLK_SEL_REG, reg_val);
    g_voltage_old = g_voltage;
    hi_reg_read16(PMU_CMU_CTL_CMU_CLK_SEL_REG, g_sfc_lp_freq_reg);
    Mb();
end:
    hi_int_restore(int_value);
}
/* ��˯���Ѻ�ָ�SFCƵ���Լ�IO�������� */
BSP_RAM_TEXT_SECTION hi_void sfc_config_lp_update_freq(hi_u32 addr)
{
    hi_u16 reg_val;
    flash_vlt_sfc_info *flash_info = (flash_vlt_sfc_info *)(uintptr_t)addr;
    hi_reg_read16(PMU_CMU_CTL_CMU_CLK_SEL_REG, reg_val);
    if (flash_info->voltage == 0) { /* 1.8V flash */
        reg_val &= ~(PLL2DBB_192M_MASK << OFFSET_8_BITS);
        hi_u16 val = flash_info->freq_high; /* high freq */
        reg_val |= val << OFFSET_8_BITS;
        hi_reg_write16(PMU_CMU_CTL_CMU_CLK_SEL_REG, reg_val);
        /* ������������ */
        hi_io_set_driver_strength(HI_IO_NAME_SFC_CLK, HI_IO_DRIVER_STRENGTH_5);
        return ;
    }
    sfc_set_driver_strength();
    reg_val &= ~(PLL2DBB_192M_MASK << OFFSET_8_BITS);
    reg_val |= g_sfc_lp_freq_reg & (PLL2DBB_192M_MASK << OFFSET_8_BITS);
    hi_reg_write16(PMU_CMU_CTL_CMU_CLK_SEL_REG, reg_val);
}


#ifdef HI_FLASH_SUPPORT_UPDATE_SFC_FREQ
BSP_RAM_TEXT_SECTION hi_u32 sfc_config_periodic_update_freq(flash_vlt_sfc_info *flash_info)
{
    hi_u32 ret;
    if (flash_info == HI_NULL) {
        return HI_ERR_FLASH_INVALID_PARAM;
    }
    ret = hi_timer_create(&g_sfc_update_timer_handle);
    if (ret != HI_ERR_SUCCESS) {
        return ret;
    }
    ret = hi_timer_start(g_sfc_update_timer_handle, HI_TIMER_TYPE_PERIOD, g_sfc_update_time_ms, sfc_config_update_freq,
        (hi_u32)flash_info);
    if (ret != HI_ERR_SUCCESS) {
        hi_timer_delete(g_sfc_update_timer_handle);
    }
    return ret;
}

hi_u32 sfc_config_set_update_time(hi_u32 time_ms)
{
    hi_u32 ret;
    hi_u32 int_value = hi_int_lock();
    g_sfc_update_time_ms = time_ms;
    ret = hi_timer_start(g_sfc_update_timer_handle, HI_TIMER_TYPE_PERIOD, g_sfc_update_time_ms, sfc_config_update_freq,
        (hi_u32)&g_flash_vlt_sfc_info);
    hi_int_restore(int_value);
    return ret;
}
hi_u32 sfc_config_get_update_time(hi_u32 *time_ms)
{
    if (time_ms == HI_NULL) {
        return HI_ERR_FLASH_INVALID_PARAM;
    }
    *time_ms = g_sfc_update_time_ms;
    return HI_ERR_SUCCESS;
}

hi_void sfc_config_set_voltage_threshold_increment(hi_u8 voltage_increment)
{
    hi_u32 int_value = hi_int_lock();
    g_vlt_threshold_delt = voltage_increment;
    hi_int_restore(int_value);
}

hi_u32 sfc_config_get_voltage_threshold_increment(hi_u8 *voltage_increment)
{
    if (voltage_increment == HI_NULL) {
        return HI_ERR_FLASH_INVALID_PARAM;
    }
    *voltage_increment = g_vlt_threshold_delt;
    return HI_ERR_SUCCESS;
}
#endif

BSP_RAM_TEXT_SECTION hi_void sfc_config_cmu_clk_sel(hi_u8 clk)
{
    hi_u32 int_value;
    int_value = hi_int_lock();
    Mb();
    if (clk == CMU_CLK_SEL_96M) {
        hi_reg_clrbits(PMU_CMU_CTL_CMU_CLK_SEL_REG, 8, 2);   /* ����8���ؿ�ʼ��2�������㣬��ʾ96M */
    } else if (clk == CMU_CLK_SEL_80M) {
        hi_reg_setbits(PMU_CMU_CTL_CMU_CLK_SEL_REG, 8, 2, 0x1); /* ����8���ؿ�ʼ��2���ظ�ֵ0x1����ʾ80M */
    } else if (clk == CMU_CLK_SEL_48M) {
        hi_reg_setbits(PMU_CMU_CTL_CMU_CLK_SEL_REG, 8, 2, 0x3); /* ����8���ؿ�ʼ��2���ظ�ֵ0x3����ʾ48M */
    }
    Mb();
    hi_int_restore(int_value);
}
#endif

BSP_RAM_TEXT_SECTION hi_void flash_clk_config(hi_void)
{
#ifdef HI_FLASH_SUPPORT_REF_VBAT
    hi_reg_clrbits(PMU_CMU_CTL_CMU_CLK_SEL_REG, 8, 2);   /* 8, 2 */
    hi_reg_setbit(PMU_CMU_CTL_CMU_CLK_SEL_REG, 8);  /* 8 48M */
    hi_reg_setbit(PMU_CMU_CTL_CMU_CLK_SEL_REG, 9);  /* 9 */
#else
    /* ���VBAT��ѹ������Ϊflash�ο���ѹ�������ʵ����ӵ�flash ���� */
    hi_reg_clrbits(PMU_CMU_CTL_CMU_CLK_SEL_REG, 8, 2);   /* 8, 2 */
    hi_reg_setbit(PMU_CMU_CTL_CMU_CLK_SEL_REG, 8);  /* 8 80M */
#endif
    hi_reg_clrbit(PMU_CMU_CTL_CLK_192M_GT_REG, 0);
    hi_reg_setbit(CLDO_CTL_CLK_SEL_REG, 1);

    /* set sfc not div: in fpga, clk is 80M */
    hi_reg_clrbits(CLDO_CTL_CLK_DIV1_REG, 4, 3);         /* 4, 3 */

#ifdef HI_BOARD_ASIC
    /* ����chipid�ж��Ƿ�������flash�����ޣ���ر�flash_ldo, �˴�����patch���ݶ���hi_u16, ��Ƭ��Ļ�Ϊhi_u8 */
    hi_u16 chip_id;
    hi_u32 ret;
    ret = hi_efuse_read(HI_EFUSE_CHIP_RW_ID, (hi_u8 *)&chip_id, (hi_u8)sizeof(hi_u8));
    if (ret == HI_ERR_SUCCESS) {
        if (chip_id == HI_CHIP_ID_1131SV200) {
            hi_reg_setbit(PMU_CMU_CTL_PMU_MAN_CLR_0_REG, 8);  /* 8 */
            hi_reg_setbit(CLDO_CTL_CLK_SEL_REG, 0);
        }
    }
#endif
}

BSP_RAM_TEXT_SECTION hi_void flash_drv_strenth_config(hi_void)
{
    hi_u16 reg_val;
    /* ʵ�ʸ��ݻ�Ƭ������Ƶ������μ�<hi1131h_����IO����汨��-20190813A.xlsx> */
    hi_io_set_driver_strength(HI_IO_NAME_SFC_CSN, HI_IO_DRIVER_STRENGTH_7);
    hi_io_set_driver_strength(HI_IO_NAME_SFC_IO1, HI_IO_DRIVER_STRENGTH_7);
    hi_io_set_driver_strength(HI_IO_NAME_SFC_IO2, HI_IO_DRIVER_STRENGTH_7);
    hi_io_set_driver_strength(HI_IO_NAME_SFC_IO0, HI_IO_DRIVER_STRENGTH_7);
#ifdef HI_FLASH_SUPPORT_REF_VBAT
    hi_io_set_driver_strength(HI_IO_NAME_SFC_CLK, HI_IO_DRIVER_STRENGTH_7);
#else
    hi_io_set_driver_strength(HI_IO_NAME_SFC_CLK, HI_IO_DRIVER_STRENGTH_5); /* ����ʵ����Ҫ���� */
#endif
    hi_io_set_driver_strength(HI_IO_NAME_SFC_IO3, HI_IO_DRIVER_STRENGTH_7);
    /* en flash ldo bypass  */
    hi_reg_read16(PMU_CMU_CTL_FLASHLDO_CFG_1_REG, reg_val);
    reg_val &= ~(0x1 << 6); /* 6 */
    reg_val |= 0x1 << 6;    /* 6 */
    hi_reg_write16(PMU_CMU_CTL_FLASHLDO_CFG_1_REG, reg_val);
}

#ifdef HI_FLASH_SUPPORT_SUSPEND
BSP_RAM_TEXT_SECTION hi_void flash_suspend(hi_u32 int_val)
{
    /* ����ʵ������ж��жϺţ������Ƿ����suspend���Ƿ����Ĭ��suspend */
    if (int_val != 0) {
        flash_suspend_prv_default(&g_flash_drv_ctrl, HI_FLASH_SUSPEND_TIMEOUT_US);
    }
}

BSP_RAM_TEXT_SECTION hi_void flash_resume(hi_u32 int_val)
{
    /* ����ʵ������ж��жϺţ������Ƿ����resume���Ƿ����Ĭ��resume */
    if (int_val != 0) {
        flash_resume_prv_default(&g_flash_drv_ctrl, HI_FLASH_RESUME_TIMEOUT_US);
    }
}

BSP_RAM_TEXT_SECTION hi_void flash_erase_prepare(hi_void)
{
    LOS_HwiRigister(flash_suspend, flash_resume);
}

BSP_RAM_TEXT_SECTION hi_void flash_erase_resume(hi_void)
{
    LOS_HwiRigister((HWI_HOOK_FUNC)(HI_NULL), (HWI_HOOK_FUNC)HI_NULL);
}

hi_void flash_suspend_init(hi_void)
{
    hi_spi_flash_ctrl *p_spif_ctrl = &g_flash_drv_ctrl;
    if ((p_spif_ctrl->basic_info.chip_attribute & HI_FLASH_SUPPORT_SUSPEND_RESUME) == 0) {
        p_spif_ctrl->sus_enable = HI_FALSE;
        return;
    }
    p_spif_ctrl->sus_enable = HI_TRUE;
    /* Ĭ�ϻָ�һ�Σ����������Ч������δ�ָ�ʱ�쳣�ϵ糡��������𣬺�����ϵ糡��һͬ���ǣ�ͬʱʵ��fboot�� */
    flash_resume_prv_default(p_spif_ctrl, HI_FLASH_RESUME_TIMEOUT_US);
    spif_register_irq_soft_patch(flash_erase_prepare, flash_erase_resume);
}
#else
BSP_RAM_TEXT_SECTION hi_void flash_flush_icache(hi_u32 int_val)
{
    hi_unref_param(int_val);
    /* ������λflashæʱ�жϴ�����з��к���flash�������� */
    LOS_FlushICacheByAll();
}

BSP_RAM_TEXT_SECTION hi_void flash_erase_prepare(hi_void)
{
    LOS_HwiRigister(flash_flush_icache, (HWI_HOOK_FUNC)HI_NULL);
}

BSP_RAM_TEXT_SECTION hi_void flash_erase_resume(hi_void)
{
    LOS_HwiRigister((HWI_HOOK_FUNC)(HI_NULL), (HWI_HOOK_FUNC)HI_NULL);
}

#endif

hi_void flash_sys_int_init(hi_void)
{
#ifdef HI_FLASH_SUPPORT_SUSPEND
    hi_u64 unmask = (hi_u64)((hi_u64)7 << 26) | (hi_u64)((hi_u64)7 << 38); /* test code 7,26,38 */
    set_force_int_unmask_in_flash(unmask);
    flash_suspend_init();
#else
    spif_register_irq_soft_patch(flash_erase_prepare, flash_erase_resume);
#endif
}

hi_u32 flash_read_crash(HI_IN hi_u32 addr, HI_IN hi_void* data, HI_IN hi_u32 size)
{
    spi_flash_prv_addr_info info;
    hi_u32 ret;
    info.flash_offset = addr;
    info.ram_data = data;
    info.size = size;
#ifdef HI_FLASH_SUPPORT_REF_VBAT
    if ((g_voltage <= HI_FLASH_VOLTAGE_TH0) &&
        (memcmp(g_flash_vlt_sfc_info.chip_id, g_flash_vlt_sfc_info_tbl[2].chip_id, HI_FLASH_CHIP_ID_NUM) == 0)) {
        sfc_config_cmu_clk_sel(CMU_CLK_SEL_48M);
    }
#endif
    ret = flash_read_prv(&g_flash_drv_ctrl, &info, HI_TRUE);
#ifdef HI_FLASH_SUPPORT_REF_VBAT
    if ((g_voltage <= HI_FLASH_VOLTAGE_TH0) &&
        (memcmp(g_flash_vlt_sfc_info.chip_id, g_flash_vlt_sfc_info_tbl[2].chip_id, HI_FLASH_CHIP_ID_NUM) == 0)) {
        sfc_config_cmu_clk_sel(CMU_CLK_SEL_80M);
    }
#endif
    return ret;
}

hi_u32 flash_write_crash(HI_IN hi_u32 addr, HI_IN hi_void* data, HI_IN hi_u32 size)
{
    spi_flash_prv_addr_info info;
    hi_u32 ret;
    info.flash_offset = addr;
    info.ram_data = data;
    info.size = size;
#ifdef HI_FLASH_SUPPORT_FLASH_PROTECT
    flash_protect_set_protect(0, HI_TRUE);
#endif
#ifdef HI_FLASH_SUPPORT_REF_VBAT
    if ((g_voltage <= HI_FLASH_VOLTAGE_TH0) &&
        (memcmp(g_flash_vlt_sfc_info.chip_id, g_flash_vlt_sfc_info_tbl[2].chip_id, HI_FLASH_CHIP_ID_NUM) == 0)) {
        sfc_config_cmu_clk_sel(CMU_CLK_SEL_48M);
    }
#endif

    ret = flash_write_prv(&g_flash_drv_ctrl, &info, HI_TRUE, HI_TRUE);
#ifdef HI_FLASH_SUPPORT_REF_VBAT
    if ((g_voltage <= HI_FLASH_VOLTAGE_TH0) &&
        (memcmp(g_flash_vlt_sfc_info.chip_id, g_flash_vlt_sfc_info_tbl[2].chip_id, HI_FLASH_CHIP_ID_NUM) == 0)) {
        sfc_config_cmu_clk_sel(CMU_CLK_SEL_80M);
    }
#endif
    return ret;
}

hi_u32 flash_erase_crash(HI_IN hi_u32 addr, HI_IN hi_u32 size)
{
    hi_u32 ret;
#ifdef HI_FLASH_SUPPORT_FLASH_PROTECT
        flash_protect_set_protect(0, HI_TRUE);
#endif
#ifdef HI_FLASH_SUPPORT_REF_VBAT
    if ((g_voltage <= HI_FLASH_VOLTAGE_TH0) &&
        (memcmp(g_flash_vlt_sfc_info.chip_id, g_flash_vlt_sfc_info_tbl[2].chip_id, HI_FLASH_CHIP_ID_NUM) == 0)) {
        sfc_config_cmu_clk_sel(CMU_CLK_SEL_48M);
    }
#endif
    ret = flash_erase_prv(&g_flash_drv_ctrl, addr, size, HI_TRUE);
#ifdef HI_FLASH_SUPPORT_REF_VBAT
    if ((g_voltage <= HI_FLASH_VOLTAGE_TH0) &&
        (memcmp(g_flash_vlt_sfc_info.chip_id, g_flash_vlt_sfc_info_tbl[2].chip_id, HI_FLASH_CHIP_ID_NUM) == 0)) {
        sfc_config_cmu_clk_sel(CMU_CLK_SEL_80M);
    }
#endif
    return ret;
}

hi_u32 hi_flash_erase(HI_IN const hi_u32 flash_offset, HI_IN const hi_u32 size)
{
    hi_u32 ret = HI_ERR_FAILURE;
    hi_spi_flash_ctrl *p_spif_ctrl = &g_flash_drv_ctrl;

    ret = sfc_check_para(p_spif_ctrl, flash_offset, size, HI_FLASH_CHECK_PARAM_OPT_ERASE);
    if (ret != HI_ERR_SUCCESS) {
        flash_info_print("hi_flash_erase ret1:%x\r\n", ret);
        return ret;
    }

    flash_lock();
#ifdef HI_FLASH_SUPPORT_FLASH_PROTECT
    ret = flash_protect(flash_offset, size, PROTECT_TIMEOUT_AUTO, HI_TRUE);
    if (ret != HI_ERR_SUCCESS) {
        return ret;
    }
#endif
#ifdef HI_FLASH_SUPPORT_REF_VBAT
    if ((g_voltage <= HI_FLASH_VOLTAGE_TH0) &&
        (memcmp(g_flash_vlt_sfc_info.chip_id, g_flash_vlt_sfc_info_tbl[2].chip_id, HI_FLASH_CHIP_ID_NUM) == 0)) {
        sfc_config_cmu_clk_sel(CMU_CLK_SEL_48M);
    }
#endif
    ret = flash_erase_prv(p_spif_ctrl, flash_offset, size, HI_FALSE);
#ifdef HI_FLASH_SUPPORT_REF_VBAT
    if ((g_voltage <= HI_FLASH_VOLTAGE_TH0) &&
        (memcmp(g_flash_vlt_sfc_info.chip_id, g_flash_vlt_sfc_info_tbl[2].chip_id, HI_FLASH_CHIP_ID_NUM) == 0)) {
        sfc_config_cmu_clk_sel(CMU_CLK_SEL_80M);
    }
#endif
    flash_unlock();

    flash_info_print("hi_flash_erase ret:%x addr:%x len:%x\r\n", ret, flash_offset, size);
    return ret;
}

hi_u32 hi_flash_write(const hi_u32 flash_offset, hi_u32 size, const hi_u8 *ram_data,
                      hi_bool do_erase)
{
    hi_spi_flash_ctrl *p_spif_ctrl = &g_flash_drv_ctrl;
    spi_flash_prv_addr_info info;

    if (ram_data == HI_NULL) {
        flash_info_print("write pBuf\r\n");
        return HI_ERR_FLASH_INVALID_PARAM;
    }

    hi_u32 ret = sfc_check_para(p_spif_ctrl, flash_offset, size, HI_FLASH_CHECK_PARAM_OPT_WRITE);
    if (ret != HI_ERR_SUCCESS) {
        flash_info_print("hi_flash_write ret1:%x\r\n", ret);
        return ret;
    }
    info.flash_offset = flash_offset;
    info.ram_data = (hi_u8 *)ram_data;
    info.size = size;

    flash_lock();
#ifdef HI_FLASH_SUPPORT_FLASH_PROTECT
    ret = flash_protect(flash_offset, size, PROTECT_TIMEOUT_AUTO, HI_TRUE);
    if (ret != HI_ERR_SUCCESS) {
        return ret;
    }
#endif
#ifdef HI_FLASH_SUPPORT_REF_VBAT
    if ((g_voltage <= HI_FLASH_VOLTAGE_TH0) && (memcmp(g_flash_vlt_sfc_info.chip_id,
        g_flash_vlt_sfc_info_tbl[2].chip_id, HI_FLASH_CHIP_ID_NUM) == 0)) { /* 2 */
        sfc_config_cmu_clk_sel(CMU_CLK_SEL_48M);
    }
#endif
    ret = flash_write_prv(p_spif_ctrl, &info, do_erase, HI_FALSE);
#ifdef HI_FLASH_SUPPORT_REF_VBAT
    if ((g_voltage <= HI_FLASH_VOLTAGE_TH0) && (memcmp(g_flash_vlt_sfc_info.chip_id,
        g_flash_vlt_sfc_info_tbl[2].chip_id, HI_FLASH_CHIP_ID_NUM) == 0)) { /* 2 */
        sfc_config_cmu_clk_sel(CMU_CLK_SEL_80M);
    }
#endif
    flash_unlock();

    flash_info_print("hi_flash_write ret:%x addr:%x len:%x\r\n", ret, flash_offset, size);
    return ret;
}

hi_u32 hi_flash_read(const hi_u32 flash_offset, const hi_u32 size, hi_u8 *ram_data)
{
    hi_u32 ret;
    hi_spi_flash_ctrl *p_spif_ctrl = &g_flash_drv_ctrl;
    spi_flash_prv_addr_info info;

    if (ram_data == HI_NULL) {
        flash_info_print("pBuf fail\r\n");
        return HI_ERR_FLASH_INVALID_PARAM_DATA_NULL;
    }

    ret = sfc_check_para(p_spif_ctrl, flash_offset, size, HI_FLASH_CHECK_PARAM_OPT_READ);
    if (ret != HI_ERR_SUCCESS) {
        flash_info_print("flash_check_para fail %x\r\n", ret);
        return ret;
    }
    info.flash_offset = flash_offset;
    info.ram_data = ram_data;
    info.size = size;

    flash_lock();
#ifdef HI_FLASH_SUPPORT_REF_VBAT
    if ((g_voltage <= HI_FLASH_VOLTAGE_TH0) &&
        (memcmp(g_flash_vlt_sfc_info.chip_id, g_flash_vlt_sfc_info_tbl[2].chip_id, HI_FLASH_CHIP_ID_NUM) == 0)) { // 2
        sfc_config_cmu_clk_sel(CMU_CLK_SEL_48M);
    }
#endif
    ret = flash_read_prv(p_spif_ctrl, &info, HI_FALSE);
#ifdef HI_FLASH_SUPPORT_REF_VBAT
    if ((g_voltage <= HI_FLASH_VOLTAGE_TH0) &&
        (memcmp(g_flash_vlt_sfc_info.chip_id, g_flash_vlt_sfc_info_tbl[2].chip_id, HI_FLASH_CHIP_ID_NUM) == 0)) { // 2
        sfc_config_cmu_clk_sel(CMU_CLK_SEL_80M);
    }
#endif
    flash_unlock();

    flash_info_print("hi_flash_read ret2:%x addr:%x len:%x\r\n", ret, flash_offset, size);
    return ret;
}

/*
 * ����壬֧��ͨ���������룬������ӳ�䣬�滻������
 */
BSP_RAM_TEXT_SECTION hi_u32 hi_flash_ioctl(hi_u16 cmd, hi_void *data)
{
    hi_u32 ret;
    hi_spi_flash_ctrl *p_spif_ctrl = &g_flash_drv_ctrl;

    if (p_spif_ctrl->init != HI_TRUE) {
        return HI_ERR_FLASH_NOT_INIT;
    }

    flash_lock();
    ret = flash_ioctl(p_spif_ctrl, cmd, data);
    flash_unlock();
    return ret;
}

BSP_RAM_TEXT_SECTION hi_u32 flash_init_cfg(hi_spi_flash_ctrl *p_spif_ctrl, hi_u8 *chip_id, hi_u32 idlen)
{
    if (idlen != HI_FLASH_CHIP_ID_NUM) {
        return HI_ERR_FAILURE;
    }
    hi_u32 ret = spi_flash_basic_info_probe(p_spif_ctrl, chip_id, HI_FLASH_CHIP_ID_NUM,
        (hi_spi_flash_basic_info *)g_flash_default_info_tbl,
        sizeof(g_flash_default_info_tbl) / sizeof(g_flash_default_info_tbl[0]));
    if (ret != HI_ERR_SUCCESS) {
        return ret;
    }
#ifdef HI_FLASH_SUPPORT_REF_VBAT
    if (g_voltage_old == 0) { /* ��һ�ε���flash��ʼ��ʱ���ݲ�����ѹ��Ƶ */
        sfc_config_set_experience(chip_id, &g_flash_vlt_sfc_info, g_flash_vlt_sfc_info_tbl,
            sizeof(g_flash_vlt_sfc_info_tbl) / sizeof(g_flash_vlt_sfc_info_tbl[0]));
        sfc_config_update_freq((hi_u32)(uintptr_t)&g_flash_vlt_sfc_info);
    } else { /* ��˯����ʱ��ʹ��˯��ǰ��Ƶ������������ */
        sfc_config_lp_update_freq((hi_u32)(uintptr_t)&g_flash_vlt_sfc_info);
    }
#endif
    ret = spi_flash_enable_quad_mode();
    if (ret == HI_ERR_SUCCESS) {
        hi_io_set_pull(HI_IO_NAME_SFC_IO2, HI_IO_PULL_NONE);
        hi_io_set_pull(HI_IO_NAME_SFC_IO3, HI_IO_PULL_NONE);
#ifdef HI_FLASH_SUPPORT_REF_VBAT
        if ((g_voltage <= HI_FLASH_VOLTAGE_TH0) &&
            (memcmp(chip_id, g_flash_vlt_sfc_info_tbl[2].chip_id, HI_FLASH_CHIP_ID_NUM) == 0)) { /* wb 2.3-2.7V */
            if (memcpy_s(&p_spif_ctrl->opt_read, sizeof(spi_flash_operation), &g_spi_opt_fast_quad_out_read, /* 6b */
                sizeof(spi_flash_operation)) != EOK) {
                return HI_ERR_FAILURE;
            }
        } else {
            if (memcpy_s(&p_spif_ctrl->opt_read, sizeof(spi_flash_operation), &g_spi_opt_fast_quad_eb_out_read, /* eb */
                sizeof(spi_flash_operation)) != EOK) {
                return HI_ERR_FAILURE;
            }
        }
#else
        if (memcpy_s(&p_spif_ctrl->opt_read, sizeof(spi_flash_operation), &g_spi_opt_fast_quad_eb_out_read,
            sizeof(spi_flash_operation)) != EOK) {
            return HI_ERR_FAILURE;
        }
#endif
    }
    return HI_ERR_SUCCESS;
}

/* ��������ram��ִ�У��Ա���flashִ��ָ������и���flash����flash���ʴ��� */
BSP_RAM_TEXT_SECTION hi_u32 hi_flash_init(hi_void)
{
    hi_u32 ret;
    hi_spi_flash_ctrl *p_spif_ctrl = &g_flash_drv_ctrl;
    hi_u8 chip_id[HI_FLASH_CHIP_ID_NUM] = { 0 };
    static hi_bool init_flag = HI_FALSE;

    if (p_spif_ctrl->init == HI_TRUE) {
        return HI_ERR_FLASH_RE_INIT;
    }

    flash_drv_strenth_config();
    flash_clk_config();

    p_spif_ctrl->dma_ram_buffer = (hi_u8 *)g_dma_buffer;
    p_spif_ctrl->dma_ram_size = 1024;      /* size 1024 */
    p_spif_ctrl->back_up_buf = (hi_u8 *)g_back_buffer;

    ret = flash_init_cfg(p_spif_ctrl, chip_id, HI_FLASH_CHIP_ID_NUM);
    if (ret != HI_ERR_SUCCESS) {
        return ret;
    }

    /* config flash sfc after flash init. */
    spif_bus_config(&(p_spif_ctrl->opt_write), p_spif_ctrl->opt_write.cmd, HI_FALSE);
    spif_bus_config(&(p_spif_ctrl->opt_read), p_spif_ctrl->opt_read.cmd, HI_TRUE);
    if (init_flag == HI_FALSE) {
#ifdef HI_FLASH_SUPPORT_REF_VBAT
#ifdef HI_FLASH_SUPPORT_UPDATE_SFC_FREQ
        ret = sfc_config_periodic_update_freq(&g_flash_vlt_sfc_info);
        if (ret != HI_ERR_SUCCESS) {
            return ret;
        }
#endif
#endif
        ret = hi_mux_create(&p_spif_ctrl->mutex_handle);
        if (ret != HI_ERR_SUCCESS) {
            return ret;
        }
        ret = hi_flash_protect_init(HI_FLASH_PROTECT_TYPE_1); /* ���ݾ����flashд�뱣������ */
        if ((ret != HI_ERR_SUCCESS) && (ret != HI_ERR_FLASH_PROTECT_NOT_FIND_CHIP)) {
            return ret;
        }
        init_flag = HI_TRUE;
    }
    flash_sys_int_init();

    p_spif_ctrl->init = HI_TRUE;
    return ret;
}

hi_u32 hi_flash_deinit(hi_void)
{
    hi_spi_flash_ctrl *p_spif_ctrl = &g_flash_drv_ctrl;
    hi_u32 ret = HI_ERR_SUCCESS;

    if (p_spif_ctrl->init == HI_TRUE) {
        hi_reg_read16(PMU_CMU_CTL_CMU_CLK_SEL_REG, g_sfc_lp_freq_reg);
        ret = hi_flash_protect_deinit();
        /* ��Դ���ͷ� */
        p_spif_ctrl->init = HI_FALSE;
    }

    return ret;
}

