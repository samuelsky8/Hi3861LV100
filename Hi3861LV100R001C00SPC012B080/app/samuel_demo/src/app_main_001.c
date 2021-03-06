/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: app main.
 * Author: Hisilicon
 * Create: 2019-03-04
 */
#include <hi3861_platform.h>
#include <hi_mdm.h>
#include "app_main.h"
#include "lwip/opt.h"
#include "lwip/ip_addr.h"
#include "lwip/netifapi.h"
#include <hi_flash.h>
#include <hi_nv.h>
#include <hi_lowpower.h>
#include <hi_diag.h>
#include <hi_crash.h>
#include <hi_sal.h>
#include <hi_shell.h>
#include "app_demo_upg_verify.h"
#ifdef CONFIG_AT_COMMAND
#include <hi_at.h>
#endif
#include <hi_fs.h>
#include "hi_wifi_api.h"
#include <hi_partition_table.h>
#include <hi_ver.h>
#include <hi_cpu.h>
#ifdef CONFIG_DMA_SUPPORT
#include <hi_dma.h>
#endif
#ifdef CONFIG_I2C_SUPPORT
#include <hi_i2c.h>
#endif
#ifdef CONFIG_I2S_SUPPORT
#include <hi_i2s.h>
#endif
#ifdef CONFIG_SPI_SUPPORT
#include <hi_spi.h>
#endif
#ifdef CONFIG_PWM_SUPPORT
#include <hi_pwm.h>
#endif
#ifdef CONFIG_SDIO_SUPPORT
#include <hi_sdio_slave.h>
#include <hi_watchdog.h>
#include <app_demo_sdio_slave.h>
#endif
#ifdef CONFIG_HILINK
#include "hilink.h"
#endif

#include <app_demo_io_gpio.h>

#define APP_INIT_EVENT_NUM  4
#define APP_INIT_VAP_NUM    2
#ifdef CONFIG_MESH_SUPPORT
#define APP_INIT_USR_NUM    6
#else
#define APP_INIT_USR_NUM    2
#endif

#define PERIPHERAL_INIT_ERR_FLASH   (1 << 0)
#define PERIPHERAL_INIT_ERR_UART0   (1 << 1)
#define PERIPHERAL_INIT_ERR_UART1   (1 << 2)
#define PERIPHERAL_INIT_ERR_UART2   (1 << 3)
#define PERIPHERAL_INIT_ERR_IO      (1 << 4)
#define PERIPHERAL_INIT_ERR_CIPHER  (1 << 5)
#define PERIPHERAL_INIT_ERR_DMA     (1 << 6)
#define PERIPHERAL_INIT_ERR_I2C     (1 << 7)
#define PERIPHERAL_INIT_ERR_I2S     (1 << 8)
#define PERIPHERAL_INIT_ERR_SPI     (1 << 9)
#define PERIPHERAL_INIT_ERR_PWM     (1 << 10)
#define PERIPHERAL_INIT_ERR_SDIO    (1 << 11)

#ifndef IO_CTRL_REG_BASE_ADDR
#define IO_CTRL_REG_BASE_ADDR 0x904
#endif
#define iocfg_reg_addr(_x) (HI_IOCFG_REG_BASE + IO_CTRL_REG_BASE_ADDR + (_x) * 4)
#define IOCFG_LOWPOWER_CFG_VAL 0xF8

#ifdef CONFIG_SDIO_SUPPORT
#define APP_SDIO_INIT_TASK_SIZE 0x1000
#define APP_SDIO_INIT_TASK_PRIO 25

static hi_void *sdio_init_task_body(hi_void *param)
{
    printf("start sdio init\r\n");
    hi_unref_param(param);
    /* 避免由于SDIO HOST长时间未配置触发看门狗异常，此处先关狗 */
    hi_watchdog_disable();
    hi_u32 ret = hi_sdio_init();
    if (ret != HI_ERR_SUCCESS) {
        printf("sdio driver init fail\r\n");
    }
    hi_watchdog_enable();
    app_demo_sdio_callback_init();
    printf("finish sdio init\r\n");
    return HI_NULL;
}

hi_u32 app_sdio_init(hi_void)
{
    /* Create a task to init sdio */
    hi_u32 sdio_init_task_id = 0;
    hi_task_attr attr = {0};
    attr.stack_size = APP_SDIO_INIT_TASK_SIZE;
    attr.task_prio = APP_SDIO_INIT_TASK_PRIO;
    attr.task_name = (hi_char*)"sdio_init";
    hi_u32 ret = hi_task_create(&sdio_init_task_id, &attr, sdio_init_task_body, HI_NULL);
    if (ret != HI_ERR_SUCCESS) {
        printf("Falied to create sdio init task!\n");
    }
    return ret;
}
#endif

#define CLKEN_I2C0      14
#define CLKEN_I2C1      15
#define CLKEN_SPI0      5
#define CLKEN_SPI1      0
#define CLKEN_MONITOR   6
#define CLKEN_DMA_WBUS  1
#define CLKEN1_PWM5     10
#define CLKEN1_PWM_BUS  6
#define CLKEN1_PWM      5
#define CLKEN1_PWM4     4
#define CLKEN1_PWM3     3
#define CLKEN1_PWM2     2
#define CLKEN1_PWM1     1
#define CLKEN1_PWM0     0
#define CLKEN1_PWM_ALL  ((1 << CLKEN1_PWM0) | (1 << CLKEN1_PWM1) | (1 << CLKEN1_PWM2) | (1 << CLKEN1_PWM3) | \
                        (1 << CLKEN1_PWM4) | (1 << CLKEN1_PWM5))
#define CLKEN2_I2S_BUS  11
#define CLKEN2_I2S      10
#define CLKEN_UART2     6
#define CLKEN_UART2_BUS 9
#define CLKEN_TIMER1    7
#define CLKEN_TIMER2    8
#define CLKEN_SDIO_WBUS 4

hi_void peripheral_close_clken(hi_void)
{
    hi_u16 reg_val;
    hi_reg_read16(CLDO_CTL_CLKEN_REG, reg_val);
    reg_val &= ~((1 << CLKEN_I2C0) | (1 << CLKEN_I2C1));
    reg_val &= ~((1 << CLKEN_SPI0) | (1 << CLKEN_SPI1));
    reg_val &= ~((1 << CLKEN_DMA_WBUS) | (1 << CLKEN_MONITOR));
    reg_val &= ~((1 << CLKEN_TIMER1) | (1 << CLKEN_TIMER2));
    hi_reg_write16(CLDO_CTL_CLKEN_REG, reg_val); /* disable clken0 clk gate */
    hi_reg_read16(CLDO_CTL_CLKEN1_REG, reg_val);
    reg_val &= ~CLKEN1_PWM_ALL;
    reg_val &= ~((1 << CLKEN1_PWM_BUS) | (1 << CLKEN1_PWM));
    hi_reg_write16(CLDO_CTL_CLKEN1_REG, reg_val); /* disable clken1 clk gate */
    hi_reg_read16(CLDO_CTL_CLKEN2_REG, reg_val);
    reg_val &= ~((1 << CLKEN2_I2S) | (1 << CLKEN2_I2S_BUS));
    hi_reg_write16(CLDO_CTL_CLKEN2_REG, reg_val); /* disable clken2 clk gate */
    hi_reg_read16(W_CTL_UART_MAC80M_CLKEN_REG, reg_val);
    reg_val &= ~((1 << CLKEN_UART2) | (1 << CLKEN_UART2_BUS) | (1 << CLKEN_SDIO_WBUS));
    hi_reg_write16(W_CTL_UART_MAC80M_CLKEN_REG, reg_val); /* disable uart_mac80m clk gate */
    hi_reg_write16(PMU_CMU_CTL_CLK_960M_GT_REG, 0x1); /* disable 960m clk gate */
}

static hi_uart_attribute g_at_uart_cfg  = {115200, 8, 1, 0, 0};

hi_bool g_have_inited = HI_FALSE;
static app_iocfg_backup g_iocfg_backup = {0};

hi_void peripheral_init(hi_void)
{
    hi_u32 ret;
    hi_u32 err_info = 0;
    hi_cipher_set_clk_switch(HI_TRUE);
    peripheral_close_clken();
    hi_flash_deinit();
    ret = hi_flash_init();
    if (ret != HI_ERR_SUCCESS) {
        err_info |= PERIPHERAL_INIT_ERR_FLASH;
    }

    if (g_have_inited == HI_FALSE) {
        ret = hi_uart_init(HI_UART_IDX_1, &g_at_uart_cfg, HI_NULL);
        if (ret != HI_ERR_SUCCESS) {
            err_info |= PERIPHERAL_INIT_ERR_UART1;
        }
    } else {
        ret = hi_uart_lp_restore(HI_UART_IDX_1);
        if (ret != HI_ERR_SUCCESS) {
            err_info |= PERIPHERAL_INIT_ERR_UART0;
        }
        ret = hi_uart_lp_restore(HI_UART_IDX_0);
        if (ret != HI_ERR_SUCCESS) {
            err_info |= PERIPHERAL_INIT_ERR_UART1;
        }
        ret = hi_uart_lp_restore(HI_UART_IDX_2);
        if (ret != HI_ERR_SUCCESS) {
            err_info |= PERIPHERAL_INIT_ERR_UART2;
        }
    }
    g_have_inited = HI_TRUE;

    app_io_init();

    ret = hi_cipher_init();
    if (ret != HI_ERR_SUCCESS) {
        err_info |= PERIPHERAL_INIT_ERR_CIPHER;
    }

#ifdef CONFIG_DMA_SUPPORT
    /* 如果需要使用UART/SPI的DMA功能，或者使用I2S驱动等，需要初始化DMA */
    /* if product use dma in uart or spi, or use I2S driver, or DMA memory transfer,
       should init DMA Driver here. */
    ret = hi_dma_init();
    if (ret != HI_ERR_SUCCESS) {
        err_info |= PERIPHERAL_INIT_ERR_DMA;
    }
#endif

#ifdef CONFIG_I2C_SUPPORT
    ret = hi_i2c_deinit(HI_I2C_IDX_0); /* if wake_up from deep sleep, should deinit first */
    ret |= hi_i2c_init(HI_I2C_IDX_0, 100000); /* baudrate: 100000 */
    if (ret != HI_ERR_SUCCESS) {
        err_info |= PERIPHERAL_INIT_ERR_I2C;
    }
#endif

#ifdef CONFIG_I2S_SUPPORT
    ret = hi_i2s_deinit();  /* if wake_up from deep sleep, should deinit first */
    hi_i2s_attribute i2s_cfg = {
        .sample_rate = HI_I2S_SAMPLE_RATE_8K,
        .resolution = HI_I2S_RESOLUTION_16BIT,
    };
    ret |= hi_i2s_init(&i2s_cfg);
    if (ret != HI_ERR_SUCCESS) {
        err_info |= PERIPHERAL_INIT_ERR_I2S;
    }
#endif

#ifdef CONFIG_SPI_SUPPORT
    ret = hi_spi_deinit(HI_SPI_ID_0); /* if wake_up from deep sleep, should deinit first */
    hi_spi_cfg_basic_info spi_cfg_basic_info;
    spi_cfg_basic_info.cpha = 1;
    spi_cfg_basic_info.cpol = 1;
    spi_cfg_basic_info.data_width = HI_SPI_CFG_DATA_WIDTH_E_7BIT;
    spi_cfg_basic_info.endian = 0;
    spi_cfg_basic_info.fram_mode = 0;
    spi_cfg_basic_info.freq = 2000000; /* set frequency 2000000 */
    hi_spi_cfg_init_param spi_init_param = {0};
    spi_init_param.is_slave = HI_FALSE;
    ret |= hi_spi_init(HI_SPI_ID_0, spi_init_param, &spi_cfg_basic_info);
    if (ret != HI_ERR_SUCCESS) {
        err_info |= PERIPHERAL_INIT_ERR_SPI;
    }
#endif

#ifdef CONFIG_PWM_SUPPORT
    ret = hi_pwm_init(HI_PWM_PORT_PWM1);
    if (ret != HI_ERR_SUCCESS) {
        err_info |= PERIPHERAL_INIT_ERR_PWM;
    }
#endif

#ifdef AT_DEBUG_CMD_SUPPORT
    if (err_info != 0) {
        hi_at_printf("peri_init:%x\n", err_info);
    }
#endif
    
}

hi_void peripheral_init_no_sleep(hi_void)
{
    /* 示例:深睡唤醒不需要重新初始化的外设，可放置在此函数初始化 */
#ifdef CONFIG_SDIO_SUPPORT
    hi_sdio_set_powerdown_when_deep_sleep(HI_FALSE);
    hi_u32 ret = app_sdio_init();
    if (ret != HI_ERR_SUCCESS) {
        printf("sdio init failed\r\n");
    }
#endif

}

hi_u32 config_before_sleep(hi_void)
{
    /* 用户根据实际io设计配置，防止深睡阶段漏电流 */
    if (hi_lpc_get_type() == HI_DEEP_SLEEP) {
#ifdef AT_DEBUG_CMD_SUPPORT
        hi_at_printf("!");
#endif
        /* 用户根据实际io使用情况设置:无上拉电阻、无下拉电阻、禁止输入信号使能等，防止漏电流，具体参考芯片手册 */
        hi_reg_read16(iocfg_reg_addr(HI_IO_NAME_GPIO_6), g_iocfg_backup.gpio6_cfg);
        hi_reg_read16(iocfg_reg_addr(HI_IO_NAME_GPIO_8), g_iocfg_backup.gpio8_cfg);
        hi_reg_read16(iocfg_reg_addr(HI_IO_NAME_GPIO_10), g_iocfg_backup.gpio10_cfg);
        hi_reg_read16(iocfg_reg_addr(HI_IO_NAME_GPIO_11), g_iocfg_backup.gpio11_cfg);
        hi_reg_read16(iocfg_reg_addr(HI_IO_NAME_GPIO_12), g_iocfg_backup.gpio12_cfg);
        hi_reg_read16(iocfg_reg_addr(HI_IO_NAME_GPIO_13), g_iocfg_backup.gpio13_cfg);
        hi_reg_read16(iocfg_reg_addr(HI_IO_NAME_SFC_CSN), g_iocfg_backup.sfc_csn_cfg);

        hi_reg_write16(iocfg_reg_addr(HI_IO_NAME_GPIO_6), IOCFG_LOWPOWER_CFG_VAL);
        hi_reg_write16(iocfg_reg_addr(HI_IO_NAME_GPIO_8), IOCFG_LOWPOWER_CFG_VAL);
        hi_reg_write16(iocfg_reg_addr(HI_IO_NAME_GPIO_10), IOCFG_LOWPOWER_CFG_VAL);
        hi_reg_write16(iocfg_reg_addr(HI_IO_NAME_GPIO_11), IOCFG_LOWPOWER_CFG_VAL);
        hi_reg_write16(iocfg_reg_addr(HI_IO_NAME_GPIO_12), IOCFG_LOWPOWER_CFG_VAL);
        hi_reg_write16(iocfg_reg_addr(HI_IO_NAME_GPIO_13), IOCFG_LOWPOWER_CFG_VAL);
        hi_reg_write16(iocfg_reg_addr(HI_IO_NAME_SFC_CSN), IOCFG_LOWPOWER_CFG_VAL);
        hi_uart_lp_save(HI_UART_IDX_0);
        hi_uart_lp_save(HI_UART_IDX_1);
        hi_uart_lp_save(HI_UART_IDX_2);
    }
    return HI_ERR_SUCCESS;
}

hi_u32 config_after_sleep(hi_void)
{
    /* 用户根据实际io设计恢复，防止深睡阶段漏电流 */
    if (hi_lpc_get_type() == HI_DEEP_SLEEP) {
        /* 用户根据实际io使用情况配置恢复 */
        hi_reg_write16(iocfg_reg_addr(HI_IO_NAME_GPIO_6), g_iocfg_backup.gpio6_cfg);
        hi_reg_write16(iocfg_reg_addr(HI_IO_NAME_GPIO_8), g_iocfg_backup.gpio8_cfg);
        hi_reg_write16(iocfg_reg_addr(HI_IO_NAME_GPIO_10), g_iocfg_backup.gpio10_cfg);
        hi_reg_write16(iocfg_reg_addr(HI_IO_NAME_GPIO_11), g_iocfg_backup.gpio11_cfg);
        hi_reg_write16(iocfg_reg_addr(HI_IO_NAME_GPIO_12), g_iocfg_backup.gpio12_cfg);
        hi_reg_write16(iocfg_reg_addr(HI_IO_NAME_GPIO_13), g_iocfg_backup.gpio13_cfg);
        hi_reg_write16(iocfg_reg_addr(HI_IO_NAME_SFC_CSN), g_iocfg_backup.sfc_csn_cfg);
#ifdef AT_DEBUG_CMD_SUPPORT
        hi_at_printf("@\n");
#endif
    }
    return HI_ERR_SUCCESS;
}

/*************************************************/
#define TASK_PRI 28
hi_u32 demo_task_id = 0;

static hi_void* example_task_entry(hi_void* data)
{
    hi_u32 ret;
    //printf("Example task is running!\n");
    while(1)
    {
    
        ret = hi_gpio_set_ouput_val(HI_GPIO_IDX_9, HI_GPIO_VALUE0);
        ret = hi_gpio_set_ouput_val(HI_GPIO_IDX_10, HI_GPIO_VALUE1);
        hi_sleep(500);
        ret = hi_gpio_set_ouput_val(HI_GPIO_IDX_9, HI_GPIO_VALUE1);
        ret = hi_gpio_set_ouput_val(HI_GPIO_IDX_10, HI_GPIO_VALUE0);
        hi_sleep(500);
    }
    
}

hi_void example_task_init(hi_void)
{
    hi_u32 ret;
    //hi_u32 demo_task_id = 0;
    hi_task_attr attr = {0};
    
    ret = hi_gpio_init();
    if(ret != HI_ERR_SUCCESS)
    {
        printf("====== ERROR ===== gpio -> hi_gpio_init ret: %d\r\n", ret);
        return;
    }
    printf("----- gpio init success -----\r\n");
    
    ret = hi_io_set_func(HI_IO_NAME_GPIO_9, HI_IO_FUNC_GPIO_9_GPIO);
    if(ret != HI_ERR_SUCCESS)
    {
        printf("===== ERROR ===== gpio -> hi_io_set_func ret: %d\r\n", ret);
        return;
    } 
    ret = hi_io_set_func(HI_IO_NAME_GPIO_10, HI_IO_FUNC_GPIO_10_GPIO);
    if(ret != HI_ERR_SUCCESS)
    {
        printf("===== ERROR ===== gpio -> hi_io_set_func ret: %d\r\n", ret);
        return;
    } 
    printf("----- io set func success -----\r\n");

    ret = hi_gpio_set_dir(HI_GPIO_IDX_9, HI_GPIO_DIR_OUT);
    if(ret != HI_ERR_SUCCESS)
    {
        printf("===== ERROR ===== gpio -> hi_gpio_set_dir ret:%d\r\n", ret);
        return;
    }
    ret = hi_gpio_set_dir(HI_GPIO_IDX_10, HI_GPIO_DIR_OUT);
    if(ret != HI_ERR_SUCCESS)
    {
        printf("===== ERROR ===== gpio -> hi_gpio_set_dir ret:%d\r\n", ret);
        return;
    }
    printf("----- gpio set dir success! -----\r\n");
    
    
    attr.stack_size = 0x2000;
    attr.task_prio = TASK_PRI;
    attr.task_name = (hi_char*)"example_task";
    attr.task_policy = 1; /*SCHED_FIFO;*/
    attr.task_cpuid = (hi_u32)NOT_BIND_CPU;

    ret = hi_task_create(&demo_task_id, &attr, example_task_entry, HI_NULL);
    if(ret != HI_ERR_SUCCESS)
    {
        printf("Example_task create failed!\n");
    }
}

/*************************************************/

hi_void app_main(hi_void)
{
    const hi_char* sdk_ver = hi_get_sdk_version();
    printf("sdk ver:%s\r\n", sdk_ver);

    hi_flash_partition_table *ptable = HI_NULL;

    peripheral_init();
    peripheral_init_no_sleep();
    hi_lpc_register_wakeup_entry(peripheral_init);

    hi_u32 ret = hi_factory_nv_init(HI_FNV_DEFAULT_ADDR, HI_NV_DEFAULT_TOTAL_SIZE, HI_NV_DEFAULT_BLOCK_SIZE);
    if (ret != HI_ERR_SUCCESS) {
        printf("factory nv init fail\r\n");
    }

    /* partion table should init after factory nv init. */
    ret = hi_flash_partition_init();
    if (ret != HI_ERR_SUCCESS) {
        printf("flash partition table init fail:0x%x \r\n", ret);
    }
    ptable = hi_get_partition_table();

    ret = hi_nv_init(ptable->table[HI_FLASH_PARTITON_NORMAL_NV].addr, ptable->table[HI_FLASH_PARTITON_NORMAL_NV].size,
        HI_NV_DEFAULT_BLOCK_SIZE);
    if (ret != HI_ERR_SUCCESS) {
        printf("nv init fail\r\n");
    }

    hi_upg_init();

#ifdef CONFIG_FILE_SYSTEM_SUPPORT
    /* if not use file system, there is no need init it */
    hi_fs_init();
#endif

    (hi_void)hi_event_init(APP_INIT_EVENT_NUM, HI_NULL);
    hi_sal_init();
    /* 此处设为TRUE后看门狗复位会显示复位时PC值，但有复位不完全风险，量产版本请务必设为FALSE */
    hi_syserr_watchdog_debug(HI_FALSE);
    hi_lpc_init();
    hi_lpc_register_hw_handler(config_before_sleep, config_after_sleep);

#ifdef CONFIG_AT_COMMAND
    ret = hi_at_init();
    if (ret == HI_ERR_SUCCESS) {
        hi_at_factory_test_cmd_register(); /* 产测相关AT命令 */
        hi_at_sys_cmd_register(); /* 非产测相关AT命令，如不需要可不注册 */
    }
#endif

    /* 如果不需要使用Histudio查看WIFI驱动运行日志等，无需初始化diag */
    /* if not use histudio for diagnostic, diag initialization is unnecessary */
    /* Shell and Diag use the same uart port, only one of them can be selected */
#ifndef ENABLE_SHELL_DEBUG
#ifdef CONFIG_DIAG_SUPPORT
    (hi_void)hi_diag_init();
#endif
#else
    (hi_void)hi_shell_init();
#endif

    tcpip_init(NULL, NULL);

    ret = hi_wifi_init(APP_INIT_VAP_NUM, APP_INIT_USR_NUM);
    if (ret != HISI_OK) {
        printf("wifi init failed!\n");
    } else {
        printf("wifi init success!\n");
    }
    
    app_demo_upg_init();
#ifdef CONFIG_HILINK
    ret = hilink_main();
    if (ret != HISI_OK) {
        printf("hilink init failed!\n");
    } else {
        printf("hilink init success!\n");
    }
#endif
    
    example_task_init();    
}
