/*
 *Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2019. All rights reserved.
 *Description: Ca and dut control link setup
 *Create: 2019-04-22
 */
 /*****************************************************************************
   头文件包含
 *****************************************************************************/
#include <stdio.h>
#include "hi_task.h"
#include "hi_uart.h"
#include "hi_sem.h"
#include "sal_inf.h"
#include "wfa_debug.h"
#include "wfa_types.h"
#include "wfa_ca.h"
#include "hi_wifitest_uart.h"
#include "hi_watchdog.h"
#include "hi_wifitest.h"

static hi_uart_idx g_sigma_uart_port = HI_UART_IDX_2;
static hi_uart_attribute g_sigma_uart_cfg = {115200, 8, 1, 0, 0};
UINT32 g_sigma_uart_send_sem_id;

#define SIGMA_UART_RECV_TASK_STAK_SIZE  (3*1024)
#define SIGMA_UART_RECV_TASK_PRIORITY    25
#define SIGMA_UART_SEND_LOCK()       do {hi_sem_wait(g_sigma_uart_send_sem_id, HI_SYS_WAIT_FOREVER);} while(0)
#define SIGMA_UART_SEND_UNLOCK()     do {hi_sem_signal(g_sigma_uart_send_sem_id);} while(0)
#define SIGMA_UART_RECV_MAX_SIZE 512

static unsigned char g_sigma_cmd_buff[SIGMA_UART_RECV_MAX_SIZE];

hi_sigma_input_func g_sigma_input_func  = HI_NULL;
hi_sigma_output_func g_sigma_output_func = HI_NULL;

hi_u16 g_sigma_uart_task_size = SIGMA_UART_RECV_TASK_STAK_SIZE;

/*****************************************************************************
   函数实现
*****************************************************************************/
hi_u32 hi_sigma_register_input_func(hi_sigma_input_func sigma_input_func)
{
    hi_bool last_uart_input = HI_FALSE; /* 上一次输入方式是否为uart */
    if (g_sigma_input_func == HI_NULL) {
        last_uart_input = HI_TRUE;
    }

    g_sigma_input_func = sigma_input_func;

    if (last_uart_input == HI_TRUE) {
        return hi_uart_quit_read(g_sigma_uart_port);
    }
    return HI_ERR_SUCCESS;
}

hi_void hi_sigma_register_output_func(hi_sigma_output_func sigma_output_func)
{
    g_sigma_output_func = sigma_output_func;
    return;
}

void sortOutCmdLine(unsigned char c)
{
    int cmdLen = 0;
    unsigned char ch = 0;
    static int count = 0;


    ch = c;
    if (count == 0 && ch != 0x0){
        (VOID)memset_s(g_sigma_cmd_buff, SIGMA_UART_RECV_MAX_SIZE, 0, SIGMA_UART_RECV_MAX_SIZE);
    }

    if(!(count < SIGMA_UART_RECV_MAX_SIZE - 1)){
        count = 0;
        return;
    }

    if (ch == 0x0A) {
        cmdLen = count + 1;
        g_sigma_cmd_buff[count] = ch;
        g_sigma_cmd_buff[cmdLen] = '\0';

        count = 0;
        sigmaCaParseCmd(g_sigma_cmd_buff, cmdLen);

        return;
    }else{
        if (count < SIGMA_UART_RECV_MAX_SIZE - 1){
            g_sigma_cmd_buff[count] = ch;
            count++;
        }else{
            g_sigma_cmd_buff[SIGMA_UART_RECV_MAX_SIZE - 1] = '\0';
            count = 0;
            return;
        }
    }

}

void *sigma_uart_recv_task(void *param)
{
    int len = 0;
    unsigned char ch;
    hi_unref_param(param);
    for (;;){
        hi_watchdog_feed();
        if (g_sigma_input_func == HI_NULL) {
            len = hi_uart_read(g_sigma_uart_port, &ch, 1);
        } else {
            len = g_sigma_input_func(&ch, 1);
        }
        if(len == 1){
            sortOutCmdLine(ch);
            continue;
        }else{
            DPRINT_WARNING(WFA_WNG, "read nothing\n");
            hi_sleep(1000);
        }
    }
}

int uart_send_rsp(char *data, unsigned int data_len)
{
    unsigned int length = data_len;
    unsigned int offset = 0;
    int len = 0;

    while (offset < length) {
        if (g_sigma_output_func == HI_NULL) {
        len = hi_uart_write(g_sigma_uart_port, (unsigned char *)data + offset, (unsigned int)(length - offset));
        } else {
            len = g_sigma_output_func((unsigned char *)data + offset, (unsigned int)(length - offset));
        }
        if ((len < 0) || (0 == len)) {
            return -1;
        }

        offset += (unsigned int) len;

        if (offset >= length) {
            break;
        }

        hi_sleep(10);
    }

    return WFA_SUCCESS;
}

int sigma_uart_send(char *paData, unsigned int ausDataSize)
{
    hi_u32 ret = -1;

    SIGMA_UART_SEND_LOCK();
    if (paData && ausDataSize) {
        ret = uart_send_rsp(paData, ausDataSize);
    }
    SIGMA_UART_SEND_UNLOCK();

    return ret;
}

int sigma_uart_init_cfg(void)
{
    int ret = WFA_FAILURE;
    hi_u8 uart_port = 0;
    ret = sal_uart_port_allocation(UART_FUNC_SIGMA, &uart_port);
    if (ret != WFA_SUCCESS) {
        return WFA_FAILURE;
    }

    if (uart_port == 0xFF) {
        if (g_sigma_input_func != HI_NULL && g_sigma_output_func != HI_NULL) {
            return WFA_SUCCESS;
        } else {
            printf("func NULL\r\n");
            return WFA_FAILURE;
        }
    }

    g_sigma_uart_port = uart_port;

    (void)hi_uart_deinit(g_sigma_uart_port);
    ret = hi_uart_init(g_sigma_uart_port, &g_sigma_uart_cfg, HI_NULL);
    if (ret != WFA_SUCCESS) {
        DPRINT_ERR(WFA_ERR, "init uart%d failed.\n", (int)g_sigma_uart_port);
        return ret;
    }

    return ret;
}

int sigma_ca_Init(void)
{
    UINT32 uart_task_id = 0;
    UINT32 ret = 0;
    hi_task_attr attr = {0};

    ret = hi_sem_bcreate(&g_sigma_uart_send_sem_id, HI_SEM_ONE);
    if (WFA_SUCCESS != ret) {
        DPRINT_ERR(WFA_ERR, "sigma uart sem init fail\r\n");
        return ret;
    }

    ret = sigma_uart_init_cfg();
    if (ret != 0) {
        return ret;
    }

    attr.stack_size = SIGMA_UART_RECV_TASK_STAK_SIZE;
    attr.task_prio = SIGMA_UART_RECV_TASK_PRIORITY;
    attr.task_name = (hi_char*)"sigma_uart_task";
    ret = hi_task_create(&uart_task_id, &attr, sigma_uart_recv_task, 0);
    return ret;
}

hi_void hi_sigma_set_channel_task_size(hi_u16 uart_task_size)
{
    if (uart_task_size < 0x400) {
        g_sigma_uart_task_size = 0x400;
    }

    g_sigma_uart_task_size = uart_task_size;
}

