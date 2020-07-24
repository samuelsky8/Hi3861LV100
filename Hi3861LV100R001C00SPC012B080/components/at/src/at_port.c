/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: AT cmd physical port
 * Author: liangguangrui
 * Create: 2019-10-15
 */
#include <hi_uart.h>
#include <at_port.h>

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

hi_void uart_send_str(const hi_char *data_str, hi_u32 length)
{
    if (data_str == HI_NULL) {
        return;
    }

    hi_u32 offset = 0;

    while (offset < length) {
        hi_s32 len = hi_uart_write(HI_UART_IDX_0, (hi_u8 *)(data_str + offset), (hi_u32)(length - offset));
        if (len < 0) {
            continue;
        }

        offset += (hi_u32) len;

        if (offset >= length) {
            break;
        }
    }
}

#ifdef __cplusplus
#if __cplusplus
    }
#endif
#endif