/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2012-2019. All rights reserved.
 * Description: Cmd loop source file.
 * Author: Hisilicon
 * Create: 2019-12-19
 */

#include <cmd_loop.h>
#include <crc.h>
#include <transfer.h>

#define CMD_RX_DELAY_MS     100 /* 100ms */
#define US_PER_MS           1000
#define CMD_FRAME_TIMEOUT   20000 /* 首字符超时20秒 */
#define CMD_ABNORMAL_MAX    100
#define CHECKSUM_SIZE       2
#define ACK_LEN             0x0C

typedef enum {
    CMD_RX_STATUS_WAIT_START_0,
    CMD_RX_STATUS_WAIT_START_1,
    CMD_RX_STATUS_WAIT_START_2,
    CMD_RX_STATUS_WAIT_START_3,
    CMD_RX_STATUS_WAIT_SIZE_0,
    CMD_RX_STATUS_WAIT_SIZE_1,
    CMD_RX_STATUS_WAIT_TYPE,
    CMD_RX_STATUS_WAIT_PAD,
    CMD_RX_STATUS_WAIT_DATA,
    CMD_RX_STATUS_WAIT_CS_0,
    CMD_RX_STATUS_WAIT_CS_1,
} cmd_rx_status;

typedef hi_u32(*cmd_func) (const uart_ctx *cmd_ctx);

typedef struct {
    hi_u8 cmd_type;
    cmd_func cmdfunc;
} loader_cmd;

uart_ctx *g_cmd_ctx = HI_NULL;

const loader_cmd g_loader_cmdtable[LOADER_CMD_MAX] = {
    { CMD_DL_IMAGE,         loader_download_image },
    { CMD_BURN_EFUSE,       loader_burn_efuse },
    { CMD_UL_DATA,          loader_upload_data },
    { CMD_READ_EFUSE,       loader_read_efuse },
    { CMD_FLASH_PROTECT,    loader_flash_protect },
    { CMD_RESET,            loader_reset },
};

hi_void loader_read_flash_protect_state(hi_void)
{
    hi_u32 reg = 0;
    hi_reg_write(SFC_REG_BASE_ADDRESS + SFC_REG_CMD_DATABUF1, 0);
    spif_wait_config_start();
    hi_reg_write(SFC_REG_BASE_ADDRESS + SFC_REG_CMD_INS, 0x05);
    hi_reg_write(SFC_REG_BASE_ADDRESS + SFC_REG_CMD_CONFIG, 0x183);
    spif_wait_config_start();
    hi_reg_read(SFC_REG_BASE_ADDRESS + SFC_REG_CMD_DATABUF1, reg);
    boot_msg1("S0 ~ S7   : ", reg);
    hi_reg_write(SFC_REG_BASE_ADDRESS + SFC_REG_CMD_DATABUF1, 0);
    spif_wait_config_start();
    hi_reg_write(SFC_REG_BASE_ADDRESS + SFC_REG_CMD_INS, 0x35);
    hi_reg_write(SFC_REG_BASE_ADDRESS + SFC_REG_CMD_CONFIG, 0x183);
    spif_wait_config_start();
    hi_reg_read(SFC_REG_BASE_ADDRESS + SFC_REG_CMD_DATABUF1, reg);
    boot_msg1("S8 ~ S15 : ", reg);
}

hi_u32 loader_reset(const uart_ctx *cmd_ctx)
{
    boot_msg0("\nReset device...\n");
    loader_ack(ACK_SUCCESS);
    mdelay(5);  /* delay 5ms */
    global_reset();
    return HI_ERR_SUCCESS;
}

hi_u32 loader_flash_protect(const uart_ctx *cmd_ctx)
{
    hi_u32 ret;
    hi_u16 cmd_type = *(hi_u16 *)(&cmd_ctx->packet.payload[0]);
    boot_msg0("Flash protect state");
    loader_read_flash_protect_state();
    if (cmd_type == 1) {
        ret = flash_protect_set_protect(0, HI_FALSE);
        if (ret == HI_ERR_SUCCESS) {
            boot_msg0("\r\nUnlock Succ\r\n");
            loader_read_flash_protect_state();
        } else {
            boot_msg0("\r\nUnlock Fail\r\n");
        }
        return ret;
    } else if (cmd_type > 1) {
        boot_msg0("Unknow cmd type");
        return HI_ERR_FAILURE;
    }
    return HI_ERR_SUCCESS;
}

hi_u32 loader_download_image(const uart_ctx *cmd_ctx)
{
    hi_u8 chip_id[HI_FLASH_CHIP_ID_NUM] = { 0 };
    hi_u32 flash_size = 0;
    hi_u32 download_addr = *(hi_u32 *)(&cmd_ctx->packet.payload[0]);
    hi_u32 file_len = *(hi_u32 *)(&cmd_ctx->packet.payload[4]); /* offset 4 is file length */
    hi_u32 erase_size = *(hi_u32 *)(&cmd_ctx->packet.payload[8]); /* offset 8 is erase size */
    hi_u8 burn_efuse = cmd_ctx->packet.payload[12]; /* offset 12 is burn efuse flag */
    hi_u32 ret = spi_flash_read_chip_id(chip_id, HI_FLASH_CHIP_ID_NUM);
    if (ret == HI_ERR_SUCCESS) {
        flash_size = spi_flash_get_size((const hi_u8 *)chip_id);
    } else {
        boot_msg0("Get flash size fail");
        return HI_ERR_FAILURE;
    }

    if (file_len == 0 || erase_size == 0 || erase_size < file_len || (download_addr + file_len) > flash_size) {
        boot_msg0("Invalid params");
        serial_puts("download_addr ");
        serial_puthex(download_addr, 1);
        serial_puts(" file_len ");
        serial_puthex(file_len, 1);
        serial_puts(" erase_size ");
        serial_puthex(erase_size, 1);
        serial_puts("\r\n");
        return HI_ERR_FAILURE;
    }

    return download_image(download_addr, erase_size, flash_size, burn_efuse);
}

hi_u32 loader_burn_efuse(const uart_ctx *cmd_ctx)
{
    hi_u32 ret;
    hi_u32 file_len = *(hi_u32 *)(&cmd_ctx->packet.payload[0]);
    if (file_len <= EFUSE_CFG_MIN_LEN || file_len > EFUSE_CFG_MAX_LEN) {
        boot_msg1("File length error : ", file_len);
        return HI_ERR_FAILURE;
    }

    hi_u8 *buf = boot_malloc(file_len);
    if (buf == HI_NULL) {
        boot_msg0("Malloc buffer error");
        return HI_ERR_FAILURE;
    }

    ret = loady_file((uintptr_t)buf);
    if (ret != HI_ERR_SUCCESS) {
        boot_msg1("Loady efuse file failed:", ret);
        return ret;
    }

    ret = efuse_burn((uintptr_t)buf, file_len);
    if (ret != HI_ERR_SUCCESS) {
        return ret;
    }
    return HI_ERR_SUCCESS;
}

hi_u32 loader_read_efuse(const uart_ctx *cmd_ctx)
{
    hi_u32 ret;
    hi_u16 start_bit = *(hi_u16 *)(&cmd_ctx->packet.payload[0]);
    hi_u16 size = *(hi_u16 *)(&cmd_ctx->packet.payload[2]); /* offset 2 is read size */
    boot_msg0("Efuse read");
    serial_puts("Start bit: ");
    serial_puthex(start_bit, 1);
    serial_puts(" len(bits)=");
    serial_puthex(size, 1);
    serial_puts("\r\n");
    if ((start_bit >= EFUSE_BIT_NUM) || ((start_bit + size) > EFUSE_BIT_NUM) || size > EFUSE_READ_MAX_BITS) {
        boot_msg0("Params err");
        return HI_ERR_FAILURE;
    }

    ret = efuse_read(start_bit, size);
    if (ret != HI_ERR_SUCCESS) {
        return HI_ERR_FAILURE;
    }

    return HI_ERR_SUCCESS;
}

hi_u32 loader_upload_data(const uart_ctx *cmd_ctx)
{
    hi_u8 chip_id[HI_FLASH_CHIP_ID_NUM] = {0};
    hi_u32 flash_size = 0;
    hi_u32 file_len = *(hi_u32 *)(&cmd_ctx->packet.payload[0]);
    hi_u32 upload_addr = *(hi_u32 *)(&cmd_ctx->packet.payload[4]);  /* offset 4 is read addr */
    boot_msg2("Upload addr, length :", upload_addr, file_len);

    hi_u32 ret = spi_flash_read_chip_id(chip_id, HI_FLASH_CHIP_ID_NUM);
    if (ret == HI_ERR_SUCCESS) {
        flash_size = spi_flash_get_size((const hi_u8 *)chip_id);
    } else {
        boot_msg0("Get flash size fail");
        return HI_ERR_FAILURE;
    }

    if (file_len == 0 || file_len > flash_size) {
        boot_msg0("Upload length error");
        return HI_ERR_FAILURE;
    }

    if ((upload_addr & 0x3) != 0) {
        boot_msg0("Upload addr error");
        return HI_ERR_FAILURE;
    }

    if ((upload_addr + file_len) > flash_size) {
        boot_msg0("Upload addr exceeds flash capacity");
        return HI_ERR_FAILURE;
    }

    return upload_data(upload_addr, file_len);
}

hi_u32 loader_frame_head_rx(uart_ctx *ctx)
{
    hi_u8 ch;
    hi_bool reset_flag = HI_FALSE;
    hi_u16 rcv = 0;

    packet_data_head *head = &ctx->packet.head;
    hi_u8 *payload = (hi_u8 *)head;

    while (rcv <= CMD_ABNORMAL_MAX) {
        hi_u32 ret = serial_getc_timeout(CMD_FRAME_TIMEOUT * US_PER_MS, &ch);
        if (ret != HI_ERR_SUCCESS) {
            continue;
        }

        rcv++;
        if (reset_flag == HI_TRUE) {
            reset_flag = HI_FALSE;
            head->start_flag = 0;
            ctx->status = CMD_RX_STATUS_WAIT_START_0;
        }
        if (ctx->status <= CMD_RX_STATUS_WAIT_START_3) {
            hi_u32 start_flag = UART_PACKET_START_FLAG;
            hi_u8 *start_byte = (hi_u8 *)&start_flag;
            if (ch == start_byte[ctx->status]) {
                payload[ctx->status] = ch;
                ctx->status++;
                continue;
            } else if (ch == 0xEF) {
                payload[CMD_RX_STATUS_WAIT_START_0] = ch;
                ctx->status = CMD_RX_STATUS_WAIT_START_1;
                continue;
            }
            reset_flag = HI_TRUE;
            continue;
        } else {
            payload[ctx->status] = ch;
            if (ctx->status >= CMD_RX_STATUS_WAIT_START_1 && (head->packet_size > UART_PACKET_PAYLOAD_MAX)) {
                reset_flag = HI_TRUE;
                continue;
            }
            ctx->status++;
            if (ctx->status >= CMD_RX_STATUS_WAIT_DATA) {
                return HI_ERR_SUCCESS;
            }
        }
    }
    return HI_ERR_FAILURE;
}

hi_u32 loader_frame_data_rx(uart_ctx *ctx)
{
    hi_u8 ch;
    hi_u32 ret;
    ctx->received = 0;

    packet_data_head *head = &ctx->packet.head;
    hi_u8 *payload = ctx->packet.payload;

    while (ctx->received < (head->packet_size - sizeof(packet_data_head))) {
        ret = serial_getc_timeout(CMD_RX_DELAY_MS * US_PER_MS, &ch);
        if (ret == HI_ERR_SUCCESS) {
            payload[ctx->received++] = ch;
            continue;
        }
        return HI_ERR_FAILURE;
    }
    ctx->packet.check_sum = (payload[head->packet_size - 9] << 8) | payload[head->packet_size - 10]; /* 8,9,10: sub */
    payload[head->packet_size - 9] = 0;  /* 9: sub 9 */
    payload[head->packet_size - 10] = 0; /* 10: sub 10 */

    if (ctx->received == (head->packet_size - sizeof(packet_data_head))) {
        return HI_ERR_SUCCESS;
    }

    return HI_ERR_FAILURE;
}

hi_void loader_ack(hi_u8 err_code)
{
    uart_ctx *ctx = g_cmd_ctx;
    packet_data_head *head = &ctx->packet.head;

    head->start_flag = UART_PACKET_START_FLAG;
    head->type = CMD_ACK;
    head->pad = (hi_u8)(~(CMD_ACK));
    head->packet_size = ACK_LEN;
    ctx->packet.payload[0] = err_code;
    ctx->packet.payload[1] = ~err_code;
    hi_u32 cs = 0 ^ (uintptr_t)(hi_u8 *)&(ctx->packet) ^ (head->packet_size - CHECKSUM_SIZE);
    ctx->packet.check_sum = crc16_ccitt(0, (hi_u8 *)&(ctx->packet), head->packet_size - CHECKSUM_SIZE, cs);

    serial_put_buf ((const char *)&(ctx->packet), (int)(head->packet_size - CHECKSUM_SIZE));
    serial_put_buf ((const char *)&(ctx->packet.check_sum), CHECKSUM_SIZE);
}

hi_u32 loader_read_frame(uart_ctx *ctx)
{
    packet_data_info *packet = &ctx->packet;
    packet_data_head *head = &packet->head;
    hi_u32 ret;
    hi_u32 cs;

    /* 复位接收状态 */
    ctx->status = CMD_RX_STATUS_WAIT_START_0;
    ctx->received = 0;
    cs = (uintptr_t)packet ^ (hi_u32)sizeof(packet_data_info) ^ 0 ^ (hi_u32)sizeof(packet_data_info);
    if (memset_s(packet, sizeof(packet_data_info), 0, sizeof(packet_data_info), cs) != EOK) {
        return HI_ERR_FAILURE;
    }

    ret = loader_frame_head_rx(ctx);
    if (ret != HI_ERR_SUCCESS) {
        return HI_ERR_FAILURE;
    }

    ret = loader_frame_data_rx(ctx);
    if (ret != HI_ERR_SUCCESS) {
        return HI_ERR_FAILURE;
    }

    cs = 0 ^ (uintptr_t)(hi_u8 *)packet ^ (head->packet_size - CHECKSUM_SIZE);
    cs = crc16_ccitt(0, (hi_u8 *)packet, head->packet_size - CHECKSUM_SIZE, cs);
    if (cs == packet->check_sum) {
        return HI_ERR_SUCCESS;
    }

    return HI_ERR_FAILURE;
}

hi_u32 loader_exe_cmd(uart_ctx *ctx)
{
    hi_u32 i = 0;

    packet_data_info *packet = &ctx->packet;
    packet_data_head *head = &packet->head;
    for (i = 0; i < LOADER_CMD_MAX; i++) {
        if (head->type == g_loader_cmdtable[i].cmd_type) {
            if (g_loader_cmdtable[i].cmdfunc != HI_NULL) {
                return g_loader_cmdtable[i].cmdfunc(ctx);
            }
        }
    }

    if (i == LOADER_CMD_MAX) {
        boot_msg1("Unsupport CMD:", head->type);
    }

    return HI_ERR_FAILURE;
}

uart_ctx *cmd_loop_init(hi_void)
{
    if (g_cmd_ctx == HI_NULL) {
        g_cmd_ctx = (uart_ctx *)boot_malloc(sizeof(uart_ctx));
    }

    if (g_cmd_ctx != HI_NULL) {
        volatile hi_u32 check_sum = (uintptr_t)g_cmd_ctx ^ (hi_u32)sizeof(uart_ctx) ^ 0 ^ (hi_u32)sizeof(uart_ctx);
        (hi_void) memset_s(g_cmd_ctx, sizeof(uart_ctx), 0, sizeof(uart_ctx), check_sum);
        return g_cmd_ctx;
    }
    return HI_NULL;
}

hi_u32 cmd_loop_deinit(hi_void)
{
    hi_u32 ret = boot_free(g_cmd_ctx);
    if (ret == HI_ERR_SUCCESS) {
        g_cmd_ctx = HI_NULL;
    }

    return ret;
}

hi_void cmd_loop(uart_ctx *ctx)
{
    hi_u32 ret;
    for (;;) {
        ret = loader_read_frame(ctx);
        if (ret != HI_ERR_SUCCESS) {
            boot_msg0("\nGet CMD fail");
            loader_ack(ACK_FAILURE);
            continue;
        }

        ret = loader_exe_cmd(ctx);
        if (ret != HI_ERR_SUCCESS) {
            loader_ack(ACK_FAILURE);
            boot_msg0("\nExecution Failure : ");
            boot_msg0("============================================\n");
            continue;
        }

        loader_ack(ACK_SUCCESS);
        boot_msg0("\nExecution Successful");
        boot_msg0("============================================\n");
    }
}

