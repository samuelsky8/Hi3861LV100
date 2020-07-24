/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: APP common API.
 * Author: wangjian
 * Create: 2019-4-3
 */
#ifndef __SPI_H__
#define __SPI_H__

#include <hi_types_base.h>
#include <hi3861_platform_base.h>
#include <hi_spi.h>
#include <hi_time.h>
#include <hi_stdlib.h>
#include <hi_isr.h>
#include <hi_event.h>
#include <hi_sem.h>

/* if some print is needed :#define SPI_DEBUG */
#ifdef SPI_DEBUG
#define spi_printf(fmt...) do{ \
            printf("[DEBUG]"fmt); \
            printf("\n"); \
            } while (0)
#define spi_process_printf(fmt...) do{ \
                printf("[PROCESS]"fmt); \
                printf("\n"); \
                } while (0)
#else
#define spi_printf(fmt, ...)
#define spi_process_printf(fmt, ...)
#endif

#define SPI_NUM             2

#define REG_SPI_CR0         0x00        /* ���ƼĴ���0ƫ�Ƶ�ַ */
#define REG_SPI_CR1         0x04        /* ���ƼĴ���1ƫ�Ƶ�ַ */
#define REG_SPI_DR          0x08        /* ����(����)���ݼĴ���ƫ�Ƶ�ַ */
#define REG_SPI_SR          0x0c        /* ״̬�Ĵ���ƫ�Ƶ�ַ */
#define REG_SPI_CPSR        0x10        /* ʱ�ӷ�Ƶ�Ĵ���ƫ�Ƶ�ַ */
#define REG_SPI_IMSC        0x14        /* �ж����μĴ���ƫ�Ƶ�ַ */
#define REG_SPI_RIS         0x18        /* ԭʼ�ж�״̬�Ĵ���ƫ�Ƶ�ַ */
#define REG_SPI_MIS         0x1c        /* ���κ��ж�״̬�Ĵ���ƫ�Ƶ�ַ */
#define REG_SPI_CR          0x20        /* �ж�����Ĵ���ƫ�Ƶ�ַ */
#define REG_SPI_DMACR       0x24        /* DMA���ܼĴ���ƫ�Ƶ�ַ */
#define REG_SPI_TXFIFOCR    0x28        /* ����FIFO���ƼĴ���ƫ�Ƶ�ַ */
#define REG_SPI_RXFIFOCR    0x2c        /* ����FIFO���ƼĴ���ƫ�Ƶ�ַ */

#define MASK_SPI_SR_TFE    (1<<0)       /* TX FIFO�Ƿ��ѿ� 0:δ�� 1:�ѿ� */
#define MASK_SPI_SR_TNF    (1<<1)       /* TX FIFO�Ƿ�δ�� 0:���� 1:δ�� */
#define MASK_SPI_SR_RNE    (1<<2)       /* RX FIFOδ�ձ�־ 0:�ѿ� 1:δ�� */
#define MASK_SPI_SR_RFF    (1<<3)       /* RX FIFO������־ 0:δ�� 1:���� */
#define MASK_SPI_SR_BSY    (1<<4)       /* SPIæ��־ 0:���� 1:æ */

#define SPI_CR0_ST_BIT_DSS  0   /* ��ʼbit:����λ�� */
#define SPI_CR0_ST_BIT_FRF  4   /* ��ʼbit:֡��ʽ */
#define SPI_CR0_ST_BIT_SPO  6   /* ��ʼbit:���� */
#define SPI_CR0_ST_BIT_SPH  7   /* ��ʼbit:��λ */
#define SPI_CR0_ST_BIT_SCR  8   /* ��ʼbit:����ʱ���� */

#define SPI_CR0_BIT_WIDTH_DSS   4       /* bit��:����λ�� */
#define SPI_CR0_BIT_WIDTH_FRF   2       /* bit��:֡��ʽ */
#define SPI_CR0_BIT_WIDTH_SPO   1       /* bit��:���� */
#define SPI_CR0_BIT_WIDTH_SPH   1       /* bit��:��λ */
#define SPI_CR0_BIT_WIDTH_SCR   8       /* bit��:����ʱ���� */

#define SPI_CR1_ST_BIT_LBM      0       /* ��ʼbit:�ػ�ģʽ */
#define SPI_CR1_ST_BIT_SSE      1       /* ��ʼbit:SPIʹ�� */
#define SPI_CR1_ST_BIT_MS       2       /* ��ʼbit:MASTER SLAVE */
#define SPI_CR1_ST_BIT_BIGEND   4       /* ��ʼbit: ��С�� */
#define SPI_CR1_ST_BIT_WAITVAL  8       /* ��ʼbit: microwireд�Ͷ�֮��ȴ����� */
#define SPI_CR1_ST_BIT_WAITEN   15      /* ��ʼbit:microwireд�Ͷ�֮��ȴ�����ʹ�� */

#define SPI_CR1_BIT_WIDTH_LBM       1   /* bit��:�ػ�ģʽ */
#define SPI_CR1_BIT_WIDTH_SSE       1   /* bit��:SPIʹ�� */
#define SPI_CR1_BIT_WIDTH_MS        1   /* bit��:MASTER SLAVE */
#define SPI_CR1_BIT_WIDTH_BIGEND    1   /* bit��: ��С�� */
#define SPI_CR1_BIT_WIDTH_WAITVAL   7   /* bit��:microwireд�Ͷ�֮��ȴ����� */
#define SPI_CR1_BIT_WIDTH_WAITEN    1   /* bit��:microwireд�Ͷ�֮��ȴ�����ʹ�� */

#define SPI_INT_BIT_TX_FIFO_WATER_LINE (1<<3)   /* ����fifo ˮ���ж� */
#define SPI_INT_BIT_RX_FIFO_WATER_LINE (1<<2)   /* ����fifo ˮ���ж� */
#define SPI_INT_BIT_RX_FIFO_TIME_OUT   (1<<1)   /* ����fifo ��ʱ�ж� */
#define SPI_INT_BIT_RX_FIFO_OVER_FLOW  (1<<0)   /* ����fifo ����ж� */

#define SPI_INT_BIT_RTIC (1<<1)   /* �����ʱ�ж� */
#define SPI_INT_BIT_RORIC (1<<0)  /* �����������ж� */

#define SPI_TX_DMAE (1<<1)  /* ʹ��DMA�ķ���FIFO */
#define SPI_RX_DMAE (1<<0)  /* ʹ��DMA�Ľ���FIFO */

#define SPI_FIFO_LINE_OFFSET    3
#define SPI_FIFO_MAX_VAL        7     /*  ����/����fifo��󳤶� */
#define SPI_FIFO_LINE_MASK      0x7

#define SPI_UNUSE_DATA      0xFFFF      /* ��˫��ģʽ����Ч���ݶ�Ӧ��ƽ */

#define spi_get_transfer_size(burst) (((burst) == DMA_BURST_MSIZE_1) ? 1 : (1 << ((burst) + 1)))

#define MEM_TO_SPI 1
#define SPI_TO_MEM 2

#define SCR_MAX                 255
#define SCR_MIN                 0
#define CPSDVSR_MAX             254
#define CPSDVSR_MIN             4

#define SPI0_FIFO_LEN           256
#define SPI1_FIFO_LEN           64
#define SPI0_FIFO_THRESHOLD     128
#define SPI1_FIFO_THRESHOLD     32

#define SPI_HOST_TIMEOUT_US         1000000
#define SPI_HOST_TIMEOUT_MS         1000

#define SPI_SLAVE_TIMEOUT_US        10000000

#define SPI0_TX_FIFO_WATER_LINE     6
#define SPI0_RX_FIFO_WATER_LINE     6
#define SPI1_TX_FIFO_WATER_LINE     4
#define SPI1_RX_FIFO_WATER_LINE     3

#define SPI0_TX_FIFO_DMA_WLINE_64  7
#define SPI0_RX_FIFO_DMA_WLINE_128 6
#define SPI1_TX_FIFO_DMA_WLINE_16  4
#define SPI1_RX_FIFO_DMA_WLINE_32  4

/* 40 or 24M */
#define SPI_DEFAULT_CLK             160000000
#define spi_max_speed(clk) ((clk) / ((SCR_MIN + 1) * CPSDVSR_MIN))
#define spi_min_speed(clk) ((clk) / ((SCR_MAX + 1) * CPSDVSR_MAX))

#define SPI_WRITE_FLAG   0x1             /* �������� */
#define SPI_READ_FLAG    0x2             /* �������� */


/* spi ���üĴ��� */
#define GPIO_00_SEL 0x604
#define GPIO_01_SEL 0x608
#define GPIO_02_SEL 0x60c
#define GPIO_03_SEL 0x610

#define GPIO_05_SEL 0x618
#define GPIO_06_SEL 0x61c
#define GPIO_07_SEL 0x620
#define GPIO_08_SEL 0x624

#define GPIO_09_SEL 0x628
#define GPIO_10_SEL 0x62c
#define GPIO_11_SEL 0x630
#define GPIO_12_SEL 0x634

/**
 * SPI EVENT����
 */
#define HI_EVENT_BIT_RX_DATA          0x1 /* ��������ͬ��EVENT */
#define HI_EVENT_BIT_TX_DATA          0x2 /* ��������ͬ��EVENT */
#define HI_EVENT_BIT_RX_DATA_TIME_OUT 0x4 /* ��������ͬ��EVENT */
#define HI_EVENT_BIT_RX_FIFO_OVER_FLOW 0x8 /* ��������ͬ��EVENT */

#define HI_EVENT_BIT_DMA_RX_DATA          0x10 /* ��������ͬ��EVENT */
#define HI_EVENT_BIT_DMA_RX_ERR_DATA      0x20 /* ��������ͬ��EVENT */
#define HI_EVENT_BIT_DMA_TX_DATA          0x40 /* ��������ͬ��EVENT */
#define HI_EVENT_BIT_DMA_TX_ERR_DATA      0x80 /* ��������ͬ��EVENT */

typedef enum {
    SPI_OPT_SET_CFG = 0x1,         /* �Ƿ��SPI�������� */
    SPI_OPT_ENABLE_SPI = 0x2,      /* �Ƿ�ʹ��SPI */
    SPI_OPT_DISABLE_SPI = 0x4,     /* �Ƿ�ر�SPI */
    SPI_OPT_TASKED_SIGNAL = 0x8,   /* ��������ź� */
    SPI_OPT_SEND_FIX_DATA = 0x10,  /* ���͹̶����� */
    SPI_OPT_RCV_FIX_DATA = 0x20,   /* ���չ̶����� */
    SPI_OPT_WAIT_SIGNAL = 0x40,    /* �Ƿ�ȴ��ź������� */
    SPI_OPT_FREE_SIGNAL = 0x80,    /* �Ƿ��ͷ��ź��� */
} spi_opt;

/**
 * @ingroup hct_spi
 *
 * ͨ�Ų����������豸��
 */
typedef enum {
    SPI_CFG_ROLE_MASTER, /* ���豸 */
    SPI_CFG_ROLE_SLAVE,  /* ���豸 */
} spi_cfg_role;

/**
 * @ingroup hct_spi
 *
 * ͨ�Ų�����SPI���BUFFER���͡�
 */
typedef enum {
    SPI_DATA_WIDTH_1BYTES = 1,  /* SPIͨ��λ�� HI_SPI_CFG_DATA_WIDTH_E_4BIT��HI_SPI_CFG_DATA_WIDTH_E_8BIT */
    SPI_DATA_WIDTH_2BYTES,      /* SPIͨ��λ�� HI_SPI_CFG_DATA_WIDTH_E_9BIT��HI_SPI_CFG_DATA_WIDTH_E_16BIT */
} spi_data_width;

/**
 * @ingroup hct_spi
 *
 * ͨ�Ų�����SPI0����ˮ�ߣ��ֽڱ�ʾһ�����͵�λ���ǹ̶�8bit��
 */
typedef enum {
    HI_SPI0_TX_FIFO_WATER_LINE_1,   /**< ����ˮ��Ϊ1byte */
    HI_SPI0_TX_FIFO_WATER_LINE_4,   /**< ����ˮ��Ϊ4byte */
    HI_SPI0_TX_FIFO_WATER_LINE_8,   /**< ����ˮ��Ϊ8byte */
    HI_SPI0_TX_FIFO_WATER_LINE_16,  /**< ����ˮ��Ϊ16byte */
    HI_SPI0_TX_FIFO_WATER_LINE_32,  /**< ����ˮ��Ϊ32byte */
    HI_SPI0_TX_FIFO_WATER_LINE_64,  /**< ����ˮ��Ϊ64byte */
    HI_SPI0_TX_FIFO_WATER_LINE_128, /**< ����ˮ��Ϊ128byte */
    HI_SPI0_TX_FIFO_WATER_LINE_192, /**< ����ˮ��Ϊ192byte */
} hi_spi0_tx_fifo_water_line;

/**
 * @ingroup hct_spi
 *
 * ͨ�Ų�����SPI0����ˮ�ߣ��ֽڱ�ʾһ�����͵�λ���ǹ̶�8bit��
 */
typedef enum {
    HI_SPI0_RX_FIFO_WATER_LINE_255, /**< ����ˮ��Ϊ255byte */
    HI_SPI0_RX_FIFO_WATER_LINE_252, /**< ����ˮ��Ϊ252byte */
    HI_SPI0_RX_FIFO_WATER_LINE_248, /**< ����ˮ��Ϊ248byte */
    HI_SPI0_RX_FIFO_WATER_LINE_240, /**< ����ˮ��Ϊ240byte */
    HI_SPI0_RX_FIFO_WATER_LINE_224, /**< ����ˮ��Ϊ224byte */
    HI_SPI0_RX_FIFO_WATER_LINE_192, /**< ����ˮ��Ϊ192byte */
    HI_SPI0_RX_FIFO_WATER_LINE_128, /**< ����ˮ��Ϊ128byte */
    HI_SPI0_RX_FIFO_WATER_LINE_32,  /**< ����ˮ��Ϊ32byte */
} hi_spi0_rx_fifo_water_line;
/**
 * @ingroup hct_spi
 *
 * ͨ�Ų�����SPI1����ˮ�ߣ��ֽڱ�ʾһ�����͵�λ���ǹ̶�8bit��
 */
typedef enum {
    HI_SPI1_TX_FIFO_WATER_LINE_1,  /**< ����ˮ��Ϊ1byte */
    HI_SPI1_TX_FIFO_WATER_LINE_4,  /**< ����ˮ��Ϊ4byte */
    HI_SPI1_TX_FIFO_WATER_LINE_8,  /**< ����ˮ��Ϊ8byte */
    HI_SPI1_TX_FIFO_WATER_LINE_16, /**< ����ˮ��Ϊ16byte */
    HI_SPI1_TX_FIFO_WATER_LINE_32, /**< ����ˮ��Ϊ32byte */
    HI_SPI1_TX_FIFO_WATER_LINE_48, /**< ����ˮ��Ϊ64byte */
    HI_SPI1_TX_FIFO_WATER_LINE_56, /**< ����ˮ��Ϊ56byte */
    HI_SPI1_TX_FIFO_WATER_LINE_64, /**< ����ˮ��Ϊ64byte */
} hi_spi1_tx_fifo_water_line;
/**
 * @ingroup hct_spi
 *
 * ͨ�Ų�����SPI1����ˮ�ߣ��ֽڱ�ʾһ�����͵�λ���ǹ̶�8bit��
 */
typedef enum {
    HI_SPI1_RX_FIFO_WATER_LINE_65, /**< ����ˮ��Ϊ65byte */
    HI_SPI1_RX_FIFO_WATER_LINE_62, /**< ����ˮ��Ϊ62byte */
    HI_SPI1_RX_FIFO_WATER_LINE_48, /**< ����ˮ��Ϊ48byte */
    HI_SPI1_RX_FIFO_WATER_LINE_32, /**< ����ˮ��Ϊ32byte */
    HI_SPI1_RX_FIFO_WATER_LINE_16, /**< ����ˮ��Ϊ16byte */
    HI_SPI1_RX_FIFO_WATER_LINE_8,  /**< ����ˮ��Ϊ8byte */
    HI_SPI1_RX_FIFO_WATER_LINE_4,  /**< ����ˮ��Ϊ4byte */
    HI_SPI1_RX_FIFO_WATER_LINE_1,  /**< ����ˮ��Ϊ1byte */
} hi_spi1_rx_fifo_water_line;

typedef struct {
    hi_u16 cr0;                 /* SPI CR0�Ĵ�������  */
    hi_u16 cr1;                 /* SPI CR1�Ĵ�������  */
    hi_u16 cpsdvsr;             /* SPI CPSR�Ĵ�������  */
} spi_inner_cfg;

typedef struct {
    hi_u16 data_width:4;        /* ����λ��ȡֵ��hi_spi_cfg_data_width  */
    hi_u16 fram_mode:2;         /* ����Э�飬ȡֵ��hi_spi_cfg_fram_mode  */
    hi_u16 cpol:1;              /* ���ԣ�ȡֵ��hi_spi_cfg_clock_cpol  */
    hi_u16 cpha:1;              /* ��λ��ȡֵ��hi_spi_cfg_clock_cpha  */
    hi_u16 scr:8;               /* ʱ���ʣ�����SPIʱ������֮һ  */
    hi_u16 loop_back:1;         /* �Ƿ�Ϊ�ػ�ģʽ  */
    hi_u16 reserver_1:1;        /* ����,SPIʹ��λ  */
    hi_u16 is_slave:1;          /* ����ģʽ  */
    hi_u16 reserver_2:1;
    hi_u16 endian:1;            /* ��С�ˣ�ȡֵ��hi_spi_cfg_endian  */
    hi_u16 reserver_3:11;
    hi_u16 cpsdvsr;             /* ʱ���ʣ�����SPIʱ������֮һ��������2��254֮���ż��  */
    hi_u16 rx_fifo_line;        /* ����ˮ��  */
    hi_u16 tx_fifo_line;        /* ����ˮ��  */
    hi_u16 rx_fifo_dma_line;        /* DMA burstˮ��  */
    hi_u16 tx_fifo_dma_line;        /* DMA burstˮ��  */
    hi_u16 pad;        /* ����ˮ��  */
} spi_hw_cfg;

typedef struct {
    hi_u32 time_out_ms;         /* ���䳬ʱʱ��   */
    hi_u32 trans_opt;
} spi_trans_attr;

typedef struct {
    hi_pvoid buf;               /* ����ָ��  */
    volatile hi_u32 cur_pos;    /* ��ǰ��λ��  */
    volatile hi_u32 cur_cnt;    /* ���ζ�������  */
} spi_buf;

typedef struct {
    hi_u32 reg_base;            /* SPI�Ĵ�������ַ  */
    hi_u32 irq_num;             /* SPI�жϺ�  */
    hi_u32 sem_id;              /* SPI�����ź���  */
    hi_u32 event_id;            /* SPI��дͬ���¼�ID  */
    hi_bool use_dma;            /* ʹ��DMA����  */
    hi_bool use_irq;            /* ʹ���жϴ���  */
    volatile hi_bool transferring;  /* �Ƿ�����  */
    volatile hi_bool disable_later; /* �Ƿ��ӳٹر�  */
    hi_spi_usr_func prepare_func;   /* ����ͨ��ǰ�û�׼������  */
    hi_spi_usr_func restore_func;   /* ����ͨ�ź��û��ָ�����  */
    spi_hw_cfg spi_cfg;
    hi_u32 single_len;          /* ���δ��䳤��, С��FIFO��ȣ���λ��DATA_WIDTH��BYTE���룩  */
    hi_u32 trans_len;           /* ���δ��䳤��, С��FIFO��ȣ���λ��DATA_WIDTH��BYTE���룩  */
    spi_buf tx_buf;
    spi_buf rx_buf;
} spi_ctrl;

HI_EXTERN spi_ctrl *g_spi_ctrl[SPI_NUM];

hi_void spi_isr(spi_ctrl *spi_dev_ctrl);
hi_void spi_isr_enable(hi_u32 reg_base, hi_u16 enable_bits);
hi_void spi_isr_disable(hi_u32 reg_base, hi_u16 disable_bits);
hi_u32 spi_trans_prepare(spi_ctrl *spi_hw_ctrl, spi_trans_attr *trans_attr);
hi_void spi_trans_restore(spi_ctrl *spi_hw_ctrl, const spi_trans_attr *trans_attr);
hi_u32 spi_transfer_8bits_block(const spi_ctrl *spi_hw_ctrl, hi_u32 options);
hi_u32 spi_transfer_16bits_block(const spi_ctrl *spi_hw_ctrl, hi_u32 options);
hi_void spi_set_fifo_line(const spi_ctrl *spi_hw_ctrl);
hi_u32 spi_config(const spi_ctrl *spi_hw_ctrl);
hi_void spi_reset(const spi_ctrl *spi_hw_ctrl);
hi_void spi_disable(spi_ctrl *ctrl);
hi_void spi_flush_fifo(hi_u32 reg_base);

hi_void spi_isr_clear_cr(hi_u32 reg_base, hi_u16 clear_bit);
#ifdef CONFIG_SPI_DMA_SUPPORT
hi_u32 spi_hd_dma_read_fifo(spi_ctrl *spi_dev_ctrl, hi_u32 timeout_ms);
hi_u32 spi_hd_dma_write_fifo(spi_ctrl *spi_dev_ctrl, hi_u32 timeout_ms);
hi_void spi_set_dma_fifo_line(const spi_ctrl *spi_hw_ctrl);
hi_void spi_dma_enable(hi_u32 reg_base, hi_u16 enable_bits);
hi_void spi_dma_disable(hi_u32 reg_base, hi_u16 disable_bits);
#endif

#endif
