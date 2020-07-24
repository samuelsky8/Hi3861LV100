/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: APP common API.
 * Author: wangjian
 * Create: 2019-3-14
 */

/**
* @file dma.h
*
* Copyright (c) Hisilicon Technologies Co., Ltd. 2019. All rights reserved.  \n
*
* Description: DMA interfaces. \n
*/

/** @defgroup hct_dma
 *  @ingroup drivers
 */

#ifndef _DMA_H_
#define _DMA_H_

#include <hi_types_base.h>
#include <hi_dma.h>

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

#ifdef DMA_DEBUG
#define dma_print(fmt...)       \
    do {                        \
        printf(fmt);            \
        printf("\r\n"); \
    } while (0)
#else
#define dma_print(fmt...)
#endif

/* DMA �Ĵ�����ַ */
#define DMA_BASE_ADDR          0x40200000
#define DMA_INT_STAT           (DMA_BASE_ADDR + 0x000)
#define DMA_INT_TC_STAT        (DMA_BASE_ADDR + 0x004)
#define DMA_INT_TC_CLR         (DMA_BASE_ADDR + 0x008)
#define DMA_INT_ERR_STAT       (DMA_BASE_ADDR + 0x00C)
#define DMA_INT_ERR_CLR        (DMA_BASE_ADDR + 0x010)
#define DMA_RAW_INT_TC_STATUS  (DMA_BASE_ADDR + 0x014)
#define DMA_RAW_INT_ERR_STATUS (DMA_BASE_ADDR + 0x018)
#define DMA_ENBLD_CHNS         (DMA_BASE_ADDR + 0x01C)
#define DMA_SOFT_BREQ          (DMA_BASE_ADDR + 0x020)
#define DMA_SOFT_SREQ          (DMA_BASE_ADDR + 0x024)
#define DMA_SOFT_LBREQ         (DMA_BASE_ADDR + 0x028)
#define DMA_SOFT_LSREQ         (DMA_BASE_ADDR + 0x02C)
#define DMA_CFG_REG            (DMA_BASE_ADDR + 0x030)
#define DMA_SYNC               (DMA_BASE_ADDR + 0x034)
/* Source Address Register for Channel x */
#define dma_sar(x) (DMA_BASE_ADDR + 0x100 + (x)*0x020)
/* Destination Address Register for Channel x */
#define dma_dar(x) (DMA_BASE_ADDR + 0x104 + (x)*0x020)
/* Linked List Pointer Register for Channel x */
#define dma_lli(x) (DMA_BASE_ADDR + 0x108 + (x)*0x020)
/* Control Register for Channel x */
#define dma_ctl(x) (DMA_BASE_ADDR + 0x10C + (x)*0x020)
/* Configuration Register for Channel x */
#define dma_cfg(x) (DMA_BASE_ADDR + 0x110 + (x)*0x020)

#define DMA_MASK_INT   0
#define DMA_UNMASK_INT 1

#define DMA_CHANNEL_0 0x01
#define DMA_CHANNEL_1 0x02
#define DMA_CHANNEL_2 0x04
#define DMA_CHANNEL_3 0x08

#define DMA_CHANNEL_NUM_0 0
#define DMA_CHANNEL_NUM_1 1
#define DMA_CHANNEL_NUM_2 2
#define DMA_CHANNEL_NUM_3 3

#define DMA_CHANNEL_NUM 4

#define DMA_DISABLE 0
#define DMA_ENABLE  1

/* ��ַ��������λ���洢���豸�ĵ�ַ����ʱ��Ҫ���������費��Ҫ */
#define DMA_TR_ADDR_INCREMENT 1
#define DMA_TR_ADDR_NOCHANGE  0

#define DMA_WORD_WIDTH 4

/* transfer_size �Ĵ���Ϊ12λ�����֧�ֳ���Ϊ4095 */
#define DMA_TS_MAX 4095
/* Ϊ��֤4�ֽڶ��룬ÿ��BLOCK������Ϊ4092 */
#define DMA_TS_BLOCK 4092

#define DMA_TRANSFER_COMPLETE   0
#define DMA_TRANSFER_INCOMPLETE 1
#define DMA_TRANSFER_ERR        2

#define DMA_TIMEOUT_US 50000

#define dma_pkt_b_to_dma_addr(_virt_addr) ((hi_u32)(_virt_addr) + PKT_B_OFFSET)
#define dma_pkt_h_to_dma_addr(_virt_addr) ((hi_u32)(_virt_addr) + PKT_H_OFFSET)

#define DCACHE_ENABLE 1
#define DCACHE_EN_REG 0x7C1 /* DCACHEʹ�ܼĴ��� */

/**
 * @ingroup hct_dma
 *
 * DMA transfer mode. CNcomment:DMA����ģʽ��CNend
 */
typedef enum {
    DMA_MEM_TO_MEM = 0,
    DMA_MEM_TO_PHL,
    DMA_PHL_TO_MEM,
    DMA_PHL_TO_PHL,
} hi_dma_tr_type;

/**
 * @ingroup hct_dma
 *
 * Peripheral ID that supports DMA transfer. CNcomment:֧��DMA���������ID��CNend
 */
typedef enum {
    UART0_RX = 0,
    UART0_TX,
    UART1_RX,
    UART1_TX,
    UART2_RX,
    UART2_TX,
    SPI0_RX,
    SPI0_TX,
    SPI1_RX,
    SPI1_TX,
    I2S0_RX,
    I2S0_TX,
    PHL_MAX,
} hi_dma_phl;

/**
 * @ingroup hct_dma
 *
 * One DMA burst transmission length. CNcomment:һ��DMA burst���䳤�ȡ�CNend
 */
typedef enum {
    DMA_BURST_MSIZE_1 = 0,
    DMA_BURST_MSIZE_4,
    DMA_BURST_MSIZE_8,
    DMA_BURST_MSIZE_16,
    DMA_BURST_MSIZE_32,
    DMA_BURST_MSIZE_64,
    DMA_BURST_MSIZE_128,
    DMA_BURST_MSIZE_256,
} hi_dma_burst_size;

/* ͨ��ID�Ĵ����ṹ */
typedef union dma_ch_sel {
    struct {
        hi_u32 channel_0 : 1;
        hi_u32 channel_1 : 1;
        hi_u32 channel_2 : 1;
        hi_u32 channel_3 : 1;
        hi_u32 reserved : 28;
    } ch_bit;
    hi_u32 ch_set_u32;
} dma_ch_sel;

/* DMA CFG�Ĵ����ṹ��Ŀǰֻ֧��master1��0:little endianģʽ 1:big endianģʽ */
typedef union dma_init_cfg {
    struct {
        hi_u32 dma_en : 1;
        hi_u32 master1_endianness : 1;
        hi_u32 master2_endianness : 1;
        hi_u32 reserved : 29;
    } dma_cfg_bit;
    hi_u32 dma_cfg_u32;
} dma_init_cfg;

/* DMA CHANNEL CFG�Ĵ����ṹ */
typedef union dma_ch_cfg {
    struct {
        hi_u32 en : 1;             /* ͨ��ʹ�� */
        hi_u32 src_peripheral : 4; /* Դ����ID */
        hi_u32 reserved0 : 1;
        hi_u32 dst_peripheral : 4; /* Ŀ������ID */
        hi_u32 reserved1 : 1;
        hi_u32 flow_cntrl : 3;   /* ����ģʽ����hi_dma_tr_type */
        hi_u32 err_int_mask : 1; /* err �ж�����λ */
        hi_u32 tc_int_mask : 1;  /* tc �ж�����λ */
        hi_u32 lock : 1;
        hi_u32 active : 1;
        hi_u32 halt : 1;
        hi_u32 reserved2 : 13;
    } ch_cfg_bit;
    hi_u32 ch_cfg_u32;
} dma_ch_cfg;

typedef union dma_llp {
    struct {
        hi_u32 lms : 1; /* ������һ���������Master,Ŀǰֻ֧��master1:0 */
        hi_u32 reserved : 1;
        hi_u32 loc : 30; /* ��һ��LLI���ڴ��е���ʼ��ַ��32λ���� */
    } llp_bit;
    hi_u32 llp_u32;
} dma_llp;

typedef struct dma_channel_para dma_channel_para_t;

/**
 * @ingroup dma
 *
 * The channel control register structure of DMA. CNcomment:DMA ͨ�����ƼĴ����ṹ��CNend
 */
typedef struct dma_ch_ctl_t dma_ch_ctl;
typedef union dma_ch_ctl {
    struct {
        hi_u32 transfer_size : 12; /* ���䳤�ȣ����4095����src_widthΪ��λ */
        hi_u32 src_burst_size : 3; /* Դ�豸һ��burst����ĳ��� */
        hi_u32 dst_burst_size : 3; /* Ŀ���豸һ��burst����ĳ��� */
        hi_u32 src_width : 3;      /* Դ�豸����λ��,�ο� hi_dma_data_width */
        hi_u32 dst_width : 3;      /* Ŀ���豸����λ��,�ο� hi_dma_data_width */
        hi_u32 master_src_sel : 1; /* Ŀǰֻ֧��master1:0 */
        hi_u32 master_dst_sel : 1; /* Ŀǰֻ֧��master1:0 */
        hi_u32 src_inc : 1;        /* Դ��ַ�Ƿ����� */
        hi_u32 dst_inc : 1;        /* Ŀ���ַ�Ƿ����� */
        hi_u32 prot : 3;
        hi_u32 lli_tc_int_en : 1; /* ��ǰLLI��㴫�����Ƿ񴥷��ж� */
    } ch_ctl_bit;
    hi_u32 ch_ctl_u32;
} dma_ch_ctl_t;

/**
 * @ingroup dma
 *
 * The link structure of DMA link list item. CNcomment:DMA link list item����ṹ��CNend
 */
typedef struct dma_lli_stru dma_lli_stru_t;
typedef struct dma_lli_stru {
    hi_u32 saddr;             /* LLI���Դ��ַ */
    hi_u32 daddr;             /* LLI���Ŀ���ַ */
    dma_lli_stru_t *llp_next; /* �¸�LLI��� */
    dma_ch_ctl_t st_ctl;      /* LLI��Ӧ��ͨ�����ƼĴ��� */
} dma_lli_stru_t;

typedef struct dma_channel_para {
    dma_llp llp;                  /* ͨ������LLI����ڶ�������ַ */
    dma_ch_ctl_t ch_ctl;            /* ͨ�����ƼĴ��� */
    dma_ch_cfg ch_cfg;            /* ͨ�����üĴ��� */
    hi_void (*cb)(hi_u32);     /* ָ���û�����Ļص����� */
    volatile hi_u32 is_transfering; /* 0��ʾ���ݴ������,1��ʾ�������ڴ��ͣ�2��ʾ������� */
    dma_lli_stru_t *ch_lli;         /* ͨ����link list����ͷ */
} dma_channel_para;

typedef struct dma_data {
    hi_bool is_inited;
    volatile hi_u32 ch_mask;
    dma_channel_para ch_data[DMA_CHANNEL_NUM]; /* 4��ͨ���������� */
} dma_data;

/**
 * @ingroup hct_dma
 *
 * The general setting structure of the user's incoming DMA. It is used for the transmission participated by IO.
 CNcomment:�û�����DMA��ͨ�����ýṹ����Ҫ�����������Ĵ��䡣CNend
 */
typedef struct hi_dma_para {
    hi_u32 tr_type;        /* DMA����ģʽ��ȡֵ��hi_dma_tr_type */
    hi_u32 src_phl;        /* Դ����ID��ȡֵ��hi_dma_phl����Դ�豸�Ǵ洢����Ϊ0 */
    hi_u32 dst_phl;        /* Ŀ������ID��ȡֵ��hi_dma_phl ��Ŀ���豸�Ǵ洢����Ϊ0 */
    uintptr_t src_addr;    /* Դ��ַ��Դ��ַ������Դ�豸�����ȶ��� */
    uintptr_t dst_addr;    /* Ŀ���ַ��Ŀ�ĵ�ַ������Ŀ���豸�Ĵ����ȶ��� */
    hi_u32 src_burst_size; /* Դ�豸һ��burst����ĳ��ȣ�ȡֵ��hi_dma_burst_size_e, ��Ŀ���豸����һ�� */
    hi_u32 dst_burst_size; /* Ŀ���豸һ��burst����ĳ��ȣ�ȡֵ��hi_dma_burst_size_e, ��Դ�豸����һ�� */
    hi_u32 src_width;      /* Դ�豸����λ��,ȡֵ��hi_dma_data_width_e����Ŀ������һ�� */
    hi_u32 dst_width;      /* Ŀ���豸����λ��,ȡֵ��hi_dma_data_width_e����Դ����һ�� */
    hi_u32 transfer_size;  /* ���䳤�ȣ���Դ�豸����λ��Ϊ��λ��������봫��ʱ����burst_size������ */
    hi_void (*cb)(hi_u32);  /* ��������ص�������Ϊ������ɻ������ #DMA_INT_XXX */
} hi_dma_para;

/**
* @ingroup  hct_dma
* @brief  Start dma transmission. CNcomment:����dma���䡣CNend
*
* @par ����:
*           Start dma transmission and channel will be released after success or failure.
CNcomment:����dma���䣬�ɹ���ʧ�ܺ���ͷ�ͨ����CNend
*
* @attention
* @param  dma_para         [IN/OUT] type #hi_dma_user_para_s�sSetting incoming dma transfer parameter.
CNcomment:����DMA����������á�CNend
* @param  block            [IN]     type #hi_bool��Whether to block for waiting dma tranmission completeness
CNcomment:�Ƿ������ȴ�DMA������ɡ�CNend
*
* @retval #HI_ERR_SUCCESS  Success.
* @retval #Other           Failure. For details, see hi_errno.h.
* @par ����:
*            @li hi_dma.h��   DMA driver implementation interface.  CNcomment:DMA����ʵ�ֽӿڡ�CNend
* @see  None
* @since Hi3861_V100R001C00
 */
hi_u32 hi_dma_transfer(const hi_dma_para *dma_para, hi_bool block);
/**
* @ingroup  hct_dma
* @brief  Start dma transmission. CNcomment:����dma���䡣CNend
*
* @par ����:
*           Start dma transmission and channel will be released after success or failure.
CNcomment:����dma���䣬�ɹ���ʧ�ܺ���ͷ�ͨ����CNend
*
* @attention
* @param  dma_para         [IN/OUT] type #hi_dma_user_para_s�sSetting incoming dma transfer parameter.
CNcomment:����DMA����������á�CNend
* @param  dma_ch            [IN]     type #hi_bool��return dma channel number
CNcomment:���������ͨ���š�CNend
*
* @retval #HI_ERR_SUCCESS  Success.
* @retval #Other           Failure. For details, see hi_errno.h.
* @par ����:
*            @li hi_dma.h��   DMA driver implementation interface.  CNcomment:DMA����ʵ�ֽӿڡ�CNend
* @see  None
* @since Hi3861_V100R001C00
 */
hi_u32 dma_hw_request_transfer(const hi_dma_para *dma_para, hi_u32 *dma_ch);
void dma_write_data(hi_u32 ch_num, const hi_dma_para *dma_para);
#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif

#endif
