/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: header file of efuse driver.
 * Author: wangjun
 * Create: 2019-05-08
 */

#ifndef __EFUSE_DRV_H__
#define __EFUSE_DRV_H__
#include <hi_boot_rom.h>

typedef struct {
    hi_u16 id_start_bit;    /* ��ʼ bitλ */
    hi_u16 id_size;         /* ��bitΪ��λ */
    hi_u8 attr;             /* 0x0:���ɶ�д��0x1:ֻ����0x2:ֻд��0x3:�ɶ���д */
} hi_efuse_stru;

#define EFUSE_PGM_EN   (HI_EFUSE_REG_BASE + 0x0)
#define EFUSE_PGM_ADDR (HI_EFUSE_REG_BASE + 0x4)
#define EFUSE_RD_EN    (HI_EFUSE_REG_BASE + 0x8)
#define EFUSE_RD_ADDR  (HI_EFUSE_REG_BASE + 0xc)
#define EFUSE_STATUS   (HI_EFUSE_REG_BASE + 0x10)
#define EFUSE_RDATA    (HI_EFUSE_REG_BASE + 0x14)

#define EFUSE_WRITE_READY_STATUS (1 << 0) /* д���״̬��1��ʾ��� */
#define EFUSE_READ_READY_STATUS  (1 << 1) /* �����״̬��1��ʾ��� */
#define EFUSE_STATUS_MASK        (0x7 << 2)
#define EFUSE_PO_STATUS_READY    (0x1 << 2) /* �ϵ��Ķ������Ƿ������1��ʾ��� */
#define EFUSE_STATUS_READY       (0x1 << 4) /* æ��״̬��0��ʾ���� */

#define EFUSE_CTRL_ST   (0x1 << 5)
#define EFUSE_EN_SWITCH (1 << 0)
#define EFUSE_EN_OK     0

#define EFUSE_STATUS_RD    (1 << 1)
#define EFUSE_8_BIT        8
#define EFUSE_KEY_LOCK_BIT 2

#define EFUSE_TIMEOUT_DEFAULT 1000000 /* 1�� */
#define EFUSE_TIMECNT_TICK    10      /* ������Ա�EFUSE_TIMEOUT_DEFAULT���� */

#define EFUSE_PGM_ADDR_SIZE          2048 /* ��λΪbit */
#define EFUSE_USER_RESEVED_START_BIT 1884 /* �û�������������ʼbit */
#define EFUSE_USER_RESEVED_END_BIT   2011 /* �û���������������bit */
#define EFUSE_LOCK_START_BITS        2012 /* ��һ��������ʼbit */
#define EFUSE_LOCK_FIELD2_START_BITS 235  /* �ڶ���������ʼbit */
#define EFUSE_LOCK_SIZE              36   /* ��һ��������������bitλ�� */
#define EFUSE_LOCK_FIELD2_SIZE       5    /* �ڶ���������������bitλ�� */
#define EFUSE_MAX_INDEX_SIZE         32   /* ���д���efuse���ݳ���(��λ�ֽ�) */

#define EFUSE_IDX_NRW 0x0 /* ���ɶ�д */
#define EFUSE_IDX_RO  0x1 /* ֻ�� */
#define EFUSE_IDX_WO  0x2 /* ֻд */
#define EFUSE_IDX_RW  0x3 /* �ɶ���д */

hi_efuse_stru *get_efuse_cfg(hi_void);
hi_void get_efuse_cfg_by_id(hi_efuse_idx idx, hi_u16 *start_bit, hi_u16 *size, hi_u8 *attr);
hi_u32 efuse_read_bits(hi_u16 start_bit, hi_u16 size, hi_u8 *key_data);
hi_u32 efuse_write_bits(hi_u16 start_bit, hi_u16 size, const hi_u8 *key_data, hi_u8 *err_state);

#endif /* __EFUSE_H__ */

