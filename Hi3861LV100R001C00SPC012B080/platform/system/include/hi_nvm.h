/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: hi_nvm.h.
 * Author: hisilicon
 * Create: 2019-08-27
 */

#ifndef __HI_NVM_H__
#define __HI_NVM_H__

#include <hi_types.h>

#define HNV_FILE_SIGNATURE               hi_make_identifier('H', 'N', 'V', '$')
#define FNV_FILE_SIGNATURE               hi_make_identifier('F', 'N', 'V', '#')

#define FLASH_BLOCK_SIZE  0x1000
#define HNV_NCRC_SIZE     8                   /* ����crc�ĳ��� */
#define NV_TOTAL_MAX_NUM  255                 /* �����õ�nv������ */
#define HNV_FAULT_TOLERANT_TIMES  3           /* �ݴ���� */

#define HNV_MANAGE_FIXED_LEN  24              /* ��ֹ��reserve */

/* ������NV �ṹ����Ҫ��kernel�±�����ȫһ�£��̶������޸� */
typedef struct _hi_nvm_manage_s_ {
    hi_u32  magic;              /*  nvͷħ���� */
    hi_u32  crc;                /*  nv��������������crc32 ��ver��ֹ��flash_size��β */
    hi_u8   ver;                /*  nv�������ṹ��汾�� */
    hi_u8   head_len;           /*  nvͷ�ĳ��ȣ���magic��ֹ��reserve��β����4�ֽ������� */
    hi_u16  total_num;          /*  nv�ܸ��� */
    hi_u32  seq;                /* дnv��ű�־(������Ȼ�������Լ�������) */
    hi_u32  ver_magic;          /* �汾ħ���֣���kernel�汾ħ����ƥ�� */
    hi_u32  flash_size;         /*  NVռ�õ�FLASH��С����4096(4K)��65536(64K),��ʱδ�ã�������һ */
    hi_u8   keep_id_range[2];   /* ��������id��Χ��0:id�±߽� 1:id�ϱ߽� size 2 */
    hi_u8   reserve[2];         /* size 2 */
    hi_u8   nv_item_data[0];    /* ������ */
} hi_nv_manage;

typedef struct hi_nv_item_index_s_ {
    hi_u8 nv_id;
    hi_u8 nv_len;                /* nvʵ�ʳ��ȣ�����crc32ֵ��crc32�����Ŵ�� */
    hi_u16 nv_offset;            /* ��Ա�nv��ƫ�� */
} hi_nv_item_index;

typedef struct _hi_nv_ctrl_s_ {
    hi_u32 base_addr;
    hi_u32 block_size;
    hi_u32 total_block_size;
    hi_u32 current_addr;         /* �������� */
    hi_u32 seq;
    hi_u32 sem_handle;

    hi_u8 init_flag;
    hi_u8 reserve;
    hi_u16 total_num;         /* nv���� */
    hi_u32 ver_magic;
    hi_nv_item_index* index;
} hi_nv_ctrl;

typedef enum _hi_nv_type_e_ {
    HI_TYPE_NV = 0,
    HI_TYPE_FACTORY_NV,
    HI_TYPE_TEMP,
    HI_TYPE_NV_MAX,
} hi_nv_type;

hi_u32 hi_nv_flush_keep_ids(hi_u8* addr, hi_u32 len);
hi_u32 hi_nv_block_write(hi_u8* nv_file, hi_u32 len, hi_u32 flag);

#endif   /* __HI_NVM_H__ */