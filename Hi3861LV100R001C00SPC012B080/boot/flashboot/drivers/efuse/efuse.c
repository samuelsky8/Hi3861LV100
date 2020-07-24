/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: efuse sdk interface implementation.
 * Author: wangjun
 * Create: 2019-05-08
 */

#include "efuse.h"
#include "efuse_drv.h"

hi_u32 efuse_start_addr_unaligned_read(hi_u16 start_bit, hi_u16 size, hi_u8 diff_head_read, hi_u8 *data)
{
    hi_u32 ret = HI_ERR_FAILURE;
    hi_u32 check_sum;

    /* ����3886 Efuse�Ų�����ʼ��ַ��8bit���룬�������ʵ�ʶ�ȡsizeֻ����Ϊ����ֵ(8/16/24/72) */
    if (size == SIZE_8_BITS) {
        ret = efuse_read_bits(start_bit, size, data);
        if (ret == HI_ERR_SUCCESS) {
            data[0] = data[0] >> diff_head_read;
        }
    } else if (size == SIZE_16_BITS) {
        hi_u16 tmp_data = 0;
        ret = efuse_read_bits(start_bit, size, (hi_u8 *)&tmp_data);
        if (ret == HI_ERR_SUCCESS) {
            tmp_data = tmp_data >> diff_head_read;
            if (start_bit == 0xE0) {
                *data = (hi_u8)(tmp_data & 0xFF);
            } else {
                *(hi_u16 *)data = tmp_data;
            }
        }
    } else if (size == SIZE_24_BITS) {
        hi_u32 tmp_data = 0;
        ret = efuse_read_bits(start_bit, SIZE_24_BITS, (hi_u8 *)&tmp_data);
        if (ret == HI_ERR_SUCCESS) {
            tmp_data = tmp_data >> diff_head_read;
            check_sum = (uintptr_t)data ^ DATA_LENGTH ^ (uintptr_t)(hi_u8 *)&tmp_data ^ DATA_LENGTH;
            if (memcpy_s(data, DATA_LENGTH, (hi_u8 *)&tmp_data, DATA_LENGTH, check_sum) != EOK) {
                return HI_ERR_FAILURE;
            }
        }
    } else if (size == SIZE_72_BITS) {
        hi_u8 tmp_data[SIZE_72_BITS / SIZE_8_BITS] = { 0 };
        hi_u32 data_u32[2]; /* U64 is divided into 2 U32 */
        hi_u8 end_u8;
        ret = efuse_read_bits(start_bit, SIZE_72_BITS, &tmp_data[0]);
        if (ret == HI_ERR_SUCCESS) {
            data_u32[0] = *(hi_u32 *)&tmp_data[0];  /* first U32 offset is 0 */
            data_u32[1] = *(hi_u32 *)&tmp_data[4];  /* sencond U32 offset is 4 */
            end_u8 = *(hi_u8 *)&tmp_data[8]; /* the last u8 bit */
            /* ������һ��U32����ĵ�λ(diff_head_readλ) */
            data_u32[0] = data_u32[0] >> diff_head_read;
            data_u32[0] = data_u32[0] | (data_u32[1] << (SIZE_32_BITS - diff_head_read));
            data_u32[1] = data_u32[1] >> diff_head_read;
            /* ȡ�ڶ���char�ĵ�λ����Ϊ�ڶ���U32�ĸ�λ(diff_head_readλ) */
            data_u32[1] = data_u32[1] | ((hi_u32)end_u8 << (SIZE_32_BITS - diff_head_read));
            *(hi_u64 *)data = (((hi_u64)data_u32[1] << SIZE_32_BITS) | data_u32[0]);
        }
    }
    return ret;
}

hi_u32 efuse_bits_read(hi_u16 start_bit, hi_u16 size, hi_u8 *data, hi_u32 data_len)
{
    hi_u8 diff_head_read = 0;
    hi_u32 origine_size;
    hi_u32 ret;
    if (data_len > EFUSE_MAX_INDEX_SIZE) {
        return HI_ERR_FAILURE;
    }

    origine_size = size;
    if ((start_bit & 0x7) != 0x0) {
        diff_head_read = start_bit % SIZE_8_BITS;
        start_bit = start_bit - diff_head_read; /* оƬҪ�� ��ʼ��ַ8bit�����ȡ */
        size = size + diff_head_read;
    }

    if ((size & 0x7) != 0x0) {
        size = ((size >> THREE_BITS_OFFSET) + 1) << THREE_BITS_OFFSET; /* оƬҪ�� 8bitΪ��λ��ȡ */
    }

    if (diff_head_read == 0) {
        /* ��ʼ��ַ8bit���� */
        ret = efuse_read_bits(start_bit, size, data);
        if (ret != HI_ERR_SUCCESS) {
            return ret;
        }
    } else {
        /* ��ʼ��ַ��8bit���� */
        ret = efuse_start_addr_unaligned_read(start_bit, size, diff_head_read, data);
        if (ret != HI_ERR_SUCCESS) {
            return ret;
        }
    }

    if (origine_size <= SIZE_8_BITS) {
        *data &= ((1 << origine_size) - 1);
    } else if (origine_size <= SIZE_16_BITS) {
        *(hi_u16 *)data &= ((1 << origine_size) - 1);
    } else if (origine_size < SIZE_32_BITS) {
        *(hi_u32 *)data &= (((hi_u32)1 << origine_size) - 1);
    }

    return HI_ERR_SUCCESS;
}

/*****************************************************************************
* ��������: hi_efuse_read
* ��������: ����������ID ��ȡefuse�ռ�����.
*
* ����˵��:
* efuse_id: efuse ����ID.
* data: ��Ŵ���ȡefuseֵ�ĵ�ַ
* data_len: ��data����Ŀռ䣬��λbyte; (data_len*8)����С��efuse_id��Ӧefuse�ֶεĳ�������8bits ���롣
*
* �� �� ֵ:
* HI_ERR_SUCCESS:�ɹ�
* ���� : ʧ��
*
* ����Ҫ��:��
* 1.���ȵ���hi_get_efuse_cfg_by_id ��ȡ���򳤶ȡ�
* 2.���ݳ�������ȡ����ȡ��ȡ�ռ䡣
* 3.���ñ��ӿڡ�
*****************************************************************************/
hi_u32 hi_efuse_read(hi_efuse_idx efuse_id, hi_u8 *data, hi_u8 data_len)
{
    hi_u16 start_bit = 0;
    hi_u16 size = 0;
    hi_u16 align_size;
    hi_u8 flag = EFUSE_IDX_NRW;

    if (efuse_id >= HI_EFUSE_IDX_MAX || data == HI_NULL) {
        return HI_ERR_EFUSE_INVALIDATE_PARA;
    }

    get_efuse_cfg_by_id(efuse_id, &start_bit, &size, &flag);

    if (flag == EFUSE_IDX_WO) {
        return HI_ERR_EFUSE_INVALIDATE_AUTH;
    }

    align_size = ((size & 0x7) != 0x0) ? (((size >> THREE_BITS_OFFSET) + 1) << THREE_BITS_OFFSET) : size;

    if (align_size > ((hi_u16)data_len * EIGHT_BITS)) {
        return HI_ERR_EFUSE_INVALIDATE_PARA;
    }

    return efuse_bits_read(start_bit, size, data, data_len);
}

/*****************************************************************************
* ��������: hi_efuse_write
* ��������: ����������ID д��efuse�ռ�����.
*
* ����˵��:
* efuse_id: efuse ����ID.
* data: ������efuse��д�������.
*
* �� �� ֵ:
* HI_ERR_SUCCESS:�ɹ�
* ���� : ʧ��
******************************************************************************/
hi_u32 hi_efuse_write(hi_efuse_idx efuse_id, const hi_u8 *data)
{
    hi_u16 start_bit = 0;
    hi_u16 size = 0;
    hi_u8 flag = EFUSE_IDX_NRW;
    hi_char err_state[EFUSE_MAX_INDEX_SIZE] = {
        0,
    };
    hi_u32 i;
    hi_u32 ret;

    if (efuse_id >= HI_EFUSE_IDX_MAX || data == HI_NULL) {
        boot_msg1("parameter err !", efuse_id);
        return HI_ERR_EFUSE_INVALIDATE_PARA;
    }

    get_efuse_cfg_by_id(efuse_id, &start_bit, &size, &flag);
    if (flag == EFUSE_IDX_RO) {
        boot_msg1("This section can not be write !flag = ", flag);
        return HI_ERR_EFUSE_INVALIDATE_AUTH;
    }

    ret = efuse_write_bits(start_bit, size, data, (hi_u8 *)&err_state[0]);
    if (ret != HI_ERR_SUCCESS) {
        boot_msg0("efuse write err");
        return ret;
    }

    for (i = 0; i < EFUSE_MAX_INDEX_SIZE; i++) {
        if (err_state[i]) {
            boot_msg1("errstate num is", i);
            return HI_ERR_EFUSE_WRITE_ERR;
        }
    }

    return HI_ERR_SUCCESS;
}

/*****************************************************************************
* ��������: hi_efuse_lock
* ��������: ����������ID ����efuseĳ����.
*
* ����˵��:
* lock_id: ����efuse ����ID.
*
* �� �� ֵ:
* HI_ERR_SUCCESS:�ɹ�
* ���� : ʧ��
*****************************************************************************/
hi_u32 hi_efuse_lock(hi_efuse_lock_id lock_id)
{
    hi_u16 err_stat = 0;
    hi_u32 ret;
    hi_u16 start_bit = 0;
    hi_u8 lock_val = 1;

    if (lock_id >= HI_EFUSE_LOCK_MAX) {
        return HI_ERR_EFUSE_INVALIDATE_ID;
    }

    if (lock_id < HI_EFUSE_LOCK_FLASH_ENCPY_CNT3_ID) {
        start_bit = EFUSE_LOCK_START_BITS + lock_id;
    } else {
        start_bit = EFUSE_LOCK_FIELD2_START_BITS + lock_id - HI_EFUSE_LOCK_FLASH_ENCPY_CNT3_ID;
    }

    ret = efuse_write_bits(start_bit, 1, &lock_val, (hi_u8 *)&err_stat);
    if ((ret == HI_ERR_SUCCESS) && (err_stat == 0)) {
        return HI_ERR_SUCCESS;
    } else if (err_stat != 0) {
        return HI_ERR_EFUSE_WRITE_ERR;
    }

    return ret;
}

/*****************************************************************************
* ��������: hi_efuse_get_lockstat
* ��������: ��ȡefuse����״̬.
*
* ����˵��:
* lock_stat: ���ص�����״̬����ָ�룬����ǰEFUSE_LOCK_SIZE��Ч.
*
* �� �� ֵ:
* HI_ERR_SUCCESS:�ɹ�
* ���� : ʧ��
*****************************************************************************/
hi_u32 hi_efuse_get_lockstat(hi_u64 *lock_stat)
{
    hi_u16 start_bit = EFUSE_LOCK_START_BITS;
    hi_u16 size = EFUSE_LOCK_SIZE;
    hi_u8 diff_head_read;
    hi_u64 tmp_data = 0;
    hi_u64 tmp_data_filed_two = 0;
    hi_u32 ret;

    if (lock_stat == HI_NULL) {
        return HI_ERR_FAILURE;
    }

    /* start address and size 8 bits align. */
    diff_head_read = start_bit % EIGHT_BITS;
    start_bit = start_bit - diff_head_read;
    size = size + diff_head_read;

    ret = efuse_read_bits(start_bit, size, (hi_u8 *)&tmp_data);
    if (ret == HI_ERR_SUCCESS) {
        tmp_data = tmp_data >> diff_head_read;
    } else {
        return HI_ERR_FAILURE;
    }

    start_bit = EFUSE_LOCK_FIELD2_START_BITS;
    size = EFUSE_LOCK_FIELD2_SIZE;

    /* start address and size 8 bits align. */
    diff_head_read = start_bit % EIGHT_BITS;
    start_bit = start_bit - diff_head_read;
    size = size + diff_head_read;

    ret = efuse_read_bits(start_bit, size, (hi_u8 *)&tmp_data_filed_two);
    if (ret == HI_ERR_SUCCESS) {
        tmp_data_filed_two = tmp_data_filed_two >> diff_head_read;
    } else {
        return HI_ERR_FAILURE;
    }

    *lock_stat = (((tmp_data_filed_two << EFUSE_LOCK_SIZE) & 0x1F000000000) | (tmp_data & 0xFFFFFFFFF));

    return HI_ERR_SUCCESS;
}

/*****************************************************************************
* ��������: hi_efuse_usr_read
* ��������: ͨ��efuse bit��ȡ�ӿڣ���ʼ��ַ�ͳ�����Ҫ8bit����.
*
* ����˵��:
* start_bit: efuse��ʼbitλ.
* size: ����ȡ��bitλ����������벻��8bit���������ڲ��ᴦ��Ϊ8bit���룬�û���ȡ���ݺ��账���ʹ�á�
* key_data: ��ȡ�������ݴ���ڴ��ַ.
*
* �� �� ֵ:
* HI_ERR_SUCCESS:�ɹ�
* ���� : ʧ��
******************************************************************************/
hi_u32 hi_efuse_usr_read(hi_u16 start_bit, hi_u16 size, hi_u8 *key_data)
{
    hi_u16 real_size = size;

    if ((start_bit >= EFUSE_PGM_ADDR_SIZE) || ((start_bit & 0x7) != 0) || (key_data == HI_NULL) || (size == 0)) {
        return HI_ERR_FAILURE;
    }

    /* оƬҪ�� 8bitΪ��λ��ȡ */
    if ((size & 0x7) != 0x0) {
        real_size = ((size >> 3) + 1) << 3; /* right shift 3bit;add;then left shift 3bit */
    }

    if ((start_bit + real_size) > EFUSE_PGM_ADDR_SIZE) {
        return HI_ERR_FAILURE;
    }

    return efuse_read_bits(start_bit, real_size, key_data);
}

/******************************************************************************
* ��������: hi_efuse_usr_write
* ��������: ͨ��eufse bitд��ӿڣ����д��32���ֽڣ���256bit.
*
* ����˵��:
* start_bit: efuse��ʼbitλ.
* size: �û�д�����ݳ��ȣ���λΪbit.
* key_data: ��д������ݷŵ��õ�ַ���Ϊ32byte��
*
* �� �� ֵ:
* ���� : ʧ��
* HI_ERR_SUCCESS:�ɹ�
*****************************************************************************/
hi_u32 hi_efuse_usr_write(hi_u16 start_bit, hi_u16 size, const hi_u8 *key_data)
{
    hi_u8 usr_err_stat[EFUSE_MAX_INDEX_SIZE];
    hi_u32 i;
    hi_u32 ret;

    if (size > (EFUSE_MAX_INDEX_SIZE * SIZE_8_BITS) || key_data == HI_NULL || size == 0) {
        return HI_ERR_FAILURE;
    }
    hi_u32 check_sum = (uintptr_t)usr_err_stat ^ EFUSE_MAX_INDEX_SIZE ^ 0 ^ EFUSE_MAX_INDEX_SIZE;
    memset_s(usr_err_stat, EFUSE_MAX_INDEX_SIZE, 0, EFUSE_MAX_INDEX_SIZE, check_sum);

    ret = efuse_write_bits(start_bit, size, key_data, (hi_u8 *)&usr_err_stat[0]);
    if (ret != HI_ERR_SUCCESS) {
        return ret;
    }

    for (i = 0; i < EFUSE_MAX_INDEX_SIZE; i++) {
        if (usr_err_stat[i]) {
            return HI_ERR_FAILURE;
        }
    }

    return HI_ERR_SUCCESS;
}

