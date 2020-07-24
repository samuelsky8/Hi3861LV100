/**
* @file hi_atomic.h
*
* Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2019. All rights reserved.  \n
* Description: Atomic operation APIs. \n
* Author: Hisilicon \n
* Create: 2019-05-29
*/

/**
 * @defgroup iot_atomic  Atomic Operation
 * @ingroup osa
 */
#ifndef __HI_ATOMIC_H__
#define __HI_ATOMIC_H__
#include <hi_types.h>
#include <los_hwi.h>

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

typedef struct {
    volatile hi_s32 counter;
} hi_atomic;

#define hi_atomic_init(i)            { (i) }
#define hi_atomic_read(v)            ((v)->counter)
#define hi_atomic_set(v, i)          (((v)->counter) = (i))

#define hi_atomic_inc(v)             hi_atomic_add_return(1, v)
#define hi_atomic_dec(v)             hi_atomic_sub_return(1, v)

#define hi_atomic_inc_return(v)      (hi_atomic_add_return(1, v))
#define hi_atomic_dec_return(v)      (hi_atomic_sub_return(1, v))

/**
 * @ingroup  iot_atomic
 * If the atomic operation is performed, the operation result is returned.
CNcomment:ԭ�ӼӲ��������ز������CNend
 */
#define hi_atomic_add_return_op(i, v)   (hi_atomic_add_return(i, v))

/**
 * @ingroup  iot_atomic
 * The operation result is returned when the atomic subtraction operation is performed.
CNcomment:ԭ�Ӽ����������ز������CNend
 */
#define hi_atomic_sub_return_op(i, v)   (hi_atomic_sub_return(i, v))

/**
 * @ingroup  iot_atomic
 * The specified bit in the atomic setting variable is 1.
CNcomment:ԭ�����ñ�����ָ��bitλΪ1CNend
 */
#define hi_atomic_bit_set_op(bit, v)    (hi_atomic_bit_set(bit, v))
/**
 * @ingroup  iot_atomic
 * The specified bit in the atomic setting variable is 0.
CNcomment:ԭ�����ñ�����ָ��bitλΪ0CNend
 */
#define hi_atomic_bit_clear_op(bit, v)  (hi_atomic_bit_clear(bit, v))

/*
* If the atomic operation is performed, the operation result is returned.
CNcomment:ԭ�ӼӲ��������ز������CNend
*
* ����:
*          If the atomic operation is performed, the operation result is returned.
CNcomment:ԭ�ӼӲ��������ز������CNend
*
* param  i     [IN] type #hi_s32�� The number of operands added to an atom.CNcomment:��ԭ����ӵĲ�����CNend
* param  v     [IN] type #hi_atomic*��Pointer to the atomic structure address.CNcomment:ԭ�ӽṹ��ַָ��CNend
*
* retval #hi_s32 Add Operation Result.CNcomment:�Ӳ������CNend
* par ����:
*           hi_atomic.h��Header file where the interface declaration is located.
CNcomment:�ýӿ��������ڵ�ͷ�ļ���CNend
*/
__attribute__((always_inline)) static inline hi_s32 hi_atomic_add_return(hi_s32 i, hi_atomic *v)
{
    hi_u32 irq_status;

    irq_status = LOS_IntLock();
    v->counter += i;
    (hi_void)LOS_IntRestore(irq_status);
    return v->counter;
}

/*
* The operation result is returned when the atomic subtraction operation is performed.
CNcomment:ԭ�Ӽ����������ز������CNend
*
* ����:
*          The operation result is returned when the atomic subtraction operation is performed.
CNcomment:ԭ�Ӽ����������ز������CNend
*
* param  i     [IN] type #hi_s32�� The number of operands subtracted from the atom.
CNcomment:��ԭ������Ĳ�����CNend
* param  v     [IN] type #hi_atomic*��Pointer to the atomic structure address.CNcomment:ԭ�ӽṹ��ַָ��CNend
*
* retval #hi_s32 Reduce the operation result. CNcomment:���������CNend
* par ����:
*           hi_atomic.h��Header file where the interface declaration is located.
CNcomment:�ýӿ��������ڵ�ͷ�ļ���CNend
*/
__attribute__((always_inline)) static inline hi_s32 hi_atomic_sub_return(hi_s32 i, hi_atomic *v)
{
    hi_u32 irq_status;

    irq_status = LOS_IntLock();
    v->counter = v->counter - i;
    (hi_void)LOS_IntRestore(irq_status);

    return v->counter;
}

/*
* The specified bit in the atomic setting variable is 1.CNcomment:ԭ�����ñ�����ָ��bitλΪ1CNend
*
* ����:
*          The specified bit in the atomic setting variable is 1.CNcomment:ԭ�����ñ�����ָ��bitλΪ1CNend
*
* param  bit     [IN] type #hi_s32�� Position of the bit that is set to 1. The value range is 0-31.
CNcomment:����1��bitλ�ã���Χ0-31.CNend
* param  value   [IN] type #hi_u32*��Address pointer of the set variable.CNcomment:��λ�����ĵ�ַָ��CNend
*
* retval #None
* par ����:
*           hi_atomic.h��Header file where the interface declaration is located.
CNcomment:�ýӿ��������ڵ�ͷ�ļ���CNend
*/
__attribute__((always_inline)) static inline hi_void hi_atomic_bit_set(hi_s32 bit, volatile hi_u32 *value)
{
    hi_u32 irq_status;
    irq_status = LOS_IntLock();

    *value |= (1 << bit);

    (hi_void)LOS_IntRestore(irq_status);
}

/*
* The specified bit in the atomic setting variable is 0.CNcomment:ԭ�����ñ�����ָ��bitλΪ0CNend
*
* ����:
*          The specified bit in the atomic setting variable is 0.CNcomment:ԭ�����ñ�����ָ��bitλΪ0CNend
*
* param  bit     [IN] type #hi_s32�� Position of the bit that is set to 0. The value range is 0-31.
CNcomment:����0��bitλ�ã���Χ0-31.CNend
* param  value   [IN] type #hi_u32*��Address pointer of the set variable.CNcomment:��λ�����ĵ�ַָ��CNend
*
* retval #None
* par ����:
*           hi_atomic.h��Header file where the interface declaration is located.
CNcomment:�ýӿ��������ڵ�ͷ�ļ���CNend
*/
__attribute__((always_inline)) static inline hi_void hi_atomic_bit_clear(hi_s32 bit, volatile hi_u32 *value)
{
    hi_u32 irq_status;
    hi_u32 mask;

    irq_status = LOS_IntLock();
    mask = 1 << bit;
    *value = (*value) & (~mask);

    (hi_void)LOS_IntRestore(irq_status);
}

#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif

#endif /* end of hi_atomic.h */

