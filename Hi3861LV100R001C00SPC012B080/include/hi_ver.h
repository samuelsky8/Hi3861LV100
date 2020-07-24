/**
* @file hi_ver.h
*
* Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2019. All rights reserved. \n
* Description: Soft ver interfaces. \n
* Author: Hisilicon \n
* Create: 2019-03-04
*/

/** @defgroup iot_ver Soft ver
 * @ingroup system
 */

#ifndef __HI_VER_H__
#define __HI_VER_H__
#include <hi_types.h>
#ifdef __cplusplus
extern "C" {
#endif

/**
* @ingroup  iot_ver
* @brief  Obtains SDK version information. CNcomment:��ȡSDK�汾��ϢCNend
*
* @par ����:
*         Obtains SDK version information. CNcomment:��ȡSDK�汾��ϢCNend
* @attention None
* @retval #hi_char*     SDK version information string. CNcomment:SDK�汾��Ϣ�ַ���CNend
*
* @par Dependency:
*      @li hi_ver.h: This file describes version information APIs.CNcomment:�ļ���������ϵͳ��ؽӿ�.CNend
* @see  None
* @since Hi3861_V100R001C00
*/
const hi_char *hi_get_sdk_version(hi_void);

/**
* @ingroup  iot_ver
* @brief  Obtains boot version in secure boot mode. CNcomment:��ȫ����ģʽ�£���ȡBOOT�汾��CNend
*
* @par ����:
*         Obtains boot version in secure boot mode. CNcomment:��ȫ����ģʽ�£���ȡBOOT�汾��CNend
* @attention Ver always be 0 in non-secure boot mode. CNcomment: �ǰ�ȫ����ģʽ�£��ð汾��ʼ��Ϊ0��CNend
* @retval #hi_u8     boot ver num, value from 0-16, Return 0xFF means get boot ver fail.
CNcomment:boot�汾�ţ���ЧֵΪ0-16������0xFF��ʾ��ȡBOOT�汾��ʧ��CNend
* @par Dependency:
*      @li hi_ver.h: This file describes version information APIs.CNcomment:�ļ���������ϵͳ��ؽӿ�.CNend
* @see  None
* @since Hi3861_V100R001C00
*/
hi_u8 hi_get_boot_ver(hi_void);

/**
* @ingroup  iot_ver
* @brief  Obtains kernel version in secure boot mode. CNcomment:��ȫ����ģʽ�£���ȡkernel�汾��CNend
*
* @par ����:
*         Obtains kernel version in secure boot mode. CNcomment:��ȫ����ģʽ�£���ȡkernel�汾��CNend
* @attention Ver always be 0 in non-secure boot mode. CNcomment:�ǰ�ȫ����ģʽ�£��ð汾��ʼ��Ϊ0��CNend
* @retval #hi_u8     kernel ver num, value from 0-48, Return 0xFF means get kernel ver fail.
CNcomment:kernel�汾�ţ���ЧֵΪ0-48������0xFF��ʾ��ȡkernel�汾��ʧ��CNend
*
* @par Dependency:
*      @li hi_ver.h: This file describes version information APIs.CNcomment:�ļ���������ϵͳ��ؽӿ�.CNend
* @see  None
* @since Hi3861_V100R001C00
*/
hi_u8 hi_get_kernel_ver(hi_void);

#ifdef __cplusplus
}
#endif
#endif
