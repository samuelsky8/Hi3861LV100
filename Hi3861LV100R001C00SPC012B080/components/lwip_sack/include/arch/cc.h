/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2013-2016. All rights reserved.
 * Description: define system adaptor unit
 * Author: none
 * Create: 2013
 */

#ifndef __CC_H__
#define __CC_H__

#include "los_typedef.h"
#include <sys/time.h>
#ifdef LWIP_DEBUG
#include "stdio.h"
#endif

#if defined (__cplusplus) && __cplusplus
extern "C" {
#endif /* __cplusplus */

#define LWIP_TIMEVAL_PRIVATE 0
#define LWIP_NO_INTTYPES_H 1
#define LWIP_MAX_VALUE 0xFFFFFFFF

/* Define (sn)printf formatters for these lwIP types */
#define X8_F "02x"
#define U8_F "hhu"
#define U16_F "hu"
#define S16_F "hd"
#define X16_F "hx"
#define U32_F "u"
#define S32_F "d"
#define X32_F "x"
#define SZT_F "uz"

/* ARM/LPC17xx is little endian only */
#ifdef BYTE_ORDER
#undef BYTE_ORDER
#endif
#define BYTE_ORDER LITTLE_ENDIAN

/* Use LWIP error codes */
#if defined(__arm__) && defined(__ARMCC_VERSION)
/* Keil uVision4 tools */
#define PACK_STRUCT_BEGIN __packed
#define PACK_STRUCT_STRUCT
#define PACK_STRUCT_END
#define PACK_STRUCT_FIELD(fld) fld
#define ALIGNED(n)  __align(n)
#elif defined (__IAR_SYSTEMS_ICC__)
/* IAR Embedded Workbench tools */
#define PACK_STRUCT_BEGIN __packed
#define PACK_STRUCT_STRUCT
#define PACK_STRUCT_END
#define PACK_STRUCT_FIELD(fld) fld
#error NEEDS ALIGNED
#else
/* GCC tools (CodeSourcery) */
#define PACK_STRUCT_BEGIN
#define PACK_STRUCT_STRUCT __attribute__ ((__packed__))
#define PACK_STRUCT_END
#define PACK_STRUCT_FIELD(fld) fld
#define ALIGNED(n)  __attribute__((aligned (n)))
#endif

/* Provide Thumb-2 routines for GCC to improve performance */
#if defined(TOOLCHAIN_GCC) && defined(__thumb2__)
#define LWIP_CHKSUM             thumb2_checksum
/*
 * Set algorithm to 0 so that unused lwip_standard_chksum function
 * doesn't generate compiler warning
 */
#define LWIP_CHKSUM_ALGORITHM   0

void *thumb2_memcpy(void *pDest, const void *pSource, size_t length);
u16_t thumb2_checksum(void *pData, int length);
#else
/* Used with IP headers only */
#define LWIP_CHKSUM_ALGORITHM   4
#endif

#ifdef LWIP_DEBUG
void assert_printf(char *msg, int line, const char *file);

/* Plaform specific diagnostic output */
#define LWIP_PLATFORM_DIAG(vars) printf vars
#define LWIP_PLATFORM_ASSERT(flag) { assert_printf((flag), __LINE__, __FILE__); }
#else
#define LWIP_PLATFORM_DIAG(msg) { ; }
#define LWIP_PLATFORM_ASSERT(flag) { ; }
#endif

#define LWIP_PLATFORM_PRINT         PRINTK
#define LWIP_PLATFORM_HTONS(x)      htons(x)
#define LWIP_PLATFORM_HTONL(x)      htonl(x)

#if defined (__cplusplus) && __cplusplus
}
#endif /* __cplusplus */
#endif /* __CC_H__ */

