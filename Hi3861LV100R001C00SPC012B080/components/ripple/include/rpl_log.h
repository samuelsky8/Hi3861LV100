/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2012-2020. All rights reserved.
 * Description: RPL logging functions
 * Author: NA
 * Create: 2019-04-02
 */

#ifndef _RPL_LOG_H_
#define _RPL_LOG_H_

#ifdef __LITEOS__
#include "shell.h"
#else
#include <stdio.h>
#endif

/* Logging Interfaces */
#define RPL_LOG_DBG 1
#define RPL_LOG_INFO 2
#define RPL_LOG_ERR 3
#define RPL_LOG_MUTE 6

#ifndef RPL_LOG_DEFAULT
#define RPL_LOG_DEFAULT RPL_LOG_MUTE
#endif

#define RPL_LOG_DETAILS 0 /* enabled if you want function:line to be printed with all logs */

static inline char *
get_log_type(uint8_t log_type)
{
  if (log_type == RPL_LOG_DBG) {
    return "DBG ";
  }
  if (log_type == RPL_LOG_INFO) {
    return "INFO";
  }
  if (log_type == RPL_LOG_ERR) {
    return "ERR ";
  }
  return "UNK ";
}

#ifdef RPL_LOG_LEVEL
/*
 * NOTE: IF YOU GET COMPILATION ERROR HERE, REMEMBER TO define LOG_LEVEL in corr
 * .c file
 */
#if RPL_LOG_DETAILS
#include <sys/time.h>
#define RPL_PRN_DETAILS(log_type) do {   \
  struct timeval tv;                     \
  (void)gettimeofday(&tv, NULL);         \
  (void)printf("%s %5ld:%-3ld [%s:%d] ", \
               get_log_type(log_type),   \
               tv.tv_sec % 100000,       \
               tv.tv_usec / 1000,        \
               __FUNCTION__,             \
               __LINE__);                \
} while (0)
#else
#define RPL_PRN_DETAILS(log_type)
#endif

#define RPL_PRN(log_type, ...) do { \
  RPL_PRN_DETAILS(log_type); \
  (void)printf(__VA_ARGS__); \
} while (0)

#define RPL_CRIT(...) RPL_PRN(__VA_ARGS__)

#if RPL_LOG_LEVEL <= RPL_LOG_INFO
#define RPL_INFO(...) RPL_PRN(RPL_LOG_INFO, __VA_ARGS__)
#endif

#if RPL_LOG_LEVEL <= RPL_LOG_ERR
#define RPL_ERR(...) RPL_PRN(RPL_LOG_ERR, __VA_ARGS__)
#endif

#if RPL_LOG_LEVEL <= RPL_LOG_DBG
#define RPL_DBG(...) RPL_PRN(RPL_LOG_DBG, __VA_ARGS__)
#endif
#endif

#ifndef RPL_INFO
#define RPL_INFO(...)
#endif

#ifndef RPL_ERR
#define RPL_ERR(...)
#endif

#ifndef RPL_DBG
#define RPL_DBG(...)
#endif

#define RPL_UCOND_RETURN(cond, ...) do { \
  if (!(cond)) { \
    RPL_ERR(__VA_ARGS__); \
    return; \
  } \
} while (0)

#define RPL_UCOND_RETURN_NULL(cond, ...) do { \
  if (!(cond)) { \
    RPL_ERR(__VA_ARGS__); \
    return NULL; \
  } \
} while (0)

#define RPL_UCOND_RETURN_FAIL(cond, ...) do { \
  if (!(cond)) { \
    RPL_ERR(__VA_ARGS__); \
    return RPL_FAIL; \
  } \
} while (0)

#define RPL_UCOND_RETURN_ZERO(cond, ...) do { \
  if (!(cond)) { \
    RPL_ERR(__VA_ARGS__); \
    return 0; \
  } \
} while (0)

#define RPL_UCOND_GOTO(cond, ...) do { \
  if (!(cond)) { \
    RPL_ERR(__VA_ARGS__); \
    goto failure; \
  } \
} while (0)

#endif /* _RPL_LOG_H_ */
