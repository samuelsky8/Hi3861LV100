/****************************************************************************
*
* Copyright (c) 2016 Wi-Fi Alliance
*
* Permission to use, copy, modify, and/or distribute this software for any
* purpose with or without fee is hereby granted, provided that the above
* copyright notice and this permission notice appear in all copies.
*
* THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
* WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
* MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
* SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER
* RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT,
* NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE
* USE OR PERFORMANCE OF THIS SOFTWARE.
*
*****************************************************************************/


#ifndef WFA_DEBUG_H
#define WFA_DEBUG_H

#include <hi_early_debug.h>

#define WFA_ERR         "Error: "
#define WFA_OUT         "Info: "
#define WFA_WNG         "Warning: "

#define WFA_DEBUG_DEFAULT          0x0001
#define WFA_DEBUG_ERR              0x0001
#define WFA_DEBUG_INFO             0x0002
#define WFA_DEBUG_WARNING          0x0004
#define WFA_DEBUG_NONE             0X0000
#define DEBUG (WFA_DEBUG_ERR | WFA_DEBUG_INFO | WFA_DEBUG_WARNING)


#if (DEBUG & WFA_DEBUG_ERR)
#define DPRINT_ERR(level, fmt...) do{ \
                      printf("Error at File %s, Line %ld: ", \
                                __FILE__, (long)__LINE__); \
                      printf(fmt); \
                  }while(0)
#else
#define DPRINT_ERR(level, fmt...)
#endif

#if (DEBUG & WFA_DEBUG_INFO)
#define DPRINT_INFO(level, fmt...) do{ \
                    printf(level); \
                    printf(fmt); \
                }while(0)
#else
#define DPRINT_INFO(level, fmt...)
#endif

#if (DEBUG & WFA_DEBUG_ERR)
#define DPRINT_WARNING(level, fmt...) do{ \
                    printf(level); \
                    printf(fmt); \
                }while(0)
#else
#define DPRINT_WARNING(level, fmt...)
#endif

#endif
