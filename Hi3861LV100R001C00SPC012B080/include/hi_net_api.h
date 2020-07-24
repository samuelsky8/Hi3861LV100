/**
 * @defgroup hi_net Lwip API
 */
/**
 * @defgroup hi_net_basic Lwip Basic Interface
 * @ingroup hi_net
 */
/**
 * @file hi_net_api.h
 *
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019. All rights reserved. \n
 *
 * Description: header file for Lwip api.CNcomment:������Lwip api�ӿ�ͷ�ļ�CNend\n
 */

#ifndef __HI_NET_API_H__
#define __HI_NET_API_H__

#include <stdint.h>
#include <stddef.h>
#include <errno.h>

#ifdef __cplusplus
extern "C"
{
#endif

typedef unsigned char  u8_t;
typedef unsigned short u16_t;
typedef unsigned int u32_t;
typedef int err_t;

/**
 * @ingroup hi_net_basic
 *
 * max length of INET ADDRESS.CNcomment:INET�����ַ������ȡ�CNend
 */
#define INET_ADDRSTRLEN 16

/**
 * @ingroup hi_net_basic
 *
 * max num of FD.CNcomment:����������������CNend
 */
#define FD_SETSIZE_MAX 1024

/*****************************************************************************
* 1��LWIPЭ��ջͨ�ô�����
*****************************************************************************/
#define  EPERM         1  /* Operation not permitted */
#define  ENOENT        2  /* No such file or directory */
#define  ESRCH         3  /* No such process */
#define  EINTR         4  /* Interrupted system call */
#define  EIO           5  /* I/O error */
#define  ENXIO         6  /* No such device or address */
#define  E2BIG         7  /* Arg list too long */
#define  ENOEXEC       8  /* Exec format error */
#define  EBADF         9  /* Bad file number */
#define  ECHILD       10  /* No child processes */
#define  EAGAIN       11  /* Try again */
#define  ENOMEM       12  /* Out of memory */
#define  EACCES       13  /* Permission denied */
#define  EFAULT       14  /* Bad address */
#define  ENOTBLK      15  /* Block device required */
#define  EBUSY        16  /* Device or resource busy */
#define  EEXIST       17  /* File exists */
#define  EXDEV        18  /* Cross-device link */
#define  ENODEV       19  /* No such device */
#define  ENOTDIR      20  /* Not a directory */
#define  EISDIR       21  /* Is a directory */
#define  ENFILE       23  /* File table overflow */
#define  EMFILE       24  /* Too many open files */
#define  ENOTTY       25  /* Not a typewriter */
#define  ETXTBSY      26  /* Text file busy */
#define  EFBIG        27  /* File too large */
#define  ENOSPC       28  /* No space left on device */
#define  ESPIPE       29  /* Illegal seek */
#define  EROFS        30  /* Read-only file system */
#define  EMLINK       31  /* Too many links */
#define  EPIPE        32  /* Broken pipe */
#define  EDOM         33  /* Math argument out of domain of func */
#define  EDEADLK      35  /* Resource deadlock would occur */
#define  ENAMETOOLONG 36  /* File name too long */
#define  ENOLCK       37  /* No record locks available */
#define  ENOSYS       38  /* Function not implemented */
#define  ENOTEMPTY    39  /* Directory not empty */
#define  ELOOP        40  /* Too many symbolic links encountered */
#define  EWOULDBLOCK  EAGAIN  /* Operation would block */
#define  ENOMSG       42  /* No message of desired type */
#define  EIDRM        43  /* Identifier removed */
#define  ECHRNG       44  /* Channel number out of range */
#define  EL2NSYNC     45  /* Level 2 not synchronized */
#define  EL3HLT       46  /* Level 3 halted */
#define  EL3RST       47  /* Level 3 reset */
#define  ELNRNG       48  /* Link number out of range */
#define  EUNATCH      49  /* Protocol driver not attached */
#define  ENOCSI       50  /* No CSI structure available */
#define  EL2HLT       51  /* Level 2 halted */
#define  EBADE        52  /* Invalid exchange */
#define  EBADR        53  /* Invalid request descriptor */
#define  EXFULL       54  /* Exchange full */
#define  ENOANO       55  /* No anode */
#define  EBADRQC      56  /* Invalid request code */
#define  EBADSLT      57  /* Invalid slot */
#define  EDEADLOCK    EDEADLK
#define  EBFONT       59  /* Bad font file format */
#define  ENOSTR       60  /* Device not a stream */
#define  ENODATA      61  /* No data available */
#define  ETIME        62  /* Timer expired */
#define  ENOSR        63  /* Out of streams resources */
#define  ENONET       64  /* Machine is not on the network */
#define  ENOPKG       65  /* Package not installed */
#define  EREMOTE      66  /* Object is remote */
#define  ENOLINK      67  /* Link has been severed */
#define  EADV         68  /* Advertise error */
#define  ESRMNT       69  /* Srmount error */
#define  ECOMM        70  /* Communication error on send */
#define  EPROTO       71  /* Protocol error */
#define  EMULTIHOP    72  /* Multihop attempted */
#define  EDOTDOT      73  /* RFS specific error */
#define  EBADMSG      74  /* Not a data message */
#define  EOVERFLOW    75  /* Value too large for defined data type */
#define  ENOTUNIQ     76  /* Name not unique on network */
#define  EBADFD       77  /* File descriptor in bad state */
#define  EREMCHG      78  /* Remote address changed */
#define  ELIBACC      79  /* Can not access a needed shared library */
#define  ELIBBAD      80  /* Accessing a corrupted shared library */
#define  ELIBSCN      81  /* .lib section in a.out corrupted */
#define  ELIBMAX      82  /* Attempting to link in too many shared libraries */
#define  ELIBEXEC     83  /* Cannot exec a shared library directly */
#define  EILSEQ       84  /* Illegal byte sequence */
#define  ERESTART     85  /* Interrupted system call should be restarted */
#define  ESTRPIPE     86  /* Streams pipe error */
#define  EUSERS       87  /* Too many users */
#define  ENOTSOCK     88  /* Socket operation on non-socket */
#define  EDESTADDRREQ 89  /* Destination address required */
#define  EMSGSIZE     90  /* Message too long */
#define  EPROTOTYPE   91  /* Protocol wrong type for socket */
#define  ENOPROTOOPT  92  /* Protocol not available */
#define  EPROTONOSUPPORT 93  /* Protocol not supported */
#define  ESOCKTNOSUPPORT 94  /* Socket type not supported */
#define  EOPNOTSUPP      95  /* Operation not supported on transport endpoint */
#define  EPFNOSUPPORT    96  /* Protocol family not supported */
#define  EAFNOSUPPORT    97  /* Address family not supported by protocol */
#define  EADDRINUSE      98  /* Address already in use */
#define  EADDRNOTAVAIL   99  /* Cannot assign requested address */
#define  ENETDOWN       100  /* Network is down */
#define  ENETUNREACH    101  /* Network is unreachable */
#define  ENETRESET      102  /* Network dropped connection because of reset */
#define  ECONNABORTED   103  /* Software caused connection abort */
#define  ECONNRESET     104  /* Connection reset by peer */
#define  ENOBUFS        105  /* No buffer space available */
#define  EISCONN        106  /* Transport endpoint is already connected */
#define  ENOTCONN       107  /* Transport endpoint is not connected */
#define  ESHUTDOWN      108  /* Cannot send after transport endpoint shutdown */
#define  ETOOMANYREFS   109  /* Too many references: cannot splice */
#define  ETIMEDOUT      110  /* Connection timed out */
#define  ECONNREFUSED   111  /* Connection refused */
#define  EHOSTDOWN      112  /* Host is down */
#define  EHOSTUNREACH   113  /* No route to host */
#define  EALREADY       114  /* Operation already in progress */
#define  EINPROGRESS    115  /* Operation now in progress */
#define  ESTALE         116  /* Stale NFS file handle */
#define  EUCLEAN        117  /* Structure needs cleaning */
#define  ENOTNAM        118  /* Not a XENIX named type file */
#define  ENAVAIL        119  /* No XENIX semaphores available */
#define  EISNAM         120  /* Is a named type file */
#define  EREMOTEIO      121  /* Remote I/O error */
#define  EDQUOT         122  /* Quota exceeded */
#define  ENOMEDIUM      123  /* No medium found */
#define  EMEDIUMTYPE    124  /* Wrong medium type */

/*****************************************************************************
* 2��LWIPЭ��ջ�׽�����������
*****************************************************************************/
#define SOCK_STREAM     1
#define SOCK_DGRAM      2
#define SOCK_RAW        3

/*****************************************************************************
* 3��LWIPЭ��ջЭ��������
*****************************************************************************/
#define AF_UNSPEC       0
#define AF_INET         2
#define AF_INET6        AF_UNSPEC
#define PF_INET         AF_INET
#define PF_INET6        AF_INET6
#define PF_UNSPEC       AF_UNSPEC

/*****************************************************************************
* 4��LWIPЭ��ջ����Э������
*****************************************************************************/
#define IPPROTO_IP      0
#define IPPROTO_TCP     6
#define IPPROTO_UDP     17
#define IPPROTO_UDPLITE 136

/*****************************************************************************
* 5��LWIPЭ��ջ�շ����ݰ��������־λ����
*****************************************************************************/
#define MSG_PEEK       0x02
#define MSG_WAITALL    0x100
#define MSG_OOB        0x01
#define MSG_DONTWAIT   0x40
#define MSG_MORE       0x8000

/*****************************************************************************
* 6��LWIPЭ��ջ��ѡ�ֶ����Ͷ���
*****************************************************************************/
#define SOL_SOCKET   1
#define SO_REUSEADDR 2
#define SO_TYPE      3
#define SO_ERROR     4
#define SO_BROADCAST 6
#define SO_SNDBUF    7
#define SO_RCVBUF    8
#define SO_KEEPALIVE 9
#define SO_NO_CHECK  11
#define SO_SNDLOWAT  19
#define SO_RCVLOWAT  18
#define SO_SNDTIMEO  21
#define SO_RCVTIMEO  20
#define SO_CONTIMEO  0x1009


#ifndef O_NONBLOCK
#define O_NONBLOCK  00004000
#endif

#ifndef O_NDELAY
#define O_NDELAY    O_NONBLOCK
#endif

#ifndef F_GETFL
#define F_GETFL 3
#endif
#ifndef F_SETFL
#define F_SETFL 4
#endif

/*****************************************************************************
* 7��LWIPЭ��ջIP(���ʻ���Э��)�����ÿ�ѡ�ֶζ���
*****************************************************************************/
#define IP_DROP_MEMBERSHIP 4
#define IP_MULTICAST_TTL   5
#define IP_MULTICAST_IF    6
#define IP_MULTICAST_LOOP  7
#define IP_ADD_MEMBERSHIP  35

/*****************************************************************************
* 8��LWIPЭ��ջ����IP��ַ�궨��
*****************************************************************************/
#define IPADDR_NONE    ((u32_t)0xffffffffUL)
#define IPADDR_ANY     ((u32_t)0x00000000UL)
#define INADDR_ANY     IPADDR_ANY

/*****************************************************************************
* 8����ȡLWIPЭ��ջIP��ַÿ���εľ�������
*****************************************************************************/
#define ip4_addr1(ipaddr) (((u8_t*)(ipaddr))[0])
#define ip4_addr2(ipaddr) (((u8_t*)(ipaddr))[1])
#define ip4_addr3(ipaddr) (((u8_t*)(ipaddr))[2])
#define ip4_addr4(ipaddr) (((u8_t*)(ipaddr))[3])

#define ip4_addr1_16(ipaddr) ((u16_t)ip4_addr1(ipaddr))
#define ip4_addr2_16(ipaddr) ((u16_t)ip4_addr2(ipaddr))
#define ip4_addr3_16(ipaddr) ((u16_t)ip4_addr3(ipaddr))
#define ip4_addr4_16(ipaddr) ((u16_t)ip4_addr4(ipaddr))

/**
 * @ingroup hi_net_basic
 *
 * host Host byte order converted to network byte order.CNcomment:������תΪ������CNend
 */
#define LWIP_PLATFORM_HTONS(_n)  ((u16_t)((((_n) & 0xff) << 8) | (((_n) >> 8) & 0xff)))

/**
 * @ingroup hi_net_basic
 *
 * network bytehost order converted to Host byte order.CNcomment:������תΪ������CNend
 */
#define LWIP_PLATFORM_HTONL(_n)  ((u32_t)((((_n) & 0xff) << 24) | (((_n) & 0xff00) << 8) | \
                                  (((_n) >> 8)  & 0xff00) | (((_n) >> 24) & 0xff)))

/*****************************************************************************
* 8��LWIPЭ��ջ����������bitλ�����á����㡢�ж��Ƿ�����Լ���յĲ���������select����
*****************************************************************************/
#undef FD_SET
#undef FD_CLR
#undef FD_ISSET
#undef FD_ZERO
#undef fd_set
#ifndef FD_SET
  #undef  FD_SETSIZE
  #define FD_SETSIZE    FD_SETSIZE_MAX
  #define FD_SET(n, p)  ((p)->fd_bits[(n) / 8] |=  (1 << ((n) & 7)))
  #define FD_CLR(n, p)  ((p)->fd_bits[(n) / 8] &= ~(1 << ((n) & 7)))
  #define FD_ISSET(n, p) ((p)->fd_bits[(n) / 8] &  (1 << ((n) & 7)))
  #define FD_ZERO(p)    memset((void *)(p), 0, sizeof(*(p)))
  typedef struct fd_set {
    unsigned char fd_bits [(FD_SETSIZE + 7) / 8];
  } fd_set;
#endif

/**
 * @ingroup hi_net_basic
 *
 * set ip addr for four address.CNcomment:����ip�Ķε�ַ������Ӧ��ֵ��CNend
 */
#define IP4_ADDR(ipaddr, a,b,c,d) \
        (ipaddr)->addr = ((u32_t)((d) & 0xff) << 24) | \
                         ((u32_t)((c) & 0xff) << 16) | \
                         ((u32_t)((b) & 0xff) << 8)  | \
                          (u32_t)((a) & 0xff)

/*****************************************************************************
* 8��LWIPЭ��ջbsd socket htons/ntohs/ntohlת��
*****************************************************************************/
#define htons(x) lwip_htons(x)
#define ntohs(x) lwip_ntohs(x)
#define htonl(x) lwip_htonl(x)
#define ntohl(x) lwip_ntohl(x)

#define lwip_htons(x) LWIP_PLATFORM_HTONS(x)
#define lwip_ntohs(x) LWIP_PLATFORM_HTONS(x)
#define lwip_htonl(x) LWIP_PLATFORM_HTONL(x)
#define lwip_ntohl(x) LWIP_PLATFORM_HTONL(x)

/**
* @ingroup  hi_net_basic
* @brief  Point to decimal.CNcomment:ip��ַ�����תΪʮ����CNend
*
* @par Description:
*           Point to decimal.CNcomment:ip��ַ�����תΪʮ����CNend
*
* @attention  cp cannot be empty. CNcomment:�����ַ�������Ϊ��CNend
* @param  the ip addr in string CNcomment:�ַ���ip��ַCNend
* @retval #IPADDR        Execute successfully.
* @retval #IPADDR_NONE   Execute failed.
* @par NA:
*         NA
* @see  NULL
* @since Hi3861_V100R001C00
*/
u32_t ipaddr_addr(const char *cp);
#define inet_addr(cp)  ipaddr_addr(cp)

/*****************************************************************************
* 9��LWIPЭ��ջ����liteos�ֳ�����
*****************************************************************************/
#if !defined(in_addr_t) && !defined(IN_ADDR_T_DEFINED)
#ifndef _IN_ADDR_T_DECLARED
typedef u32_t in_addr_t;
#define _IN_ADDR_T_DECLARED
#endif
#endif

#if !defined(sa_family_t) && !defined(SA_FAMILY_T_DEFINED)
typedef u16_t sa_family_t;
#endif

#if !defined(in_port_t) && !defined(IN_PORT_T_DEFINED)
typedef u16_t in_port_t;
#endif

#if !defined(socklen_t) && !defined(SOCKLEN_T_DEFINED)
typedef u32_t socklen_t;
#endif

/**
 * @ingroup hi_net_basic
 *
 * ip address in decimal.CNcomment:ʮ����ip��ַCNend
 *
 */
struct ip_addr {
  u32_t addr;
};

/**
 * @ingroup hi_net_basic
 *
 * Package structure ip_addr_t to in_addr.CNcomment:��װ�ṹ��in_addr_t��in_addrCNend
 *
 */
struct in_addr {
  in_addr_t s_addr;
};

/**
 * @ingroup hi_net_basic
 *
 * Address form of socket in Internet Environment.CNcomment:internet�������׽��ֵĵ�ַ��ʽCNend
 *
 */
struct sockaddr_in {
  sa_family_t     sin_family;
  in_port_t       sin_port;
  struct in_addr  sin_addr;
#define SIN_ZERO_LEN 8
  char            sin_zero[SIN_ZERO_LEN];
};

/**
 * @ingroup hi_net_basic
 *
 * General socket address.CNcomment:ͨ�õ��׽��ֵ�ַCNend
 *
 */
struct sockaddr {
  sa_family_t sa_family;
#define SA_DATA_LEN 14
  char sa_data[SA_DATA_LEN];
};

/**
 * @ingroup hi_net_basic
 *
 * Multicast address and interface.CNcomment:�ಥ��ַ�ͽӿ�CNend
 *
 */
typedef struct ip_mreq {
  struct in_addr imr_multiaddr;
  struct in_addr imr_interface;
} ip_mreq;

/**
 * @ingroup hi_net_basic
 *
 * IPv4 address.CNcomment:ipv4�ĵ�ַCNend
 *
 */
struct ip4_addr {
  u32_t addr;
};
typedef struct ip4_addr ip4_addr_t;
typedef ip4_addr_t ip_addr_t;

/**
* @ingroup  hi_net_basic
* @brief  Network byte order IP address converted to dotted decimal format.
*         CNcomment:�����ֽ����IP��ַת��Ϊ���ʮ���Ƹ�ʽCNend
*
* @par Description:
*           Address translation.CNcomment:��ַת��CNend
*
* @attention  NULL
* @param  cp    [IN]     Type #ip4_addr_t *, Network byte order IP address.CNcomment:���ʮ���Ƹ�ʽ��IP��ַCNend
* @param  addr  [IN]     Type #const char *, length of device name.CNcomment:���ʮ����ip��ַCNend
*
* @retval #1    Excute successfully
* @retval #0    Excute failure
* @par  NULL
*
* @see  NULL
* @since Hi3861_V100R001C00
*/
int ip4addr_aton(const char *cp, ip4_addr_t *addr);
#define inet_aton(cp, addr)  ip4addr_aton(cp, (ip4_addr_t*)addr)

/**
* @ingroup  hi_net_basic
* @brief  Dotted decimal format IP address converted to Network byte order.
*         CNcomment:���ʮ���Ƶ�IP��ַת��Ϊ�����ֽ����ʽCNend
*
* @par Description:
*           Address translation.CNcomment:��ַת��CNend
*
* @attention  NULL
* @param  addr [IN]  Type #ip4_addr_t *, addr ip address in network order to convert.CNcomment:�����ֽ���ip��ַCNend
*
* @retval #Not NULL  Excute successfully
* @retval #NULL      Excute failure
* @par  NULL
*
* @see  NULL
* @since Hi3861_V100R001C00
*/
char *ip4addr_ntoa(const ip4_addr_t *addr);
#define inet_ntoa(addr)  ip4addr_ntoa((ip4_addr_t*)&(addr))


typedef void (*dns_found_callback)(const char *name, ip_addr_t *ipaddr, void *callback_arg);
err_t dns_gethostbyname(const char *hostname, ip_addr_t *addr,
                        dns_found_callback found, void *callback_arg);

/**
 * @ingroup hi_net_basic
 *
 * Domain name and network address structure.CNcomment:�����������ַ�ṹ��CNend
 *
 */
struct hostent {
    char  *h_name;      /**< Indicates the official name of the host. */
    char **h_aliases;   /**< Indicates a pointer to an array of pointers to alternative host names,
                           terminated by a null pointer. */
    int    h_addrtype;  /**< Indicates the address type. */
    int    h_length;    /**< Indicates the length, in bytes, of the address. */
    char **h_addr_list; /**< Indicates a pointer to an array of pointers to network addresses (in
                           network byte order) for the host, terminated by a null pointer. */
#define h_addr h_addr_list[0] /* for backward compatibility */
};

/**
* @ingroup  hi_net_basic
* @brief  Get IP address according to domain name.CNcomment:����������ȡIP��ַCNend
*
* @par Description:
*           The IP address is obtained by using the domain name in string format,
*           and the address information is loaded into the host domain name structure
*           CNcomment:�����ַ�����ʽ���������IP��ַ�����ҽ���ַ��Ϣװ��hostent�����ṹ��CNend
*
* @attention  NULL
* @param  name            [IN]    Type #const char * the hostname to resolve.CNcomment:����������CNend
*
* @retval #hostent        Execute successfully.
* @retval #NULL           Execute failed.
* @par Dependency:
*         #NULL
* @see  NULL
* @since Hi3861_V100R001C00
*/
struct hostent *gethostbyname(const char *name);

/**
 * @ingroup hi_net_basic
 *
 * Network interface structure.CNcomment:����ӿڽṹ��CNend
 *
 */
struct netif {
#define NETIF_DATA_LEN 8
  unsigned char data[NETIF_DATA_LEN];
};

/**
* @ingroup  hi_net_basic
* @brief  Get the corresponding interface pointer according to the interface name.
*         CNcomment:���ݽӿ����ֻ�ȡ��Ӧ�ӿ�ָ��CNend
*
* @par Description:
*         Get the corresponding interface pointer according to the interface name
*         CNcomment:���ݽӿ����ֻ�ȡ��Ӧ�ӿ�ָ��CNend
*
* @attention  NULL
* @param  name            [IN]    Type #const char * the interface name to find.CNcomment:Ҫ�ҵĽӿ�����CNend
*
* @retval #struct netif * Execute successfully.
* @retval #NULL           Execute failed.
* @par Dependency:
*         #NULL
* @see  NULL
* @since Hi3861_V100R001C00
*/
struct netif *netif_find(const char *name);

/**
* @ingroup  hi_net_basic
* @brief  Start DHCP client according to interface.CNcomment:���ݽӿ�����dhcp�ͻ���CNend
*
* @par Description:
*         Start DHCP client according to interface
*         CNcomment:���ݽӿ�����dhcp�ͻ���CNend
*
* @attention  NULL
* @param  netif      [IN]    Type #struct netif * Interface address.CNcomment:�ӿڵ�ַCNend
*
* @retval #ERR_OK    Execute successfully.
* @retval #OTHERS    Execute failed.
* @par Dependency:
*         #NULL
* @see  NULL
* @since Hi3861_V100R001C00
*/
err_t netifapi_dhcp_start(struct netif *netif);

/**
* @ingroup  hi_net_basic
* @brief  Start DHCP server according to interface.CNcomment:���ݽӿ�����dhcp�����CNend
*
* @par Description:
*         Start DHCP server according to interface
*         CNcomment:���ݽӿ�����dhcp�����CNend
*
* @attention  NULL
* @param  netif      [IN]    Type #struct netif * Interface address.CNcomment:�ӿڵ�ַCNend
* @param  start_ip   [IN]    Type #char * Assigned client start address.CNcomment:����Ŀͻ�����ʼ��ַCNend
* @param  ip_num     [IN]    Type #u16_t  Total number of clients assigned.CNcomment:����Ŀͻ�������ĿCNend
* @retval #ERR_OK    Execute successfully.
* @retval #OTHERS    Execute failed.
* @par Dependency:
*         #NULL
* @see  NULL
* @since Hi3861_V100R001C00
*/
err_t netifapi_dhcps_start(struct netif *netif, char *start_ip, u16_t ip_num);

/**
* @ingroup  hi_net_basic
* @brief  This API is used to set the the vendor class identifier information
*         of the netif, which is using in DHCP Message.
*         CNcomment:���API��������dhcp��hostname��ϢCNend
*
* @par Description:
*         The hostname string lenght should be less than NETIF_HOSTNAME_MAX_LEN,
*         otherwise the hostname will truncate to (NETIF_HOSTNAME_MAX_LEN-1).
*         CNcomment:hostname�ĳ���ҪС��NETIF_HOSTNAME_MAX_LEN,����ᱻ����Ϊ(NETIF_HOSTNAME_MAX_LEN-1)CNend
*
* @attention  NULL
* @param  netif      [IN]    Type #struct netif * Interface address.CNcomment:�ӿڵ�ַCNend
* @param  hostname   [IN]    Type #char * hostname The new hostname to use.CNcomment:����ʹ�õ�����CNend
* @param  namelen    [IN]    Type #u8_t The hostname string length.CNcomment:���Ƴ���CNend
* @retval #ERR_OK    Execute successfully.
* @retval #ERR_ARG:  On passing invalid arguments.
* @par Dependency:
*       #NULL
* @see  NULL
* @since Hi3861_V100R001C00
*/
err_t netifapi_set_hostname(struct netif *netif, char *hostname, u8_t namelen);


/**
* @ingroup  hi_net_basic
* @brief  This API is used to set the vendor class identifier information, which is used in DHCP message.
*         CNcomment:����dhcp��Ϣ��vci��ϢCNend
*
* @par Description:
*    Length of vendor class identifier information string ,should be not more than DHCP_VCI_MAX_LEN(default 32),
*    otherwise it will return with ERR_ARG. vci_len is the real length of vendor class identifier information string.
*    CNcomment:vci��Ϣ���Ȳ�����32���ֽ�,����᷵��ERR_ARG,vci_len�ǳ��̷�����Ϣ����ʵ����CNend
*
* @attention  NULL
* @param  vci    [IN]    Type #char * The new vendor class identifier information to use.CNcomment:�����豸��Ϣ����CNend
* @param  vci_len [IN]    Type #u8_t   The length of vendor class identifier information string.CNcomment:�������ݵĳ���CNend
* @retval #ERR_OK On success
* @retval #ERR_ARG On passing invalid arguments
* @retval #ERR_VAL On failure
* @par Dependency:
*       #NULL
* @see  NULL
* @since Hi3861_V100R001C00
*/
err_t netifapi_set_vci(char *vci, u8_t vci_len);

/**
* @ingroup  hi_net_basic
* @brief  allocate a socket.CNcomment:�����׽���CNend
*
* @par Description:
*        It creates an endpoint for communication and returns a file descriptor
*        CNcomment:Ϊͨ�Ŵ���һ���˵㲢����һ���ļ�������CNend
*
* @attention  NULL
* @param  domain     [IN]    Type #int Specifies a protocol family.CNcomment:ָ��Э����CNend
* @param  type       [IN]    Type #int Specifies the socket type.CNcomment:ָ��Э������CNend
* @param  protocol   [IN]    Type #int Specifies the protocol to be used with the socket.
*                            CNcomment:ָ��Ҫ���׽���һ��ʹ�õ�Э��CNend
* @retval #>0       Execute successfully.
* @retval #-1       Execute failed.
* @par Dependency:
*       #NULL
* @see  NULL
* @since Hi3861_V100R001C00
*/
int socket(int domain, int type, int protocol);

/**
* @ingroup  hi_net_basic
* @brief  bind a socket.CNcomment:���׽���CNend
*
* @par Description:
*        It creates an endpoint for communication and returns a file descriptor
*        CNcomment:Ϊͨ�Ŵ���һ���˵㲢����һ���ļ�������CNend
*
* @attention  NULL
* @param s     [IN]    Type #int Specifies the file descriptor of the socket to be bound.CNcomment:Ҫ�󶨵�������CNend
* @param name  [IN]    Type #struct sockaddr *  Points to a sockaddr structure containing the address
*                              to be bound to the socket.    CNcomment:ָ�����Ҫ�󶨵��׽��ֵĵ�ַ��sockaddr�ṹCNend
* @param namelen [IN] Type #socklen_t Specifies the length of the sockaddr structure pointed to by the address argument.
*                                     CNcomment:ָ��address����ָ���sockaddr�ṹ�ĳ���CNend
* @retval #0        Execute successfully.
* @retval #-1       Execute failed.
* @par Dependency:
*       #NULL
* @see  NULL
* @since Hi3861_V100R001C00
*/
int bind(int s, const struct sockaddr *name, socklen_t namelen);

/**
* @ingroup  hi_net_basic
* @brief  Get socket optional fields.CNcomment:��ȡ�׽��ֿ�ѡ�ֶ�CNend
*
* @par Description:
*        Get socket optional fields
*        CNcomment:��ȡ�׽��ֿ�ѡ�ֶ�CNend
*
* @attention  NULL
* @param  socket  [IN]       Type #int Specifies a socket file descriptor.CNcomment:ָ�����ļ�������CNend
* @param  level   [IN]       Type #int Specifies the protocol level at which the option resides.
*                                      CNcomment:ָ��ѡ�����ڵ�Э�鼶��CNend
* @param  option_name  [IN]  Type #int Specifies a single option to set.CNcomment:ָ��ѡ�������CNend
* @param  option_value [OUT] Type #void * Indicates the pointer to the option value.CNcomment:ָʾָ��ѡ��ֵ��ָ��CNend
* @param  option_len   [IN]  Type #socklen_t * Specifies the size of option value.CNcomment:ָ��ѡ���ֵCNend
* @retval #0     Execute successfully.
* @retval #-1    Execute failed.
* @par Dependency:
*       #NULL
* @see  NULL
* @since Hi3861_V100R001C00
*/
int getsockopt(int s, int level, int optname, void *optval, socklen_t *optlen);

/**
* @ingroup  hi_net_basic
* @brief  Set socket optional fields.CNcomment:�����׽��ֿ�ѡ�ֶ�CNend
*
* @par Description:
*        Set socket optional fields
*        CNcomment:�����׽��ֿ�ѡ�ֶ�CNend
*
* @attention  NULL
* @param  socket    [IN]     Type #int Specifies a socket file descriptor.CNcomment:ָ�����ļ�������CNend
* @param  level     [IN]     Type #int Specifies the protocol level at which the option resides.
*                                      CNcomment:ָ��ѡ�����ڵ�Э�鼶��CNend
* @param  option_name  [IN]  Type #int Specifies a single option to set.CNcomment:ָ��ѡ�������CNend
* @param  option_value [OUT] Type #void * Indicates the pointer to the option value.CNcomment:ָʾָ��ѡ��ֵ��ָ��CNend
* @param  option_len   [IN]  Type #socklen_t Specifies the size of option value.CNcomment:ָ��ѡ���ֵCNend
* @retval #0     Execute successfully.
* @retval #-1    Execute failed.
* @par Dependency:
*       #NULL
* @see  NULL
* @since Hi3861_V100R001C00
*/
int setsockopt(int s, int level, int optname, const void *optval, socklen_t optlen);

/**
* @ingroup  hi_net_basic
* @brief  Accepts a new connection on a socket.CNcomment:�׽����Ͻ���һ������CNend
*
* @par Description:
*        Accepts a new connection on a socket
*        CNcomment:�׽����Ͻ���һ������CNend
*
* @attention  NULL
* @param  socket    [IN]   Type #int Specifies a socket that was created with socket(),has been bound to an address
*                               with bind(),and has issued a successful call to listen().
*                               CNcomment:ָ����socket()�������׽���,���׽�����bind()��,���ѳɹ�����listen()CNend
* @param  address   [OUT]  Type #struct sockaddr * Indicates either a null pointer, or a pointer to a sockaddr structure
*                                 where the address of the connecting socket shall be returned.
*                                 CNcomment:ָʾ��ָ���ָ��sockaddr�ṹ��ָ��,����Ӧ���������׽��ֵĵ�ַCNend
* @param  address_len  [IN,OUT]  Type #socklen_t * Indicates either a null pointer,if address is a null pointer,
*                                                  or a pointer to a socklen_t object which on input
*                                 specifies the length of the supplied sockaddr structure,and on output specifies
*                                 the length of the stored address.
*                                 CNcomment:�����ַ�ǿ�ָ��,��ָʾ��ָ��,����ָʾָ��socklen_t�����ָ��,
*                                           �ö���������ʱָ���ṩ��sockaddr�ṹ�ĳ���,�����ʱָ���洢��ַ�ĳ���.CNend
* @retval #>0     Execute successfully.
* @retval #-1     Execute failed.
* @par Dependency:
*       #NULL
* @see  NULL
* @since Hi3861_V100R001C00
*/
int accept(int s, struct sockaddr *addr, socklen_t *addrlen);

/**
* @ingroup  hi_net_basic
* @brief  Connection to peer IP address.CNcomment:���ӶԶ�IP��ַCNend
*
* @par Description:
*        attempt to make a connection on a connection-mode socket or to set or
*        reset the peer address of a connectionless-mode socket
*        CNcomment:����������ģʽ�׽����Ͻ�������,�����û�����������ģʽ�׽��ֵĶԵȵ�ַCNend
*
* @attention  NULL
* @param      s     [IN]  Type #int Specifies a socket file descriptor.CNcomment:ָ���׽���CNend
* @param      name  [IN]  Type #struct sockaddr * Specifies a pointer to the sockaddr structure
*                            which identifies the connection. CNcomment:ָ��ָ��sockaddr�ṹ��ָ�룬�ýṹ��ʶ����CNend
* @param      namelen [IN] Type # socklen_t Specifies the size of name structure.
*                                 CNcomment:ָ�����ֽṹ��ĳ���CNend
* @retval #0     Execute successfully.
* @retval #-1    Execute failed.
* @par Dependency:
*       #NULL
* @see  NULL
* @since Hi3861_V100R001C00
*/
int connect(int s, const struct sockaddr *name, socklen_t namelen);

/**
* @ingroup  hi_net_basic
* @brief  Recieve a message from connected socket.CNcomment:���Ѿ����ӵ��׽��ֽ�����ϢCNend
*
* @par Description:
*        Recieve a message from connected socket.
*        CNcomment:���Ѿ����ӵ��׽��ֽ�����ϢCNend
*
* @attention  NULL
* @param      socket  [IN]  Type #int    Specifies the socket file descriptor.CNcomment:ָ���׽���CNend
* @param      buffer  [OUT] Type #void *  Points to a buffer where the message should be stored.
*                                         CNcomment:���մ洢�Ļ���CNend
* @param      length  [IN]  Type #size_t  Specifies the length in bytes of the buffer pointed to by the buffer argument.
*                                         CNcomment:ÿ�ν��յĳ���CNend
* @param      flags   [IN]  Type #int     Specifies the type of message reception.CNcomment:ָ���׽��ֵı�־λCNend
* @retval #>0     Execute successfully.
* @retval #-1     Execute failed.
* @par Dependency:
*       #NULL
* @see  NULL
* @since Hi3861_V100R001C00
*/
int recv(int s, void *mem, size_t len, int flags);

/**
* @ingroup  hi_net_basic
* @brief  Recieve a message from connected socket.CNcomment:���Ѿ����ӵ��׽��ֽ�����ϢCNend
*
* @par Description:
*        Recieve a message from connected socket.
*        CNcomment:���Ѿ����ӵ��׽��ֽ�����ϢCNend
*
* @attention  NULL
* @param      socket    [IN]    Type #int     Specifies the socket file descriptor.CNcomment:ָ���׽���CNend
* @param      buffer    [OUT]   Type #void *  Points to a buffer where the message should be stored.
*                                             CNcomment:���մ洢�Ļ���CNend
* @param      length    [IN]    Type #size_t  Specifies the length in bytes of the buffer pointed to
*                                             by the buffer argument.CNcomment:ÿ�ν��յĳ���CNend
* @param      flags     [IN]    Type #int     Specifies the type of message reception.CNcomment:ָ���׽��ֵı�־λCNend
* @param      flags     [IN]    Type #struct  sockaddr *  A null pointer, or points to a sockaddr structure in which
*                                                        the sending address is to be stored.
*                                                        CNcomment:��ָ�룬��ָ��Ҫ�洢���͵�ַ��sockaddr�ṹCNend
* @param      flags     [IN]    Type #socklen_t *   Either a null pointer, if address is a null pointer, or a pointer
*                        to a socklen_t objectwhich on input specifies the length of the supplied sockaddr structure,
*                        and on output specifies the length of the stored address.
*                        CNcomment:�����ַ�ǿ�ָ�룬��Ϊ��ָ�룬����ָ��socklen_t�����ָ��,
*                        �ö���������ʱָ���ṩ��sockaddr�ṹ�ĳ��ȣ������ʱָ���洢��ַ�ĳ���CNend
* @retval #>0     Execute successfully.
* @retval #-1     Execute failed.
* @par Dependency:
*       #NULL
* @see  NULL
* @since Hi3861_V100R001C00
*/
int recvfrom(int s, void *mem, size_t len, int flags,
             struct sockaddr *from, socklen_t *fromlen);

/**
* @ingroup  hi_net_basic
* @brief Initiates transmission of a message from the specified socket to its peer.CNcomment:����ָ��������Ϣ���Զ�CNend
*
* @par Description:
*        Initiates transmission of a message from the specified socket to its peer
*        CNcomment:������ָ���׽��ֵ���Եȶ˵���Ϣ���䡣CNend
*
* @attention  NULL
* @param      socket  [IN]  Type #int     Specifies the socket file descriptor.CNcomment:ָ���׽���CNend
* @param      buffer  [IN]  Type #void *  Specifies a buffer containing the message to send.
*                                         CNcomment:ָ��Ҫ���͵Ļ���CNend
* @param      length  [IN]  Type #size_t  Specifies the length of the message to send.CNcomment:ָ����Ϣ����CNend
* @param      flags   [IN]  Type #int     Specifies the type of message reception.CNcomment:ָ���׽��ֵı�־λCNend
* @retval #>0     Execute successfully.
* @retval #-1     Execute failed.
* @par Dependency:
*       #NULL
* @see  NULL
* @since Hi3861_V100R001C00
*/
int send(int s, const void *dataptr, size_t size, int flags);

/**
* @ingroup  hi_net_basic
* @brief  send messages from a connection-oriented and connectionless sockets.
*         CNcomment:���������Ӻ������ӵ��׽��ַ�����ϢCNend
*
* @par Description:
*      If the socket is in the connectionless mode, the message is sent to the address specified by the 'to' parameter.
*
*      CNcomment:����׽��ִ���������ģʽ������Ϣ���͵���to������ָ���ĵ�ַ
*                ����׽��ִ�������ģʽ������ԡ�to�������е�Ŀ���ַCNend
* @attention  NULL
* @param      socket    [IN]   Type #int    Specifies the socket file descriptor.CNcomment:ָ���׽���CNend
* @param      buffer    [IN]   Type #void * Specifies a buffer containing the message to send.
*                                           CNcomment:ָ��Ҫ���͵Ļ���CNend
* @param      length    [IN]   Type #size_t Specifies the length of the message to send.CNcomment:ָ����Ϣ����CNend
* @param      flags     [IN]   Type #int    Specifies the type of message reception.CNcomment:ָ���׽��ֵı�־λCNend
* @param      flags     [IN]   Type #struct sockaddr *  Specifies a pointer to the sockaddr structure
*                                                       that contains the destination address.
*                                                       CNcomment:ָ��ָ�����Ŀ���ַ��sockaddr�ṹ��ָ��CNend
* @param      flags     [IN]   Type #socklen_t *        Specifies the size of the 'to' structure.
*                                                       CNcomment:ָ����to���ṹ�Ĵ�СCNend
* @retval #>0     Execute successfully.
* @retval #-1     Execute failed.
* @par Dependency:
*       #NULL
* @see  NULL
* @since Hi3861_V100R001C00
*/
int sendto(int s, const void *dataptr, size_t size, int flags,
           const struct sockaddr *to, socklen_t tolen);

/**
* @ingroup  hi_net_basic
* @brief  Allows a program to monitor multiple file descriptors.CNcomment:���������Ӷ���ļ�������CNend
*
* @par Description:
*        select() can monitor only file descriptors numbers that are less than FD_SETSIZE.
*        select() uses a timeout that is a struct timeval (with seconds and microseconds).
*        CNcomment:select()ֻ�ܼ���С��FD_SETSIZE���ļ����������.
*                  select()ʹ�õĳ�ʱֵ��struct timeval(���΢��)CNend
* @attention  NULL
* @param      nfds      [IN]  Type #int Specifies a range of file descriptors.CNcomment:���������Ӷ���ļ�������CNend
* @param      readfds   [IN]  Type #fd_set *  Specifies a pointer to struct fd_set, and specifies the descriptor to
*                                             check for being ready to read.
*                                             CNcomment:ָ��struct fd_set��ָ�룬��Ҫ����Ƿ�׼���ö�ȡ��������CNend
* @param      writefds  [IN]  Type #fd_set *  Specifies a pointer to struct fd_set, and specifies the descriptor
*                                             to check for being ready to write.CNcomment:
*                                             ָ��ָ��struct fd_set��ָ�룬��ָ��Ҫ����Ƿ�׼����д���������CNend
* @param     exceptfds  [IN]  Type #fd_set *  Specifies a pointer to struct fd_set, and specifies the descriptor
*                                             to check for pending error conditions.CNcomment:
*                                             ָ��ָ��struct fd_set��ָ�룬��ָ��Ҫ���������������������CNend
* @param     timeout    [IN]  Type #struct timeval *  Specifies a pointer to struct timeval, for timeout application.
*                                                      CNcomment:Ϊ��ʱӦ�ó���ָ��ָ��struct timeval��ָ��CNend
* @retval #>0     Execute successfully.
* @retval #-1     Execute failed.
* @par Dependency:
*       #NULL
* @see  NULL
* @since Hi3861_V100R001C00
*/
#if LWIP_TIMEVAL_PRIVATE
int select(int maxfdp1, fd_set *readset, fd_set *writeset, fd_set *exceptset,
           struct timeval *timeout);
#endif
/**
* @ingroup  hi_net_basic
* @brief Initiates transmission of a message from the specified socket to its peer.CNcomment:����ָ��������Ϣ���Զ�CNend
*
* @par Description:
*      Initiates transmission of a message from the specified socket to its peer
*      CNcomment:������ָ���׽��ֵ���Եȶ˵���Ϣ���䡣CNend
*
* @attention  NULL
* @param      s      [IN]   Type #int  Indicates the socket file descriptor.CNcomment:ָ���ļ�������CNend
* @param      cmd    [IN]   Type #int  Indicates a command to select an operation[F_GETFL, F_SETFL].
*                                      CNcomment:ָʾѡ�����������[F_GETFL, F_SETFL]CNend
* @param      val    [IN]   Type #int  Indicates an additional flag, to set non-blocking.
*                                      CNcomment:ָʾһ�����ӱ�־�������÷�����CNend
* @retval #0               Execute successfully.
* @retval #-1 & Others     Execute failed.
* @par Dependency:
*       #NULL
* @see  NULL
* @since Hi3861_V100R001C00
*/
int fcntl(int s, int cmd, int val);

/**
* @ingroup  hi_net_basic
* @brief  Close the socket.CNcomment:�ر��׽���CNend
*
* @par Description:
*      If O_NONBLOCK is not set and if there is data on the module's write queue,
*      close() waits for an unspecified time for any output to drain before dismantling the STREAM.
*      If the O_NONBLOCK flag is set,close() does not wait for output to drain, and dismantles the STREAM immediately.
*      CNcomment:���δ����O_NONBLOCK������ģ���д�������������,close()�ȴ�δָ����ʱ��,�ȴ��κ�����ų�,Ȼ���ٲ�ж��.
*                ���������O_NONBLOCK��־,close()����ȴ�����ľ�,������ȡ����CNend
*
* @attention  NULL
* @param      s    [IN]     Type #int  Indicates the socket file descriptor.CNcomment:ָ���ļ�������CNend
* @retval #0               Execute successfully.
* @retval #-1 & Others     Execute failed.
* @par Dependency:
*       #NULL
* @see  NULL
* @since Hi3861_V100R001C00
*/
int closesocket(int s);
#define close(s)  closesocket(s)

#ifdef __cplusplus
}
#endif

#endif
