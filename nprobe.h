/* 
 *        nProbe - a Netflow v5/v9/IPFIX probe for IPv4/v6 
 *
 *       Copyright (C) 2002-2010 Luca Deri <deri@ntop.org> 
 *
 *                     http://www.ntop.org/ 
 * 
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License along
 *  with this program; if not, write to the Free Software Foundation, Inc.,
 *  51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#ifndef _NPROBE_H_
#define _NPROBE_H_

/* *************************** */

/* #define DEMO */

#define MAX_DEMO_FLOWS    2000
#ifdef DEMO
#define DEMO_MODE
//#define MAKE_STATIC_PLUGINS
#endif

/* *************************** */


#include "config.h"

/* See http://www.redhat.com/magazine/009jul05/features/execshield/ */
#ifndef _FORTIFY_SOURCE
#define _FORTIFY_SOURCE 2
#endif

#if defined(linux) || defined(__linux__)
/*
 * This allows to hide the (minimal) differences between linux and BSD
 */
#include <features.h>
#ifndef __FAVOR_BSD
#define __FAVOR_BSD
#endif
#ifndef _BSD_SOURCE
#define _BSD_SOURCE
#endif
#endif /* linux || __linux__ */

#ifdef WIN32
#include <winsock2.h> /* winsock.h is included automatically */
#include <process.h>
#include "dirent.h"
#endif

#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#ifdef HAVE_SYS_TIME_H
#include <sys/time.h>
#endif
#include <signal.h>
#include <fcntl.h>
#include <ctype.h>
#include <string.h>
#ifndef WIN32
#include <strings.h>
#endif
#include <limits.h>
#include <float.h>
#include <math.h>
#include <sys/types.h>
#ifdef linux
#include <sys/sysinfo.h>
#endif

#ifdef HAVE_SCHED_H
#ifndef __USE_GNU
#define  __USE_GNU
#endif
#include <sched.h>
#endif

#ifndef WIN32
#include <sys/mman.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>

#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <netdb.h>

#ifdef HAVE_GDBM
#include <gdbm.h>
#endif

/* Courtesy of Curt Sampson  <cjs@cynic.net> */
#ifdef __NetBSD__
#include <net/if_ether.h>
#endif
#ifdef HAVE_NETINET_IF_ETHER_H
#include <netinet/if_ether.h>
#endif

#ifdef HAVE_NET_ETHERNET_H
#include <net/ethernet.h>
#endif

#include <netinet/in_systm.h>

#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#endif

#ifndef EMBEDDED
#include <sys/stat.h>
#endif

#ifdef __TILECC__
#include "pcap.h"
#else
#include <pcap.h>
#endif

#ifdef HAVE_DL_H
#include <dl.h>
#endif

#ifdef HAVE_DLFCN_H
#include <dlfcn.h>
#endif

#ifdef HAVE_DIRENT_H
#include <dirent.h>
#endif

#ifdef WIN32
#define HAVE_MYSQL
#define HAVE_SQLITE
#endif

#ifdef HAVE_MYSQL
#include <mysql.h>
#define MYSQL_OPT              "--mysql"
#define MYSQL_SKIP_DB_CREATION "--mysql-skip-db-creation"
#endif

#ifdef HAVE_LIBSQLITE3
#define HAVE_SQLITE
#endif

#ifdef HAVE_SQLITE
#include <sqlite3.h>
#endif

/* GeoIP */
#ifdef HAVE_GEOIP
#include "GeoIP.h"
#include "GeoIPCity.h"
#endif

#define TEMPLATE_LIST_LEN   50

typedef struct ether80211q {
  u_int16_t vlanId;
  u_int16_t protoType;
} Ether80211q;

#ifndef TH_FIN
#define TH_FIN  0x01
#endif
#ifndef TH_SYN
#define TH_SYN  0x02
#endif
#ifndef TH_RST
#define TH_RST  0x04
#endif
#ifndef TH_PUSH
#define TH_PUSH 0x08
#endif
#ifndef TH_ACK
#define TH_ACK  0x10
#endif
#ifndef TH_URG
#define TH_URG  0x20
#endif

#ifdef __TILECC__
#include "private/tilera/tilera_pthread.h"
#endif

#ifndef WIN32
#ifndef __TILECC__
#include <pthread.h>
#endif /* __TILECC__ */

#include <stdarg.h>
#include <syslog.h>

#ifndef PTHREAD_RWLOCK_INITIALIZER
#undef HAVE_RW_LOCK
#endif

#ifndef HAVE_RW_LOCK
#define pthread_rwlock_t       pthread_mutex_t
#define pthread_rwlock_init    pthread_mutex_init
#define pthread_rwlock_wrlock  pthread_mutex_lock
#define pthread_rwlock_unlock  pthread_mutex_unlock
#endif


#else /* WIN32 */
#define pthread_t              HANDLE
#define pthread_mutex_t        HANDLE
#define pthread_rwlock_t       HANDLE


/*
 * Ethernet address - 6 octets
 */
struct ether_addr {
  u_char ether_addr_octet[6];
};

/*
 * Structure of a 10Mb/s Ethernet header.
 */
struct ether_header {
  u_char  ether_dhost[6];
  u_char  ether_shost[6];
  u_short ether_type;
};

#if !defined (__GNUC__)
typedef u_int tcp_seq;
#endif

/*
 * TCP header.
 * Per RFC 793, September, 1981.
 */
struct tcphdr {
  u_short th_sport;   /* source port */
  u_short th_dport;   /* destination port */
  tcp_seq th_seq;     /* sequence number */
  tcp_seq th_ack;     /* acknowledgement number */
#if BYTE_ORDER == LITTLE_ENDIAN
  u_char  th_x2:4,    /* (unused) */
    th_off:4;   /* data offset */
#else
  u_char  th_off:4,   /* data offset */
    th_x2:4;    /* (unused) */
#endif
  u_char  th_flags;
  u_short th_win;     /* window */
  u_short th_sum;     /* checksum */
  u_short th_urp;     /* urgent pointer */
};

/* ********************************************* */

struct ip {
#if BYTE_ORDER == LITTLE_ENDIAN
  u_char  ip_hl:4,    /* header length */
    ip_v:4;     /* version */
#else
  u_char  ip_v:4,     /* version */
    ip_hl:4;    /* header length */
#endif
  u_char  ip_tos;     /* type of service */
  short ip_len;     /* total length */
  u_short ip_id;      /* identification */
  short ip_off;     /* fragment offset field */
#define IP_DF 0x4000      /* dont fragment flag */
#define IP_MF 0x2000      /* more fragments flag */
#define IP_OFFMASK 0x1fff   /* mask for fragmenting bits */
  u_char  ip_ttl;     /* time to live */
  u_char  ip_p;     /* protocol */
  u_short ip_sum;     /* checksum */
  struct  in_addr ip_src,ip_dst;  /* source and dest address */
};

/* ********************************************* */

/*
 * Udp protocol header.
 * Per RFC 768, September, 1981.
 */
struct udphdr {
  u_short uh_sport;   /* source port */
  u_short uh_dport;   /* destination port */
  short uh_ulen;    /* udp length */
  u_short uh_sum;     /* udp checksum */
};

extern int gettimeofday(struct timeval *tv, struct timezone *tz);
extern char *strtok_r(char *s, const char *delim, char **save_ptr);
extern int nprobe_sleep(int secToSleep);

extern int pthread_create(pthread_t *threadId, void* notUsed, void *(*__start_routine) (void *), char* userParm);
extern void pthread_detach(pthread_t *threadId);
extern int pthread_mutex_init(pthread_mutex_t *mutex, char* notused);
extern void pthread_mutex_destroy(pthread_mutex_t *mutex);
extern int pthread_mutex_lock(pthread_mutex_t *mutex);
extern int pthread_mutex_trylock(pthread_mutex_t *mutex);
extern int pthread_mutex_unlock(pthread_mutex_t *mutex);

#define pthread_rwlock_init     pthread_mutex_init
#define pthread_rwlock_wrlock     pthread_mutex_lock
#define pthread_rwlock_unlock     pthread_mutex_unlock

#endif /* WIN32 */

/* DNS header */
typedef struct {
  u_int16_t id;
  u_int8_t flags1;
  u_int8_t flags2;
  u_int16_t qdcount;
  u_int16_t ancount;
  u_int16_t nscount;
  u_int16_t arcount;
} HEADER;

#define NAMESERVER_PORT  53
#define DNS_QR(np)  ((np)->flags1 & 0x80)   /* response flag */


#include "bucket.h"

/* GPRS Tunneling Protocol */
struct gtp_header {
  u_int8_t flags, message_type;
  u_int16_t total_length;
  u_int32_t tunnel_id;
  u_int16_t sequence_number;
  u_int8_t pdu_nuber, next_ext_header;
};

/* VxLAN Protocol */
struct vxlan_header {
  u_int8_t i;
  // 0x ....I...
  u_int8_t resv0[3];
  u_int8_t vni[3];
  u_int8_t resv1;
};

/* GRE Protocol */
struct gre_header {
  u_int16_t c_p:1;
  u_int16_t r_p:1;
  u_int16_t k_p:1;
  u_int16_t s_p:1;
  u_int16_t resv0:9;
  u_int16_t ver:3;
  u_int16_t protocol;
};

#define NPROBE_REVISION "$Revision: 2212 $"
extern char nprobe_revision[];

typedef enum {
  text_format = 0,
  sqlite_format,
  binary_format
} DumpFormat;

extern void allocateHash(void);

#ifdef ETHER_HEADER_HAS_EA
#  define ESRC(ep) ((ep)->ether_shost.ether_addr_octet)
#  define EDST(ep) ((ep)->ether_dhost.ether_addr_octet)
#else
#  define ESRC(ep) ((ep)->ether_shost)
#  define EDST(ep) ((ep)->ether_dhost)
#endif

/* BSD AF_ values. */
#define BSD_AF_INET             2
#define BSD_AF_INET6_BSD        24      /* OpenBSD (and probably NetBSD), BSD/OS */
#define BSD_AF_INET6_FREEBSD    28
#define BSD_AF_INET6_DARWIN     30

#if defined(DARWIN) && !defined(SNOW_LEOPARD)
#define PLUGIN_EXTENSION          "Plugin.dylib"
#else
#define PLUGIN_EXTENSION          "Plugin.so"
#endif

#if !defined(HAVE_U_INT32_T)
typedef unsigned int u_int32_t;
#endif

#if !defined(HAVE_U_INT16_T)
typedef unsigned short u_int16_t;
#endif

#if !defined(HAVE_U_INT8_T)
typedef unsigned char u_int8_t;
#endif

#if !defined(HAVE_INT32_T)
typedef int int32_t;
#endif

#if !defined(HAVE_INT16_T)
typedef short int16_t;
#endif

#if !defined(HAVE_INT8_T)
typedef char int8_t;
#endif

#ifndef bool
#define bool u_int8_t
#endif

/*
  Courtesy of http://ettercap.sourceforge.net/
*/
#ifndef CFG_LITTLE_ENDIAN
#define ptohs(x) ( (u_int16_t)                       \
                      ((u_int16_t)*((u_int8_t *)x+1)<<8|  \
                      (u_int16_t)*((u_int8_t *)x+0)<<0)   \
                    )

#define ptohl(x) ( (u_int32)*((u_int8_t *)x+3)<<24|  \
                      (u_int32)*((u_int8_t *)x+2)<<16|  \
                      (u_int32)*((u_int8_t *)x+1)<<8|   \
                      (u_int32)*((u_int8_t *)x+0)<<0    \
                    )
#else
#define ptohs(x) *(u_int16_t *)(x)
#define ptohl(x) *(u_int32 *)(x)
#endif

#define TCPOPT_EOL              0
#define TCPOPT_NOP              1
#define TCPOPT_MAXSEG           2
#define TCPOPT_WSCALE           3
#define TCPOPT_SACKOK           4
#define TCPOPT_TIMESTAMP        8

/* ************************************ */

#ifndef ETHERTYPE_IP
#define ETHERTYPE_IP    0x0800  /* IP protocol */
#endif

#ifndef ETHERTYPE_IPV6
#define ETHERTYPE_IPV6    0x86DD  /* IPv6 protocol */
#endif

#ifndef ETHERTYPE_MPLS
#define ETHERTYPE_MPLS    0x8847  /* MPLS protocol */
#endif

#ifndef ETHERTYPE_MPLS_MULTI
#define ETHERTYPE_MPLS_MULTI  0x8848  /* MPLS multicast packet */
#endif

#ifndef ETHERTYPE_PPPoE
#define ETHERTYPE_PPPoE   0x8864  /* PPP over Ethernet */
#endif

struct ether_mpls_header {
  u_char label, exp, bos;
  u_char ttl;
};

struct ppp_header {
  u_int8_t address, control;
  u_int16_t proto;
};

#define NULL_HDRLEN             4

#ifndef SOLARIS
/* VLAN support - Courtesy of  Mikael Cam <mca@mgn.net> - 2002/08/28 */
#ifndef ETHER_ADDR_LEN
#define ETHER_ADDR_LEN  6
#endif

struct  ether_vlan_header {
  u_char    evl_dhost[ETHER_ADDR_LEN];
  u_char    evl_shost[ETHER_ADDR_LEN];
  u_int16_t evl_encap_proto;
  u_int16_t evl_tag;
  u_int16_t evl_proto;
};
#endif

#ifdef SOLARIS
struct  ip6_ext {
        u_int8_t ip6e_nxt;
        u_int8_t ip6e_len;
} __attribute__((__packed__));
#endif

#define NO_VLAN       (u_int16_t)-1
#define MAX_VLAN      4096

#ifndef ETHERTYPE_VLAN
#define ETHERTYPE_VLAN    0x08100
#endif

typedef struct ipV4Fragment {
  u_int32_t src, dst;
  u_short fragmentId, numPkts, len, sport, dport;
  time_t firstSeen;
  struct ipV4Fragment *next;
} IpV4Fragment;

/* ************************************ */

#define TRANSPORT_UDP          1
#define TRANSPORT_TCP          2
#define TRANSPORT_SCTP         3
#ifdef IP_HDRINCL
#define TRANSPORT_UDP_RAW      4
#endif

typedef struct collectorAddress {
  u_char isIPv6; /* 0=IPv4, 1=IPv6 or anything else (generic addrinfo) */     
  u_char transport; /* TRANSPORT_XXXX */
  u_int  flowSequence;

  union {
    struct sockaddr_in v4Address;
#ifndef IPV4_ONLY
    struct sockaddr_in6 v6Address;
#endif
  } u;

  int sockFd; /* Socket file descriptor */
  struct timeval lastExportTime; /* Time when last packet was exported [Set only with -e] */
} CollectorAddress;

/* ************************************ */

#ifndef WIN32
#include <pthread.h>

typedef struct conditionalVariable {
  pthread_mutex_t mutex;
  pthread_cond_t  condvar;
  int predicate;
} ConditionalVariable;

#else

typedef struct conditionalVariable {
  HANDLE condVar;
  CRITICAL_SECTION criticalSection;
} ConditionalVariable;

#endif

extern int createCondvar(ConditionalVariable *condvarId);
extern void deleteCondvar(ConditionalVariable *condvarId);
extern int waitCondvar(ConditionalVariable *condvarId);
extern int signalCondvar(ConditionalVariable *condvarId, int broadcast);

#define TEMP_PREFIX        ".temp"
#define BUF_SIZE           512

#define NO_INTERFACE_INDEX ((u_int16_t)-1)

#define TRACE_ERROR     0, __FILE__, __LINE__
#define TRACE_WARNING   1, __FILE__, __LINE__
#define TRACE_NORMAL    2, __FILE__, __LINE__
#define TRACE_INFO      3, __FILE__, __LINE__

/* ************************************************ */

extern char *optarg;

/* ********** ICMP ******************** */

#ifdef WIN32

struct icmp_ra_addr
{
  u_int32_t ira_addr;
  u_int32_t ira_preference;
};
#endif /* WIN32 */

struct icmp_hdr
{
  u_int8_t  icmp_type;   /* type of message, see below */
  u_int8_t  icmp_code;   /* type sub code */
  u_int16_t icmp_cksum;  /* ones complement checksum of struct */
  u_int16_t icmp_identifier, icmp_seqnum;

};

/*
 * Definition of ICMP types and code field values.
 */
#define NPROBE_ICMP_ECHOREPLY   0   /* echo reply */
#define NPROBE_ICMP_UNREACH   3   /* dest unreachable, codes: */
#define NPROBE_ICMP_UNREACH_NET         0   /* bad net */
#define NPROBE_ICMP_UNREACH_HOST  1   /* bad host */
#define NPROBE_ICMP_UNREACH_PROTOCOL  2   /* bad protocol */
#define NPROBE_ICMP_UNREACH_PORT  3   /* bad port */
#define NPROBE_ICMP_UNREACH_NEEDFRAG  4   /* IP_DF caused drop */
#define NPROBE_ICMP_UNREACH_SRCFAIL 5   /* src route failed */
#define NPROBE_ICMP_UNREACH_NET_UNKNOWN 6   /* unknown net */
#define NPROBE_ICMP_UNREACH_HOST_UNKNOWN 7    /* unknown host */
#define NPROBE_ICMP_UNREACH_ISOLATED  8   /* src host isolated */
#define NPROBE_ICMP_UNREACH_NET_PROHIB  9   /* prohibited access */
#define NPROBE_ICMP_UNREACH_HOST_PROHIB 10    /* ditto */
#define NPROBE_ICMP_UNREACH_TOSNET  11    /* bad tos for net */
#define NPROBE_ICMP_UNREACH_TOSHOST 12    /* bad tos for host */
#define NPROBE_ICMP_UNREACH_FILTER_PROHIB 13    /* admin prohib */
#define NPROBE_ICMP_UNREACH_HOST_PRECEDENCE 14    /* host prec vio. */
#define NPROBE_ICMP_UNREACH_PRECEDENCE_CUTOFF 15  /* prec cutoff */
#define NPROBE_ICMP_SOURCEQUENCH   4    /* packet lost, slow down */
#define NPROBE_ICMP_REDIRECT     5    /* shorter route, codes: */
#define NPROBE_ICMP_REDIRECT_NET   0    /* for network */
#define NPROBE_ICMP_REDIRECT_HOST  1    /* for host */
#define NPROBE_ICMP_REDIRECT_TOSNET  2    /* for tos and net */
#define NPROBE_ICMP_REDIRECT_TOSHOST   3    /* for tos and host */
#define NPROBE_ICMP_ECHO     8    /* echo service */
#define NPROBE_ICMP_ROUTERADVERT   9    /* router advertisement */
#define NPROBE_ICMP_ROUTERSOLICIT 10    /* router solicitation */
#define NPROBE_ICMP_TIMXCEED    11    /* time exceeded, code: */
#define NPROBE_ICMP_TIMXCEED_INTRANS   0    /* ttl==0 in transit */
#define NPROBE_ICMP_TIMXCEED_REASS   1    /* ttl==0 in reass */
#define NPROBE_ICMP_PARAMPROB   12    /* ip header bad */
#define NPROBE_ICMP_PARAMPROB_ERRATPTR   0    /* error at param ptr */
#define NPROBE_ICMP_PARAMPROB_OPTABSENT  1    /* req. opt. absent */
#define NPROBE_ICMP_PARAMPROB_LENGTH     2      /* bad length */
#define NPROBE_ICMP_TSTAMP    13    /* timestamp request */
#define NPROBE_ICMP_TSTAMPREPLY         14    /* timestamp reply */
#define NPROBE_ICMP_IREQ    15    /* information request */
#define NPROBE_ICMP_IREQREPLY   16    /* information reply */
#define NPROBE_ICMP_MASKREQ   17    /* address mask request */
#define NPROBE_ICMP_MASKREPLY   18    /* address mask reply */

#define NPROBE_ICMP_MAXTYPE   18

/* ********* NETFLOW ****************** */

#ifdef WIN32
typedef unsigned char u_int8_t;
typedef unsigned short u_int16_t;
typedef unsigned int u_int32_t;
#endif

/*
  For more info see:

  http://www.cisco.com/warp/public/cc/pd/iosw/ioft/neflct/tech/napps_wp.htm

  ftp://ftp.net.ohio-state.edu/users/maf/cisco/
*/

/* ********************************* */

#define FLOW_VERSION_1         1
#define V1FLOWS_PER_PAK       30

struct flow_ver1_hdr {
  u_int16_t version;         /* Current version = 1*/
  u_int16_t count;           /* The number of records in PDU. */
  u_int32_t sysUptime;       /* Current time in msecs since router booted */
  u_int32_t unix_secs;       /* Current seconds since 0000 UTC 1970 */
  u_int32_t unix_nsecs;      /* Residual nanoseconds since 0000 UTC 1970 */
};

struct flow_ver1_rec {
  u_int32_t srcaddr;    /* Source IP Address */
  u_int32_t dstaddr;    /* Destination IP Address */
  u_int32_t nexthop;    /* Next hop router's IP Address */
  u_int16_t input;      /* Input interface index */
  u_int16_t output;     /* Output interface index */
  u_int32_t dPkts;      /* Packets sent in Duration */
  u_int32_t dOctets;    /* Octets sent in Duration */
  u_int32_t first;      /* SysUptime at start of flow */
  u_int32_t last;       /* and of last packet of the flow */
  u_int16_t srcport;    /* TCP/UDP source port number (.e.g, FTP, Telnet, etc.,or equivalent) */
  u_int16_t dstport;    /* TCP/UDP destination port number (.e.g, FTP, Telnet, etc.,or equivalent) */
  u_int16_t pad;        /* pad to word boundary */
  u_int8_t  proto;      /* IP protocol, e.g., 6=TCP, 17=UDP, etc... */
  u_int8_t  tos;        /* IP Type-of-Service */
  u_int8_t  pad2[7];    /* pad to word boundary */
};

typedef struct single_flow_ver1_rec {
  struct flow_ver1_hdr flowHeader;
  struct flow_ver1_rec flowRecord[V1FLOWS_PER_PAK+1 /* safe against buffer overflows */];
} NetFlow1Record;

/* ***************************************** */

#define FLOW_VERSION_5     5
#define V5FLOWS_PER_PAK   30

struct flow_ver5_hdr {
  u_int16_t version;         /* Current version=5*/
  u_int16_t count;           /* The number of records in PDU. */
  u_int32_t sysUptime;       /* Current time in msecs since router booted */
  u_int32_t unix_secs;       /* Current seconds since 0000 UTC 1970 */
  u_int32_t unix_nsecs;      /* Residual nanoseconds since 0000 UTC 1970 */
  u_int32_t flow_sequence;   /* Sequence number of total flows seen */
  u_int8_t  engine_type;     /* Type of flow switching engine (RP,VIP,etc.)*/
  u_int8_t  engine_id;       /* Slot number of the flow switching engine */
  u_int16_t sampleRate;      /* Packet capture sample rate */
};

struct flow_ver5_rec {
  u_int32_t srcaddr;    /* Source IP Address */
  u_int32_t dstaddr;    /* Destination IP Address */
  u_int32_t nexthop;    /* Next hop router's IP Address */
  u_int16_t input;      /* Input interface index */
  u_int16_t output;     /* Output interface index */
  u_int32_t dPkts;      /* Packets sent in Duration (milliseconds between 1st
         & last packet in this flow)*/
  u_int32_t dOctets;    /* Octets sent in Duration (milliseconds between 1st
         & last packet in  this flow)*/
  u_int32_t first;      /* SysUptime at start of flow */
  u_int32_t last;       /* and of last packet of the flow */
  u_int16_t srcport;    /* TCP/UDP source port number (.e.g, FTP, Telnet, etc.,or equivalent) */
  u_int16_t dstport;    /* TCP/UDP destination port number (.e.g, FTP, Telnet, etc.,or equivalent) */
  u_int8_t pad1;        /* pad to word boundary */
  u_int8_t tcp_flags;   /* Cumulative OR of tcp flags */
  u_int8_t proto;        /* IP protocol, e.g., 6=TCP, 17=UDP, etc... */
  u_int8_t tos;         /* IP Type-of-Service */
  u_int16_t src_as;     /* source peer/origin Autonomous System */
  u_int16_t dst_as;     /* dst peer/origin Autonomous System */
  u_int8_t src_mask;    /* source route's mask bits */
  u_int8_t dst_mask;    /* destination route's mask bits */
  u_int16_t pad2;       /* pad to word boundary */
};

typedef struct single_flow_ver5_rec {
  struct flow_ver5_hdr flowHeader;
  struct flow_ver5_rec flowRecord[V5FLOWS_PER_PAK+1 /* safe against buffer overflows */];
} NetFlow5Record;

/* ************************************ */

#define FLOW_VERSION_7        7
#define V7FLOWS_PER_PAK       28

/* ********************************* */

struct flow_ver7_hdr {
  u_int16_t version;         /* Current version=7*/
  u_int16_t count;           /* The number of records in PDU. */
  u_int32_t sysUptime;       /* Current time in msecs since router booted */
  u_int32_t unix_secs;       /* Current seconds since 0000 UTC 1970 */
  u_int32_t unix_nsecs;      /* Residual nanoseconds since 0000 UTC 1970 */
  u_int32_t flow_sequence;   /* Sequence number of total flows seen */
  u_int32_t reserved;
};

struct flow_ver7_rec {
  u_int32_t srcaddr;    /* Source IP Address */
  u_int32_t dstaddr;    /* Destination IP Address */
  u_int32_t nexthop;    /* Next hop router's IP Address */
  u_int16_t input;      /* Input interface index */
  u_int16_t output;     /* Output interface index */
  u_int32_t dPkts;      /* Packets sent in Duration */
  u_int32_t dOctets;    /* Octets sent in Duration */
  u_int32_t first;      /* SysUptime at start of flow */
  u_int32_t last;       /* and of last packet of the flow */
  u_int16_t srcport;    /* TCP/UDP source port number (.e.g, FTP, Telnet, etc.,or equivalent) */
  u_int16_t dstport;    /* TCP/UDP destination port number (.e.g, FTP, Telnet, etc.,or equivalent) */
  u_int8_t  flags;      /* Shortcut mode(dest only,src only,full flows*/
  u_int8_t  tcp_flags;  /* Cumulative OR of tcp flags */
  u_int8_t  proto;      /* IP protocol, e.g., 6=TCP, 17=UDP, etc... */
  u_int8_t  tos;        /* IP Type-of-Service */
  u_int16_t dst_as;     /* dst peer/origin Autonomous System */
  u_int16_t src_as;     /* source peer/origin Autonomous System */
  u_int8_t  dst_mask;   /* destination route's mask bits */
  u_int8_t  src_mask;   /* source route's mask bits */
  u_int16_t pad2;       /* pad to word boundary */
  u_int32_t router_sc;  /* Router which is shortcut by switch */
};

typedef struct single_flow_ver7_rec {
  struct flow_ver7_hdr flowHeader;
  struct flow_ver7_rec flowRecord[V7FLOWS_PER_PAK+1 /* safe against buffer overflows */];
} NetFlow7Record;

/* ************************************ */

#define IN_PAYLOAD_ID         96
#define OUT_PAYLOAD_ID        97

/* NetFlow v9/IPFIX */

typedef struct flow_ver9_hdr {
  u_int16_t version;         /* Current version=9*/
  u_int16_t count;           /* The number of records in PDU. */
  u_int32_t sysUptime;       /* Current time in msecs since router booted */
  u_int32_t unix_secs;       /* Current seconds since 0000 UTC 1970 */
  u_int32_t flow_sequence;   /* Sequence number of total flows seen */
  u_int32_t sourceId;        /* Source id */
} V9FlowHeader; 

typedef struct flow_ver9_template_field {
  u_int16_t fieldType;
  u_int16_t fieldLen;
} V9TemplateField;

typedef struct flow_ver9_template {
  u_int16_t templateFlowset; /* = 0 */
  u_int16_t flowsetLen;
  u_int16_t templateId;
  u_int16_t fieldCount;
} V9Template;

typedef struct flow_ver9_option_template {
  u_int16_t templateFlowset; /* = 0 */
  u_int16_t flowsetLen;
  u_int16_t templateId;
  u_int16_t optionScopeLen;
  u_int16_t optionLen;
} V9OptionTemplate;

typedef struct flow_ver9_flow_set {
  u_int16_t templateId;
  u_int16_t flowsetLen;
} V9FlowSet;

typedef struct ipfix_flow_set {
  u_int16_t templateId;
  u_int16_t fieldCount;
} IPFIXFlowSet;

typedef struct flowSetV9 {
  V9Template templateInfo;
  V9TemplateField *fields;
  struct flowSetV9 *next;
} FlowSetV9;

#define STANDARD_ENTERPRISE_ID            0
#define NTOP_ENTERPRISE_ID           0x1968

typedef enum {
  ascii_format = 0,
  hex_format,
  numeric_format,
  ipv6_address_format
} ElementFormat;

typedef enum {
  /* 
     NOTE

     whenever this datastructure is updated
     you ought to also update
     dumpformat2ascii and printMetadata (plugin.c)
  */
  dump_as_uint = 0, /* 1234567890 */
  dump_as_formatted_uint, /* 123'456 */
  dump_as_ip_port,
  dump_as_ip_proto,
  dump_as_ipv4_address,
  dump_as_ipv6_address,
  dump_as_mac_address,
  dump_as_epoch,
  dump_as_bool,
  dump_as_tcp_flags,
  dump_as_hex,
  dump_as_ascii
} ElementDumpFormat;

#define FLOW_TEMPLATE       0
#define OPTION_TEMPLATE     1

typedef struct flow_ver9_ipfix_template_elementids {
  u_int8_t  isOptionTemplate; /* 0=flow template, 1=option template */
  u_int32_t templateElementEnterpriseId;
  u_int16_t templateElementId;
  u_int16_t templateElementLen;
  ElementFormat elementFormat; /* Only for elements longer than 4 bytes */
  ElementDumpFormat fileDumpFormat; /* Hint when data has to be printed on
               a human readable form */
  char      *templateElementName, *templateElementDescr;
} V9V10TemplateElementId;

#define NTOP_BASE_ID 57472

/* ******************************************* */

/*
  0                   1                   2                   3 
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ 
   |       Version Number          |            Length             | 
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ 
   |                           Export Time                         | 
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ 
   |                       Sequence Number                         | 
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ 
   |                    Observation Domain ID                      | 
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ 
*/
  
typedef struct flow_ipfix_hdr {
  u_int16_t version;             /* Current version = 10 */
  u_int16_t count;               /* The number of records in PDU. */
  u_int32_t sysUptime;           /* Current time in msecs since router booted */
  u_int32_t flow_sequence;       /* Sequence number of total flows seen */
  u_int32_t observationDomainId; /* Source id */
} IPFIXFlowHeader;

typedef struct flow_ipfix_set {
  u_int16_t set_id, set_len;
} IPFIXSet;

typedef struct flow_ipfix_field {
  u_int16_t field_id, field_len;
  u_int32_t enterprise_number;
} IPFIXField;

/* Bitmask */
typedef struct {
  u_int32_t num_bits;
  void *bits_memory;
} bitmask_selector;

/* ******************************************* */

#define NETFLOW_MAX_BUFFER_LEN    1440
#define MAX_EXPORT_QUEUE_LEN   20*65536

#define ACT_NUM_PCAP_THREADS      2
#define MAX_NUM_PCAP_THREADS     32

#define DEFAULT_INPUT_INTERFACE_INDEX  0
#define DEFAULT_OUTPUT_INTERFACE_INDEX 0

/* It must stay here as it needs the definition of v9 types */
#include "engine.h"
#include "util.h"

#ifdef HAVE_RFLOWS
#include "pro/rflows.h"
#endif

#ifdef HAVE_PF_RING
#include "pro/pf_ring.h"
#define CHECKSUM
#endif

/* ************************************ */

/*

############################################################################
#                                                                          #
# The fingerprint database has the following structure:                    #
#                                                                          #
# WWWW:MSS:TTL:WS:S:N:D:T:F:LEN:OS                                         #
#                                                                          #
# WWWW: 4 digit hex field indicating the TCP Window Size                   #
# MSS : 4 digit hex field indicating the TCP Option Maximum Segment Size   #
#       if omitted in the packet or unknown it is "_MSS"                   #
# TTL : 2 digit hex field indicating the IP Time To Live                   #
# WS  : 2 digit hex field indicating the TCP Option Window Scale           #
#       if omitted in the packet or unknown it is "WS"                     #
# S   : 1 digit field indicating if the TCP Option SACK permitted is true  #
# N   : 1 digit field indicating if the TCP Options contain a NOP          #
# D   : 1 digit field indicating if the IP Don't Fragment flag is set      #
# T   : 1 digit field indicating if the TCP Timestamp is present           #
# F   : 1 digit ascii field indicating the flag of the packet              #
#       S = SYN                                                            #
#       A = SYN + ACK                                                      #
# LEN : 2 digit hex field indicating the length of the packet              #
#       if irrilevant or unknown it is "LT"                                #
# OS  : an ascii string representing the OS                                #
#                                                                          #
# IF YOU FIND A NEW FINGERPRING, PLEASE MAIL IT US WITH THE RESPECTIVE OS  #
# or use the appropriate form at:                                          #
#    http://ettercap.sourceforge.net/index.php?s=stuff&p=fingerprint       #
#                                                                          #
# TO GET THE LATEST DATABASE:                                              #
#                                                                          #
#    http://cvs.sourceforge.net/cgi-bin/viewcvs.cgi/~checkout~/ettercap/   #
#           ettercap/etter.passive.os.fp?rev=HEAD&content-type=text/plain  #
#                                                                          #
############################################################################
*/


#define MAX_PAYLOAD_LEN         1400
#define MAX_HASH_MUTEXES        1024

/* ************************************ */

struct mypcap {
  int fd, snapshot, linktype, tzoff, offset;
  FILE *rfile;

  /* Other fields have been skipped. Please refer
     to pcap-int.h for the full datatype.
  */
};

/* ******** ANY (Linux) ************ */

#ifndef DLT_ANY
#define DLT_ANY 113
#endif

typedef struct anyHeader {
  u_int16_t  pktType;
  u_int16_t  llcAddressType;
  u_int16_t  llcAddressLen;
  u_char     ethAddress[6];
  u_int16_t  pad;
  u_int16_t  protoType;
} AnyHeader;

/* ************************************ */

#define DUMP_TIMEOUT      30   /* seconds */
#define PCAP_FILE_TIMEOUT 300

/* #define DEBUG  */

#define MIN_HASH_SIZE       4096 /* buckets */
#define DEFAULT_HASH_SIZE  32768 /* buckets */

#if 0
#define getopt getopt____
extern int getopt(int num, char *const *argv, const char *opts);
extern char *optarg;
#else
#include <getopt.h>
#endif

/* *************************** */

/* version.c */
extern char *version, *osName, *buildDate;

/* **************************************************************** */

struct ip_header {
#if BYTE_ORDER == LITTLE_ENDIAN
  u_int ihl:4,    /* header length */
    version:4;      /* version */
#else
  u_int version:4,      /* version */
    ihl:4;    /* header length */
#endif
  u_char  tos;      /* type of service */
  u_short tot_len;      /* total length */
  u_short id;     /* identification */
  u_short frag_off;     /* fragment offset field */
  u_char  ttl;      /* time to live */
  u_char  protocol;     /* protocol */
  u_short check;      /* checksum */
        u_int32_t saddr, daddr; /* source and dest address */
};

/*
 * Udp protocol header.
 * Per RFC 768, September, 1981.
 */
struct udp_header {
  u_short source;   /* source port */
  u_short dest;   /* destination port */
  u_short len;    /* udp length */
  u_short check;    /* udp checksum */
};

/* ************************************* */

#define MAX_NUM_COLLECTORS          8
#define MAX_NUM_OPTIONS            48
#define DISPLAY_TIME               30
#define DEFAULT_TEMPLATE_ID       257
#define NUM_MAC_INTERFACES          8
#define TCP_PROTOCOL             0x06
#define DEFAULT_FASTBIT_MINS_ROTATION 5
#define NUM_FRAGMENT_LISTS         64
#define GTP_DATA_PORT            2152
#define VXLAN_DATA_PORT          4789
#ifdef WIN32
typedef float Counter;
#else
typedef unsigned long long Counter;
#endif

struct mac_export_if {
  u_char mac_address[6];
  u_int16_t interface_id;
};

struct fileList {
  char *path;
  struct fileList *next;
};

typedef struct {
#ifndef WIN32
  u_char becomeDaemon;
#endif
  u_int pktSampleRate, flowSampleRate, capture_num_packet_and_quit, fakePktSampling;
  u_int8_t setAllNonLocalHostsToZero, setLocalTrafficDirection,
    none_specified, rebuild_hash, promisc_mode, tunnel_mode;
  u_int maxNumActiveFlows;
  u_int idTemplate;
  char *dump_stats_path;
  int collectorInPort;
#ifdef linux
  short cpuAffinity; /* -1 means no affinity */
#endif
#ifdef HAVE_RFLOWS
  int rflows_fd, rflows_port;
#endif
  struct timeval initialSniffTime;
  u_short flowExportDelay, scanCycle;
  /* -B support courtesy of Mark Notarus <notarus@uiuc.edu> */
  u_short packetFlowGroup; /* # packets to send before we delay */
#ifndef WIN32
  char nprobeId[255+1];
#endif
  struct fileList *pcapFileList;
  char *pcapFile, *flowLockFile, *pidPath;
  u_char ignoreVlan, ignoreProtocol, ignoreIP, 
    ignorePorts, ignoreTos, usePortsForICMP;
  u_char reflectorMode, calculateJitter, handleFragments;
  pcap_t *pcapPtr;
  int datalink;
  char *tmpDev, *netFilter, *flowDumpFormat;
  char *addr, *port, *lcdDevice;
  char *bindAddr, *bindPort;
  u_int16_t inputInterfaceIndex, outputInterfaceIndex;
  char *dirPath;
  u_char useNetFlow, computeFingerprint, dontSentBidirectionalV9Flows, use_vlanId_as_ifId;
  char *stringTemplate;
  u_int file_dump_timeout;

  /* MAC Export */
  struct mac_export_if mac_if_match[NUM_MAC_INTERFACES];

  /* Export Options */
  u_char netFlowVersion, bidirectionalFlows;
  short minNumFlowsPerPacket;
  u_short templatePacketsDelta;
  struct sockaddr_in sockIn;
  u_short packetsBeforeSendingTemplates;
  u_short numPcapThreads;
  u_int8_t enableHostStats;

  /* V9 Templates */
  V9V10TemplateElementId *v9TemplateElementList[TEMPLATE_LIST_LEN];
  char templateBuffer[NETFLOW_MAX_BUFFER_LEN];
  u_int templateBufBegin, templateBufMax, minFlowSize;
  int  numTemplateFieldElements;
  /* approximate # of flows that the template takes up */
  u_short templateFlowSize;

  /* V9 Options */
  V9V10TemplateElementId *v9OptionTemplateElementList[TEMPLATE_LIST_LEN];
  char optionTemplateBuffer[NETFLOW_MAX_BUFFER_LEN];
  u_int optionTemplateBufBegin, optionTemplateBufMax, flowHashSize;
  int numOptionTemplateFieldElements;
  /* approximate # of flows that the template takes up */
  u_short optionTemplateFlowSize;

  /* Hosts Hash */
  u_int hostHashSize;

  /* Collectors addresses */
  u_char useIpV6;
  CollectorAddress netFlowDest[MAX_NUM_COLLECTORS];
  u_int8_t numCollectors;
  DumpFormat dumpFormat;
  u_char traceMode;
#ifndef WIN32
  int useSyslog;
#endif
  int traceLevel;
  u_int8_t deferredHostUpdate;
  u_short maxPayloadLen;
  u_short idleTimeout;
  u_short lifetimeTimeout;
  u_short sendTimeout;
  u_int8_t engineType, engineId, accountL2Traffic;
  u_int32_t numLocalNetworks;
  u_char tcpPayloadExport, udpPayloadExport, icmpPayloadExport, otherPayloadExport;
  u_char hasSrcMacExport, srcMacExport[6];
  u_int32_t numBlacklistNetworks;
  char *csv_separator;

  /* FastBit */
#ifdef HAVE_FASTBIT
  char *fastbit_dump_directory, *fastbit_dump_template, 
    *fastbit_index_columns, *fastbit_exec;
  u_int8_t fastbit_index_directory;
  u_short fastbit_mins_rotation;  
#endif

#ifdef HAVE_GEOIP
  /* GeoIP */
  GeoIP *geo_ip_asn_db, *geo_ip_city_db;
#endif

  /* Protocols bitmask */
  bitmask_selector udpProto, tcpProto;

  /* save packet to pcap file */
  u_int8_t isSavePcapFile;
  char *pcapDirPath;
} ReadOnlyGlobals;

typedef struct {
  Counter pkts, bytes;
  Counter tcpFlows, udpFlows, icmpFlows;
  Counter tcpPkts, tcpBytes;
  Counter udpPkts, udpBytes;
  Counter icmpPkts, icmpBytes;
} ProbeStats;

typedef struct {
  time_t now;
  struct timeval lastExportTime;
  FILE *flowFd;
  u_int droppedPktsTooManyFlows;
  u_int numExports, totFlows;
  u_int64_t totExports;
  u_int8_t shutdownInProgress, stopPacketCapture;
  u_int bucketsAllocated;
  FlowHashBucket *exportQueue;
  /* Export Options */
  NetFlow5Record theV5Flow;
  V9FlowHeader theV9Header;
  IPFIXFlowHeader theIPFIXHeader;
  int numFlows;
  char *buffer;
  IpV4Fragment *fragmentsList[NUM_FRAGMENT_LISTS];
  u_int32_t bufferLen;
  u_int32_t exportBucketsLen, fragmentListLen[NUM_FRAGMENT_LISTS];
  u_int32_t totBytesExp, totExpPktSent, totFlowExp, totFlowDropped;
  u_short packetSentCount; /* packets sent before a delay */
  u_char num_src_mac_export;

  /* Flow Sampling */
  u_int flowsToGo; 

  /* Threads */
  pthread_mutex_t exportMutex, fragmentMutex[NUM_FRAGMENT_LISTS];
  pthread_rwlock_t statsRwLock, rwGlobalsRwLock, pcapLock;
  pthread_rwlock_t flowHashRwLock[MAX_NUM_PCAP_THREADS][MAX_HASH_MUTEXES];
  pthread_mutex_t hostHashMutex[MAX_HASH_MUTEXES];
  ConditionalVariable exportQueueCondvar, termCondvar;
  pthread_t dequeueThread, walkHashThread;
  pthread_rwlock_t exportRwLock;
  pthread_rwlock_t pcapFileLock;

  /* Stats */
  time_t lastSample;
  Counter currentPkts, currentBytes;
  ProbeStats accumulateStats, lastMinStats;

#ifdef HAVE_SQLITE
  sqlite3 *sqlite3Handler;
#endif
  u_int sql_row_idx;
  FlowHashBucket **theFlowHash[MAX_NUM_PCAP_THREADS], **thePrevFlowHash[MAX_NUM_PCAP_THREADS];
  HostHashBucket **theHostHash;
  u_int maxBucketSearch;
  struct timeval actTime;
  char dumpFilePath[512];
  u_int lastMaxBucketSearch, numTerminatedFetchPackets;

#ifdef HAVE_FASTBIT
  struct {
    u_int16_t num_entries, max_num_entries, fb_element_len /* < TEMPLATE_LIST_LEN */;
    char *fb_element[TEMPLATE_LIST_LEN]; 
    /* 
       Memory layout:
       
       fb_element[0][max_num_entries]
       fb_element[1][max_num_entries]
       
       fb_element[fb_element_len][max_num_entries]
       
       where each element fb_element[x][y] has length as
       readOnlyGlobals.v9TemplateElementList[x]->templateElementLen             
    */
    pthread_mutex_t fb_mutex;
  } fastbit;
#endif

#ifndef WIN32
  u_char syslog_opened;
#ifdef HAVE_PF_RING
  pfring *ring;
#endif
#endif

#ifdef __TILECC__
  void *total_packets_mutex;
#endif

#ifdef HAVE_FASTBIT
  time_t next_fastbit_rotation;
  char fastbit_actual_dump_dir[256];
  u_int8_t fastbit_dump_switch[TEMPLATE_LIST_LEN];
#endif

  FILE *pcapDumperFile;
  pcap_dumper_t *pcapDumper;
  char pcapFilePath[512];

} ReadWriteGlobals;

#include "globals.h"
#include "export.h"


#ifdef __TILECC__
#include "private/tilera/tilera.h"
#endif

/* ********************************************* */

extern void exportBucket(FlowHashBucket *myBucket, u_char free_memory);
extern void close_dump_file(void);

extern void SavePktToPcap(const struct pcap_pkthdr *h, const u_char *p);
extern void ClosePcapFile(void);

/* nprobe.c */
extern void decodePacket(struct pcap_pkthdr *h, u_char *p,
       int input_index, int output_index,
       u_int32_t flow_sender_ip);
extern void recycleBucket(FlowHashBucket *myBucket);

/* database.c */
extern u_char db_initialized;
extern int exec_sql_query(char *sql, u_char dump_error_if_any);
extern char* get_last_db_error(void);
extern int init_database(char *db_host, char* user, char *pw, 
       char *db_name, char *tp);
extern int init_db_table(void);
extern void dump_flow2db(char *buffer, u_int32_t buffer_len);
extern char * get_db_table_prefix(void);

/* Win32 */
extern void revertSlash(char *str, int mode);

/* engine.c */
extern void addPktToHash(u_int8_t proto, u_char isFragment,
       u_short numPkts, u_char tos,
       u_short vlanId, u_int32_t tunnel_id,
       struct ether_header *ehdr,
       IpAddress src, u_short sport,
       IpAddress dst, u_short dport,
       u_int len, u_int8_t flags,
       u_int8_t icmpType, u_int8_t icmpCode, struct icmp_hdr *icmpPkt,
       u_short numMplsLabels,
       u_char mplsLabels[MAX_NUM_MPLS_LABELS][MPLS_LABEL_LEN],
       u_int16_t if_input, u_int16_t if_output,
       char *fingerprint,
       struct pcap_pkthdr *h, u_char *p,
       u_int16_t payload_shift, int payloadLen,
       time_t firstSeen,
       u_int16_t src_as, u_int16_t dst_as,
       u_int16_t src_mask, u_int16_t dst_mask,
       u_int32_t flow_sender_ip);
extern u_int8_t db_initialized, skip_db_creation;
extern HostHashBucket* findHost(IpAddress *host, u_int8_t allocHostIfNecessary,
        u_int32_t ifHost, u_int16_t ifIdx);
#ifdef HAVE_GEOIP
extern GeoIPRecord* geoLocate(IpAddress *host);
#endif
extern void timeval_diff(struct timeval *begin, struct timeval *end, 
       struct timeval *result, u_short divide_by_two);

/* collect.c */
extern int createNetFlowListener(u_short collectorInPort);
extern void closeNetFlowListener(void);
extern void dissectNetFlow(u_int32_t netflow_device_ip, char *buffer, int bufferLen);

/* sflow_collect.c */
extern void dissectSflow(u_char *buffer, u_int buffer_len, struct sockaddr_in *fromHost);

/* fastbit.c */
#ifdef HAVE_FASTBIT
extern int init_fastbit(char *config_file);
extern void term_fastbit(void);
extern void dump_flow2fastbit(char *buffer, u_int32_t buffer_len);
#endif

//pthread_mutex_t buf_mutex;
#ifdef WIN32
#define strdup(a)    _strdup(a)
#define stricmp(a,b) _stricmp(a,b)
#define snprintf sprintf_s 
#endif

#endif /* _NPROBE_H_ */
