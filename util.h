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

/* ********************** */

#define MAX_NUM_NETWORKS                    64

#define CONST_NETWORK_ENTRY                 0
#define CONST_NETMASK_ENTRY                 1
#define CONST_BROADCAST_ENTRY               2
#define CONST_NETMASK_V6_ENTRY              3
#define CONST_INVALIDNETMASK               -1

#define CONST_NETWORK_SIZE                  4  /* [0]=network, [1]=mask, [2]=broadcast [3]=mask v6 */

/* ********************************************** */

#ifdef WIN32
#define nprobe_sleep(a /* sec */) waitForNextEvent(1000*a /* ms */)
extern unsigned long waitForNextEvent(unsigned long ulDelay /* ms */);
extern void initWinsock32();
extern short isWinNT();
#define close(fd) closesocket(fd)
#else
int nprobe_sleep(int secs);
#endif

extern void traceEvent(const int eventTraceLevel, const char* file, const int line, const char * format, ...);
extern void daemonize(void);
/*
#ifndef WIN32
extern int snprintf(char *string, size_t maxlen, const char *format, ...);
#endif
*/
extern void checkHostFingerprint(char *fingerprint, char *osName, int osNameLen);
extern u_int16_t ip2AS(IpAddress ip);
extern u_int8_t ip2mask(IpAddress ip);
extern void readASs(char *path);
extern void readCities(char *path);
extern V9V10TemplateElementId ver9_templates[];
extern void printTemplateInfo(V9V10TemplateElementId *templates, u_char show_private_elements);
extern void dumpPluginHelp(void);
extern void dumpPluginTemplates(void);
extern void enablePlugins(void);
extern void setupPlugins(void);
extern void flowPrintf(V9V10TemplateElementId **templateList, char *outBuffer,
		       u_int *outBufferBegin, u_int *outBufferMax,
		       int *numElements, char buildTemplate,
		       FlowHashBucket *theFlow, int direction,
		       int addTypeLen, int optionTemplate);
extern void flowFilePrintf(V9V10TemplateElementId **templateList, 
			   FILE *stream, FlowHashBucket *theFlow, int direction);
extern void compileTemplate(char *_fmt, V9V10TemplateElementId **templateList, int templateElements);
extern double toMs(struct timeval theTime);
extern u_int32_t msTimeDiff(struct timeval end, struct timeval begin);
extern unsigned int ntop_sleep(unsigned int secs);
extern FlowHashBucket* getListHead(FlowHashBucket **list);
extern void addToList(FlowHashBucket *bkt, FlowHashBucket **list);
extern void parseLocalAddressLists(char* _addresses);
extern unsigned short isLocalAddress(struct in_addr *addr);
extern uint32_t str2addr(char *address);
extern char* etheraddr_string(const u_char *ep, char *buf);
extern void setPayloadLength(int len);
extern u_int16_t ifIdx(FlowHashBucket *theFlow, int direction, int inputIf);

extern void bitmask_set(u_int32_t n, bitmask_selector* p);
extern void bitmask_clr(u_int32_t n, bitmask_selector* p);
extern u_int8_t bitmask_isset(u_int32_t n, bitmask_selector* p);

extern void loadApplProtocols(void);
extern u_int16_t port2ApplProtocol(u_int8_t proto, u_int16_t port);

extern void copyInt8(u_int8_t t8, char *outBuffer, u_int *outBufferBegin, u_int *outBufferMax);
extern void copyInt16(u_int16_t _t16, char *outBuffer, u_int *outBufferBegin, u_int *outBufferMax);
extern void copyInt32(u_int32_t _t32, char *outBuffer, u_int *outBufferBegin, u_int *outBufferMax);
extern void copyLen(u_char *str, int strLen, char *outBuffer, u_int *outBufferBegin, u_int *outBufferMax);

extern int32_t gmt2local(time_t t);
extern void resetBucketStats(FlowHashBucket* bkt,
			     const struct pcap_pkthdr *h, 
			     u_int len,
			     u_short sport, u_short dport,
			     u_char *payload, int payloadLen);
extern void maximize_socket_buffer(int sock_fd, int buf_type);

/* bitmask */
extern void reset_bitmask(bitmask_selector *selector);
extern int alloc_bitmask(u_int32_t tot_bits, bitmask_selector *selector);
extern void free_bitmask(bitmask_selector *selector);

/* nprobe.c */
extern int exportBucketToNetflow(FlowHashBucket *myBucket, int direction, u_char free_memory);
extern void parseBlacklistNetworks(char* _addresses);
extern u_short isBlacklistedAddress(struct in_addr *addr) ;

#ifndef min
#define min(a, b) ((a > b) ? b : a)
#endif

#ifndef max
#define max(a, b) ((a > b) ? a : b)
#endif

#ifdef linux
extern void setCpuAffinity(char *dev_name, int cpuId);
#endif
