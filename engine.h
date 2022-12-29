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

/* ********************************** */

#define LONG_SNAPLEN             1600
#define DEFAULT_SNAPLEN           128

#define MAX_NUM_PLUGINS            24

#define CREATE_FLOW_CALLBACK        1
#define DELETE_FLOW_CALLBACK        2
#define PACKET_CALLBACK             3

extern V9V10TemplateElementId* getPluginTemplate(char* template_name);
extern int checkPluginExport(V9V10TemplateElementId *theTemplate, int direction,
			     FlowHashBucket *theFlow, char *outBuffer,
			     u_int* outBufferBegin, u_int* outBufferMax);
extern int checkPluginPrint(V9V10TemplateElementId *theTemplate, int direction,
			    FlowHashBucket *bkt, char *line_buffer, u_int line_buffer_len);
typedef V9V10TemplateElementId* (*PluginConf)(void);
extern void discardBucket(FlowHashBucket *myBucket);
extern void* dequeueBucketToExport(void*);
typedef void (*PluginInitFctn)(int argc, char *argv[]);
typedef void (*PluginTermFctn)(void);
typedef void (*PluginFctn)(FlowHashBucket*, void*);
typedef void (*PluginPacketFctn)(u_char new_bucket, void*, FlowHashBucket*,
				 u_short proto, u_char isFragment,
				 u_short numPkts, u_char tos,
				 u_short vlanId, struct ether_header *ehdr,
				 IpAddress *src, u_short sport,
				 IpAddress *dst, u_short dport,
				 u_int len, u_int8_t flags, u_int8_t icmpType, struct icmp_hdr *icmpPkt,
				 u_short numMplsLabels,
				 u_char mplsLabels[MAX_NUM_MPLS_LABELS][MPLS_LABEL_LEN],
				 char *fingerprint,
				 const struct pcap_pkthdr *h, const u_char *p,
				 u_char *payload, int payloadLen);
typedef V9V10TemplateElementId* (*PluginGetPluginTemplateFctn)(char* template_name);
typedef int (*PluginCheckPluginExportFctn)(void*, V9V10TemplateElementId *theTemplate, int direction,
					   FlowHashBucket *theFlow, char *outBuffer,
					   u_int* outBufferBegin, u_int* outBufferMax);
typedef int (*PluginCheckPluginPrintFctn)(void*, V9V10TemplateElementId *theTemplate, int direction,
					  FlowHashBucket *theFlow, char *line_buffer, u_int line_buffer_len);
typedef void (*PluginSetupFctn)(void);
typedef void (*PluginHelpFctn)(void);

typedef struct pluginInfo {
  char *nprobe_revision, *name, *version, *descr, *author;
  u_char always_enabled, enabled;
  PluginInitFctn initFctn;
  PluginTermFctn termFctn;
  PluginConf pluginFlowConf;
  PluginFctn deleteFlowFctn;
  u_char call_packetFlowFctn_for_each_packet;
  PluginPacketFctn packetFlowFctn;
  PluginGetPluginTemplateFctn getPluginTemplateFctn;
  PluginCheckPluginExportFctn checkPluginExportFctn;
  PluginCheckPluginPrintFctn checkPluginPrintFctn;
  PluginSetupFctn setupFctn;
  PluginHelpFctn helpFctn;
} PluginInfo;

extern PluginInfo* PluginEntryFctn(void);

/* ********************************** */

extern char* _intoa(IpAddress addr, char* buf, u_short bufLen);
extern char* _intoaV4(unsigned int addr, char* buf, u_short bufLen);
extern char* formatTraffic(float numBits, int bits, char *buf);
extern char* formatPackets(float numPkts, char *buf);
extern u_char ttlPredictor(u_char x);
extern char* proto2name(u_int8_t proto);
extern void load_mappings(void);
extern void unload_mappings(void);
extern void setPayload(FlowHashBucket *bkt, const struct pcap_pkthdr *h,
		       u_char *payload, int payloadLen, int direction);
extern void updateApplLatency(u_short proto, FlowHashBucket *bkt,
			      int direction, struct timeval *stamp,
			      u_int8_t icmpType, u_int8_t icmpCode);
extern void updateTcpFlags(FlowHashBucket *bkt, int direction,
			   struct timeval *stamp, u_int8_t flags,
			   char *fingerprint);
extern int cmpIpAddress(IpAddress *src, IpAddress *dst);
extern void printICMPflags(u_int32_t flags, char *icmpBuf, int icmpBufLen);
extern void printFlow(FlowHashBucket *theFlow, int direction);
extern int isFlowExpired(FlowHashBucket *myBucket, time_t theTime);
extern int isFlowExpiredSinceTooLong(FlowHashBucket *myBucket, time_t theTime);
extern void printBucket(FlowHashBucket *myBucket);
extern void walkHash(u_int32_t hash_idx, int flushHash);
extern void purgeBucket(FlowHashBucket *myBucket);

/* nprobe.c or nprobe_mod.c */
extern void queueBucketToExport(FlowHashBucket *myBucket);

/* plugin.c */
extern u_short num_plugins_enabled;
extern void initPlugins(int argc, char* argv[]);
extern void termPlugins(void);
extern void pluginCallback(u_char callbackType, FlowHashBucket* bucket,
			   u_short proto, u_char isFragment,
			   u_short numPkts, u_char tos,
			   u_short vlanId, struct ether_header *ehdr,
			   IpAddress *src, u_short sport,
			   IpAddress *dst, u_short dport,
			   u_int len, u_int8_t flags, u_int8_t icmpType, struct icmp_hdr *icmpPkt,
			   u_short numMplsLabels,
			   u_char mplsLabels[MAX_NUM_MPLS_LABELS][MPLS_LABEL_LEN],
			   char *fingerprint,
			   const struct pcap_pkthdr *h, const u_char *p,
			   u_char *payload, int payloadLen);
extern void buildActivePluginsList(V9V10TemplateElementId *template_element_list[]);
extern void printMetadata(FILE *file);
