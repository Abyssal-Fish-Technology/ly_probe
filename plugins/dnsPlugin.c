/*
 *  Contact Us: abyssalfish <opensource@abyssalfish.com.cn>
 *
 *             http://www.abyssalfish.com.cn/
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
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */

#include "nprobe.h"

#define BASE_ID             NTOP_BASE_ID+200
#define MAX_DOMAIN_LENGTH   256

#define DNS_REQ             "Domain Name System (query)" 

static V9V10TemplateElementId dnsPlugin_template[] = {
  {FLOW_TEMPLATE, NTOP_ENTERPRISE_ID, BASE_ID, 128, ascii_format, dump_as_ascii, "DNS_REQ_DOMAIN", "DNS request domain name"},
  {FLOW_TEMPLATE, NTOP_ENTERPRISE_ID, BASE_ID+1, 2, numeric_format, dump_as_uint, "DNS_REQ_TYPE", "DNS request type"},
  {FLOW_TEMPLATE, FLOW_TEMPLATE, BASE_ID+2, 2, numeric_format, dump_as_uint, "DNS_REQ_CLASS", "DNS request class"},
  {FLOW_TEMPLATE, FLOW_TEMPLATE, BASE_ID+3, 16, numeric_format, dump_as_uint, "DNS_RES_IP", "DNS response ip"},
  {FLOW_TEMPLATE, FLOW_TEMPLATE, 0, 0, 0, 0, NULL, NULL}
};


struct plugin_info {
  char dns_req_name[MAX_DOMAIN_LENGTH+1];
  u_int16_t dns_req_type;
  u_int16_t dns_req_class;
  u_int32_t dns_res[4];
};


/* ********************************************** */

static PluginInfo dnsPlugin;

/* ********************************************** */

void dnsPlugin_init(int argc, char *argv[]) {
  traceEvent(TRACE_INFO, "Initialized DNS plugin");
}

/* ********************************************** */

/* Handler called whenever an incoming packet is received */

static void dnsPlugin_packet(u_char new_bucket, void *pluginData,
            FlowHashBucket* bkt,
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
            u_char *payload, int payloadLen) {
  PluginInformation *info;
  struct plugin_info *pinfo;

  // traceEvent(TRACE_INFO, "dnsPlugin_packet(%d)", payloadLen);

  if(new_bucket) {
    info = (PluginInformation*)malloc(sizeof(PluginInformation));
    if(info == NULL) {
      traceEvent(TRACE_ERROR, "Not enough memory?");
      return; /* Not enough memory */
    } 
    
    info->pluginPtr  = (void*)&dnsPlugin;
    pluginData = info->pluginData = malloc(sizeof(struct plugin_info));
    
    if(info->pluginData == NULL) {
      traceEvent(TRACE_ERROR, "Not enough memory?");
      free(info);
      return; /* Not enough memory */
    } else 
      memset(info->pluginData, 0, sizeof(struct plugin_info));
    
    info->next = bkt->plugin;
    bkt->plugin = info;
  }   
    
  pinfo = (struct plugin_info*)pluginData;
 
  int qdcount, ancount;
  HEADER *np;
  u_int16_t qtype[2];
  u_int16_t qclass[2];
  u_int8_t tm[1];
  u_int16_t rdata_len[1];
  //u_int32_t res_ip[1];
  char qname[MAX_DOMAIN_LENGTH+1];
  memset(qname, 0, MAX_DOMAIN_LENGTH+1); 
  if (payloadLen <= (int)sizeof(HEADER)) return;

  if (payloadLen > 0 && (proto == IPPROTO_UDP) && (sport == 53 || dport == 53)) {
    np = (HEADER *)payload;
    payloadLen -= sizeof(HEADER);
    qdcount = ntohs(np->qdcount);
    if (qdcount == 0) return;
    if (qdcount > 1) return;
    ancount = ntohs(np->ancount);

    const u_int8_t *ds = (u_int8_t *)(np+1);
    const u_int8_t *d = ds;
    if (!(DNS_QR(np))) {  //dns请求
      if (cmpIpAddress(&bkt->src->host, src))
        bkt->src2dstTos |= 0x01;
      else
        bkt->dst2srcTos |= 0x01;

      //const u_int8_t *ds = (u_int8_t *)(np+1);
      //const u_int8_t *d = ds;
      int count = 0;
      int len = 0;
      while(qdcount-- && payloadLen) {
        while (*d && payloadLen>0)
          d++, payloadLen--;

        len = d - ds;
        payloadLen -= 4;
        if (payloadLen < 0) break; //broken packet

        if (len >= MAX_DOMAIN_LENGTH) break;
        memcpy(qname, ds, len);
        memcpy(qtype, d+1, 2);
        memcpy(qclass, d+3, 2);
        if (1 != ntohs(*qclass)) return;   //qclass 通常为1（过滤一些非dns数据包）
        pinfo->dns_req_type = ntohs(*qtype);
        pinfo->dns_req_class = ntohs(*qclass);
 
        int length = qname[0];
        int i = 1, j = 1;
       
        for(i = 1;i <= len;i++) {
          if (qname[i] == '\0') {
            pinfo->dns_req_name[i-1] = '\0';
            break;
          }
          if (j < length + 1){
            pinfo->dns_req_name[i-1] = qname[i];
            j++;
            continue; 
          }
          if (j == length + 1) {
            pinfo->dns_req_name[i-1] = '.';
            length = qname[i];
            j = 1;
          }
        }
         
        ds = d + 4;
        d = ds;
        //pinfo->req_len = pinfo->req_len + len + 4;
        
        count++;
        if (count>=1) break;
      }

      //解析完请求直接导出flow
      if(pinfo->dns_req_name[0] != '\0') {
        exportBucket(bkt, 0);
        resetBucketStats(bkt, h, len, sport, dport, payload, payloadLen);
        memset(pinfo, 0, sizeof(struct plugin_info));
      }
    } else {  //dns回应
      if (sport != 53) return;
   
      int count = 0;
      int len = 0;
      while(qdcount-- && payloadLen) {
        while (*d && payloadLen>0)
          d++, payloadLen--;

        len = d - ds;
        payloadLen -= 4;
        if (payloadLen < 0) break; //broken packet

        if (len >= MAX_DOMAIN_LENGTH) break;
        memcpy(qname, ds, len);
        memcpy(qtype, d+1, 2);
        memcpy(qclass, d+3, 2);
        if (1 != ntohs(*qclass)) return;   //qclass 通常为1（过滤一些非dns数据包）
        pinfo->dns_req_type = ntohs(*qtype);
        pinfo->dns_req_class = ntohs(*qclass);
 
        int length = qname[0];
        int i = 1, j = 1;
       
        for(i = 1;i <= len;i++) {
          if (qname[i] == '\0') {
            pinfo->dns_req_name[i-1] = '\0';
            break;
          }
          if (j < length + 1){
            pinfo->dns_req_name[i-1] = qname[i];
            j++;
            continue; 
          }
          if (j == length + 1) {
            pinfo->dns_req_name[i-1] = '.';
            length = qname[i];
            j = 1;
          }
        }
         
        ds = d + 4;
        d = ds;
        //pinfo->req_len = pinfo->req_len + len + 4;
        
        count++;
        if (count>=1) break;
      }
      d++;

      int remain = d - (u_int8_t *)payload;
      if ( remain <= payloadLen ) return;

      while (ancount) {
        memcpy(tm, d, 1);
        //回答区域域名字段可能为2字节指针或不定长
        if (0xc0 == ((*tm) & 0xc0)) {  //2字节指针
          d += 2;
        } else {  //不定长域名
          while (*d) {
            if (0xc0 == ((*d) & 0xc0)) {   //查询与应答中name字段有一部分相同，用指针纸指派
              d++;
              break;
            } else {
              d++;
            }
          }

          d++;
        }
        memcpy(qtype, d, 2);
        d += 8; //查询类型TYPE 2字节， 查询类CLASS 2字节，生存时间 4字节
        memcpy(rdata_len, d, 2);  //资源数据长度
        d += 2;

        //返回ipv6地址则保留一个
        if (ancount == 1 && 28 == ntohs(*qtype)) {
          memcpy(pinfo->dns_res, d, ntohs(*rdata_len));
        }
        //返回ipv4地址，最多保留4个
        if (ancount <= 4 && (1 == ntohs(*qtype))) {  //直解析type为A和AAAA的
          memcpy(pinfo->dns_res + 4 - ancount, d, ntohs(*rdata_len));
          //pinfo->dns_res = ntohl(*res_ip);
        }
        d += ntohs(*rdata_len);

        ancount--;
      }

      if(pinfo->dns_req_name[0] != '\0') {
        exportBucket(bkt, 0);
        resetBucketStats(bkt, h, len, sport, dport, payload, payloadLen);
        memset(pinfo, 0, sizeof(struct plugin_info));
      }
    }
  }

}

/* ***************************************************** */

/* Handler called when the flow is deleted (after export) */

static void dnsPlugin_delete(FlowHashBucket* bkt, void *pluginData) {
  if(pluginData != NULL)
    free(pluginData);
}

/* ***************************************************** */

/* Handler called at startup when the template is read */

static V9V10TemplateElementId* dnsPlugin_get_template(char* template_name) {
  int i;
  
  for(i=0; dnsPlugin_template[i].templateElementId != 0; i++) { 
    if(!strcmp(template_name, dnsPlugin_template[i].templateElementName)) {
      return(&dnsPlugin_template[i]);
    }
  }
  return(NULL); 
}

/* **************************************************** */
  
/* Handler called whenever a flow attribute needs to be exported */

static int dnsPlugin_export(void *pluginData, V9V10TemplateElementId *theTemplate,
            int direction /* 0 = src->dst, 1 = dst->src */,
            FlowHashBucket *bkt, char *outBuffer,
            u_int* outBufferBegin, u_int* outBufferMax) {
  int i;
  for(i=0; dnsPlugin_template[i].templateElementId != 0; i++) {
    if(theTemplate->templateElementId == dnsPlugin_template[i].templateElementId) {
      if((*outBufferBegin)+dnsPlugin_template[i].templateElementLen > (*outBufferMax))
        return(-2); /* Too long */
  
      if (pluginData) {
        struct plugin_info *info = (struct plugin_info *)pluginData;
        switch(dnsPlugin_template[i].templateElementId) {
        case BASE_ID:
          if (strlen(info->dns_req_name) < 128) {
            memcpy(&outBuffer[*outBufferBegin], info->dns_req_name, 128);
          } else  {
            memcpy(&outBuffer[*outBufferBegin], info->dns_req_name+strlen(info->dns_req_name)-127, 128);
          }
          //memcpy(&outBuffer[*outBufferBegin], info->dns_req_name, 64);
          (*outBufferBegin) += dnsPlugin_template[i].templateElementLen;
          break;
        case BASE_ID+1:
          copyInt16(info->dns_req_type, outBuffer, outBufferBegin, outBufferMax);
          break;
        case BASE_ID+2:
          copyInt16(info->dns_req_class, outBuffer, outBufferBegin, outBufferMax);
          break;
        case BASE_ID+3:
          memcpy(&outBuffer[*outBufferBegin], info->dns_res, 16);
          (*outBufferBegin) += dnsPlugin_template[i].templateElementLen;
          break;
        default:
          return(-1);
        }
        return(0); 
      }
    }
  }  

  return(-1);
}

/* ***************************************************** */

/* Handler called whenever a flow attribute needs to be printed on file */

static int dnsPlugin_print(void *pluginData, V9V10TemplateElementId *theTemplate,
              int direction /* 0 = src->dst, 1 = dst->src */,
              FlowHashBucket *bkt, char *line_buffer, u_int line_buffer_len) {
  int i;
  
  for(i=0; dnsPlugin_template[i].templateElementId != 0; i++) {
    if(theTemplate->templateElementId == dnsPlugin_template[i].templateElementId) {
      if(pluginData) {
        struct plugin_info *info = (struct plugin_info *)pluginData;
        switch(dnsPlugin_template[i].templateElementId) {
        case BASE_ID:
          snprintf(&line_buffer[strlen(line_buffer)], (line_buffer_len-strlen(line_buffer)), "%s", info->dns_req_name);
          break;
        case BASE_ID+1:
          snprintf(&line_buffer[strlen(line_buffer)], (line_buffer_len-strlen(line_buffer)), "%d", info->dns_req_type);
          break;
        case BASE_ID+2:
          snprintf(&line_buffer[strlen(line_buffer)], (line_buffer_len-strlen(line_buffer)), "%d", info->dns_req_class);
          break;
        case BASE_ID+3:
          snprintf(&line_buffer[strlen(line_buffer)], (line_buffer_len-strlen(line_buffer)), "%u", ntohl(info->dns_res[0]));
          break;
        default:
          return(-1);
        }
        return(0);
      }
    }
  }
  return(-1);
}

/* **************************************************** */

static V9V10TemplateElementId* dnsPlugin_conf(void) {
  return(dnsPlugin_template);
}

/* **************************************************** */

/* Plugin entrypoint */
static PluginInfo dnsPlugin = {
  NPROBE_REVISION,
  "DNS",
  "",
  "Handle DNS protocol",
  "abyssalfish <opensource@abyssalfish.com.cn>",
  0 /* not always enabled */, 1, /* enabled */
  dnsPlugin_init,
  NULL, /* Term */
  dnsPlugin_conf, 
  dnsPlugin_delete,
  1, /* call packetFlowFctn for each packet */
  dnsPlugin_packet,
  dnsPlugin_get_template,
  dnsPlugin_export,
  dnsPlugin_print,
  NULL,
  NULL
};

/* **************************************************** */

/* Plugin entry fctn */
#ifdef MAKE_STATIC_PLUGINS
PluginInfo* dnsPluginEntryFctn(void)
#else
  PluginInfo* PluginEntryFctn(void)
#endif
{
  return(&dnsPlugin);
}
