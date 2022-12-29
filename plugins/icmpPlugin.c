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
#include "base64.h"

#define BASE_ID            NTOP_BASE_ID+180
#define ICMP_DATA_LEN      128

static V9V10TemplateElementId icmpPlugin_template[] = {
  { FLOW_TEMPLATE, NTOP_ENTERPRISE_ID, BASE_ID, ICMP_DATA_LEN, ascii_format, dump_as_ascii, "ICMP_DATA", "ICMP payload" },
  { FLOW_TEMPLATE, NTOP_ENTERPRISE_ID, BASE_ID+1, 2, numeric_format, dump_as_uint, "ICMP_SEQ_NUM", "ICMP sequence num" },
  { FLOW_TEMPLATE, NTOP_ENTERPRISE_ID, BASE_ID+2, 4, numeric_format, dump_as_uint, "ICMP_PAYLOAD_LEN", "ICMP payload len" },
  { FLOW_TEMPLATE, NTOP_ENTERPRISE_ID, 0, 0, 0, 0, NULL, NULL }
};

struct plugin_info {
  char icmp_con[ICMP_DATA_LEN+1];
  u_int16_t  seq_num;
  u_int32_t  payload_len;
};

/* *********************************************** */

static PluginInfo icmpPlugin; /* Forward */

/* ******************************************* */

void icmpPlugin_init(int argc, char *argv[]) {
  traceEvent(TRACE_INFO, "Initialized HTTP plugin");
}

/* *********************************************** */

/* Handler called whenever an incoming packet is received */

static void icmpPlugin_packet(u_char new_bucket, void *pluginData,
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

  // traceEvent(TRACE_INFO, "icmpPlugin_packet(%d)", payloadLen);

  if(new_bucket) {
    info = (PluginInformation*)malloc(sizeof(PluginInformation));
    if(info == NULL) {
      	traceEvent(TRACE_ERROR, "Not enough memory?");
	return; /* Not enough memory */
    }

    info->pluginPtr  = (void*)&icmpPlugin;
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

  if(payloadLen > 0 && proto == IPPROTO_ICMP) {
    if (icmpType == 8 || icmpType == 0 || icmpType == 13 || icmpType == 15 || icmpType == 17) {
      if (icmpType == 8 || icmpType == 13 || icmpType == 15 || icmpType == 17) { 
        if (cmpIpAddress(&bkt->src->host, src))
          bkt->src2dstTos |= 0x01;
        else
          bkt->dst2srcTos |= 0x01;
      }

      /* We need to export this flow now */
      if(pinfo->icmp_con[0] != '\0') {
        exportBucket(bkt, 0);
        resetBucketStats(bkt, h, len, sport, dport, payload, payloadLen);
        memset(pinfo, 0, sizeof(struct plugin_info));	  
      }

      int w_len;
      if(payloadLen<=8){
        w_len = payloadLen;
      } else {
        w_len = min(96, payloadLen-8);
      }
      char *ori = malloc(w_len*sizeof(char));
      memset(ori, 0, w_len);
      memcpy(ori, (char *)payload, w_len);

      char * enc = base64_encode(ori, w_len);
      memcpy(pinfo->icmp_con, enc, strlen(enc));

    //  memcpy(ori, (char *)payload, min(96, payloadLen));
    //  memcpy(pinfo->icmp_con, base64_encode(ori, 96), ICMP_DATA_LEN);
      pinfo->seq_num = ntohs(icmpPkt->icmp_seqnum);
      pinfo->payload_len = payloadLen;

      free(ori);
      free(enc);
    }
  }
}

/* *********************************************** */

/* Handler called when the flow is deleted (after export) */

static void icmpPlugin_delete(FlowHashBucket* bkt, void *pluginData) {
  if(pluginData != NULL)
    free(pluginData);
}

/* *********************************************** */
   
/* Handler called at startup when the template is read */

static V9V10TemplateElementId* icmpPlugin_get_template(char* template_name) {
  int i;

  for(i=0; icmpPlugin_template[i].templateElementId != 0; i++) {
    if(!strcmp(template_name, icmpPlugin_template[i].templateElementName)) {
      return(&icmpPlugin_template[i]);
    }
  }

  return(NULL); /* Unknown */
}

/* *********************************************** */

/* Handler called whenever a flow attribute needs to be exported */

static int icmpPlugin_export(void *pluginData, V9V10TemplateElementId *theTemplate,
			     int direction /* 0 = src->dst, 1 = dst->src */,
			     FlowHashBucket *bkt, char *outBuffer,
			     u_int* outBufferBegin, u_int* outBufferMax) {
  int i;

  for(i=0; icmpPlugin_template[i].templateElementId != 0; i++) {
    if(theTemplate->templateElementId == icmpPlugin_template[i].templateElementId) {
      if((*outBufferBegin)+icmpPlugin_template[i].templateElementLen > (*outBufferMax))
	return(-2); /* Too long */

      if(pluginData) {
	struct plugin_info *info = (struct plugin_info *)pluginData;

	switch(icmpPlugin_template[i].templateElementId) {
    case BASE_ID:
      memcpy(&outBuffer[*outBufferBegin], info->icmp_con, ICMP_DATA_LEN);
      (*outBufferBegin) += icmpPlugin_template[i].templateElementLen;
      break;
    case BASE_ID+1:
      copyInt16(info->seq_num, outBuffer, outBufferBegin, outBufferMax);
      break;
    case BASE_ID+2:
      copyInt32(info->payload_len, outBuffer, outBufferBegin, outBufferMax);
      break;
    default:
      return(-1); /* Not handled */
	}

	return(0);
      }
    }
  }

  return(-1); /* Not handled */
}

/* *********************************************** */

/* Handler called whenever a flow attribute needs to be printed on file */

static int icmpPlugin_print(void *pluginData, V9V10TemplateElementId *theTemplate,
			    int direction /* 0 = src->dst, 1 = dst->src */,
			    FlowHashBucket *bkt, char *line_buffer, u_int line_buffer_len) {
  int i;

  for(i=0; icmpPlugin_template[i].templateElementId != 0; i++) {
    if(theTemplate->templateElementId == icmpPlugin_template[i].templateElementId) {

      if(pluginData) {
	struct plugin_info *info = (struct plugin_info *)pluginData;

	switch(icmpPlugin_template[i].templateElementId) {
    case BASE_ID:
      snprintf(&line_buffer[strlen(line_buffer)], (line_buffer_len-strlen(line_buffer)), "%s", info->icmp_con);
      break;
    case BASE_ID+1:
      snprintf(&line_buffer[strlen(line_buffer)], (line_buffer_len-strlen(line_buffer)), "%d", info->seq_num);
      break;
    case BASE_ID+2:
      snprintf(&line_buffer[strlen(line_buffer)], (line_buffer_len-strlen(line_buffer)), "%d", info->payload_len);
      break;
    default:
      return(-1); /* Not handled */
	}

	return(0);
      }
    }
  }

  return(-1); /* Not handled */
}

/* *********************************************** */

static V9V10TemplateElementId* icmpPlugin_conf(void) {
  return(icmpPlugin_template);
}

/* *********************************************** */

/* Plugin entrypoint */
static PluginInfo icmpPlugin = {
  NPROBE_REVISION,
  "ICMP Protocol Dissector",
  "0.1",
  "Handle ICMP protocol",
  "abyssalfish <opensource@abyssalfish.com.cn>",
  0 /* not always enabled */, 1, /* enabled */
  icmpPlugin_init,
  NULL, /* Term */
  icmpPlugin_conf,
  icmpPlugin_delete,
  1, /* call packetFlowFctn for each packet */
  icmpPlugin_packet,
  icmpPlugin_get_template,
  icmpPlugin_export,
  icmpPlugin_print,
  NULL,
  NULL
};

/* *********************************************** */

/* Plugin entry fctn */
#ifdef MAKE_STATIC_PLUGINS
PluginInfo* icmpPluginEntryFctn(void)
#else
  PluginInfo* PluginEntryFctn(void)
#endif
{
  return(&icmpPlugin);
}
 
