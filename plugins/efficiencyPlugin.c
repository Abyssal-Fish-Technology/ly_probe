/*
 *  Copyright (C) 2007-10 Luca Deri <deri@ntop.org>
 *
 *  		       http://www.ntop.org/
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

/*
  This plugin is used to calculate the efficiency of
  transmissions when using fixed size packets such
  as ATM where the cell size is 47 bytes.
*/

#define BASE_ID           NTOP_BASE_ID+168

static V9V10TemplateElementId efficiencyPlugin_template[] = {
  { FLOW_TEMPLATE, NTOP_ENTERPRISE_ID, BASE_ID,   1, numeric_format, dump_as_uint, "EFFICIENCY_SENT", "Avg. transmission efficiency % (send)" },
  { FLOW_TEMPLATE, NTOP_ENTERPRISE_ID, BASE_ID+1, 1, numeric_format, dump_as_uint, "EFFICIENCY_RCVD", "Avg. transmission efficiency % (rcvd)" },
  { FLOW_TEMPLATE, NTOP_ENTERPRISE_ID, 0, 0, 0, 0, NULL, NULL } /* End of templates */
};

struct plugin_info {
  u_int32_t efficiency_sent, efficiency_rcvd;
};

static u_int32_t cellLength = 47; /* Default (47 is the ATM payload) */

#define EFFICIENCY_OPT "--cell-length="

/* *********************************************** */

static PluginInfo efficiencyPlugin; /* Forward */

/* ******************************************* */

void efficiencyPlugin_init(int argc, char *argv[]) {
  int i;

  if((argc == 2) && (argv[1][0] != '-')) {
    FILE * fd;
    char line[256];
    
    fd = fopen(argv[1], "r");
    if(fd == NULL) {
      traceEvent(TRACE_ERROR, "Unable to read config. file %s", argv[1]);
      fclose(fd);
      return;
    }

    while(fgets(line, sizeof(line), fd)) {
	if (strncmp(line, EFFICIENCY_OPT, strlen(EFFICIENCY_OPT)) == 0)
	    cellLength = atoi(&line[strlen(EFFICIENCY_OPT)]);
    }
    fclose(fd);
  } else 
      for(i=0; i<argc; i++)
        if(strncmp(argv[i], EFFICIENCY_OPT, strlen(EFFICIENCY_OPT)) == 0) {
	   cellLength = atoi(&argv[i][strlen(EFFICIENCY_OPT)]);
	   break;
	}
}

/* *********************************************** */

static u_int efficiency(u_int pktLen) {
  u_int pktEfficiency;

  if(cellLength == 0)
    pktEfficiency = 0;
  else
    pktEfficiency = 100 - (((pktLen % cellLength) * 100) / cellLength);

  // traceEvent(TRACE_ERROR, "=====> [pktEfficiency=%d][pkt_len=%d]", pktEfficiency, pktLen);
  return(pktEfficiency);
}

/* *********************************************** */

/* Handler called whenever an incoming packet is received */

static void efficiencyPlugin_packet(u_char new_bucket, void *pluginData,
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
  struct plugin_info *pinfo;

  if(new_bucket) {
    PluginInformation *info;

    /* Bucket memory allocation: nothing to do here */

    info = (PluginInformation*)malloc(sizeof(PluginInformation));
    if(info == NULL) {
      traceEvent(TRACE_ERROR, "Not enough memory?");
      return; /* Not enough memory */
    }

    info->pluginPtr  = (void*)&efficiencyPlugin;
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

  if((bkt->sport == sport) && (bkt->dport == dport)
     && cmpIpAddress(&bkt->src->host, src)
     && cmpIpAddress(&bkt->dst->host, dst))
    pinfo->efficiency_sent += efficiency(len);
  else
    pinfo->efficiency_rcvd += efficiency(len);
}

/* *********************************************** */

/* Handler called when the flow is deleted (after export) */

static void efficiencyPlugin_delete(FlowHashBucket* bkt, void *pluginData) {
  if(pluginData != NULL) {
    /* Free any nested datastructure of "struct plugin_info" */
    free(pluginData);
  }
}

/* *********************************************** *

/*
Handler called at startup when the template is read
*/

static V9V10TemplateElementId* efficiencyPlugin_get_template(char* template_name) {
  int i;

  for(i=0; efficiencyPlugin_template[i].templateElementId != 0; i++) {
    if(!strcmp(template_name, efficiencyPlugin_template[i].templateElementName)) {
      return(&efficiencyPlugin_template[i]);
    }
  }

  return(NULL); /* Unknown */
}

/* *********************************************** */

/* Handler called whenever a flow attribute needs to be exported */

static int efficiencyPlugin_export(void *pluginData, V9V10TemplateElementId *theTemplate,
			   int direction /* 0 = src->dst, 1 = dst->src */,
			   FlowHashBucket *bkt, char *outBuffer,
			   u_int* outBufferBegin, u_int* outBufferMax) {
  int i, debug = 0;

  for(i=0; efficiencyPlugin_template[i].templateElementId != 0; i++) {
    if(theTemplate->templateElementId == efficiencyPlugin_template[i].templateElementId) {
      if((*outBufferBegin)+efficiencyPlugin_template[i].templateElementLen > (*outBufferMax))
	return(-2); /* Too long */

      if(pluginData) {
	struct plugin_info *info = (struct plugin_info *)pluginData;

	switch(efficiencyPlugin_template[i].templateElementId) {
	case BASE_ID:
	  {
	    u_int8_t my_value =  bkt->flowCounters.pktSent ? (info->efficiency_sent / bkt->flowCounters.pktSent) : 0;

	    copyLen(&my_value, efficiencyPlugin_template[i].templateElementLen,
		    outBuffer, outBufferBegin, outBufferMax);
	    if(debug) traceEvent(TRACE_INFO, "-> EFFICIENCY_SENT: %d", my_value);
	  }
	  break;
	case BASE_ID+1:
	  {
	    u_int8_t my_value = bkt->flowCounters.pktRcvd ? (info->efficiency_rcvd / bkt->flowCounters.pktRcvd) : 0;

	    copyLen(&my_value, efficiencyPlugin_template[i].templateElementLen,
                  outBuffer, outBufferBegin, outBufferMax);	    
	    if(debug) traceEvent(TRACE_INFO, "-> EFFICIENCY_RCVD: %d", my_value);
	  }
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

static int efficiencyPlugin_print(void *pluginData, V9V10TemplateElementId *theTemplate,
				  int direction /* 0 = src->dst, 1 = dst->src */,
				  FlowHashBucket *bkt, char *line_buffer, u_int line_buffer_len) {
  int i;

  for(i=0; efficiencyPlugin_template[i].templateElementId != 0; i++) {
    if(theTemplate->templateElementId == efficiencyPlugin_template[i].templateElementId) {

      if(pluginData) {
	struct plugin_info *info = (struct plugin_info *)pluginData;
	u_int8_t my_value;

	switch(efficiencyPlugin_template[i].templateElementId) {
	case BASE_ID:
	  my_value =  bkt->flowCounters.pktSent ? (info->efficiency_sent / bkt->flowCounters.pktSent) : 0;
	  snprintf(&line_buffer[strlen(line_buffer)], (line_buffer_len-strlen(line_buffer)), "%d", my_value);
	  break;
	case BASE_ID+1:
	  my_value = bkt->flowCounters.pktRcvd ? (info->efficiency_rcvd / bkt->flowCounters.pktRcvd) : 0;
	  snprintf(&line_buffer[strlen(line_buffer)], (line_buffer_len-strlen(line_buffer)), "%d", my_value);
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

static V9V10TemplateElementId* efficiencyPlugin_conf(void) {
  return(efficiencyPlugin_template);
}

/* *********************************************** */

/* Plugin entrypoint */
static PluginInfo efficiencyPlugin = {
  NPROBE_REVISION,
  "Efficiency calculation",
  "0.1",
  "Handle efficiency protocols",
  "L.Deri <deri@ntop.org>",
  0 /* not always enabled */, 1, /* enabled */
  efficiencyPlugin_init,
  NULL, /* Term */
  efficiencyPlugin_conf,
  efficiencyPlugin_delete,
  1, /* call packetFlowFctn for each packet */
  efficiencyPlugin_packet,
  efficiencyPlugin_get_template,
  efficiencyPlugin_export,
  efficiencyPlugin_print,
  NULL,
  NULL
};

/* *********************************************** */

/* Plugin entry fctn */
#ifdef MAKE_STATIC_PLUGINS
PluginInfo* efficiencyPluginEntryFctn(void)
#else
     PluginInfo* PluginEntryFctn(void)
#endif
{
  return(&efficiencyPlugin);
}

