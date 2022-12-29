/*
 *  Copyright (C) 2008-10 Luca Deri <deri@ntop.org>
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
  This plugin is used to calculate the process of
  transmissions when using fixed size packets such
  as ATM where the cell size is 47 bytes.
*/

#define BASE_ID           NTOP_BASE_ID+168
#define PROC_NAME_LEN      16

static V9V10TemplateElementId processPlugin_template[] = {
  { FLOW_TEMPLATE, NTOP_ENTERPRISE_ID, BASE_ID,   4,  numeric_format, dump_as_uint, "PROC_ID",   "Process Identifier (PID)" },
  { FLOW_TEMPLATE, NTOP_ENTERPRISE_ID, BASE_ID+1, PROC_NAME_LEN, ascii_format, dump_as_ascii, "PROC_NAME", "Process name" },
  { FLOW_TEMPLATE, NTOP_ENTERPRISE_ID, 0, 0, 0, 0, NULL, NULL } /* End of templates */
};

struct plugin_info {
  u_int32_t process_id;
  char process_name[PROC_NAME_LEN];
};



/* *********************************************** */

static PluginInfo processPlugin; /* Forward */

extern void init_pid();
extern int getProcess(u_int src_address, u_int src_port,
		      u_int dst_address, u_int dst_port,
		      u_char is_tcp, u_int *process_id,
		      char *process_name, u_int process_name_len);

/* ******************************************* */

void processPlugin_init(int argc, char *argv[]) {
  traceEvent(TRACE_INFO, "Initialized process plugin\n");
  init_pid();
}


/* *********************************************** */

/* Handler called whenever an incoming packet is received */
static void processPlugin_packet(u_char new_bucket, void *pluginData,
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
  if(new_bucket) {
    PluginInformation *info;
    struct plugin_info *pinfo;

    /* Bucket memory allocation: nothing to do here */

    info = (PluginInformation*)malloc(sizeof(PluginInformation));
    if(info == NULL) {
      traceEvent(TRACE_ERROR, "Not enough memory?");
      return; /* Not enough memory */
    }

    info->pluginPtr  = (void*)&processPlugin;
    pluginData = info->pluginData = malloc(sizeof(struct plugin_info));

    if(info->pluginData == NULL) {
      traceEvent(TRACE_ERROR, "Not enough memory?");
      free(info);
      return; /* Not enough memory */
    } else
      memset(info->pluginData, 0, sizeof(struct plugin_info));

    info->next = bkt->plugin;
    bkt->plugin = info;

    pinfo = (struct plugin_info*)pluginData;

    if(src->ipVersion == 4) {
      getProcess(src->ipType.ipv4, sport,
		 dst->ipType.ipv4, dport,
		 (proto == TCP_PROTOCOL) ? 1 : 0, 
		 &pinfo->process_id,
		 pinfo->process_name, sizeof(pinfo->process_name));
    }
  }
}

/* *********************************************** */

/* Handler called when the flow is deleted (after export) */

static void processPlugin_delete(FlowHashBucket* bkt, void *pluginData) {
  if(pluginData != NULL) {
    /* Free any nested datastructure of "struct plugin_info" */
    free(pluginData);
  }
}

/* *********************************************** *

   /*
   Handler called at startup when the template is read
*/

static V9V10TemplateElementId* processPlugin_get_template(char* template_name) {
  int i;

  for(i=0; processPlugin_template[i].templateElementId != 0; i++) {
    if(!strcmp(template_name, processPlugin_template[i].templateElementName)) {
      return(&processPlugin_template[i]);
    }
  }

  return(NULL); /* Unknown */
}

/* *********************************************** */

/* Handler called whenever a flow attribute needs to be exported */

static int processPlugin_export(void *pluginData, V9V10TemplateElementId *theTemplate,
				int direction /* 0 = src->dst, 1 = dst->src */,
				FlowHashBucket *bkt, char *outBuffer,
				u_int* outBufferBegin, u_int* outBufferMax) {
  int i, debug = 0;

  for(i=0; processPlugin_template[i].templateElementId != 0; i++) {
    if(theTemplate->templateElementId == processPlugin_template[i].templateElementId) {
      if((*outBufferBegin)+processPlugin_template[i].templateElementLen > (*outBufferMax))
	return(-2); /* Too long */

      if(pluginData) {
	struct plugin_info *info = (struct plugin_info *)pluginData;

	switch(processPlugin_template[i].templateElementId) {
	case BASE_ID:
	  {
	    copyInt32(info->process_id, outBuffer, outBufferBegin, outBufferMax);
	    if(debug) traceEvent(TRACE_INFO, "-> process_id: %d", info->process_id);
	  }
	  break;
	case BASE_ID+1:
	  {
	    copyLen(info->process_name, processPlugin_template[i].templateElementLen,
		    outBuffer, outBufferBegin, outBufferMax);	    
	    if(debug) traceEvent(TRACE_INFO, "-> process_name: %s", info->process_name);
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

static int processPlugin_print(void *pluginData, V9V10TemplateElementId *theTemplate,
			       int direction /* 0 = src->dst, 1 = dst->src */,
			       FlowHashBucket *bkt, char *line_buffer, u_int line_buffer_len) {
  int i;

  for(i=0; processPlugin_template[i].templateElementId != 0; i++) {
    if(theTemplate->templateElementId == processPlugin_template[i].templateElementId) {

      if(pluginData) {
	struct plugin_info *info = (struct plugin_info *)pluginData;

	switch(processPlugin_template[i].templateElementId) {
	case BASE_ID:
	  snprintf(&line_buffer[strlen(line_buffer)], (line_buffer_len-strlen(line_buffer)), "%d", info->process_id);
	  break;
	case BASE_ID+1:
	  snprintf(&line_buffer[strlen(line_buffer)], (line_buffer_len-strlen(line_buffer)), "%s", info->process_name);
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

static V9V10TemplateElementId* processPlugin_conf(void) {
  return(processPlugin_template);
}

/* *********************************************** */

/* Plugin entrypoint */
static PluginInfo processPlugin = {
  NPROBE_REVISION,
  "Process information",
  "0.1",
  "Handle process identification",
  "L.Deri <deri@ntop.org>",
  0 /* not always enabled */, 1, /* enabled */
  processPlugin_init,
  NULL, /* Term */
  processPlugin_conf,
  processPlugin_delete,
  1, /* call packetFlowFctn for each packet */
  processPlugin_packet,
  processPlugin_get_template,
  processPlugin_export,
  processPlugin_print,
  NULL,
  NULL
};

/* *********************************************** */

/* Plugin entry fctn */
#ifdef MAKE_STATIC_PLUGINS
PluginInfo* processPluginEntryFctn(void)
#else
PluginInfo* PluginEntryFctn(void)
#endif
{
  return(&processPlugin);
}

