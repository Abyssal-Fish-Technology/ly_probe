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

#define BASE_ID           NTOP_BASE_ID+190

static u_int32_t last_flow_id;

static V9V10TemplateElementId flowIdPlugin_template[] = {
  { FLOW_TEMPLATE, NTOP_ENTERPRISE_ID, BASE_ID,  4, numeric_format, dump_as_uint, "FLOW_ID", "Serial Flow Identifier" },
  { FLOW_TEMPLATE, NTOP_ENTERPRISE_ID, 0, 0, 0, 0, NULL, NULL }
};

struct plugin_info {
  u_int32_t flow_id;
};

/* *********************************************** */

static PluginInfo flowIdPlugin; /* Forward */
#ifdef HAVE_GDBM
#define RECORD_EXPIRE_TIME   60*30 /* 30 mins */
struct flow_id_record {
  u_int32_t flow_id, entry_last_change;
};

static void* purge_database_loop(void* notUsed);
static GDBM_FILE flow_database;
static pthread_mutex_t purge_database;
static pthread_t purge_database_thread;
#endif

/* ******************************************* */

void flowIdPlugin_init(int argc, char *argv[]) {
  traceEvent(TRACE_INFO, "Initialized FlowId plugin");

  last_flow_id = 0;
  unlink("flow.database");

#ifdef HAVE_GDBM
  if((flow_database = gdbm_open("flow.database", 0, GDBM_WRCREAT, 00664, NULL)) == NULL) {
    traceEvent(TRACE_ERROR, "Unable to create flow database. Using serial flowId");
  }

  pthread_mutex_init(&purge_database, NULL);
  pthread_create(&purge_database_thread, NULL, purge_database_loop, NULL);
#endif
}

/* *********************************************** */

static u_int32_t getFlowId(FlowHashBucket *bkt) {
  u_int32_t flow_id = 0;

#ifdef HAVE_GDBM
  if(flow_database != NULL) {
    char key[64];
    u_int32_t srcHost, dstHost;
    datum key_data, data_data;

    if(bkt->src.ipVersion == 4) {
      srcHost = bkt->src.ipType.ipv4, dstHost = bkt->dst.ipType.ipv4;
    } else {
      srcHost = bkt->src.ipType.ipv6.s6_addr32[0]+bkt->src.ipType.ipv6.s6_addr32[1]
	+bkt->src.ipType.ipv6.s6_addr32[2]+bkt->src.ipType.ipv6.s6_addr32[3];
      dstHost = bkt->dst.ipType.ipv6.s6_addr32[0]+bkt->dst.ipType.ipv6.s6_addr32[1]
	+bkt->dst.ipType.ipv6.s6_addr32[2]+bkt->dst.ipType.ipv6.s6_addr32[3];
    }

    if(srcHost < dstHost)
      snprintf(key, sizeof(key), "%u%u%u%u%u%u", bkt->vlanId, bkt->proto,
	       srcHost, dstHost, bkt->sport, bkt->dport);
    else
      snprintf(key, sizeof(key), "%u%u%u%u%u%u", bkt->vlanId, bkt->proto,
	       dstHost, srcHost, bkt->dport, bkt->sport);

    pthread_mutex_lock(&purge_database);
    key_data.dptr = key, key_data.dsize = strlen(key)+1;
    data_data = gdbm_fetch(flow_database, key_data);

    if((data_data.dptr != NULL)
       && (data_data.dsize == sizeof(struct flow_id_record))) {
      struct flow_id_record *rec = (struct flow_id_record*)data_data.dptr;
      if(rec->entry_last_change < time(NULL)-RECORD_EXPIRE_TIME) {
	gdbm_delete(flow_database, key_data); /* too old */
      } else {
	flow_id = rec->flow_id;
	rec->entry_last_change = time(NULL); /* Update time */
	gdbm_store(flow_database, key_data, data_data, GDBM_REPLACE);
      }
    } else {
      struct flow_id_record rec;

      flow_id = rec.flow_id = ++last_flow_id, rec.entry_last_change = time(NULL);
      data_data.dptr = (void*)&rec, data_data.dsize = sizeof(struct flow_id_record);
      gdbm_store(flow_database, key_data, data_data, GDBM_REPLACE);
    }

    pthread_mutex_unlock(&purge_database);
  }
#endif

  if(flow_id == 0) {
    flow_id = ++last_flow_id;
    /* It cannot happen that we're in this branch and
       the record has not been saved into the database */
  }

  /* traceEvent(TRACE_INFO, "flow_id=%u", flow_id); */
  return(flow_id);
}

/* *********************************************** */

/* Handler called whenever an incoming packet is received */

static void flowIdPlugin_packet(u_char new_bucket, void *pluginData,
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

  /* traceEvent(TRACE_INFO, "flowIdPlugin_packet(%d)", payloadLen); */

  if(new_bucket) {
    info = (PluginInformation*)malloc(sizeof(PluginInformation));
    if(info == NULL) {
      traceEvent(TRACE_ERROR, "Not enough memory?");
      return; /* Not enough memory */
    }

    info->pluginPtr  = (void*)&flowIdPlugin;
    pluginData = info->pluginData = malloc(sizeof(struct plugin_info));

    if(info->pluginData == NULL) {
      traceEvent(TRACE_ERROR, "Not enough memory?");
      free(info);
      return; /* Not enough memory */
    } else
      memset(info->pluginData, 0, sizeof(struct plugin_info));

    info->next = bkt->plugin;
    bkt->plugin = info;

    /* ((struct plugin_info*)info->pluginData)->flow_id = getFlowId(bkt); */
  }
}

/* *********************************************** */

/* Handler called when the flow is deleted (after export) */

static void flowIdPlugin_delete(FlowHashBucket* bkt, void *pluginData) {
  if(pluginData != NULL)
    free(pluginData);
}

/* *********************************************** */

/* Handler called at startup when the template is read */

static V9V10TemplateElementId* flowIdPlugin_get_template(char* template_name) {
  int i;

  for(i=0; flowIdPlugin_template[i].templateElementId != 0; i++) {
    if(!strcmp(template_name, flowIdPlugin_template[i].templateElementName)) {
      return(&flowIdPlugin_template[i]);
    }
  }

  return(NULL); /* Unknown */
}

/* *********************************************** */

/* Handler called whenever a flow attribute needs to be exported */

static int flowIdPlugin_export(void *pluginData, V9V10TemplateElementId *theTemplate,
			       int direction /* 0 = src->dst, 1 = dst->src */,
			       FlowHashBucket *bkt, char *outBuffer,
			       u_int* outBufferBegin, u_int* outBufferMax) {
  int i;

  for(i=0; flowIdPlugin_template[i].templateElementId != 0; i++) {
    if(theTemplate->templateElementId == flowIdPlugin_template[i].templateElementId) {
      if((*outBufferBegin)+flowIdPlugin_template[i].templateElementLen > (*outBufferMax))
	return(-2); /* Too long */

      if(pluginData) {
	struct plugin_info *info = (struct plugin_info *)pluginData;
	u_int32_t val;

	switch(flowIdPlugin_template[i].templateElementId) {
	case BASE_ID:
	  if(info->flow_id == 0) info->flow_id = getFlowId(bkt);
	  if(info->flow_id != 0) {
	    val = info->flow_id;
	  } else
	    val = 0;

	  copyInt32(val, outBuffer, outBufferBegin, outBufferMax);
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

static int flowIdPlugin_print(void *pluginData, V9V10TemplateElementId *theTemplate,
			      int direction /* 0 = src->dst, 1 = dst->src */,
			      FlowHashBucket *bkt, char *line_buffer, u_int line_buffer_len) {
  int i;

  for(i=0; flowIdPlugin_template[i].templateElementId != 0; i++) {
    if(theTemplate->templateElementId == flowIdPlugin_template[i].templateElementId) {
      if(pluginData) {
	struct plugin_info *info = (struct plugin_info *)pluginData;

	if(info->flow_id == 0) info->flow_id = getFlowId(bkt);

	switch(flowIdPlugin_template[i].templateElementId) {
	case BASE_ID:
	  snprintf(&line_buffer[strlen(line_buffer)], (line_buffer_len-strlen(line_buffer)), "%u", info->flow_id);
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

static V9V10TemplateElementId* flowIdPlugin_conf(void) {
  return(flowIdPlugin_template);
}

/* *********************************************** */

/* Plugin entrypoint */
static PluginInfo flowIdPlugin = {
  NPROBE_REVISION,
  "Flow Serial Identifier",
  "0.1",
  "Implement persistent flow indentifier",
  "L.Deri <deri@ntop.org>",
  0 /* not always enabled */, 1, /* enabled */
  flowIdPlugin_init,
  NULL, /* Term */
  flowIdPlugin_conf,
  flowIdPlugin_delete,
  1, /* call packetFlowFctn for each packet */
  flowIdPlugin_packet,
  flowIdPlugin_get_template,
  flowIdPlugin_export,
  flowIdPlugin_print,
  NULL,
  NULL
};

/* *********************************************** */

/* Plugin entry fctn */
#ifdef MAKE_STATIC_PLUGINS
PluginInfo* flowIdPluginEntryFctn(void)
#else
  PluginInfo* PluginEntryFctn(void)
#endif
{
  return(&flowIdPlugin);
}

/* *********************************************** */

#ifdef HAVE_GDBM
static void* purge_database_loop(void* notUsed) {
  while(1) {
    datum key_data, data_data;

    sleep(300); /* 5 min */

    pthread_mutex_lock(&purge_database);
    data_data = gdbm_firstkey(flow_database);
    pthread_mutex_unlock(&purge_database);

    while(data_data.dptr != NULL) {
      pthread_mutex_lock(&purge_database);
      if(data_data.dsize == sizeof(struct flow_id_record)) {
	struct flow_id_record *rec = (struct flow_id_record*)data_data.dptr;
	if(rec->entry_last_change < time(NULL)-RECORD_EXPIRE_TIME)
	  gdbm_delete(flow_database, data_data);
      } else
	gdbm_delete(flow_database, data_data);

      key_data = data_data;
      data_data = gdbm_nextkey(flow_database, key_data);
      free(key_data.dptr); /* Free the 'former' data_data */
      pthread_mutex_unlock(&purge_database);
    }
  }

  return(NULL);
}
#endif
