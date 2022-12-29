/*
 *  Copyright (C) 2005-10 Luca Deri <deri@ntop.org>
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

// #define SIP_DEBUG

#define SIP_INVITE        "INVITE" /* User Info */
#define SIP_OK            "SIP/2.0 200 Ok" /* Stream Info */

#include "nprobe.h"

#define BASE_ID             NTOP_BASE_ID+130
#define MAX_SIP_STR_LEN      50
#define SIP_CODECS_STR_LEN   32
#define DEFAULT_SIP_PORT   5060

static V9V10TemplateElementId sipPlugin_template[] = {
  { FLOW_TEMPLATE, NTOP_ENTERPRISE_ID, BASE_ID,    MAX_SIP_STR_LEN,   ascii_format, dump_as_ascii, "SIP_CALL_ID",       "SIP call-id" },
  { FLOW_TEMPLATE, NTOP_ENTERPRISE_ID, BASE_ID+1,  MAX_SIP_STR_LEN,   ascii_format, dump_as_ascii, "SIP_CALLING_PARTY", "SIP Call initiator" },
  { FLOW_TEMPLATE, NTOP_ENTERPRISE_ID, BASE_ID+2,  MAX_SIP_STR_LEN,   ascii_format, dump_as_ascii, "SIP_CALLED_PARTY",  "SIP Called party" },
  { FLOW_TEMPLATE, NTOP_ENTERPRISE_ID, BASE_ID+3,  SIP_CODECS_STR_LEN,ascii_format, dump_as_ascii, "SIP_RTP_CODECS",    "SIP RTP codecs" },
  { FLOW_TEMPLATE, NTOP_ENTERPRISE_ID, BASE_ID+4,   4,                numeric_format, dump_as_uint, "SIP_INVITE_TIME",   "SIP SysUptime (msec) of INVITE" },
  { FLOW_TEMPLATE, NTOP_ENTERPRISE_ID, BASE_ID+5,   4,                numeric_format, dump_as_uint, "SIP_TRYING_TIME",   "SIP SysUptime (msec) of Trying" },
  { FLOW_TEMPLATE, NTOP_ENTERPRISE_ID, BASE_ID+6,   4,                numeric_format, dump_as_uint, "SIP_RINGING_TIME",  "SIP SysUptime (msec) of RINGING" },
  { FLOW_TEMPLATE, NTOP_ENTERPRISE_ID, BASE_ID+7,   4,                numeric_format, dump_as_uint, "SIP_OK_TIME",       "SIP SysUptime (msec) of OK" },
  { FLOW_TEMPLATE, NTOP_ENTERPRISE_ID, BASE_ID+8,   4,                numeric_format, dump_as_uint, "SIP_BYE_TIME",      "SIP SysUptime (msec) of BYE" },
  { FLOW_TEMPLATE, NTOP_ENTERPRISE_ID, BASE_ID+9,   4,                numeric_format, dump_as_ipv4_address, "SIP_RTP_SRC_IP",    "SIP RTP stream source IP" },
  { FLOW_TEMPLATE, NTOP_ENTERPRISE_ID, BASE_ID+10,  2,                numeric_format, dump_as_ip_port, "SIP_RTP_SRC_PORT",  "SIP RTP stream source port" },
  { FLOW_TEMPLATE, NTOP_ENTERPRISE_ID, BASE_ID+11,  4,                numeric_format, dump_as_ipv4_address, "SIP_RTP_DST_IP",    "SIP RTP stream dest IP" },
  { FLOW_TEMPLATE, NTOP_ENTERPRISE_ID, BASE_ID+12,  2,                numeric_format, dump_as_ip_port, "SIP_RTP_DST_PORT",  "SIP RTP stream dest port" },
  { FLOW_TEMPLATE, NTOP_ENTERPRISE_ID, 0, 0, 0, 0, NULL, NULL }
};

/* *********************************************** */

struct plugin_info {
  char sip_call_id[MAX_SIP_STR_LEN];
  char sip_calling_party[MAX_SIP_STR_LEN];
  char sip_called_party[MAX_SIP_STR_LEN];
  char rtp_codecs[SIP_CODECS_STR_LEN];
  struct timeval sip_invite_time, sip_trying_time,
    sip_ringing_time, sip_ok_time, sip_bye_time;
  u_int16_t rtp_src_port, rtp_dst_port;
  u_int32_t rtp_src_ip, rtp_dst_ip;
};

/* *********************************************** */

static PluginInfo sipPlugin; /* Forward */

/* ******************************************* */

void sipPlugin_init(int argc, char *argv[]) {
  traceEvent(TRACE_INFO, "Initialized SIP plugin\n");
}

/* *********************************************** */

/* Handler called whenever an incoming packet is received */

static void sipPlugin_packet(u_char new_bucket, void *pluginData,
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

  if((payload == NULL) || (payloadLen == 0)) return;

  if(new_bucket /* This bucket has been created recently */) {
    /* Check whether this is an RTP or SIP flow */
    if((bkt->proto == 17 /* UDP */)
       && ((bkt->sport == DEFAULT_SIP_PORT) || (bkt->dport == DEFAULT_SIP_PORT)) /* SIP */
       ) {
      PluginInformation *info;

      info = (PluginInformation*)malloc(sizeof(PluginInformation));
      if(info == NULL) {
	traceEvent(TRACE_ERROR, "Not enough memory?");
	return; /* Not enough memory */
      }

      info->pluginPtr  = (void*)&sipPlugin;
      pluginData = info->pluginData = (struct plugin_info*)malloc(sizeof(struct plugin_info));

      if(info->pluginData == NULL) {
	traceEvent(TRACE_ERROR, "Not enough memory?");
	free(info);
	return; /* Not enough memory */
      } else {
	/* Set defaults */
	struct plugin_info *infos = (struct plugin_info*)pluginData;

	info->next = bkt->plugin;
	bkt->plugin = info;

	memset(infos, 0, sizeof(struct plugin_info));
      }
    }
  }

  if((pluginData != NULL) && (payloadLen > 0)) {
    char *my_payload, *strtokState, *row;
    char *from = NULL, *to = NULL, *server = NULL, *audio = NULL, *video = NULL, *c_ip = NULL;
    struct plugin_info *info = (struct plugin_info*)pluginData;

    /* Handle your Sip packet here */
    my_payload = malloc(payloadLen+1);

    if(my_payload != NULL) {
      char *rtpmap;

      memcpy(my_payload, payload, payloadLen);
      my_payload[payloadLen] = '\0';

      row = strtok_r((char*)my_payload, "\r\n", &strtokState);

      if(row != NULL) {
	if(strstr(row, "INVITE"))
	  info->sip_invite_time.tv_sec = h->ts.tv_sec, info->sip_invite_time.tv_usec = h->ts.tv_usec;
	else if(strstr(row, "Trying"))
	  info->sip_trying_time.tv_sec = h->ts.tv_sec, info->sip_trying_time.tv_usec = h->ts.tv_usec;
	else if(strstr(row, "Ringing"))
	  info->sip_ringing_time.tv_sec = h->ts.tv_sec, info->sip_ringing_time.tv_usec = h->ts.tv_usec;
	else if(strstr(row, "OK"))
	  info->sip_ok_time.tv_sec = h->ts.tv_sec, info->sip_ok_time.tv_usec = h->ts.tv_usec;
	else if(strstr(row, "BYE"))
	  info->sip_bye_time.tv_sec = h->ts.tv_sec, info->sip_bye_time.tv_usec = h->ts.tv_usec;

	row = strtok_r(NULL, "\r\n", &strtokState);

	while(row != NULL) {
#ifdef SIP_DEBUG
	  //traceEvent(TRACE_INFO, "==> SIP [%d] '%s'", strlen(row), row);
#endif
	  if((from == NULL)
	     && ((!strncmp(row, "From: ", 6))  || (!strncmp(row, "f: ", 3)))) {
	    from = row;
	  } else if((to == NULL)
		    && ((!strncmp(row, "To: ", 4)) || (!strncmp(row, "t: ", 3)))) {
	    to = row;
	  } else if(!strncmp(row, "Call-ID: ", 8)) {
	    strncpy(info->sip_call_id, &row[9], MAX_SIP_STR_LEN);
	  } else if((server == NULL) && (!strncmp(row, "Server: ", 8))) {
	    server = row;
	  } else if((audio == NULL) && (!strncmp(row, "m=audio ", 8))) {
	    audio = row;
	  } else if((video == NULL) && (!strncmp(row, "m=video ", 8))) {
	    video = row;
	  } else if((c_ip == NULL) && (!strncmp(row, "c=IN IP4 ", 9))) {
	    c_ip = &row[9];
	  } else if((rtpmap = strstr(row, "=rtpmap:")) != NULL) {
	    char *codec;
	    int i;

	    if(rtpmap[10] == ' ')
	      codec = &rtpmap[11];
	    else
	      codec = &rtpmap[10];

	    for(i=0; codec[i] != '\0'; i++)
	      if(codec[i] == '/') {
		codec[i] = '\0';
		break;
	      }

	    if(strstr(codec, "telephone-event") == NULL) {
	      if(info->rtp_codecs[0] == '\0') {
		snprintf(info->rtp_codecs, sizeof(info->rtp_codecs)-1, "%s", codec);
	      } else {
		if(strstr(info->rtp_codecs, codec) == NULL) {
		  char tmpStr[SIP_CODECS_STR_LEN];
		  
		  snprintf(tmpStr, sizeof(tmpStr)-1, "%s;%s",
			   info->rtp_codecs, codec);
		  strcpy(info->rtp_codecs, tmpStr);
		}
	      }
	    }
	  }

	  row = strtok_r(NULL, "\r\n", &strtokState);
	}
      }

      if(server) {
	strtok_r(server, ":", &strtokState);
	server = strtok_r(NULL, ":", &strtokState);
#ifdef SIP_DEBUG
	/* traceEvent(TRACE_INFO, "Server '%s'", server); */
#endif
      }

      if(from && to /* && (!strncasecmp((char*)my_payload, SIP_INVITE, strlen(SIP_INVITE))) */ ) {
	strtok_r(from, ":", &strtokState);
	strtok_r(NULL, ":\"", &strtokState);
	from = strtok_r(NULL, "\"@>", &strtokState);

	strtok_r(to, ":", &strtokState);
	strtok_r(NULL, "\":", &strtokState);
	to = strtok_r(NULL, "\"@>", &strtokState);
#ifdef SIP_DEBUG
	traceEvent(TRACE_INFO, "'%s'->'%s'", from, to);
#endif
	strncpy(info->sip_calling_party, from, MAX_SIP_STR_LEN);
	strncpy(info->sip_called_party, to, MAX_SIP_STR_LEN);
      }

      if(audio) {
	strtok_r(audio, " ", &strtokState);
	audio = strtok_r(NULL, " ", &strtokState);
#ifdef SIP_DEBUG
	traceEvent(TRACE_INFO, "RTP '%s:%s'", c_ip /* _intoa(*src, buf, sizeof(buf))*/, audio);
#endif

	if(cmpIpAddress(&bkt->src->host, src)) {
	  /* Direction: src -> dst */

	  info->rtp_src_ip = c_ip ? ntohl(inet_addr(c_ip)) : 0;

	  if(audio)
	    info->rtp_src_port = atoi(audio);
	} else {
	  /* Direction: dst -> src */

	  info->rtp_dst_ip = c_ip ? ntohl(inet_addr(c_ip)) : 0;
	  if(audio) info->rtp_dst_port = atoi(audio);
	}
      }

      if(video) {
	strtok_r(video, " ", &strtokState);
	video = strtok_r(NULL, " ", &strtokState);
#ifdef SIP_DEBUG
	traceEvent(TRACE_INFO, "RTP '%s:%s'", c_ip /* _intoa(*src, buf, sizeof(buf)) */, video);
#endif
      }

      free(my_payload);
    } else
      traceEvent(TRACE_ERROR, "Not enough memory?");
  }
}

/* *********************************************** */

/* Handler called when the flow is deleted (after export) */

static void sipPlugin_delete(FlowHashBucket* bkt, void *pluginData) {

  if(pluginData != NULL) {
    struct plugin_info *info = (struct plugin_info*)pluginData;

#ifdef SIP_DEBUG
    char buf[256], buf1[256];

    traceEvent(TRACE_INFO, "SIP: '%s'->'%s'", info->sip_calling_party, info->sip_called_party);
    traceEvent(TRACE_INFO, "RTP  '%s:%d'->'%s:%d'",
	       _intoaV4(info->rtp_src_ip, buf, sizeof(buf)), info->rtp_src_port,
	       _intoaV4(info->rtp_dst_ip, buf1, sizeof(buf1)), info->rtp_dst_port);
#endif

    free(info);
  }
}

/* *********************************************** */

/* Handler called at startup when the template is read */

static V9V10TemplateElementId* sipPlugin_get_template(char* template_name) {
  int i;

  for(i=0; sipPlugin_template[i].templateElementId != 0; i++) {
    if(!strcmp(template_name, sipPlugin_template[i].templateElementName)) {
      return(&sipPlugin_template[i]);
    }
  }

  return(NULL); /* Unknown */
}

/* *********************************************** */

/* Handler called whenver a flow attribute needs to be exported */

static int sipPlugin_export(void *pluginData, V9V10TemplateElementId *theTemplateElement,
			    int direction /* 0 = src->dst, 1 = dst->src */,
			    FlowHashBucket *bkt, char *outBuffer,
			    u_int* outBufferBegin, u_int* outBufferMax) {
  int i;
#ifdef SIP_DEBUG
    char buf[32];
#endif

  for(i=0; sipPlugin_template[i].templateElementId != 0; i++) {
    if(theTemplateElement->templateElementId == sipPlugin_template[i].templateElementId) {
      if((*outBufferBegin)+sipPlugin_template[i].templateElementLen > (*outBufferMax))
	return(-2); /* Too long */

      if(pluginData) {
	struct plugin_info *info = (struct plugin_info *)pluginData;

	switch(sipPlugin_template[i].templateElementId) {
	case BASE_ID:
	  copyLen((u_char*)info->sip_call_id, sipPlugin_template[i].templateElementLen,
		  outBuffer, outBufferBegin, outBufferMax);
#ifdef SIP_DEBUG
	  if(readOnlyGlobals.traceMode) traceEvent(TRACE_INFO, "sip_call_id: %s", info->sip_call_id);
#endif
	  break;
	case BASE_ID+1:
	  copyLen((u_char*)info->sip_calling_party, sipPlugin_template[i].templateElementLen,
		  outBuffer, outBufferBegin, outBufferMax);
#ifdef SIP_DEBUG
	  if(readOnlyGlobals.traceMode) traceEvent(TRACE_INFO, "sip_calling_party: %s", info->sip_calling_party);
#endif
	  break;
	case BASE_ID+2:
	  copyLen((u_char*)info->sip_called_party, sipPlugin_template[i].templateElementLen,
		  outBuffer, outBufferBegin, outBufferMax);
#ifdef SIP_DEBUG
	  if(readOnlyGlobals.traceMode) traceEvent(TRACE_INFO, "sip_called_party: %s", info->sip_called_party);
#endif
	  break;
	case BASE_ID+3:
	  copyLen((u_char*)info->rtp_codecs, sipPlugin_template[i].templateElementLen,
		  outBuffer, outBufferBegin, outBufferMax);
#ifdef SIP_DEBUG
	  if(readOnlyGlobals.traceMode) traceEvent(TRACE_INFO, "rtp_codecs: %s", info->rtp_codecs);
#endif
	  break;
	case BASE_ID+4:
	  copyInt32(info->sip_invite_time.tv_sec, outBuffer, outBufferBegin, outBufferMax);
#ifdef SIP_DEBUG
	  if(readOnlyGlobals.traceMode) traceEvent(TRACE_INFO, "sip_invite_time: %u", info->sip_invite_time.tv_sec);
#endif
	  break;
	case BASE_ID+5:
	  copyInt32(info->sip_trying_time.tv_sec, outBuffer, outBufferBegin, outBufferMax);
#ifdef SIP_DEBUG
	  if(readOnlyGlobals.traceMode) traceEvent(TRACE_INFO, "sip_trying_time: %u",
		     info->sip_trying_time.tv_sec);
#endif
	  break;
	case BASE_ID+6:
	  copyInt32(info->sip_ringing_time.tv_sec, outBuffer, outBufferBegin, outBufferMax);
#ifdef SIP_DEBUG
	  if(readOnlyGlobals.traceMode) traceEvent(TRACE_INFO, "sip_ringing_time: %u",
		     info->sip_ringing_time.tv_sec);
#endif
	  break;
	case BASE_ID+7:
	  copyInt32(info->sip_ok_time.tv_sec, outBuffer, outBufferBegin, outBufferMax);
#ifdef SIP_DEBUG
	  if(readOnlyGlobals.traceMode) traceEvent(TRACE_INFO, "sip_ok_time: %u",
		     info->sip_ok_time.tv_sec);
#endif
	  break;
	case BASE_ID+8:
	  copyInt32(info->sip_bye_time.tv_sec, outBuffer, outBufferBegin, outBufferMax);
#ifdef SIP_DEBUG
	  if(readOnlyGlobals.traceMode) traceEvent(TRACE_INFO, "sip_bye_time: %u",
		     info->sip_bye_time.tv_sec);
#endif
	  break;
	case BASE_ID+9:
	  copyInt32(direction == 0 ? info->rtp_src_ip :
		    info->rtp_dst_ip, outBuffer, outBufferBegin, outBufferMax);
#ifdef SIP_DEBUG
	  if(readOnlyGlobals.traceMode) 
	    traceEvent(TRACE_INFO, "rtp_src_ip: %s",
		       _intoaV4(info->rtp_src_ip, buf, sizeof(buf)));
#endif
	  break;
	case BASE_ID+10:
	  copyInt16(direction == 0 ? info->rtp_src_port :
		    info->rtp_dst_port, outBuffer, outBufferBegin, outBufferMax);
#ifdef SIP_DEBUG
	  if(readOnlyGlobals.traceMode) traceEvent(TRACE_INFO, "rtp_src_port: %d",
						   info->rtp_src_port);
#endif
	  break;
	case BASE_ID+11:
	  copyInt32(direction != 0 ? info->rtp_src_ip :
		    info->rtp_dst_ip, outBuffer, outBufferBegin, outBufferMax);
#ifdef SIP_DEBUG
	  if(readOnlyGlobals.traceMode) traceEvent(TRACE_INFO, "rtp_dst_ip: %s",
						   _intoaV4(info->rtp_dst_ip, buf, sizeof(buf)));
#endif
	  break;
	case BASE_ID+12:
	  copyInt16(direction != 0 ? info->rtp_src_port :
		    info->rtp_dst_port, outBuffer, outBufferBegin, outBufferMax);
#ifdef SIP_DEBUG
	  if(readOnlyGlobals.traceMode) traceEvent(TRACE_INFO, "rtp_dst_port: %d",
						   info->rtp_dst_port);
#endif
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

static int sipPlugin_print(void *pluginData, V9V10TemplateElementId *theTemplateElement,
			   int direction /* 0 = src->dst, 1 = dst->src */,
			   FlowHashBucket *bkt, char *line_buffer, u_int line_buffer_len) {
  int i;
  char buf[32];

  for(i=0; sipPlugin_template[i].templateElementId != 0; i++) {
    if(theTemplateElement->templateElementId == sipPlugin_template[i].templateElementId) {
      if(pluginData) {
	struct plugin_info *info = (struct plugin_info *)pluginData;

	switch(sipPlugin_template[i].templateElementId) {
	case BASE_ID:
	  snprintf(&line_buffer[strlen(line_buffer)], (line_buffer_len-strlen(line_buffer)), "%s",
		   info->sip_call_id);
	  break;
	case BASE_ID+1:
	  snprintf(&line_buffer[strlen(line_buffer)], (line_buffer_len-strlen(line_buffer)), "%s",
		   info->sip_calling_party);
	  break;
	case BASE_ID+2:
	  snprintf(&line_buffer[strlen(line_buffer)], (line_buffer_len-strlen(line_buffer)), "%s",
		   info->sip_called_party);
	  break;
	case BASE_ID+3:
	  snprintf(&line_buffer[strlen(line_buffer)], (line_buffer_len-strlen(line_buffer)), "%s",
		   info->rtp_codecs);
	  break;
	case BASE_ID+4:
	  snprintf(&line_buffer[strlen(line_buffer)], (line_buffer_len-strlen(line_buffer)), "%u",
		   (unsigned int)info->sip_invite_time.tv_sec);
	  break;
	case BASE_ID+5:
	  snprintf(&line_buffer[strlen(line_buffer)], (line_buffer_len-strlen(line_buffer)), "%u",
		   (unsigned int)info->sip_trying_time.tv_sec);
	  break;
	case BASE_ID+6:
	  snprintf(&line_buffer[strlen(line_buffer)], (line_buffer_len-strlen(line_buffer)), "%u",
		   (unsigned int)info->sip_ringing_time.tv_sec);
	  break;
	case BASE_ID+7:
	  snprintf(&line_buffer[strlen(line_buffer)], (line_buffer_len-strlen(line_buffer)), "%u",
		   (unsigned int)info->sip_ok_time.tv_sec);
	  break;
	case BASE_ID+8:
	  snprintf(&line_buffer[strlen(line_buffer)], (line_buffer_len-strlen(line_buffer)), "%u",
		   (unsigned int)info->sip_bye_time.tv_sec);
	  break;
	case BASE_ID+9:
	  snprintf(&line_buffer[strlen(line_buffer)], (line_buffer_len-strlen(line_buffer)), "%s",
		   _intoaV4(direction == 0 ? info->rtp_src_ip : info->rtp_dst_ip, buf, sizeof(buf)));
	  break;
	case BASE_ID+10:
	  snprintf(&line_buffer[strlen(line_buffer)], (line_buffer_len-strlen(line_buffer)), "%d",
		   direction == 0 ? info->rtp_src_port : info->rtp_dst_port);
	  break;
	case BASE_ID+11:
	  snprintf(&line_buffer[strlen(line_buffer)], (line_buffer_len-strlen(line_buffer)), "%s",
		   _intoaV4(direction != 0 ? info->rtp_src_ip : info->rtp_dst_ip, buf, sizeof(buf)));
	  break;
	case BASE_ID+12:
	  snprintf(&line_buffer[strlen(line_buffer)], (line_buffer_len-strlen(line_buffer)), "%d",
		   direction != 0 ? info->rtp_src_port : info->rtp_dst_port);
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

static V9V10TemplateElementId* sipPlugin_conf(void) {
  return(sipPlugin_template);
}

/* *********************************************** */

/* Plugin entrypoint */
static PluginInfo sipPlugin = {
  NPROBE_REVISION,
  "SIP",
  "0.2",
  "Handle SIP protocol",
  "L.Deri <deri@ntop.org>",
  0 /* not always enabled */, 1, /* enabled */
  sipPlugin_init,
  NULL, /* Term */
  sipPlugin_conf,
  sipPlugin_delete,
  1, /* call packetFlowFctn for each packet */
  sipPlugin_packet,
  sipPlugin_get_template,
  sipPlugin_export,
  sipPlugin_print,
  NULL,
  NULL
};


/* *********************************************** */

/* Plugin entry fctn */
#ifdef MAKE_STATIC_PLUGINS
PluginInfo* sipPluginEntryFctn(void)
#else
PluginInfo* PluginEntryFctn(void)
#endif
{
  return(&sipPlugin);
}

