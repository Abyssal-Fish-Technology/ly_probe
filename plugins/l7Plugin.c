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


#include "nprobe.h"

#if defined(HAVE_PCRE_H) && defined(HAVE_LIBPCRE)

#define BASE_ID           NTOP_BASE_ID+165
#define FIELD_LEN           8

static V9V10TemplateElementId l7Plugin_template[] = {
  { FLOW_TEMPLATE, NTOP_ENTERPRISE_ID, BASE_ID, FIELD_LEN, ascii_format, dump_as_ascii, "L7_PROTO", "Symbolic layer 7 protocol description" },
  { FLOW_TEMPLATE, NTOP_ENTERPRISE_ID, 0, 0, 0, 0, NULL, NULL }
};

#include "pcre.h"

struct plugin_info {
  char *protocol_name;
  u_int8_t proto_checked;
};

/* *********************************************** */

struct proto_info {
  char *proto_name;
  pcre *proto_regex;
  struct proto_info *next;
};

static struct proto_info *proto_root;
static u_int num_patterns;

#define CONST_PATTERN_EXTENSION   ".pat"
#define MAX_BYTES_SENT            1024
#define MAX_BYTES_RCVD            1024

/* *********************************************** */

static PluginInfo l7Plugin; /* Forward */

/* ******************************************* */

static struct proto_info* loadPattern(char *base_dir, char *pattern_filename) {
  FILE *fd;
  struct proto_info *proto;
  char path[512];

  proto = (struct proto_info*)malloc(sizeof(struct proto_info));
  if(proto == NULL) {
    traceEvent(TRACE_WARNING, "Not enough memory while loading pattern");
    return(NULL);
  } else
    memset(proto, 0, sizeof(struct proto_info));

  snprintf(path, sizeof(path), "%s/%s", base_dir, pattern_filename);
  fd = fopen(path, "r");

  if(fd) {
    char buffer[512];

    while((!feof(fd)) && (fgets(buffer, sizeof(buffer), fd) != NULL)) {
      if((buffer[0] != '#')
	 && (buffer[0] != ' ') && (buffer[0] != '\n')
	 && (buffer[0] != '\r') && (buffer[0] != '\t')) {
	buffer[strlen(buffer)-1] = '\0';

	if(proto->proto_name == NULL)
	  proto->proto_name = strdup(buffer);
	else if(proto->proto_regex == NULL) {
	  const char *error;
	  int erroffset;

	  proto->proto_regex = pcre_compile(buffer,               /* the pattern */
					    PCRE_CASELESS,        /* default options */
					    &error,               /* for error message */
					    &erroffset,           /* for error offset */
					    NULL);                /* use default character tables */
	  
	  if(proto->proto_regex == NULL) {
	    if(proto->proto_name != NULL) free(proto->proto_name);
	    free(proto);
            return(NULL);
	    traceEvent(TRACE_WARNING, "Invalid pattern. Skipping...");
	  } else {
	    /* traceEvent(TRACE_INFO, "L7: [%s][%s]", proto->proto_name, buffer); */
	  }

	  break;
	}
      }
    }

    fclose(fd);
  } else
    traceEvent(TRACE_WARNING, "Unable to read pattern file %s", path);
  
  if(proto->proto_name && proto->proto_regex)
    return(proto);
  else {
    free(proto);
    return(NULL);
  }
}

/* ******************************************* */

void l7Plugin_init(int argc, char *argv[]) {
  DIR* directoryPointer = NULL;
  char* dirPath = "/bin/plugins/l7-patterns/";
  struct dirent* dp;
  struct proto_info *the_proto;

  traceEvent(TRACE_INFO, "Initialized L7 plugin");

  proto_root = NULL;
  num_patterns = 0;

  if((directoryPointer = opendir(dirPath)) == NULL) {
    traceEvent(TRACE_INFO, "Unable to read directory '%s'", dirPath);
    return;
  }

  while((dp = readdir(directoryPointer)) != NULL) {
    if(dp->d_name[0] == '.')
      continue;
    else if(strlen(dp->d_name) < strlen(CONST_PATTERN_EXTENSION))
      continue;

    traceEvent(TRACE_INFO, "Loading pattern %s", dp->d_name);

    the_proto = loadPattern(dirPath, dp->d_name);

    if(the_proto) {
      the_proto->next = proto_root;
      proto_root = the_proto;
      num_patterns++;
    }
  }

  closedir(directoryPointer);

  traceEvent(TRACE_INFO, "Loaded %d patterns", num_patterns);
}

/* *********************************************** */

static char* protocolMatch(u_char *payload, int payloadLen) {
  struct proto_info *scanner = proto_root;
  
  /* traceEvent(TRACE_INFO, "protocolMatch(%s)", payload); */

  while(scanner) {
    //traceEvent(TRACE_INFO, "protocolMatch(%s, %d)", scanner->proto_name, payloadLen);

    int rc = pcre_exec(scanner->proto_regex, /* the compiled pattern */
		       NULL,                 /* no extra data - we didn't study the pattern */
		       (char*)payload,       /* the subject string */
		       payloadLen,           /* the length of the subject */
		       0,                    /* start at offset 0 in the subject */
		       0 /* PCRE_PARTIAL*/,         /* default options */
		       NULL,                 /* output vector for substring information */
		       0);                   /* number of elements in the output vector */
    
    if(rc >= 0) {
      //traceEvent(TRACE_INFO, "protocolMatch(%s)", scanner->proto_name);
      return(scanner->proto_name);
    } else {
      // traceEvent(TRACE_ERROR, "pcre_exec returned %d", rc);
    }

    scanner = scanner->next;
  }

  return(NULL);
}

/* *********************************************** */

/* Handler called whenever an incoming packet is received */

static void l7Plugin_packet(u_char new_bucket, void *pluginData,
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

  // traceEvent(TRACE_INFO, "l7Plugin_packet(%d)", payloadLen)

  if(new_bucket) {
    info = (PluginInformation*)malloc(sizeof(PluginInformation));
    if(info == NULL) {
      traceEvent(TRACE_ERROR, "Not enough memory?");
      return; /* Not enough memory */
    }

    info->pluginPtr  = (void*)&l7Plugin;
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
}

/* *********************************************** */

/* Handler called when the flow is deleted (after export) */

static void l7Plugin_delete(FlowHashBucket* bkt, void *pluginData) {
  if(pluginData != NULL)
    free(pluginData);
}

/* *********************************************** */

/* Handler called at startup when the template is read */

static V9V10TemplateElementId* l7Plugin_get_template(char* template_name) {
  int i;

  for(i=0; l7Plugin_template[i].templateElementId != 0; i++) {
    if(!strcmp(template_name, l7Plugin_template[i].templateElementName)) {
      return(&l7Plugin_template[i]);
    }
  }

  return(NULL); /* Unknown */
}

/* *********************************************** */

/* Handler called whenever a flow attribute needs to be exported */

static int l7Plugin_export(void *pluginData, V9V10TemplateElementId *theTemplate,
			   int direction /* 0 = src->dst, 1 = dst->src */,
			   FlowHashBucket *bkt, char *outBuffer,
			   u_int* outBufferBegin, u_int* outBufferMax) {
  int i;
  struct plugin_info *pinfo = (struct plugin_info*)pluginData;

  /* traceEvent(TRACE_INFO, "==> Payload (%d/%d)", bkt->src2dstPayloadLen, bkt->dst2srcPayloadLen); */

  if((pinfo->protocol_name == NULL) && (!pinfo->proto_checked)) {
    char *proto_name = NULL;

    proto_name = protocolMatch(bkt->src2dstPayload, bkt->src2dstPayloadLen);
    if(!proto_name)
      proto_name = protocolMatch(bkt->dst2srcPayload, bkt->dst2srcPayloadLen);
    
    if(proto_name) {
      /* traceEvent(TRACE_INFO, "*******> Found '%s' protocol flow", proto_name); */
      pinfo->protocol_name = proto_name;
    }

    pinfo->proto_checked = 1;
  }

  for(i=0; l7Plugin_template[i].templateElementId != 0; i++) {
    if(theTemplate->templateElementId == l7Plugin_template[i].templateElementId) {
      if((*outBufferBegin)+l7Plugin_template[i].templateElementLen > (*outBufferMax))
	return(-2); /* Too long */

      if(pluginData) {
	struct plugin_info *info = (struct plugin_info *)pluginData;

	switch(l7Plugin_template[i].templateElementId) {
	case BASE_ID:
	  memset(&outBuffer[*outBufferBegin], 0, FIELD_LEN);
	  
	  if(info->protocol_name) {
	    int len = strlen(info->protocol_name);

	    if(len > FIELD_LEN) len = FIELD_LEN;
	    memcpy(&outBuffer[*outBufferBegin], info->protocol_name, len);
	    traceEvent(TRACE_INFO, "-> L7_PROTO: %s", info->protocol_name);
	  }
	  (*outBufferBegin) += l7Plugin_template[i].templateElementLen;
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

static int l7Plugin_print(void *pluginData, V9V10TemplateElementId *theTemplate,
			  int direction /* 0 = src->dst, 1 = dst->src */,
			  FlowHashBucket *bkt, char *line_buffer, u_int line_buffer_len) {
  int i;

  for(i=0; l7Plugin_template[i].templateElementId != 0; i++) {
    if(theTemplate->templateElementId == l7Plugin_template[i].templateElementId) {
 
      if(pluginData) {
	struct plugin_info *info = (struct plugin_info *)pluginData;

	switch(l7Plugin_template[i].templateElementId) {
	case BASE_ID:
	  snprintf(&line_buffer[strlen(line_buffer)], 
		   (line_buffer_len-strlen(line_buffer)),
		   "%s", info->protocol_name ? info->protocol_name : "");
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

static V9V10TemplateElementId* l7Plugin_conf(void) {
  return(l7Plugin_template);
}

/* *********************************************** */

/* Plugin entrypoint */
static PluginInfo l7Plugin = {
  NPROBE_REVISION,
  "L7 Protocol Recognition",
  "0.1",
  "Handle L7 protocols",
  "L.Deri <deri@ntop.org>",
  0 /* not always enabled */, 1, /* enabled */
  l7Plugin_init,
  NULL, /* Term */
  l7Plugin_conf,
  l7Plugin_delete,
  1, /* call packetFlowFctn for each packet */
  l7Plugin_packet,
  l7Plugin_get_template,
  l7Plugin_export,
  l7Plugin_print,
  NULL,
  NULL
};

/* *********************************************** */
#endif

/* Plugin entry fctn */
#ifdef MAKE_STATIC_PLUGINS
PluginInfo* l7PluginEntryFctn(void)
#else
     PluginInfo* PluginEntryFctn(void)
#endif
{
#if defined(HAVE_PCRE_H) && defined(HAVE_LIBPCRE)
  return(&l7Plugin);
#else
  traceEvent(TRACE_INFO, "L7 plugin disabled (missing 'pcre' library)");
  return(NULL);
#endif
}
