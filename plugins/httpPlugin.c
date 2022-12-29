/*
 *  Copyright (C) 2006-10 Luca Deri <deri@ntop.org>
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

#define BASE_ID            NTOP_BASE_ID+170
#define URL_MAX_LEN        128
#define HOST_MAX_LEN       64
#define METHOD_LEN         8
#define REQ_CONTENT_LEN    256
#define MIME_LEN           40
#define USER_AGENT_LEN     128
#define COOKIE_LEN         128

#define MAX_BYTES_SENT     64
#define MAX_BYTES_RCVD     64

/* RFC 2616 */
/* Request */
#define GET_URL            "GET /"
#define POST_URL           "POST /"
#define HEAD_URL           "HEAD /"
/* Note the other methods (PUT, DELETE, TRACE, CONNECT)
   have not been implemented as they are used very seldom */

/* Response */
#define HTTP_1_0_URL       "HTTP/1.0 "
#define HTTP_1_1_URL       "HTTP/1.1 "

/*Host*/
#define HOST               "Host: "

/*Host*/
#define USER_AGENT         "User-Agent: "

/*Host*/
#define COOKIE             "Cookie: "

/*Mime*/
#define MIME               "Content-Type: "

static V9V10TemplateElementId httpPlugin_template[] = {
  { FLOW_TEMPLATE, NTOP_ENTERPRISE_ID, BASE_ID,   URL_MAX_LEN, ascii_format, dump_as_ascii, "HTTP_URL", "HTTP URL" },
  { FLOW_TEMPLATE, NTOP_ENTERPRISE_ID, BASE_ID+1, 2, numeric_format, dump_as_uint, "HTTP_RET_CODE", "HTTP return code (e.g. 200, 304...)" },
  { FLOW_TEMPLATE, NTOP_ENTERPRISE_ID, BASE_ID+2, HOST_MAX_LEN, ascii_format, dump_as_ascii, "HTTP_HOST", "HTTP HOST" },
  { FLOW_TEMPLATE, NTOP_ENTERPRISE_ID, BASE_ID+3, METHOD_LEN, ascii_format, dump_as_ascii, "HTTP_REQ_METHOD", "HTTP REQUEST METHOD" },
  { FLOW_TEMPLATE, NTOP_ENTERPRISE_ID, BASE_ID+4, REQ_CONTENT_LEN, ascii_format, dump_as_ascii, "HTTP_POST_CONTENT", "HTTP POST REQ CONTENT" },
  { FLOW_TEMPLATE, NTOP_ENTERPRISE_ID, BASE_ID+5, MIME_LEN, ascii_format, dump_as_ascii, "HTTP_MIME", "HTTP MIME TYPE" },
  { FLOW_TEMPLATE, NTOP_ENTERPRISE_ID, BASE_ID+6, USER_AGENT_LEN, ascii_format, dump_as_ascii, "HTTP_USER_AGENT", "HTTP USER AGENT" },
  { FLOW_TEMPLATE, NTOP_ENTERPRISE_ID, BASE_ID+7, COOKIE_LEN, ascii_format, dump_as_ascii, "HTTP_COOKIE", "HTTP COOKIE" },
  { FLOW_TEMPLATE, NTOP_ENTERPRISE_ID, 0, 0, 0, 0, NULL, NULL }
};

struct plugin_info {
  char http_url[URL_MAX_LEN+1];
  char http_host[HOST_MAX_LEN+1];
  char http_req_method[METHOD_LEN+1];
  char post_content[REQ_CONTENT_LEN+1];
  u_int16_t ret_code;
  char http_mime[MIME_LEN+1];
  char http_user_agent[USER_AGENT_LEN+1];
  char http_cookie[COOKIE_LEN+1];
};

/* *********************************************** */

static PluginInfo httpPlugin; /* Forward */

/* ******************************************* */

void httpPlugin_init(int argc, char *argv[]) {
  traceEvent(TRACE_INFO, "Initialized HTTP plugin");
}

/* *********************************************** */

/* Handler called whenever an incoming packet is received */

static void httpPlugin_packet(u_char new_bucket, void *pluginData,
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

  // traceEvent(TRACE_INFO, "httpPlugin_packet(%d)", payloadLen);

  if(new_bucket) {
    info = (PluginInformation*)malloc(sizeof(PluginInformation));
    if(info == NULL) {
      	traceEvent(TRACE_ERROR, "Not enough memory?");
	return; /* Not enough memory */
    }

    info->pluginPtr  = (void*)&httpPlugin;
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

  if(payloadLen > 0 && proto == IPPROTO_TCP) {

    char *method;

    //traceEvent(TRACE_INFO, "==> [%d][%d]'%s'", bkt->bytesSent, bkt->bytesRcvd, payload);

    if((!strncmp((char*)payload, GET_URL, strlen(GET_URL)))) method = GET_URL;
    else if((!strncmp((char*)payload, POST_URL, strlen(POST_URL)))) method = POST_URL;
    else if((!strncmp((char*)payload, HTTP_1_0_URL, strlen(HTTP_1_0_URL)))) method = HTTP_1_0_URL;
    else if((!strncmp((char*)payload, HTTP_1_1_URL, strlen(HTTP_1_1_URL)))) method = HTTP_1_1_URL;
    else method = NULL;

    if(method) {
      char url[URL_MAX_LEN+1] = "";
      char host[HOST_MAX_LEN+1] = "";
      char user_agent[USER_AGENT_LEN+1] = "";
      char cookie[COOKIE_LEN+1] = "";
      char post_data[REQ_CONTENT_LEN+1] = "";
      int i, displ;
      char* line = NULL;
      
      if((!strncmp(method, GET_URL, strlen(GET_URL))) 
            || (!strncmp(method, POST_URL, strlen(POST_URL)))) {
        
        if (cmpIpAddress(&bkt->src->host, src))
          bkt->src2dstTos |= 0x01;
        else
          bkt->dst2srcTos |= 0x01;

    /* We need to export this flow now */
        //if(pinfo->http_url[0] != '\0' && pinfo->http_mime[0] != '\0') {
        if(pinfo->http_url[0] != '\0') {
          exportBucket(bkt, 0);
          resetBucketStats(bkt, h, len, sport, dport, payload, payloadLen);
          memset(pinfo, 0, sizeof(struct plugin_info));	  
        }

        //parse host out
        char* p = strstr((char*)payload, HOST);
        int Len;
        char* tmp = NULL;
        if(p) {
            p = p + strlen(HOST);
            memcpy(host, p, min(strlen(p), HOST_MAX_LEN));
            host[HOST_MAX_LEN] = '\0';
            for (i = 0; i < HOST_MAX_LEN; i++) {
              if (host[i] == '\n' || host[i] == '\r') {
                host[i] = '\0';
                break;
              }
            }
            //find empty line ,between http requset headder and body
            /*if (!strncmp(method, POST_URL, strlen(POST_URL))) {
              q = q + 2;
              while((line = strstr(q, "\r\n")) != NULL) {
                if (strlen(q) == strlen(line)) {
                  tmp = line + 2;
                  if (REQ_CONTENT_LEN >= strlen(tmp)) {
                    memcpy(post_data, tmp, strlen(tmp));
                    post_data[strlen(tmp)] = '\0';
                  } else {
                    memcpy(post_data, tmp, REQ_CONTENT_LEN);
                    post_data[REQ_CONTENT_LEN] = '\0';
                  }
                  break;
                }
                q = line + 2;
              }
            }*/
        }

        //Get User-Agent:
        char* user_agent_ptr = strstr((char*)payload, USER_AGENT);
        if(user_agent_ptr) {
          user_agent_ptr = user_agent_ptr + strlen(USER_AGENT);
          memcpy(user_agent, user_agent_ptr, min(strlen(user_agent_ptr), USER_AGENT_LEN));
          user_agent[USER_AGENT_LEN] = '\0';
          for (i = 0; i < USER_AGENT_LEN; i++) {
            if (user_agent[i] == '\n' || user_agent[i] == '\r') {
              user_agent[i] = '\0';
              break;
            }
          }
        }

        //Get Cookie: 
        char* cookie_ptr = strstr((char*)payload, COOKIE);
        if(cookie_ptr) {
          cookie_ptr = cookie_ptr + strlen(COOKIE);
          memcpy(cookie, cookie_ptr, min(strlen(cookie_ptr), COOKIE_LEN));
          cookie[COOKIE_LEN] = '\0';
          for (i = 0; i < COOKIE_LEN; i++) {
            if (cookie[i] == '\n' || cookie[i] == '\r') {
              cookie[i] = '\0';
              break;
            }
          }
        }

        char* ver_s = strstr((char*)payload, " HTTP/");
        if (ver_s) {
          memcpy(url, (char*)&payload[strlen(method)-1], 
                 min(URL_MAX_LEN, ver_s-(char*)&payload[strlen(method)-1]));
          url[URL_MAX_LEN] = '\0';
        }

        displ = 1;
      } else {
        //parse mime type
        char* mime_start = strstr((char*)payload, MIME);
        if (mime_start) {
          mime_start += strlen(MIME);
          memcpy(pinfo->http_mime, mime_start, min(MIME_LEN, strlen(mime_start)));
          pinfo->http_mime[MIME_LEN] = '\0';
          
          for (i=0; i<MIME_LEN; i++) {
            if (pinfo->http_mime[i] == ';' || pinfo->http_mime[i] == '\r' || pinfo->http_mime[i] == '\n') {
              pinfo->http_mime[i] = '\0';
              break;
            }
          }
        }
    
        memcpy(url, (char*)&payload[strlen(method)], 3);
        url[3] = '\0';
        displ = 0;
      }
      
      if(displ == 1) {
	      memcpy(pinfo->http_url, url, strlen(url));
	      memcpy(pinfo->http_host, host, strlen(host));
        memcpy(pinfo->http_req_method, method, strlen(method) - 2);
        pinfo->http_req_method[strlen(method) - 2] = '\0';
        memcpy(pinfo->http_user_agent, user_agent, strlen(user_agent));
        memcpy(pinfo->http_cookie, cookie, strlen(cookie));
        memcpy(pinfo->post_content, post_data, strlen(post_data));
      } else 
	      pinfo->ret_code = atoi(url);
    }
  }
}

/* *********************************************** */

/* Handler called when the flow is deleted (after export) */

static void httpPlugin_delete(FlowHashBucket* bkt, void *pluginData) {
  if(pluginData != NULL)
    free(pluginData);
}

/* *********************************************** */
   
/* Handler called at startup when the template is read */

static V9V10TemplateElementId* httpPlugin_get_template(char* template_name) {
  int i;

  for(i=0; httpPlugin_template[i].templateElementId != 0; i++) {
    if(!strcmp(template_name, httpPlugin_template[i].templateElementName)) {
      return(&httpPlugin_template[i]);
    }
  }

  return(NULL); /* Unknown */
}

/* *********************************************** */

/* Handler called whenever a flow attribute needs to be exported */

static int httpPlugin_export(void *pluginData, V9V10TemplateElementId *theTemplate,
			     int direction /* 0 = src->dst, 1 = dst->src */,
			     FlowHashBucket *bkt, char *outBuffer,
			     u_int* outBufferBegin, u_int* outBufferMax) {
  int i;

  for(i=0; httpPlugin_template[i].templateElementId != 0; i++) {
    if(theTemplate->templateElementId == httpPlugin_template[i].templateElementId) {
      if((*outBufferBegin)+httpPlugin_template[i].templateElementLen > (*outBufferMax))
	return(-2); /* Too long */

      if(pluginData) {
	struct plugin_info *info = (struct plugin_info *)pluginData;

	switch(httpPlugin_template[i].templateElementId) {
	case BASE_ID:
	  memcpy(&outBuffer[*outBufferBegin], info->http_url, URL_MAX_LEN);
	  // traceEvent(TRACE_INFO, "==> URL='%s'", info->http_url);
	  (*outBufferBegin) += httpPlugin_template[i].templateElementLen;
	  break;
	case BASE_ID+1:
	  copyInt16(info->ret_code, outBuffer, outBufferBegin, outBufferMax);
	  // traceEvent(TRACE_INFO, "==> RetCode='%d'", info->ret_code);
	  break;
  case BASE_ID+2:
    memcpy(&outBuffer[*outBufferBegin], info->http_host, HOST_MAX_LEN);
    (*outBufferBegin) += httpPlugin_template[i].templateElementLen;
    break;
  case BASE_ID+3:
    memcpy(&outBuffer[*outBufferBegin], info->http_req_method, METHOD_LEN);
    (*outBufferBegin) += httpPlugin_template[i].templateElementLen;
    break;
  case BASE_ID+4:
    memcpy(&outBuffer[*outBufferBegin], info->post_content, REQ_CONTENT_LEN);
    (*outBufferBegin) += httpPlugin_template[i].templateElementLen;
    break;
  case BASE_ID+5:
    memcpy(&outBuffer[*outBufferBegin], info->http_mime, MIME_LEN);
    (*outBufferBegin) += httpPlugin_template[i].templateElementLen;
    break;
  case BASE_ID+6:
    memcpy(&outBuffer[*outBufferBegin], info->http_user_agent, USER_AGENT_LEN);
    (*outBufferBegin) += httpPlugin_template[i].templateElementLen;
    break;
  case BASE_ID+7:
    memcpy(&outBuffer[*outBufferBegin], info->http_cookie, COOKIE_LEN);
    (*outBufferBegin) += httpPlugin_template[i].templateElementLen;
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

static int httpPlugin_print(void *pluginData, V9V10TemplateElementId *theTemplate,
			    int direction /* 0 = src->dst, 1 = dst->src */,
			    FlowHashBucket *bkt, char *line_buffer, u_int line_buffer_len) {
  int i;

  for(i=0; httpPlugin_template[i].templateElementId != 0; i++) {
    if(theTemplate->templateElementId == httpPlugin_template[i].templateElementId) {

      if(pluginData) {
	struct plugin_info *info = (struct plugin_info *)pluginData;

	switch(httpPlugin_template[i].templateElementId) {
	case BASE_ID:
	  snprintf(&line_buffer[strlen(line_buffer)], (line_buffer_len-strlen(line_buffer)), "%s", info->http_url);
	  break;
	case BASE_ID+1:
	  snprintf(&line_buffer[strlen(line_buffer)], (line_buffer_len-strlen(line_buffer)), "%d", info->ret_code);
	  break;
  case BASE_ID+2:
    snprintf(&line_buffer[strlen(line_buffer)], (line_buffer_len-strlen(line_buffer)), "%s", info->http_host);
    break;
  case BASE_ID+3:
    snprintf(&line_buffer[strlen(line_buffer)], (line_buffer_len-strlen(line_buffer)), "%s", info->http_req_method);
    break;
  case BASE_ID+4:
    snprintf(&line_buffer[strlen(line_buffer)], (line_buffer_len-strlen(line_buffer)), "%s", info->post_content);
    break;
  case BASE_ID+5:
    snprintf(&line_buffer[strlen(line_buffer)], (line_buffer_len-strlen(line_buffer)), "%s", info->http_mime);
    break;
  case BASE_ID+6:
    snprintf(&line_buffer[strlen(line_buffer)], (line_buffer_len-strlen(line_buffer)), "%s", info->http_user_agent);
    break;
  case BASE_ID+7:
    snprintf(&line_buffer[strlen(line_buffer)], (line_buffer_len-strlen(line_buffer)), "%s", info->http_cookie);
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

static V9V10TemplateElementId* httpPlugin_conf(void) {
  return(httpPlugin_template);
}

/* *********************************************** */

/* Plugin entrypoint */
static PluginInfo httpPlugin = {
  NPROBE_REVISION,
  "HTTP Protocol Dissector",
  "0.1",
  "Handle HTTP protocol",
  "L.Deri <deri@ntop.org>",
  0 /* not always enabled */, 1, /* enabled */
  httpPlugin_init,
  NULL, /* Term */
  httpPlugin_conf,
  httpPlugin_delete,
  1, /* call packetFlowFctn for each packet */
  httpPlugin_packet,
  httpPlugin_get_template,
  httpPlugin_export,
  httpPlugin_print,
  NULL,
  NULL
};

/* *********************************************** */

/* Plugin entry fctn */
#ifdef MAKE_STATIC_PLUGINS
PluginInfo* httpPluginEntryFctn(void)
#else
  PluginInfo* PluginEntryFctn(void)
#endif
{
  return(&httpPlugin);
}
 
