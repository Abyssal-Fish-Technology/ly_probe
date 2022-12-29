/* 
 *        nProbe - a Netflow v5/v9/IPFIX probe for IPv4/v6 
 *
 *       Copyright (C) 2007-10 Luca Deri <deri@ntop.org> 
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

#include "nprobe.h"

// #define DEBUG_FLOWS

#define LEN_SMALL_WORK_BUFFER 2048

static int collectorInSocket = -1, collectorInSctpSocket = -1, remoteInSocket = -1;
static pthread_t collectThread = 0;
static FlowSetV9 *templates;
static u_int32_t num_dissected_flows = 0;

/* forward */
void* netFlowCollectLoop(void* notUsed);

struct generic_netflow_record {
  /* v5 */
  u_int32_t srcaddr;    /* Source IP Address */
  u_int32_t dstaddr;    /* Destination IP Address */
  u_int32_t nexthop;    /* Next hop router's IP Address */
  u_int16_t input;      /* Input interface index */
  u_int16_t output;     /* Output interface index */
  u_int32_t sentPkts, rcvdPkts;
  u_int32_t sentOctets, rcvdOctets;
  u_int32_t first;      /* SysUptime at start of flow */
  u_int32_t last;       /* and of last packet of the flow */
  u_int16_t srcport;    /* TCP/UDP source port number (.e.g, FTP, Telnet, etc.,or equivalent) */
  u_int16_t dstport;    /* TCP/UDP destination port number (.e.g, FTP, Telnet, etc.,or equivalent) */
  u_int8_t  tcp_flags;  /* Cumulative OR of tcp flags */
  u_int8_t  proto;      /* IP protocol, e.g., 6=TCP, 17=UDP, etc... */
  u_int8_t  tos;        /* IP Type-of-Service */
  u_int16_t dst_as;     /* dst peer/origin Autonomous System */
  u_int16_t src_as;     /* source peer/origin Autonomous System */
  u_int8_t  dst_mask;   /* destination route's mask bits */
  u_int8_t  src_mask;   /* source route's mask bits */

  /* v9 */
  u_int16_t vlanId;

  /* Latency extensions */
  u_int32_t nw_latency_sec, nw_latency_usec;

  /* VoIP Extensions */
  char sip_call_id[50], sip_calling_party[50], sip_called_party[50];
};

/* ********************************************************* */

int createNetFlowListener(u_short collectorInPort) {
  int sockopt = 1;
  struct sockaddr_in sockIn;

  if(collectorInPort > 0) {
    errno = 0;
    collectorInSocket = socket(AF_INET, SOCK_DGRAM, 0);
    if((collectorInSocket < 0) || (errno != 0) ) {
      traceEvent(TRACE_INFO, "Unable to create a UDP socket - returned %d, error is '%s'(%d)",
		 collectorInSocket, strerror(errno), errno);
      return(-1);
    }

#ifdef HAVE_SCTP
    collectorInSctpSocket = socket(AF_INET, SOCK_SEQPACKET, IPPROTO_SCTP);

    if((collectorInSctpSocket < 0) || (errno != 0)) {
      traceEvent(TRACE_INFO, "Unable to create a SCTP socket - returned %d, error is '%s'(%d)",
		 collectorInSocket, strerror(errno), errno);
    }
#endif

    traceEvent(TRACE_INFO, "Created a UDP socket (%d)", collectorInSocket);

#ifdef HAVE_SCTP
    if(collectorInSctpSocket > 0)
      traceEvent(TRACE_INFO, "Created a SCTP socket (%d)", collectorInSctpSocket);
#endif

    setsockopt(collectorInSocket, SOL_SOCKET, SO_REUSEADDR, (char *)&sockopt, sizeof(sockopt));

    sockIn.sin_family            = AF_INET;
    sockIn.sin_port              = (int)htons(collectorInPort);
    sockIn.sin_addr.s_addr       = INADDR_ANY;

    if((bind(collectorInSocket, (struct sockaddr *)&sockIn, sizeof(sockIn)) < 0)
#ifdef HAVE_SCTP
       || ((collectorInSctpSocket > 0)
	   && (bind(collectorInSctpSocket, (struct sockaddr *)&sockIn, sizeof(sockIn)) < 0))
#endif
       ) {
      traceEvent(TRACE_ERROR, "Collector port %d already in use", collectorInPort);
      close(collectorInSocket);
      collectorInSocket = 0;
#ifdef HAVE_SCTP
      if(collectorInSctpSocket) close(collectorInSctpSocket);
      collectorInSctpSocket = 0;
#endif
      return(0);
    }

#ifdef HAVE_SCTP
    if(collectorInSctpSocket > 0) {
      if(listen(collectorInSctpSocket, 100) == -1) {
	traceEvent(TRACE_ERROR, "Listen on SCTP socket failed [%s]", strerror(errno));
      }
    }
#endif

    traceEvent(TRACE_NORMAL, "Collector listening on port %d", collectorInPort);
    pthread_create(&collectThread, NULL, netFlowCollectLoop, NULL);
  }

  return(0);
}

/* ********************************************************* */

void closeNetFlowListener() {
  if(collectorInSocket != -1)     close(collectorInSocket);
  if(collectorInSctpSocket != -1) close(collectorInSctpSocket);
}

/* ********************************************************* */

int createRemoteListener(u_short remoteInPort) {
  int sockopt = 1;
  struct sockaddr_in sockIn;

  if(remoteInPort > 0) {
    errno = 0;
    remoteInSocket = socket(AF_INET, SOCK_DGRAM, 0);
    if((remoteInSocket <= 0) || (errno != 0) ) {
      traceEvent(TRACE_INFO, "Unable to create a UDP socket - returned %d, error is '%s'(%d)",
		 remoteInSocket, strerror(errno), errno);
      return(-1);
    }

    traceEvent(TRACE_INFO, "Created a UDP socket (%d)", remoteInSocket);

    setsockopt(remoteInSocket, SOL_SOCKET, SO_REUSEADDR, (char *)&sockopt, sizeof(sockopt));

    sockIn.sin_family            = AF_INET;
    sockIn.sin_port              = (int)htons(remoteInPort);
    sockIn.sin_addr.s_addr       = INADDR_ANY;

    if(bind(remoteInSocket, (struct sockaddr *)&sockIn, sizeof(sockIn)) < 0) {
      traceEvent(TRACE_ERROR, "Remote collector port %d already in use", remoteInPort);
      close(remoteInSocket);
      remoteInSocket = 0;
      return(0);
    }
  }

  return(0);
}

/* ********************************************************* */

void closeRemoteListener(void) {
  if(remoteInSocket != -1) close(remoteInSocket);
}

/* *************************** */

static void handleGenericFlow(u_int32_t netflow_device_ip,
			      time_t recordActTime, time_t recordSysUpTime,
			      struct generic_netflow_record *record) {
  IpAddress src, dst;
  struct pcap_pkthdr h;
  time_t firstSeen, lastSeen;
  time_t initTime;

  initTime = recordActTime-(recordSysUpTime/1000);
  firstSeen = (ntohl(record->first)/1000) + initTime;
  lastSeen  = (ntohl(record->last)/1000) + initTime;

  /* Sanity check */
  if(readOnlyGlobals.initialSniffTime.tv_sec == 0)
    readOnlyGlobals.initialSniffTime.tv_sec = firstSeen, readOnlyGlobals.initialSniffTime.tv_usec = 0;

  if(firstSeen < readOnlyGlobals.initialSniffTime.tv_sec)
    firstSeen = readOnlyGlobals.initialSniffTime.tv_sec;

  if(lastSeen < readOnlyGlobals.initialSniffTime.tv_sec)
    lastSeen = readOnlyGlobals.initialSniffTime.tv_sec;

  h.ts.tv_sec = lastSeen, h.ts.tv_usec = 0;
  src.ipVersion = 4, dst.ipVersion = 4;
  src.ipType.ipv4 = ntohl(record->srcaddr), dst.ipType.ipv4 = ntohl(record->dstaddr);

#if 0
  traceEvent(TRACE_INFO, 
	     "Called addPktToHash() [firstSeen=%u][lastSeen=%u][initial=%u]",
	     firstSeen, lastSeen, readOnlyGlobals.initialSniffTime.tv_sec);
#endif

  record->first = htonl(firstSeen), record->last = htonl(lastSeen);

  addPktToHash(record->proto,
	       0 /* isFragment */,
	       ntohl(record->sentPkts),
	       record->tos,
	       record->vlanId,
	       0, /* tunnel_id */
	       NULL, /* Ethernet */
	       src,
	       ntohs(record->srcport),
	       dst,
	       ntohs(record->dstport),
	       ntohl(record->sentOctets),
	       record->tcp_flags,
	       0,
	       0, NULL,
	       0, NULL, /* MPLS */
	       ntohs(record->input), ntohs(record->output),
	       NULL, /* fingerprint */
	       &h, NULL, 0, 0, /* payload */
	       firstSeen,
	       htons(record->src_as), htons(record->dst_as),
	       record->src_mask, record->dst_mask,
	       netflow_device_ip);

  if(record->rcvdOctets > 0) {
    addPktToHash(record->proto,
		 0 /* isFragment */,
		 record->rcvdPkts,
		 record->tos,
		 record->vlanId,
		 0, /* tunnel_id */
		 NULL, /* Ethernet */
		 dst,
		 ntohs(record->dstport),
		 src,
		 ntohs(record->srcport),
		 ntohl(record->rcvdOctets),
		 record->tcp_flags,
		 0,
		 0, NULL,
		 0, NULL, /* MPLS */
		 ntohs(record->input), ntohs(record->output),
		 NULL, /* fingerprint */
		 &h, NULL, 0, 0, /* payload */
		 firstSeen,
		 htons(record->src_as), htons(record->dst_as),
		 record->src_mask, record->dst_mask,
		 netflow_device_ip);
  }
}

/* ********************************************************* */

void dissectNetFlow(u_int32_t netflow_device_ip,
		    char *buffer, int bufferLen) {
  NetFlow5Record the5Record;
  int flowVersion;
  time_t recordActTime = 0, recordSysUpTime = 0;
  struct generic_netflow_record record;

#ifdef DEBUG_FLOWS
  if(0)
    traceEvent(TRACE_INFO, "NETFLOW: dissectNetFlow(len=%d)", bufferLen);
#endif

  num_dissected_flows++;
  memcpy(&the5Record, buffer, bufferLen > sizeof(the5Record) ? sizeof(the5Record): bufferLen);
  flowVersion = ntohs(the5Record.flowHeader.version);

#ifdef DEBUG_FLOWS
  if(0)
    traceEvent(TRACE_INFO, "NETFLOW: +++++++ version=%d",  flowVersion);
#endif

  /*
    Convert V7 flows into V5 flows in order to make ntop
    able to handle V7 flows.

    Courtesy of Bernd Ziller <bziller@ba-stuttgart.de>
  */
  if((flowVersion == 1) || (flowVersion == 7)) {
    int numFlows, i;
    NetFlow1Record the1Record;
    NetFlow7Record the7Record;

    if(flowVersion == 1) {
      memcpy(&the1Record, buffer, bufferLen > sizeof(the1Record) ?
	     sizeof(the1Record): bufferLen);
      numFlows = ntohs(the1Record.flowHeader.count);
      if(numFlows > V1FLOWS_PER_PAK) numFlows = V1FLOWS_PER_PAK;
      recordActTime   = ntohl(the1Record.flowHeader.unix_secs);
      recordSysUpTime = ntohl(the1Record.flowHeader.sysUptime);
    } else {
      memcpy(&the7Record, buffer, bufferLen > sizeof(the7Record) ?
	     sizeof(the7Record): bufferLen);
      numFlows = ntohs(the7Record.flowHeader.count);
      if(numFlows > V7FLOWS_PER_PAK) numFlows = V7FLOWS_PER_PAK;
      recordActTime   = ntohl(the7Record.flowHeader.unix_secs);
      recordSysUpTime = ntohl(the7Record.flowHeader.sysUptime);
    }

#ifdef DEBUG_FLOWS
    if(0)
      traceEvent(TRACE_INFO, "NETFLOW: +++++++ flows=%d",  numFlows);
#endif

    the5Record.flowHeader.version = htons(5);
    the5Record.flowHeader.count = htons(numFlows);

    /* rest of flowHeader will not be used */
    for(i=0; i<numFlows; i++) {
      if(flowVersion == 7) {
	the5Record.flowRecord[i].srcaddr   = the7Record.flowRecord[i].srcaddr;
	the5Record.flowRecord[i].dstaddr   = the7Record.flowRecord[i].dstaddr;
	the5Record.flowRecord[i].srcport   = the7Record.flowRecord[i].srcport;
	the5Record.flowRecord[i].dstport   = the7Record.flowRecord[i].dstport;
	the5Record.flowRecord[i].dPkts     = the7Record.flowRecord[i].dPkts;
	the5Record.flowRecord[i].dOctets   = the7Record.flowRecord[i].dOctets;
	the5Record.flowRecord[i].proto     = the7Record.flowRecord[i].proto;
	the5Record.flowRecord[i].tos       = the7Record.flowRecord[i].tos;
	the5Record.flowRecord[i].first     = the7Record.flowRecord[i].first;
	the5Record.flowRecord[i].last      = the7Record.flowRecord[i].last;
	the5Record.flowRecord[i].tcp_flags = the7Record.flowRecord[i].tcp_flags;
	/* rest of flowRecord will not be used */
      } else {
	/*
	  Some NetFlow v1 implementations (e.g. Extreme Networks) are
	  limited and most of the NetFlow fields are empty. In particular
	  the following fields are empty:
	  - input
	  - output
	  - dOctets
	  - first
	  - last
	  - tos
	  - tcp_flags

	  In this case we add a patch for filling some of the fields
	  in order to let ntop digest this flow.
	*/

	the5Record.flowRecord[i].srcaddr   = the1Record.flowRecord[i].srcaddr;
	the5Record.flowRecord[i].dstaddr   = the1Record.flowRecord[i].dstaddr;
	the5Record.flowRecord[i].srcport   = the1Record.flowRecord[i].srcport;
	the5Record.flowRecord[i].dstport   = the1Record.flowRecord[i].dstport;
	the5Record.flowRecord[i].dPkts     = the1Record.flowRecord[i].dPkts;

	if(ntohl(the1Record.flowRecord[i].dOctets) == 0) {
	  /* We assume that all packets are 512 bytes long */
	  u_int32_t tmp = ntohl(the1Record.flowRecord[i].dPkts);
	  the5Record.flowRecord[i].dOctets = htonl(tmp*512);
	} else
	  the5Record.flowRecord[i].dOctets = the1Record.flowRecord[i].dOctets;

	the5Record.flowRecord[i].proto     = the1Record.flowRecord[i].proto;
	the5Record.flowRecord[i].tos       = the1Record.flowRecord[i].tos;
	the5Record.flowRecord[i].first     = the1Record.flowRecord[i].first;
	the5Record.flowRecord[i].last      = the1Record.flowRecord[i].last;
	/* rest of flowRecord will not be used */
      }
    }
  }  /* DON'T ADD a else here ! */

  if((the5Record.flowHeader.version == htons(9))
     || (the5Record.flowHeader.version == htons(10))) {
    /* NetFlowV9/IPFIX Record */
    u_char foundRecord = 0, done = 0;
    u_short numEntries, displ;
    V9Template template;
    IPFIXFlowSet ipfix_template;
    int i;
    u_char handle_ipfix;

    if(the5Record.flowHeader.version == htons(9)) handle_ipfix = 0; else handle_ipfix = 1;

    if(handle_ipfix) {
      numEntries = ntohs(the5Record.flowHeader.count), displ = sizeof(V9FlowHeader)-4; // FIX
#ifdef DEBUG_FLOWS
      traceEvent(TRACE_INFO, "IPFIX Length: %d", numEntries);
#endif
    } else {
      numEntries = ntohs(the5Record.flowHeader.count), displ = sizeof(V9FlowHeader);
    }

    recordActTime = ntohl(the5Record.flowHeader.unix_secs);
    recordSysUpTime = ntohl(the5Record.flowHeader.sysUptime);
    /*     NTOHL(recordActTime); NTOHL(recordSysUpTime); */

    for(i=0; (!done) && (displ < bufferLen) && (i < numEntries); i++) {
      u_char isOptionTemplate;
      u_int16_t flowsetLen;

      /* 1st byte */
#ifdef DEBUG_FLOWS
      traceEvent(TRACE_INFO, "[displ=%d][%02X %02X %02X]", 
		 displ, buffer[displ] & 0xFF, 
		 buffer[displ+1] & 0xFF,
		 buffer[displ+2] & 0xFF);
#endif
      
      if(buffer[displ] == 0) {
	isOptionTemplate = (u_char)buffer[displ+1];


	/* Template */
#ifdef DEBUG_FLOWS
	traceEvent(TRACE_INFO, "Found Template [displ=%d]", displ);
	traceEvent(TRACE_INFO, "Found Template Type: %d", isOptionTemplate);
#endif

	if(handle_ipfix && (isOptionTemplate == 2)) isOptionTemplate = 0;

	if(handle_ipfix) {
	  displ += 2;
	  memcpy(&flowsetLen, &buffer[displ], sizeof(flowsetLen));
	  flowsetLen = htons(flowsetLen);	  
	  displ += 2;
	}

	if(bufferLen > (displ+sizeof(V9Template))) {
	  FlowSetV9 *cursor = templates;
	  u_char found = 0;
	  u_short len;
	  int fieldId;

	  if(!isOptionTemplate) {
	    u_char goodTemplate = 0;
	    len = sizeof(V9Template);

	    if(handle_ipfix) {
	      memcpy(&ipfix_template, &buffer[displ], sizeof(ipfix_template));
	      ipfix_template.templateId = htons(ipfix_template.templateId);
	      ipfix_template.fieldCount = htons(ipfix_template.fieldCount);
	      template.flowsetLen = (ipfix_template.fieldCount * 4) + sizeof(IPFIXFlowSet);
	      template.templateId = ipfix_template.templateId;
	      template.fieldCount = ipfix_template.fieldCount;

	      if(((ipfix_template.fieldCount * 4) + sizeof(IPFIXFlowSet) + 4 /* templateFlowSet + FlowsetLen */) >  flowsetLen) {
		traceEvent(TRACE_WARNING, "Bad length [expected=%d][real=%d]",
			   ipfix_template.fieldCount * 4,
			   numEntries + sizeof(IPFIXFlowSet));
	      } else {
		goodTemplate = 1;

		/* Check the template before to handle it */
		for(fieldId=0; (fieldId < template.fieldCount) && (len < template.flowsetLen); fieldId++) {
#ifdef DEBUG_FLOWS
		  V9FlowSet *set = (V9FlowSet*)&buffer[displ+sizeof(ipfix_template)+fieldId*sizeof(V9FlowSet)]; 
#endif

		  len += 4; /* Field Type (2) + Field Length (2) */
#ifdef DEBUG_FLOWS
		  if(1)
		    traceEvent(TRACE_INFO, "[%d] fieldType=%d/len=%d",
			       1+fieldId, htons(set->templateId), htons(set->flowsetLen));
#endif
		}
	      }
	    } else {
	      /* NetFlow */
	      memcpy(&template, &buffer[displ], sizeof(V9Template));

	      template.templateId = ntohs(template.templateId);
	      template.fieldCount = ntohs(template.fieldCount);
	      template.flowsetLen = ntohs(template.flowsetLen);

#ifdef DEBUG_FLOWS
	      if(1)
		traceEvent(TRACE_INFO, "Template [id=%d] fields: %d [len=%d]",
			   template.templateId, template.fieldCount, template.flowsetLen);
#endif

	      goodTemplate = 1;

	      /* Check the template before handling it */
	      for(fieldId=0; (fieldId < template.fieldCount) && (len < template.flowsetLen); fieldId++) {
		/* V9FlowSet *set = (V9FlowSet*)&buffer[displ+sizeof(V9Template)+fieldId*sizeof(V9FlowSet)]; */

		len += 4; /* Field Type (2) + Field Length (2) */
#ifdef DEBUG_FLOWS
		if(1)
		  traceEvent(TRACE_INFO, "[%d] fieldLen=%d/len=%d",
			     1+fieldId, template.flowsetLen, len);
#endif
	      }

	      if(len > template.flowsetLen) {
		static u_short lastBadTemplate = 0;

		if(template.templateId != lastBadTemplate) {
		  traceEvent(TRACE_WARNING, "Template %d has wrong size [actual=%d/expected=%d]: skipped",
			     template.templateId, len, template.flowsetLen);
		  lastBadTemplate = template.templateId;
		}

		goodTemplate = 0;
	      }
	    }

	    if(goodTemplate) {
	      while(cursor != NULL) {
		if(cursor->templateInfo.templateId == template.templateId) {
		  found = 1;
		  break;
		} else
		  cursor = cursor->next;
	      }

	      if(found) {
#ifdef DEBUG_FLOWS
		traceEvent(TRACE_INFO, ">>>>> Redefined existing template [id=%d]",
			   template.templateId);
#endif

		free(cursor->fields);
	      } else {
#ifdef DEBUG_FLOWS
		traceEvent(TRACE_INFO, ">>>>> Found new flow template definition [id=%d]",
			   template.templateId);
#endif

		cursor = (FlowSetV9*)malloc(sizeof(FlowSetV9));
		cursor->next = templates;
		templates = cursor;
	      }

	      if(handle_ipfix) {
		cursor->templateInfo.templateFlowset = 0;
		cursor->templateInfo.flowsetLen = ((ipfix_template.fieldCount * 4) + sizeof(IPFIXFlowSet) + 4);
		cursor->templateInfo.templateId = ipfix_template.templateId;
		cursor->templateInfo.fieldCount = ipfix_template.fieldCount;

		cursor->fields = (V9TemplateField*)malloc(cursor->templateInfo.flowsetLen-4);
		memcpy(cursor->fields, &buffer[displ+sizeof(ipfix_template)], cursor->templateInfo.flowsetLen-4);

	      } else {
		memcpy(&cursor->templateInfo, &buffer[displ], sizeof(V9Template));
		cursor->templateInfo.flowsetLen = ntohs(cursor->templateInfo.flowsetLen);
		cursor->templateInfo.templateId = ntohs(cursor->templateInfo.templateId);
		cursor->templateInfo.fieldCount = ntohs(cursor->templateInfo.fieldCount);

		cursor->fields = (V9TemplateField*)malloc(cursor->templateInfo.flowsetLen-sizeof(V9Template));
		memcpy(cursor->fields, &buffer[displ+sizeof(V9Template)],
		       cursor->templateInfo.flowsetLen-sizeof(V9Template));
	      }
	    } else {
#ifdef DEBUG_FLOWS
	      traceEvent(TRACE_INFO, ">>>>> Skipping bad template [id=%d]", template.templateId);
#endif
	    }
	  } else {
	    u_short move_ahead;

	    memcpy(&move_ahead, &buffer[displ+2], 2);
	    template.flowsetLen = ntohs(move_ahead);
	  }

	  /* Skip template definition */
	  displ += template.flowsetLen;

#ifdef DEBUG_FLOWS
	  traceEvent(TRACE_INFO, "Moving ahead of %d bytes: new offset is %d", 
		     template.flowsetLen, displ);
#endif
	} else
	  done = 1;
      } else {
#ifdef DEBUG_FLOWS
	traceEvent(TRACE_INFO, "Found FlowSet [displ=%d]", displ);
#endif
	foundRecord = 1;
      }

      if(foundRecord) {
	V9FlowSet fs;

	if(bufferLen > (displ+sizeof(V9FlowSet))) {
	  FlowSetV9 *cursor = templates;
	  u_short tot_len = 4;  /* 4 bytes header */

	  memcpy(&fs, &buffer[displ], sizeof(V9FlowSet));

	  fs.flowsetLen = ntohs(fs.flowsetLen);
	  fs.templateId = ntohs(fs.templateId);

	  while(cursor != NULL) {
	    if(cursor->templateInfo.templateId == fs.templateId) {
	      break;
	    } else
	      cursor = cursor->next;
	  }

	  if(cursor != NULL) {
	    /* Template found */
	    int fieldId, init_displ;
	    V9TemplateField *fields = cursor->fields;

	    init_displ = displ;
	    displ += sizeof(V9FlowSet);

#ifdef DEBUG_FLOWS
	    if(1)
	      traceEvent(TRACE_INFO, ">>>>> Rcvd flow with known template %d [%d...%d]",
			 fs.templateId, displ, fs.flowsetLen);
#endif

	    while(displ < (init_displ + fs.flowsetLen)) {
	      u_short accum_len = 0;

	      if(((init_displ + fs.flowsetLen)-displ) <= 4) break;

	      /* Defaults */
	      memset(&record, 0, sizeof(record));
	      record.vlanId = NO_VLAN; /* No VLAN */
	      record.nw_latency_sec = record.nw_latency_usec = htonl(0);

#ifdef DEBUG_FLOWS
	      if(1)
		traceEvent(TRACE_INFO, ">>>>> Stats [%d...%d]", displ, (init_displ + fs.flowsetLen));
#endif

	      for(fieldId=0; fieldId<cursor->templateInfo.fieldCount; fieldId++) {
		if(!(displ < (init_displ + fs.flowsetLen))) break; /* Flow too short */

#ifdef DEBUG_FLOWS
		if(1)
		  traceEvent(TRACE_INFO, ">>>>> Dissecting flow field "
			     "[displ=%d/%d][template=%d][fieldType=%d][fieldLen=%d][field=%d/%d] [%d...%d]" /* "[%s]" */,
			     displ, fs.flowsetLen,
			     fs.templateId, ntohs(fields[fieldId].fieldType),
			     ntohs(fields[fieldId].fieldLen),
			     fieldId, cursor->templateInfo.fieldCount,
			     displ, (init_displ + fs.flowsetLen)
			     /* ,nf_hex_dump(&buffer[displ], ntohs(fields[fieldId].fieldLen)) */);
#endif

		switch(ntohs(fields[fieldId].fieldType)) {
		case 1: /* IN_BYTES */
		  memcpy(&record.rcvdOctets, &buffer[displ], 4);
		  break;
		case 2: /* IN_PKTS */
		  memcpy(&record.rcvdPkts, &buffer[displ], 4);
		  break;
		case 4: /* PROT */
		  memcpy(&record.proto, &buffer[displ], 1);
		  break;
		case 5: /* TOS */
		  memcpy(&record.tos, &buffer[displ], 1);
		  break;
		case 6: /* TCP_FLAGS */
		  memcpy(&record.tcp_flags, &buffer[displ], 1);
		  break;
		case 7: /* L4_SRC_PORT */
		  memcpy(&record.srcport, &buffer[displ], 2);
		  break;
		case 8: /* IP_SRC_ADDR */
		  memcpy(&record.srcaddr, &buffer[displ], 4);
		  break;
		case 9: /* SRC_MASK */
		  memcpy(&record.src_mask, &buffer[displ], 1);
		  break;
		case 10: /* INPUT SNMP */
		  memcpy(&record.input, &buffer[displ], 2);
		  break;
		case 11: /* L4_DST_PORT */
		  memcpy(&record.dstport, &buffer[displ], 2);
		  break;
		case 12: /* IP_DST_ADDR */
		  memcpy(&record.dstaddr, &buffer[displ], 4);
		  break;
		case 13: /* DST_MASK */
		  memcpy(&record.dst_mask, &buffer[displ], 1);
		  break;
		case 14: /* OUTPUT SNMP */
		  memcpy(&record.output, &buffer[displ], 2);
		  break;
		case 15: /* IP_NEXT_HOP */
		  memcpy(&record.nexthop, &buffer[displ], 4);
		  break;
		case 17: /* DST_AS */
		  memcpy(&record.dst_as, &buffer[displ], 2);
		  break;
		case 21: /* LAST_SWITCHED */
		  memcpy(&record.last, &buffer[displ], 4);
		  break;
		case 22: /* FIRST SWITCHED */
		  memcpy(&record.first, &buffer[displ], 4);
		  break;
		case 23: /* OUT_BYTES */
		  memcpy(&record.sentOctets, &buffer[displ], 4);
		  break;
		case 24: /* OUT_PKTS */
		  memcpy(&record.sentPkts, &buffer[displ], 4);
		  break;
		case 58: /* SRC_VLAN */
		case 59: /* DST_VLAN */
		  memcpy(&record.vlanId, &buffer[displ], 2);
		  record.vlanId = ntohs(record.vlanId);
		  break;
		case NTOP_BASE_ID+92: /* NW_LATENCY_SEC */
		  memcpy(&record.nw_latency_sec, &buffer[displ], 4);
		  break;
		case NTOP_BASE_ID+93: /* NW_LATENCY_USEC */
		  memcpy(&record.nw_latency_usec, &buffer[displ], 4);
		  break;

		  /* VoIP Extensions */
		case NTOP_BASE_ID+130: /* SIP_CALL_ID */
		  memcpy(&record.sip_call_id, &buffer[displ], 50);
		  traceEvent(TRACE_INFO, "SIP: sip_call_id=%s", record.sip_call_id);
		  break;
		case NTOP_BASE_ID+131: /* SIP_CALLING_PARTY */
		  memcpy(&record.sip_calling_party, &buffer[displ], 50);
		  traceEvent(TRACE_INFO, "SIP: sip_calling_party=%s", record.sip_calling_party);
		  break;
		case NTOP_BASE_ID+132: /* SIP_CALLED_PARTY */
		  memcpy(&record.sip_called_party, &buffer[displ], 50);
		  traceEvent(TRACE_INFO, "SIP: sip_called_party=%s", record.sip_called_party);
		  break;
		}

		accum_len += ntohs(fields[fieldId].fieldLen);
		displ += ntohs(fields[fieldId].fieldLen);
	      }

	      /*
		IMPORTANT NOTE

		handleGenericFlow handles monodirectional flows, whereas
		v9 flows and bidirectional. This means that if there's some
		bidirectional traffic, handleGenericFlow is called twice.
	      */
	      handleGenericFlow(netflow_device_ip, recordActTime,
				recordSysUpTime, &record);

#ifdef DEBUG_FLOWS
	      if(1)
		traceEvent(TRACE_INFO,
			   ">>>> NETFLOW: Calling insert_flow_record() [accum_len=%d]",
			   accum_len);
#endif

	      tot_len += accum_len;

	      if(record.rcvdPkts > 0) {
		u_int32_t tmp;

		record.sentPkts   = record.rcvdPkts;
		record.sentOctets = record.rcvdOctets;

		tmp = record.srcaddr;
		record.srcaddr = record.dstaddr;
		record.dstaddr = tmp;
		tmp = record.srcport;
		record.srcport = record.dstport;
		record.dstport = tmp;

		handleGenericFlow(netflow_device_ip, recordActTime, recordSysUpTime, &record);		
	      }
	    }

	    if(tot_len < fs.flowsetLen) {
	      u_short padding = fs.flowsetLen - tot_len;
		  
	      if(padding > 4) {
		traceEvent(TRACE_WARNING, "Template len mismatch [tot_len=%d][flow_len=%d][padding=%d][num_dissected_flows=%d]",
			   tot_len, fs.flowsetLen, padding, num_dissected_flows);
	      } else {
#ifdef DEBUG_FLOWS
		traceEvent(TRACE_INFO, ">>>>> %d bytes padding [tot_len=%d][flow_len=%d]",
			   padding, tot_len, fs.flowsetLen);
#endif
		displ += padding;
	      }
	    }
	  } else {
#ifdef DEBUG_FLOWS
	    traceEvent(TRACE_INFO, ">>>>> Rcvd flow with UNKNOWN template %d [displ=%d][len=%d]",
		       fs.templateId, displ, fs.flowsetLen);
#endif
	    displ += fs.flowsetLen;
	  }
	}
      }
    } /* for */
  } else if(the5Record.flowHeader.version == htons(5)) {
    int i, numFlows = ntohs(the5Record.flowHeader.count);

    recordActTime   = ntohl(the5Record.flowHeader.unix_secs);
    recordSysUpTime = ntohl(the5Record.flowHeader.sysUptime);

    if(numFlows > V5FLOWS_PER_PAK) numFlows = V5FLOWS_PER_PAK;

#ifdef DEBUG_FLOWS
    if(0) traceEvent(TRACE_INFO, "dissectNetFlow(%d flows)", numFlows);
#endif

    /*
      Reset the record so that fields that are not contained
      into v5 records are set to zero
    */
    memset(&record, 0, sizeof(record));
    record.vlanId = NO_VLAN; /* No VLAN */
    record.nw_latency_sec = record.nw_latency_usec = htonl(0);

    for(i=0; i<numFlows; i++) {
      record.srcaddr    = the5Record.flowRecord[i].srcaddr;
      record.dstaddr    = the5Record.flowRecord[i].dstaddr;
      record.nexthop    = the5Record.flowRecord[i].nexthop;
      record.input      = the5Record.flowRecord[i].input;
      record.output     = the5Record.flowRecord[i].output;
      record.sentPkts   = the5Record.flowRecord[i].dPkts;
      record.sentOctets = the5Record.flowRecord[i].dOctets;
      record.first      = the5Record.flowRecord[i].first;
      record.last       = the5Record.flowRecord[i].last;
      record.srcport    = the5Record.flowRecord[i].srcport;
      record.dstport    = the5Record.flowRecord[i].dstport;
      record.tcp_flags  = the5Record.flowRecord[i].tcp_flags;
      record.proto      = the5Record.flowRecord[i].proto;
      record.dst_as     = the5Record.flowRecord[i].dst_as;
      record.src_as     = the5Record.flowRecord[i].src_as;
      record.dst_mask   = the5Record.flowRecord[i].dst_mask;
      record.src_mask   = the5Record.flowRecord[i].src_mask;

      handleGenericFlow(netflow_device_ip, recordActTime,
			recordSysUpTime, &record);
    }
  }
}

/* ********************************************************* */

void* netFlowCollectLoop(void* notUsed) {
  fd_set netflowMask;
  int rc, len;
#ifdef DEBUG_FLOWS
  int deviceId = 0;
#endif
  u_char buffer[2048];
  struct sockaddr_in fromHost;

  traceEvent(TRACE_INFO, "netFlowMainLoop() thread...");

  readOnlyGlobals.datalink = DLT_EN10MB; 

  while(!readWriteGlobals->shutdownInProgress) {
    int maxSock = collectorInSocket;
    struct timeval wait_time = { 1, 0 };

    FD_ZERO(&netflowMask);
    FD_SET(collectorInSocket, &netflowMask);

#ifdef HAVE_SCTP
    if(collectorInSctpSocket > 0) {
      FD_SET(collectorInSctpSocket, &netflowMask);
      if(collectorInSctpSocket > maxSock)
	maxSock = collectorInSctpSocket;
    }
#endif

    rc = select(maxSock+1, &netflowMask, NULL, NULL, &wait_time);
    if(readWriteGlobals->shutdownInProgress) break;

    if(rc > 0) {
      if(FD_ISSET(collectorInSocket, &netflowMask)){
	len = sizeof(fromHost);
	rc = recvfrom(collectorInSocket,
		      (char*)&buffer, sizeof(buffer),
		      0, (struct sockaddr*)&fromHost, (socklen_t*)&len);
      }
#ifdef HAVE_SCTP
      else {
	struct msghdr msg;
	struct iovec iov[2];
	char controlVector[256];

	memset(controlVector, 0, sizeof(controlVector));
	iov[0].iov_base = buffer;
	iov[0].iov_len  = sizeof(buffer);
	iov[1].iov_base = NULL;
	iov[1].iov_len  = 0;
	msg.msg_name = (caddr_t)&fromHost;
	msg.msg_namelen = sizeof(fromHost);
	msg.msg_iov = iov;
	msg.msg_iovlen = 1;
#ifndef SOLARIS
	msg.msg_control = (caddr_t)controlVector;
	msg.msg_controllen = sizeof(controlVector);
#endif
	rc = recvmsg(collectorInSctpSocket, &msg, 0);
      }
#endif

#ifdef DEBUG_FLOWS
      traceEvent(TRACE_INFO, "NETFLOW_DEBUG: Received NetFlow packet(len=%d)(deviceId=%d)",
		 rc,  deviceId);
#endif

      if(rc > 0) {
#ifdef MAX_NETFLOW_PACKET_BUFFER
        gettimeofday(&netflowStartOfRecordProcessing, NULL);
#endif

	readWriteGlobals->now = time(NULL);
	if((buffer[0] == 0) && (buffer[1] == 0))
	  dissectSflow(buffer, rc, &fromHost); /* sFlow */
	else
	  dissectNetFlow(fromHost.sin_addr.s_addr, (char*)buffer, rc);
      }
    }
  }

  return(NULL);
}

