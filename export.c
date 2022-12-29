/* 
 *        nProbe - a Netflow v5/v9/IPFIX probe for IPv4/v6 
 *
 *       Copyright (C) 2002-10 Luca Deri <deri@ntop.org> 
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


/* ****************************************************** */

static int exportBucketToNetflowV5(FlowHashBucket *myBucket, int direction,
				   u_char free_memory /* Ignored */) {

  if(direction == 0 /* src -> dst */) {
    if(myBucket->flowCounters.pktSent == 0) return(0); /* Nothing to export */

    readWriteGlobals->theV5Flow.flowRecord[readWriteGlobals->numFlows].input     = htons(myBucket->if_input);
    readWriteGlobals->theV5Flow.flowRecord[readWriteGlobals->numFlows].output    = htons(myBucket->if_output);
    readWriteGlobals->theV5Flow.flowRecord[readWriteGlobals->numFlows].srcaddr   = htonl(myBucket->src->host.ipType.ipv4);
    readWriteGlobals->theV5Flow.flowRecord[readWriteGlobals->numFlows].dstaddr   = htonl(myBucket->dst->host.ipType.ipv4);
    readWriteGlobals->theV5Flow.flowRecord[readWriteGlobals->numFlows].dPkts     = htonl(myBucket->flowCounters.pktSent);
    readWriteGlobals->theV5Flow.flowRecord[readWriteGlobals->numFlows].dOctets   = htonl(myBucket->flowCounters.bytesSent);
    readWriteGlobals->theV5Flow.flowRecord[readWriteGlobals->numFlows].first     = htonl(msTimeDiff(myBucket->flowTimers.firstSeenSent,
												    readOnlyGlobals.initialSniffTime));
    readWriteGlobals->theV5Flow.flowRecord[readWriteGlobals->numFlows].last      = htonl(msTimeDiff(myBucket->flowTimers.lastSeenSent,
												    readOnlyGlobals.initialSniffTime));
    readWriteGlobals->theV5Flow.flowRecord[readWriteGlobals->numFlows].srcport   = htons(myBucket->sport);
    readWriteGlobals->theV5Flow.flowRecord[readWriteGlobals->numFlows].dstport   = htons(myBucket->dport);
    readWriteGlobals->theV5Flow.flowRecord[readWriteGlobals->numFlows].tos       = myBucket->src2dstTos;
    readWriteGlobals->theV5Flow.flowRecord[readWriteGlobals->numFlows].src_as    = (myBucket->src_as != 0) ? myBucket->src_as : htons(ip2AS(myBucket->src->host));
    readWriteGlobals->theV5Flow.flowRecord[readWriteGlobals->numFlows].dst_as    = (myBucket->dst_as != 0) ? myBucket->dst_as : htons(ip2AS(myBucket->dst->host));
    readWriteGlobals->theV5Flow.flowRecord[readWriteGlobals->numFlows].src_mask  = (myBucket->src_mask != 0) ? myBucket->src_mask : ip2mask(myBucket->src->host);
    readWriteGlobals->theV5Flow.flowRecord[readWriteGlobals->numFlows].dst_mask  = (myBucket->dst_mask != 0) ? myBucket->dst_mask : ip2mask(myBucket->dst->host);
    readWriteGlobals->theV5Flow.flowRecord[readWriteGlobals->numFlows].tcp_flags = (u_int8_t)myBucket->src2dstTcpFlags;
  } else {
    if(myBucket->flowCounters.pktRcvd == 0) return(0); /* Nothing to export */

    readWriteGlobals->theV5Flow.flowRecord[readWriteGlobals->numFlows].input     = htons(myBucket->if_input);
    readWriteGlobals->theV5Flow.flowRecord[readWriteGlobals->numFlows].output    = htons(myBucket->if_output);
    readWriteGlobals->theV5Flow.flowRecord[readWriteGlobals->numFlows].srcaddr   = htonl(myBucket->dst->host.ipType.ipv4);
    readWriteGlobals->theV5Flow.flowRecord[readWriteGlobals->numFlows].dstaddr   = htonl(myBucket->src->host.ipType.ipv4);
    readWriteGlobals->theV5Flow.flowRecord[readWriteGlobals->numFlows].dPkts     = htonl(myBucket->flowCounters.pktRcvd);
    readWriteGlobals->theV5Flow.flowRecord[readWriteGlobals->numFlows].dOctets   = htonl(myBucket->flowCounters.bytesRcvd);
    readWriteGlobals->theV5Flow.flowRecord[readWriteGlobals->numFlows].first     = htonl(msTimeDiff(myBucket->flowTimers.firstSeenRcvd,
												    readOnlyGlobals.initialSniffTime));
    readWriteGlobals->theV5Flow.flowRecord[readWriteGlobals->numFlows].last      = htonl(msTimeDiff(myBucket->flowTimers.lastSeenRcvd,
												    readOnlyGlobals.initialSniffTime));
    readWriteGlobals->theV5Flow.flowRecord[readWriteGlobals->numFlows].srcport   = htons(myBucket->dport);
    readWriteGlobals->theV5Flow.flowRecord[readWriteGlobals->numFlows].dstport   = htons(myBucket->sport);
    readWriteGlobals->theV5Flow.flowRecord[readWriteGlobals->numFlows].tos       = myBucket->dst2srcTos;
    readWriteGlobals->theV5Flow.flowRecord[readWriteGlobals->numFlows].src_as    = (myBucket->dst_as != 0) ? myBucket->dst_as : htons(ip2AS(myBucket->dst->host));
    readWriteGlobals->theV5Flow.flowRecord[readWriteGlobals->numFlows].dst_as    = (myBucket->src_as != 0) ? myBucket->src_as : htons(ip2AS(myBucket->src->host));
    readWriteGlobals->theV5Flow.flowRecord[readWriteGlobals->numFlows].src_mask  = (myBucket->dst_mask != 0) ? myBucket->dst_mask : ip2mask(myBucket->dst->host);
    readWriteGlobals->theV5Flow.flowRecord[readWriteGlobals->numFlows].dst_mask  = (myBucket->src_mask != 0) ? myBucket->src_mask : ip2mask(myBucket->src->host);
    readWriteGlobals->theV5Flow.flowRecord[readWriteGlobals->numFlows].tcp_flags = (u_int8_t)myBucket->dst2srcTcpFlags;
  }

  readWriteGlobals->theV5Flow.flowRecord[readWriteGlobals->numFlows].proto       = (u_int8_t)myBucket->proto;

#ifdef HAVE_MYSQL
  if(db_initialized) {
    char sql[2048];
    unsigned int first, last;

    first = (ntohl(readWriteGlobals->theV5Flow.flowRecord[readWriteGlobals->numFlows].first) / 1000) + readOnlyGlobals.initialSniffTime.tv_sec;
    last  = (ntohl(readWriteGlobals->theV5Flow.flowRecord[readWriteGlobals->numFlows].last) / 1000) + readOnlyGlobals.initialSniffTime.tv_sec;

    // traceEvent(TRACE_ERROR, "====> %u / %u [num_collectors=%u]", first, last, readOnlyGlobals.numCollectors);  

    /* When you change DEFAULT_V9_TEMPLATE please also update the variable below */
    snprintf(sql, sizeof(sql),
	     "INSERT DELAYED INTO `%sflows` (PROTOCOL, IPV4_SRC_ADDR, IPV4_DST_ADDR, INPUT_SNMP, OUTPUT_SNMP, IN_PKTS, "
	     "IN_BYTES, FIRST_SWITCHED, LAST_SWITCHED, L4_SRC_PORT, L4_DST_PORT, SRC_TOS, SRC_AS, DST_AS, TCP_FLAGS) "
	     "VALUES ('%u', '%u', '%u', '%u', '%u', '%u', '%u', '%u', '%u', '%u', '%u', '%u', '%u', '%u', '%u')",
	     get_db_table_prefix(),
	     readWriteGlobals->theV5Flow.flowRecord[readWriteGlobals->numFlows].proto,
	     ntohl(readWriteGlobals->theV5Flow.flowRecord[readWriteGlobals->numFlows].srcaddr),
	     ntohl(readWriteGlobals->theV5Flow.flowRecord[readWriteGlobals->numFlows].dstaddr),
	     ntohs(readWriteGlobals->theV5Flow.flowRecord[readWriteGlobals->numFlows].input),
	     ntohs(readWriteGlobals->theV5Flow.flowRecord[readWriteGlobals->numFlows].output),
	     ntohl(readWriteGlobals->theV5Flow.flowRecord[readWriteGlobals->numFlows].dPkts),
	     ntohl(readWriteGlobals->theV5Flow.flowRecord[readWriteGlobals->numFlows].dOctets),
	     first,
	     last,
	     ntohs(readWriteGlobals->theV5Flow.flowRecord[readWriteGlobals->numFlows].srcport),
	     ntohs(readWriteGlobals->theV5Flow.flowRecord[readWriteGlobals->numFlows].dstport),
	     readWriteGlobals->theV5Flow.flowRecord[readWriteGlobals->numFlows].tos,
	     ntohs(readWriteGlobals->theV5Flow.flowRecord[readWriteGlobals->numFlows].src_as),
	     ntohs(readWriteGlobals->theV5Flow.flowRecord[readWriteGlobals->numFlows].dst_as),
	     readWriteGlobals->theV5Flow.flowRecord[readWriteGlobals->numFlows].tcp_flags);

    exec_sql_query(sql, 1);
  }
#endif

#ifdef HAVE_FASTBIT
  dump_flow2fastbit((char*)&readWriteGlobals->theV5Flow.flowRecord[readWriteGlobals->numFlows],
		    sizeof(struct flow_ver5_rec));
#endif

  return(1);
}

/* ****************************************************** */

static int exportBucketToNetflowV9(FlowHashBucket *myBucket, int direction,
				   u_char free_memory /* Ignored */) {
  u_int flowBufBegin, flowBufMax;
  int numElements;

  if(readOnlyGlobals.dontSentBidirectionalV9Flows) {
    if(((myBucket->swap_flow == 0) && (direction == 1))
       ||
       ((myBucket->swap_flow == 1) && (direction == 0)))
      return(0);
  }
  
  if((direction == 1)
     && readOnlyGlobals.dontSentBidirectionalV9Flows) return(0);


  flowBufBegin = readWriteGlobals->bufferLen, flowBufMax = NETFLOW_MAX_BUFFER_LEN;

  if(direction == 0 /* src -> dst */) {
    if(myBucket->flowCounters.pktSent == 0) 
      return(0); /* Nothing to export */
  } else {
    if(myBucket->flowCounters.pktRcvd == 0) return(0); /* Nothing to export */
  }

  flowPrintf(readOnlyGlobals.v9TemplateElementList, readWriteGlobals->buffer,
	     &flowBufBegin, &flowBufMax,
	     &numElements, 0, myBucket, direction, 0, 0);

#ifdef HAVE_MYSQL
  dump_flow2db(&readWriteGlobals->buffer[readWriteGlobals->bufferLen],
	       flowBufBegin - readWriteGlobals->bufferLen);
#endif

#ifdef HAVE_FASTBIT
  dump_flow2fastbit(&readWriteGlobals->buffer[readWriteGlobals->bufferLen],
		    flowBufBegin - readWriteGlobals->bufferLen);
#endif

  readWriteGlobals->bufferLen = flowBufBegin;
  return(1);
}

/* ****************************************************** */

int exportBucketToNetflow(FlowHashBucket *myBucket, int direction,
			  u_char free_memory /* Ignored */) {
  int rc = 0;

  if(readOnlyGlobals.netFlowVersion == 5) {
    if(myBucket->src->host.ipVersion == 4)
      rc = exportBucketToNetflowV5(myBucket, direction, free_memory);
    else {
      static char msgPrinted = 0;
      
      if(!msgPrinted) {
	traceEvent(TRACE_INFO,
		   "Unable to export IPv6 flow using NetFlow v5. Dropped.");
	msgPrinted = 1;
      }
    }
  } else
    rc = exportBucketToNetflowV9(myBucket, direction, free_memory);
  
  if(rc) {
    if(readOnlyGlobals.traceMode == 2)
      printFlow(myBucket, direction);

    if((readOnlyGlobals.dumpFormat != binary_format)
       && (readWriteGlobals->flowFd
#ifdef HAVE_SQLITE
	|| (readWriteGlobals->sqlite3Handler != NULL)
#endif
	)
       && (readOnlyGlobals.v9TemplateElementList[0] != NULL))
      flowFilePrintf(readOnlyGlobals.v9TemplateElementList,
		     readWriteGlobals->flowFd, myBucket, direction);

    readWriteGlobals->numFlows++, readWriteGlobals->totFlows++;
    checkNetFlowExport(0);
  }

  return(rc);
}

/* ****************************************************** */

void checkNetFlowExport(int forceExport) {
  int emitFlow, deltaFlows, flowExpired;

  if(readWriteGlobals->numFlows == 0)     return;
  if(readOnlyGlobals.numCollectors == 0) {
    readWriteGlobals->numFlows = 0; /* Fake flow export so that everything works
				       but flows are not exported
				    */
    return;
  }

  if((readOnlyGlobals.netFlowVersion == 9 || readOnlyGlobals.netFlowVersion == 10)
     && (readOnlyGlobals.numCollectors > 1) && (!readOnlyGlobals.reflectorMode) /* Round-robin mode */
     && (readOnlyGlobals.packetsBeforeSendingTemplates == 0) /* It's time to send the template */
     ) {
    if(readOnlyGlobals.netFlowVersion == 9) {
      initNetFlowV9Header(&readWriteGlobals->theV9Header);
      readWriteGlobals->theV9Header.count = htons(3);
    } else
      initIPFIXHeader(&readWriteGlobals->theIPFIXHeader);

    sendNetFlowV9V10(0, 1, 1);
    deltaFlows = 0, readOnlyGlobals.packetsBeforeSendingTemplates
      = readOnlyGlobals.numCollectors*readOnlyGlobals.templatePacketsDelta;
  } else {
    if((readOnlyGlobals.netFlowVersion == 9 || readOnlyGlobals.netFlowVersion == 10) 
       && (readOnlyGlobals.packetsBeforeSendingTemplates == 0))
      deltaFlows = readOnlyGlobals.templateFlowSize;
    else
      deltaFlows = 0;
  }

  emitFlow = ((deltaFlows+readWriteGlobals->numFlows) >= readOnlyGlobals.minNumFlowsPerPacket)
    || (forceExport && readWriteGlobals->shutdownInProgress) /* || (pcapFile != NULL) */;

  gettimeofday(&readWriteGlobals->actTime, NULL);

  flowExpired = 
    readWriteGlobals->lastExportTime.tv_sec 
    && (((time(NULL)-readWriteGlobals->lastExportTime.tv_sec) > readOnlyGlobals.sendTimeout)
	|| (readWriteGlobals->actTime.tv_sec > (readWriteGlobals->lastExportTime.tv_sec+readOnlyGlobals.sendTimeout)));

  if(forceExport || emitFlow || flowExpired) {
    if(readOnlyGlobals.netFlowVersion == 5) {
      initNetFlowV5Header(&readWriteGlobals->theV5Flow);
      readWriteGlobals->theV5Flow.flowHeader.count = htons(readWriteGlobals->numFlows);
      sendNetFlowV5(&readWriteGlobals->theV5Flow, 0);
    } else {
      /*      if(readOnlyGlobals.netFlowVersion == 9) {
	initNetFlowV9Header(&readWriteGlobals->theV9Header);
	readWriteGlobals->theV9Header.count = htons(3);
	} else */
	if(readOnlyGlobals.netFlowVersion == 9) {
	  initNetFlowV9Header(&readWriteGlobals->theV9Header);
	  readWriteGlobals->theV9Header.count = (deltaFlows > 0) ? htons(4) : htons(1);
	} else {
	  initIPFIXHeader(&readWriteGlobals->theIPFIXHeader);
	  readWriteGlobals->theIPFIXHeader.count = (deltaFlows > 0) ? htons(4) : htons(1);
	}

      sendNetFlowV9V10(0, deltaFlows > 0 ? 1 : 0, 0);

      if(readOnlyGlobals.packetsBeforeSendingTemplates == 0)
	readOnlyGlobals.packetsBeforeSendingTemplates = readOnlyGlobals.templatePacketsDelta;
      else
	readOnlyGlobals.packetsBeforeSendingTemplates--;
    }

    readWriteGlobals->totFlowExp += readWriteGlobals->numFlows;
    readWriteGlobals->numFlows = 0; 
    readWriteGlobals->totExports++, readWriteGlobals->numExports++;
    readWriteGlobals->lastExportTime.tv_sec = readWriteGlobals->actTime.tv_sec,
      readWriteGlobals->lastExportTime.tv_usec = readWriteGlobals->actTime.tv_usec;
  }

  if(readWriteGlobals->lastExportTime.tv_sec == 0) {
    readWriteGlobals->lastExportTime.tv_sec = readWriteGlobals->actTime.tv_sec,
      readWriteGlobals->lastExportTime.tv_usec = readWriteGlobals->actTime.tv_usec;
  }
}

/* ******************************************* */

static int send_buffer(int s, const void *msg, size_t len,
		       int flags, const struct sockaddr *to, socklen_t tolen) {

  if(is_locked_send())
    return(len); /* Emulate successful send */
  else
    return(sendto(s, msg, len, flags, to, tolen));
}

/* ****************************************************** */

#ifdef IP_HDRINCL

#define BUFFER_SIZE 1500

/*
 * Checksum routine for Internet Protocol family headers (C Version)
 *
 * Borrowed from DHCPd
 */

static u_int32_t in_cksum(unsigned char *buf,
			  unsigned nbytes, u_int32_t sum) {
  u_int i;

  /* Checksum all the pairs of bytes first... */
  for (i = 0; i < (nbytes & ~1U); i += 2) {
    sum += (u_int16_t) ntohs(*((u_int16_t *)(buf + i)));
    /* Add carry. */
    if(sum > 0xFFFF)
      sum -= 0xFFFF;
  }

  /* If there's a single byte left over, checksum it, too.   Network
     byte order is big-endian, so the remaining byte is the high byte. */
  if(i < nbytes) {
#ifdef DEBUG_CHECKSUM_VERBOSE
    debug ("sum = %x", sum);
#endif
    sum += buf [i] << 8;
    /* Add carry. */
    if(sum > 0xFFFF)
      sum -= 0xFFFF;
  }

  return sum;
}

/* ******************************************* */

static u_int32_t wrapsum (u_int32_t sum) {
  sum = ~sum & 0xFFFF;
  return htons(sum);
}

/* ******************************************* */

static int send_raw_socket(int sock, const void *dataBuffer,
			   int dataBufferLen, struct sockaddr_in *dest) {
  if(is_locked_send())
    return(dataBufferLen); /* Emulate successful send */
  else {
    static int ipHdrId = 0;
    int rc;
    char buffer[BUFFER_SIZE];
    unsigned int buffer_size = BUFFER_SIZE, headerLen;
    struct ip_header *ip_header;
    struct udp_header *udp_header;

    ip_header = (struct ip_header*) buffer;
    ip_header->ihl = 5;
    ip_header->version = 4;
    ip_header->tos = 0;
    ip_header->tot_len = htons(buffer_size);
    ip_header->id = htons(ipHdrId++);
    ip_header->ttl = 64;
    ip_header->frag_off = htons(0);
    ip_header->protocol = IPPROTO_UDP;
    ip_header->check = wrapsum(in_cksum((unsigned char *)ip_header,
					sizeof(struct ip_header), 0));
    ip_header->daddr = dest->sin_addr.s_addr;
    ip_header->saddr =  readOnlyGlobals.sockIn.sin_addr.s_addr;

    udp_header = (struct udp_header*)(buffer + sizeof(struct ip_header));
    udp_header->source = readOnlyGlobals.sockIn.sin_port;
    udp_header->dest = dest->sin_port;
    udp_header->len = htons(sizeof(struct udp_header)+dataBufferLen);
    udp_header->check  = 0; /* It must be 0 to compute the checksum */

    headerLen = sizeof(struct ip_header)+sizeof(struct udp_header);
    if(dataBufferLen > (BUFFER_SIZE-headerLen))
      dataBufferLen = BUFFER_SIZE-headerLen-1;
    memcpy(&buffer[headerLen], dataBuffer, dataBufferLen);

    buffer_size = headerLen+dataBufferLen;
    ip_header->tot_len  = htons(buffer_size);

    /*
      http://www.cs.nyu.edu/courses/fall01/G22.2262-001/class11.htm
      http://www.ietf.org/rfc/rfc0761.txt
      http://www.ietf.org/rfc/rfc0768.txt
    */
    udp_header->check = wrapsum(in_cksum((unsigned char *)udp_header, sizeof(struct udphdr),
					 in_cksum((unsigned char *)dataBuffer, dataBufferLen,
						  in_cksum((unsigned char *)&ip_header->saddr,
							   2*sizeof(ip_header->saddr),
							   IPPROTO_UDP + ntohs(udp_header->len)))));
    rc = send_buffer(sock, buffer, buffer_size, 0,
		     (struct sockaddr*)dest,
		     sizeof(struct sockaddr_in));

    /*
      printf("buff %d [rc=%d][dataBufferLen=%d]\n",
      buffer_size, rc, dataBufferLen);
    */

    return(rc > 0 ? (rc-headerLen) : rc);
  }
}

#endif /* IP_HDRINCL */

/* ******************************************* */

#define MAX_LOCK_CHECK_FREQUENCY   10 /* sec */

int is_locked_send(void) {
  static u_char show_message = 1;
  static time_t last_check = 0;
  static int last_returned_value = 0;
  time_t now = time(NULL);

  /* Avoid checking the lock file too often */
  if((now-last_check) < MAX_LOCK_CHECK_FREQUENCY)
    return(last_returned_value);

  if(readOnlyGlobals.flowLockFile != NULL) {
    struct stat buf;

    last_check = now;
    /* The lock file exists so no flows will be sent */
    if(stat(readOnlyGlobals.flowLockFile, &buf) == 0) {
      if(show_message) {
	traceEvent(TRACE_WARNING,
		   "Lock file is present: no flows will be emitted.");
	show_message = 0;
      }
      return(last_returned_value = 1);
    }
  }

  show_message = 1;
  return(last_returned_value = 0); /* Not locked */
}

/* ****************************************************** */

void reopenSocket(CollectorAddress *collector) {
  int rc, sockopt = 1;

  traceEvent(TRACE_WARNING,
	     "Attempting to reopen the socket. Please wait....");

  close(collector->sockFd), collector->sockFd = -1;

  if(collector->transport == TRANSPORT_TCP)
    collector->sockFd = socket(AF_INET, SOCK_STREAM, 0);
#ifdef HAVE_SCTP
  else if(collector->transport == TRANSPORT_SCTP)
    collector->sockFd = socket(AF_INET, SOCK_SEQPACKET, IPPROTO_SCTP);
#endif

  if(collector->sockFd == -1) {
    traceEvent(TRACE_ERROR,
	       "Fatal error while creating socket (%s). Trying again later.",
	       strerror(errno));
    return;
  }

  setsockopt(collector->sockFd, SOL_SOCKET, SO_REUSEADDR,
	     (char *)&sockopt, sizeof(sockopt));

  if(collector->transport == TRANSPORT_TCP) {
#ifndef IPV4_ONLY
    if(collector->isIPv6)
      {
	rc = connect(collector->sockFd,
		     (struct sockaddr *)&collector->u.v6Address,
		     sizeof(collector->u.v6Address));
      }
    else
#endif
      {
	rc = connect(collector->sockFd,
		     (struct sockaddr *)&collector->u.v4Address,
		     sizeof(struct sockaddr_in));
      }

    if(rc == -1)
      traceEvent(TRACE_ERROR,
		 "Connection failed with remote peer [%s]. "
		 "Trying again later.\n", strerror(errno));
    else {
      /* Peer reconnected */
      /*
	NOTE
	When a peer is reconnected the template should be resent
	only to it. However in order to keep the code simple, the
	template is resent to everyone.
      */
      /* Force the probe to resend the template */
      readOnlyGlobals.packetsBeforeSendingTemplates = 0;
    }
  }

  collector->flowSequence = 0;
}

/* ****************************************************** */

static int sendFlowData(CollectorAddress *collector, char *buffer,
			int bufferLength, int sequenceIncrement) {
  int rc, offset = 0;
  u_int32_t flow_sequence;
  struct timeval now;

#ifdef DEMO_MODE
  if(collector->flowSequence > MAX_DEMO_FLOWS) return(0);
#endif

  errno = 0;
  gettimeofday(&now, NULL);

#ifdef DEBUG
  traceEvent(TRACE_INFO, "sendFlowData: len=%d\n", bufferLength);
#endif

  if(readWriteGlobals->flowFd
     && (readOnlyGlobals.dumpFormat == binary_format)) {
    int rc;

    fprintf(readWriteGlobals->flowFd, "%04d", bufferLength);
    rc = fwrite(buffer, 1, bufferLength, readWriteGlobals->flowFd);

    if(rc != bufferLength)
      traceEvent(TRACE_WARNING, "fwrite error: wrote %d, expected %d", rc, bufferLength);
  }

  /*
    We need to fill the sequence number according to the collector
    sequence.
  */

  /* traceEvent(TRACE_INFO, "**** flowSequence=%d", collector->flowSequence); */

  flow_sequence = htonl(collector->flowSequence);
  if(readOnlyGlobals.netFlowVersion == 5)
    offset = 16; /* version+count+sysUptime+unis_secs+unis_nsecs */
  else if(readOnlyGlobals.netFlowVersion == 9)
    offset = 12; /* version+count+sysUptime+unix_secs */
  else if(readOnlyGlobals.netFlowVersion == 10)
    offset = 8; /* version+count+sysUptime+unix_secs */

  /* Fill flow sequence */
  memcpy((char*)&buffer[offset], &flow_sequence, 4);

  /*
    This delay is used to slow down export rate as some
    collectors might not be able to catch up with nProbe
  */
  if(readOnlyGlobals.flowExportDelay > 0) {
#ifndef WIN32
    struct timespec timeout;
#endif
    u_int32_t msDiff;
    u_short canPause = 0;

    /*
      if -B packetFlowGroup is set, we'll set
      canPause if we've sent packetFlowGroup packets
      then we'll pause for readOnlyGlobals.flowExportDelay
    */
    if(readOnlyGlobals.packetFlowGroup > 0) {
      readWriteGlobals->packetSentCount++;

      if(readWriteGlobals->packetSentCount == readOnlyGlobals.packetFlowGroup) {
	if(readOnlyGlobals.traceMode == 2)
	  traceEvent(TRACE_INFO, "Pausing %d ms because we've sent %d packet(s)",
		     readOnlyGlobals.flowExportDelay, readWriteGlobals->packetSentCount);
	canPause = 1;
	readWriteGlobals->packetSentCount = 0;
      }
    }

    if(canPause) {
      msDiff = msTimeDiff(now, collector->lastExportTime);

#if defined(DEBUG)
      traceEvent(TRACE_WARNING, "====>>>>>>> Last flow was sent %d ms ago", msDiff);
#endif

      if(msDiff < readOnlyGlobals.flowExportDelay) {
	msDiff = readOnlyGlobals.flowExportDelay - msDiff;

#ifndef WIN32
	timeout.tv_sec = 0;
	timeout.tv_nsec = 1000000*msDiff;

	while((nanosleep(&timeout, &timeout) == -1) && (errno == EINTR))
	  ; /* Do nothing */
#else
	waitForNextEvent(msDiff);
#endif
      }
    }
  }

  if(collector->transport == TRANSPORT_TCP)
    rc = send(collector->sockFd, buffer, bufferLength, 0);
  else {
    if(!collector->isIPv6) {
#ifdef IP_HDRINCL
      if(collector->transport == TRANSPORT_UDP_RAW)
	rc = send_raw_socket(collector->sockFd, buffer, bufferLength,
			     &collector->u.v4Address);
      else
#endif
	rc = send_buffer(collector->sockFd, buffer, bufferLength,
			 0, (struct sockaddr *)&collector->u.v4Address,
			 sizeof(collector->u.v4Address));
    }
#ifndef IPV4_ONLY
    else
      rc = send_buffer(collector->sockFd, buffer, bufferLength,
		       0, (struct sockaddr *)&collector->u.v6Address,
		       sizeof(collector->u.v6Address));
#endif
  }

  /*
    Note that on NetFlow v9 the sequence number is
    incremented per NetFlow packet sent and not per
    flow sent as for previous versions.
  */
  collector->flowSequence += sequenceIncrement;

  if(readOnlyGlobals.flowExportDelay > 0)
    memcpy(&collector->lastExportTime, &now, sizeof(struct timeval));

  if((rc == -1) && (errno == EPIPE /* Broken pipe */)) {
    traceEvent(TRACE_WARNING, "Socket %d disconnected.", collector->sockFd);
    reopenSocket(collector);
  }

  if(rc == bufferLength) {
    /* Everything is ok */
    readWriteGlobals->totBytesExp += rc, readWriteGlobals->totExpPktSent++;
  }

  return(rc);
}

/* ****************************************************** */

void sendNetFlow(void *buffer, u_int32_t bufferLength,
		 u_char lastFlow, int sequenceIncrement,
		 u_char broadcastToAllCollectors) {
  u_int32_t rc = 0;
  static u_short collectorId = 0;

#ifdef TIME_PROTECTION
  {
    struct tm expireDate;

#define EXPIRE_DAY    30
#define EXPIRE_MONTH  8
#define EXPIRE_YEAR   2005

    memset(&expireDate, 0, sizeof(expireDate));
    expireDate.tm_mday = EXPIRE_DAY;
    expireDate.tm_mon  = EXPIRE_MONTH-1;
    expireDate.tm_year = EXPIRE_YEAR-1900;

    if(time(NULL) > mktime(&expireDate)) {
      traceEvent(TRACE_ERROR, "Sorry: this copy of nProbe is expired.\n");
      exit(0);
    }
  }
#endif

#ifdef DEBUG
  traceEvent(TRACE_INFO, "==>> sendNetFlow(%d) [numCollectors=%d]",
	     bufferLength, readOnlyGlobals.numCollectors);
#endif

  if((readOnlyGlobals.numCollectors == 0) || readOnlyGlobals.none_specified)
    return;

  if(readOnlyGlobals.reflectorMode || broadcastToAllCollectors) {
    /* Send all the flows to all collectors */
    int i;

    for(i = 0; i<readOnlyGlobals.numCollectors; i++) {
      if(readWriteGlobals->shutdownInProgress) break;

      rc = sendFlowData(&readOnlyGlobals.netFlowDest[i],
			buffer, bufferLength,
			sequenceIncrement);

      if(rc != bufferLength) {
	static u_char msgSent = 0;

	if(!msgSent) {
	  traceEvent(TRACE_WARNING, "Error while exporting flows (%s)",
		     strerror(errno));
	  msgSent = 1;
	}
      } else {
#ifdef DEBUG
	char addrbuf[INET6_ADDRSTRLEN];

	if(readOnlyGlobals.netFlowDest[i].isIP == 0)
	  traceEvent(TRACE_INFO, "Sent flow packet to %s",
		     inet_ntoa(readOnlyGlobals.netFlowDest[i].u.v4Address.sin_addr));
	else
	  traceEvent(TRACE_INFO, "Sent flow packet to [%s]",
		     inet_ntop(AF_INET6, (void *)&(readOnlyGlobals.netFlowDest[i].u.IPAddress.ip),
			       addrbuf, sizeof (addrbuf)));
#endif /* DEBUG */
      }
    }
  } else {
    /* Send flows to all collectors in round robin */
    rc = sendFlowData(&readOnlyGlobals.netFlowDest[collectorId], buffer,
		      bufferLength, sequenceIncrement);

    /* Switch to next collector */
    collectorId = (collectorId + 1) % readOnlyGlobals.numCollectors;
  }

  if(rc != bufferLength) {
    static u_char msgSent = 0;

    if(!msgSent) {
      traceEvent(TRACE_WARNING, "Error while exporting flows (%s)", strerror(errno));
      msgSent = 1;
    }
  }
}

/* ****************************************************** */

void sendNetFlowV5(NetFlow5Record *theV5Flow, u_char lastFlow) {
  int len;

  if(theV5Flow->flowHeader.count == 0) return;

  if(readOnlyGlobals.traceMode == 2)
    traceEvent(TRACE_INFO, "Sending %d flows (NetFlow v5 format)",
	       ntohs(theV5Flow->flowHeader.count));

  len = (ntohs(theV5Flow->flowHeader.count)*sizeof(struct flow_ver5_rec)
	 +sizeof(struct flow_ver5_hdr));

  sendNetFlow((char *)theV5Flow, len, lastFlow,
	      ntohs(theV5Flow->flowHeader.count), 0);
}

/* ****************************************************** */

void initNetFlowV5Header(NetFlow5Record *theV5Flow) {
  memset(&theV5Flow->flowHeader, 0, sizeof(theV5Flow->flowHeader));

  theV5Flow->flowHeader.version        = htons(5);
  theV5Flow->flowHeader.sysUptime      = htonl(msTimeDiff(readWriteGlobals->actTime,
							  readOnlyGlobals.initialSniffTime));
  theV5Flow->flowHeader.unix_secs      = htonl(readWriteGlobals->actTime.tv_sec);
  theV5Flow->flowHeader.unix_nsecs     = htonl(readWriteGlobals->actTime.tv_usec/1000);
  /* NOTE: theV5Flow->flowHeader.flow_sequence will be filled by sendFlowData */
  theV5Flow->flowHeader.engine_type    = (u_int8_t)readOnlyGlobals.engineType;
  theV5Flow->flowHeader.engine_id      = (u_int8_t)readOnlyGlobals.engineId;

  theV5Flow->flowHeader.sampleRate     = readOnlyGlobals.fakePktSampling ? 0 : htons(readOnlyGlobals.pktSampleRate-1);
}

/* ****************************************************** */

void initNetFlowV9Header(V9FlowHeader *v9Header) {
  memset(v9Header, 0, sizeof(V9FlowHeader));
  v9Header->version        = htons(readOnlyGlobals.netFlowVersion);
  v9Header->sysUptime      = htonl(msTimeDiff(readWriteGlobals->actTime, readOnlyGlobals.initialSniffTime));
  v9Header->unix_secs      = htonl(time(NULL));
  v9Header->sourceId       = readOnlyGlobals.engineType; /* CHECK */
}

/* ****************************************************** */

void initIPFIXHeader(IPFIXFlowHeader *v10Header) {
  memset(v10Header, 0, sizeof(IPFIXFlowHeader));
  v10Header->version             = htons(readOnlyGlobals.netFlowVersion);
  v10Header->sysUptime           = htonl(msTimeDiff(readWriteGlobals->actTime, readOnlyGlobals.initialSniffTime));
  v10Header->observationDomainId = htonl(readOnlyGlobals.engineType); /* CHECK */
}

/* ****************************************************** */

static int padding(int len) {
  int module = len % 4;

  if(module == 0)
    return(0);
  else
    return(4 - module);
}

/* ****************************************************** */

void sendNetFlowV9V10(u_char lastFlow, u_char sendTemplate,
		      u_char sendOnlyTheTemplate) {
  V9FlowSet flowSet;
  char flowBuffer[1514 /* Ethernet MTU */ - 42 /* Ethernet+IP+UDP header */];
  int bufLen = 0, len, pad;

  /* NOTE: flow_sequence will be filled by sendFlowData */
  if(readOnlyGlobals.netFlowVersion == 9) {
    memcpy(&flowBuffer[bufLen], &readWriteGlobals->theV9Header, sizeof(readWriteGlobals->theV9Header));
    bufLen += sizeof(readWriteGlobals->theV9Header);
  } else {
    /* IPFIX */
    memcpy(&flowBuffer[bufLen], &readWriteGlobals->theIPFIXHeader, sizeof(readWriteGlobals->theIPFIXHeader));
    bufLen += sizeof(readWriteGlobals->theIPFIXHeader);
  }

  /*
    NOTE:
    In order to keep things simple, whenever there are multiple
    collectors in round robin and the template needs to be sent out
    it is sent alone (i.e. without incuding flows) to all the collectors.

    If there is just one collector, the template also contains flows
    up to the MTU size.
  */
  if(sendTemplate) {
    V9Template templateDef;
    V9OptionTemplate optionTemplateDef;
    char tmpBuffer[256];
    u_int flowBufBegin, flowBufMax;
    int numElements, optionTemplateId = readOnlyGlobals.idTemplate+1;

    templateDef.templateFlowset = (readOnlyGlobals.netFlowVersion == 9) ? htons(0) : htons(2);
    len = sizeof(V9Template)+readOnlyGlobals.templateBufBegin;
    pad = padding(len); len += pad;
    templateDef.fieldCount = htons(readOnlyGlobals.numTemplateFieldElements);
    templateDef.flowsetLen = htons(len);
    templateDef.templateId = htons(readOnlyGlobals.idTemplate);

    memcpy(&flowBuffer[bufLen], &templateDef, sizeof(V9Template));
    bufLen += sizeof(V9Template);
    memcpy(&flowBuffer[bufLen], readOnlyGlobals.templateBuffer, readOnlyGlobals.templateBufBegin);
    bufLen += readOnlyGlobals.templateBufBegin;
    bufLen += pad;

    /* Options Template */
    optionTemplateDef.templateFlowset = (readOnlyGlobals.netFlowVersion == 9) ? htons(1) : htons(3);
    len = sizeof(V9OptionTemplate)+readOnlyGlobals.optionTemplateBufBegin;
    pad = padding(len); len += pad;
    optionTemplateDef.flowsetLen     = htons(len);
    optionTemplateDef.templateId     = htons(optionTemplateId);
    optionTemplateDef.optionScopeLen = htons(4 /* SystemId=2 + SystemLen=2 */);
    optionTemplateDef.optionLen      = htons(4 /* each field is 4 bytes */
					     * (readOnlyGlobals.numOptionTemplateFieldElements-1 /* 1=interface hack */));

    memcpy(&flowBuffer[bufLen], &optionTemplateDef, sizeof(V9OptionTemplate));
    bufLen += sizeof(V9OptionTemplate);
    memcpy(&flowBuffer[bufLen], readOnlyGlobals.optionTemplateBuffer, readOnlyGlobals.optionTemplateBufBegin);
    bufLen += readOnlyGlobals.optionTemplateBufBegin;
    bufLen += pad;

    /* Options DataRecord */
    flowBufBegin = 0, flowBufMax = sizeof(tmpBuffer);
    flowPrintf(readOnlyGlobals.v9OptionTemplateElementList, tmpBuffer, &flowBufBegin, &flowBufMax,
	       &numElements, 0, NULL, 0, 0, 1);

    len = flowBufBegin+sizeof(flowSet);
    pad = padding(len); len += pad;
    flowSet.templateId = htons(optionTemplateId);
    flowSet.flowsetLen = htons(len);

    memcpy(&flowBuffer[bufLen], &flowSet, sizeof(flowSet));
    bufLen += sizeof(flowSet);
    memcpy(&flowBuffer[bufLen], tmpBuffer, flowBufBegin);
    bufLen += flowBufBegin;
    bufLen += pad;
  }

  if(!sendOnlyTheTemplate) {
    /* Fill the PDU with records up to the MTU size */
    flowSet.templateId = htons(readOnlyGlobals.idTemplate);
    len = readWriteGlobals->bufferLen+4;
    pad = padding(len); len += pad;
    flowSet.flowsetLen = htons(len);
    memcpy(&flowBuffer[bufLen], &flowSet, sizeof(flowSet));
    bufLen += sizeof(flowSet);

    if((bufLen+readWriteGlobals->bufferLen) >= sizeof(flowBuffer)) {
      static u_char warning_sent = 0;
      
      if(!warning_sent) {
	traceEvent(TRACE_WARNING,
		   "Internal error: too many NetFlow flows per packet (see -m)");
	warning_sent = 1;
      }

      readWriteGlobals->bufferLen = sizeof(flowBuffer)-bufLen-1;
    }

    memcpy(&flowBuffer[bufLen], readWriteGlobals->buffer, readWriteGlobals->bufferLen);
    bufLen += readWriteGlobals->bufferLen;
    bufLen += pad;
    sendNetFlow(&flowBuffer, bufLen, 0, 1, 0);
  } else
    sendNetFlow(&flowBuffer, bufLen, 0, 1, 1);

  readWriteGlobals->bufferLen = 0;
}

