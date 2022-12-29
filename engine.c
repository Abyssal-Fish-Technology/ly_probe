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

extern u_int8_t dequeueBucketToExport_up;

/* ****************************** */

/*
 * A faster replacement for inet_ntoa().
 */
char* _intoaV4(unsigned int addr, char* buf, u_short bufLen) {
  char *cp, *retStr;
  u_int byte;
  int n;

  cp = &buf[bufLen];
  *--cp = '\0';

  n = 4;
  do {
    byte = addr & 0xff;
    *--cp = byte % 10 + '0';
    byte /= 10;
    if (byte > 0) {
      *--cp = byte % 10 + '0';
      byte /= 10;
      if (byte > 0)
  *--cp = byte + '0';
    }
    *--cp = '.';
    addr >>= 8;
  } while (--n > 0);

  /* Convert the string to lowercase */
  retStr = (char*)(cp+1);

  return(retStr);
}

/* ****************************** */

char* _intoa(IpAddress addr, char* buf, u_short bufLen) {
  if(addr.ipVersion == 4)
    return(_intoaV4(addr.ipType.ipv4, buf, bufLen));
  else {
    char *ret;
    int len;

    ret = (char*)inet_ntop(AF_INET6, &addr.ipType.ipv6, &buf[1], bufLen-2);

    if(ret == NULL) {
      traceEvent(TRACE_WARNING, "Internal error (buffer too short)");
      buf[0] = '\0';
    } else {
      len = strlen(ret);
      buf[0] = '[';
      buf[len+1] = ']';
      buf[len+2] = '\0';
    }

    ret = buf;

    return(ret);
  }
}

/* ****************************************************** */

char* formatTraffic(float numBits, int bits, char *buf) {
  char unit;

  if(bits)
    unit = 'b';
  else
    unit = 'B';

  if(numBits < 1024) {
    snprintf(buf, 32, "%lu %c", (unsigned long)numBits, unit);
  } else if (numBits < 1048576) {
    snprintf(buf, 32, "%.0f K%c", (float)(numBits)/1024, unit);
  } else {
    float tmpMBits = ((float)numBits)/1048576;

    if(tmpMBits < 1024) {
      snprintf(buf, 32, "%.0f M%c", tmpMBits, unit);
    } else {
      tmpMBits /= 1024;

      if(tmpMBits < 1024) {
  snprintf(buf, 32, "%.0f G%c", tmpMBits, unit);
      } else {
  snprintf(buf, 32, "%.0f T%c", (float)(tmpMBits)/1024, unit);
      }
    }
  }

  return(buf);
}

/* ****************************************************** */

char* formatPackets(float numPkts, char *buf) {
  if(numPkts < 1000) {
    snprintf(buf, 32, "%.3f", numPkts);
  } else if(numPkts < 1000000) {
    snprintf(buf, 32, "%.3f K", numPkts/1000);
  } else {
    numPkts /= 1000000;
    snprintf(buf, 32, "%.3f M", numPkts);
  }

  return(buf);
}

/* ******************************************************** */

/*
  Fingerprint code courtesy of ettercap
  http://ettercap.sourceforge.net
*/
u_char ttlPredictor(u_char x) {
  /* coded by awgn <awgn@antifork.org> */
  /* round the TTL to the nearest power of 2 (ceiling) */
  u_char i = x, j = 1, c = 0;

  do {
    c += i & 1;
    j <<= 1;
  } while(i >>= 1);

  if(c == 1)
    return(x);
  else
    return(j ? j : 0xff);
}

/* ****************************************************** */

void setPayload(FlowHashBucket *bkt, const struct pcap_pkthdr *h,
    u_char *payload, int payloadLen, int direction) {

  if((readOnlyGlobals.maxPayloadLen > 0) && (payloadLen > 0)) {
    int diff;

    /* traceEvent(TRACE_ERROR, "Payload [%d][%s]", payloadLen, payload); */

    if(direction == 0) {
      if(bkt->src2dstPayload == NULL)
  bkt->src2dstPayload = (u_char*)malloc(sizeof(char)*(readOnlyGlobals.maxPayloadLen+1));

      if(bkt->src2dstPayload != NULL) {
  diff = readOnlyGlobals.maxPayloadLen-bkt->src2dstPayloadLen;

  if(diff > 0) {
    if(diff > payloadLen) diff = payloadLen;
    memcpy(&bkt->src2dstPayload[bkt->src2dstPayloadLen], payload, diff);
    bkt->src2dstPayloadLen += diff;
  }
      } else
  traceEvent(TRACE_ERROR, "Not enough memory?");
    } else {
      if(bkt->dst2srcPayload == NULL)
  bkt->dst2srcPayload = (u_char*)malloc(sizeof(char)*(readOnlyGlobals.maxPayloadLen+1));

      if(bkt->dst2srcPayload != NULL) {
  diff = readOnlyGlobals.maxPayloadLen-bkt->dst2srcPayloadLen;

  if(diff > 0) {
    if(diff > payloadLen) diff = payloadLen;
    memcpy(&bkt->dst2srcPayload[bkt->dst2srcPayloadLen], payload, diff);
    bkt->dst2srcPayloadLen += diff;
  }
      } else
  traceEvent(TRACE_ERROR, "Not enough memory?");
    }

    /* Jitter Calculation */
  }
}

/* ************************************************* */

void updateApplLatency(u_short proto, FlowHashBucket *bkt,
           int direction, struct timeval *stamp,
           u_int8_t icmpType, u_int8_t icmpCode) {

  if(!applLatencyComputed(bkt)) {
    /*
      src ---------> dst -+
      | Application
      | Latency
      <--------      -+

      NOTE:
      1. Application latency is calculated as the time passed since the first
      packet sent the first packet on the opposite direction is received.
      2. Application latency is calculated only on the first packet

    */

    if(direction  == 0) {
      /* src->dst */
      if(bkt->src2dstApplLatency.tv_sec == 0)
  bkt->src2dstApplLatency.tv_sec = stamp->tv_sec, bkt->src2dstApplLatency.tv_usec = stamp->tv_usec;

      if(bkt->dst2srcApplLatency.tv_sec != 0) {
  bkt->dst2srcApplLatency.tv_sec  = bkt->src2dstApplLatency.tv_sec-bkt->dst2srcApplLatency.tv_sec;

  if((bkt->src2dstApplLatency.tv_usec-bkt->dst2srcApplLatency.tv_usec) < 0) {
    bkt->dst2srcApplLatency.tv_usec = 1000000 + bkt->src2dstApplLatency.tv_usec - bkt->dst2srcApplLatency.tv_usec;
    if(bkt->dst2srcApplLatency.tv_usec > 1000000) bkt->dst2srcApplLatency.tv_usec = 1000000;
    bkt->dst2srcApplLatency.tv_sec--;
  } else
    bkt->dst2srcApplLatency.tv_usec = bkt->src2dstApplLatency.tv_usec-bkt->dst2srcApplLatency.tv_usec;

  bkt->src2dstApplLatency.tv_sec = 0, bkt->src2dstApplLatency.tv_usec = 0;
  NPROBE_FD_SET(FLAG_APPL_LATENCY_COMPUTED, &(bkt->flags));
      }
    } else {
      /* dst -> src */
      if(bkt->dst2srcApplLatency.tv_sec == 0)
  bkt->dst2srcApplLatency.tv_sec = stamp->tv_sec, bkt->dst2srcApplLatency.tv_usec = stamp->tv_usec;

      if(bkt->src2dstApplLatency.tv_sec != 0) {
  bkt->src2dstApplLatency.tv_sec  = bkt->dst2srcApplLatency.tv_sec-bkt->src2dstApplLatency.tv_sec;

  if((bkt->dst2srcApplLatency.tv_usec-bkt->src2dstApplLatency.tv_usec) < 0) {
    bkt->src2dstApplLatency.tv_usec = 1000000 + bkt->dst2srcApplLatency.tv_usec - bkt->src2dstApplLatency.tv_usec;
    if(bkt->src2dstApplLatency.tv_usec > 1000000) bkt->src2dstApplLatency.tv_usec = 1000000;
    bkt->src2dstApplLatency.tv_sec--;
  } else
    bkt->src2dstApplLatency.tv_usec = bkt->dst2srcApplLatency.tv_usec-bkt->src2dstApplLatency.tv_usec;

  bkt->dst2srcApplLatency.tv_sec = 0, bkt->dst2srcApplLatency.tv_usec = 0;
  NPROBE_FD_SET(FLAG_APPL_LATENCY_COMPUTED, &(bkt->flags));
      }
    }

#if 0
    if(applLatencyComputed(bkt)) {
      char buf[64], buf1[64];

      if(bkt->src2dstApplLatency.tv_sec || bkt->src2dstApplLatency.tv_usec)
  printf("[Appl: %.2f ms (%s->%s)]", (float)(bkt->src2dstApplLatency.tv_sec*1000
               +(float)bkt->src2dstApplLatency.tv_usec/1000),
         _intoa(bkt->src, buf, sizeof(buf)), _intoa(bkt->dst, buf1, sizeof(buf1)));
      else
  printf("[Appl: %.2f ms (%s->%s)]", (float)(bkt->dst2srcApplLatency.tv_sec*1000
               +(float)bkt->dst2srcApplLatency.tv_usec/1000),
         _intoa(bkt->dst, buf, sizeof(buf)), _intoa(bkt->src, buf1, sizeof(buf1))
         );
    }
#endif
  }

  if(proto == IPPROTO_ICMP) {
    u_int16_t val = (256 * icmpType) + icmpCode;

    if(direction == 0) {
      bkt->src2dstIcmpType = val;
      NPROBE_FD_SET(icmpType, &bkt->src2dstIcmpFlags);
    } else {
      bkt->dst2srcIcmpType = val;
      NPROBE_FD_SET(icmpType, &bkt->dst2srcIcmpFlags);
    }
  }
}

/* ****************************************************** */

void updateTos(FlowHashBucket *bkt, int direction, u_char tos) {
  if(direction == 0)
    bkt->src2dstTos |= tos;
  else
    bkt->dst2srcTos |= tos;
}

/* ****************************************************** */

void timeval_diff(struct timeval *begin, struct timeval *end, 
      struct timeval *result, u_short divide_by_two) {
  if(end->tv_sec >= begin->tv_sec) {
    result->tv_sec = end->tv_sec-begin->tv_sec;

    if((end->tv_usec - begin->tv_usec) < 0) {
      result->tv_usec = 1000000 + end->tv_usec - begin->tv_usec;
      if(result->tv_usec > 1000000) begin->tv_usec = 1000000;
      result->tv_sec--;
    } else
      result->tv_usec = end->tv_usec-begin->tv_usec;

    if(divide_by_two)
      result->tv_sec /= 2, result->tv_usec /= 2;
  } else
    result->tv_sec = 0, result->tv_usec = 0;
}

/* ****************************************************** */

#if 0
static void print_flags(u_int8_t flags) {
  printf("%s%s%s%s%s\n",
   (flags & TH_SYN) ? " SYN" : "",
   (flags & TH_ACK) ? " ACK" : "",
   (flags & TH_FIN) ? " FIN" : "",
   (flags & TH_RST) ? " RST" : "",
   (flags & TH_PUSH) ? " PUSH" : "");
}
#endif

/* ****************************************************** */

/*
                   Client           nProbe            Server
    ->    SYN                       synTime
    <-    SYN|ACK                   synAckTime
    ->    ACK                       ackTime

    serverNwDelay = (synAckTime - synTime) / 2
    clientNwDelay = (ackTime - synAckTime) / 2
*/

void updateTcpFlags(FlowHashBucket *bkt, int direction,
        struct timeval *stamp, u_int8_t flags,
        char *fingerprint) {
  if(!nwLatencyComputed(bkt)) {
    if(flags == TH_SYN) {
      bkt->synTime.tv_sec = stamp->tv_sec;
      bkt->synTime.tv_usec = stamp->tv_usec;
    } else if(flags == (TH_SYN | TH_ACK)) {
      if((bkt->synTime.tv_sec != 0) && (bkt->synAckTime.tv_sec == 0)) {
  bkt->synAckTime.tv_sec  = stamp->tv_sec;
  bkt->synAckTime.tv_usec = stamp->tv_usec;
  timeval_diff(&bkt->synTime, stamp, &bkt->serverNwDelay, 1);
      }
    } else if(flags == TH_ACK) {
      if(bkt->synTime.tv_sec == 0) {
  /* We missed the SYN flag */
  NPROBE_FD_SET(FLAG_NW_LATENCY_COMPUTED,   &(bkt->flags));
  NPROBE_FD_SET(FLAG_APPL_LATENCY_COMPUTED, &(bkt->flags)); /* We cannot calculate it as we have
                     missed the 3-way handshake */
  return;
      }

      if(((direction  == 0)    && (bkt->src2dstTcpFlags != TH_SYN))
   || ((direction  == 1) && (bkt->dst2srcTcpFlags != TH_SYN)))
  return; /* Wrong flags */

      if(bkt->synAckTime.tv_sec > 0) {
  timeval_diff(&bkt->synAckTime, stamp, &bkt->clientNwDelay, 1);

#if 0
  printf("[Client: %.1f ms][Server: %.1f ms]\n",
         (float)(bkt->clientNwDelay.tv_sec*1000+(float)bkt->clientNwDelay.tv_usec/1000),
         (float)(bkt->serverNwDelay.tv_sec*1000+(float)bkt->serverNwDelay.tv_usec/1000));
#endif

  NPROBE_FD_SET(FLAG_NW_LATENCY_COMPUTED, &(bkt->flags));
  updateApplLatency(IPPROTO_TCP, bkt, direction, stamp, 0, 0);
      }
    }
  } else {
    /* Nw latency computed */
    if(!applLatencyComputed(bkt)) {
      /*
  src ---------> dst -+
  | Application
  | Latency
  <--------      -+

  NOTE:
  1. Application latency is calculated as the time passed since the first
  packet sent after the 3-way handshake until the first packet on
  the opposite direction is received.
  2. Application latency is calculated only on the first packet
      */

      updateApplLatency(IPPROTO_TCP, bkt, direction, stamp, 0, 0);
    }
  }

  if(fingerprint != NULL) {
    if((direction == 0) && (bkt->src2dstFingerprint[0] == '\0'))
      memcpy(bkt->src2dstFingerprint, fingerprint, FINGERPRINT_LEN);
    else if((direction == 1) && (bkt->dst2srcFingerprint[0] == '\0'))
      memcpy(bkt->dst2srcFingerprint, fingerprint, FINGERPRINT_LEN);
  }
}

/* ****************************************************** */

/*
  1 - equal
  0 - different
*/
int cmpIpAddress(IpAddress *src, IpAddress *dst) {
  if(src->ipVersion != dst->ipVersion) return(0);

  if(src->ipVersion == 4) {
    return(src->ipType.ipv4 == dst->ipType.ipv4 ? 1 : 0);
  } else {
    return(!memcmp(&src->ipType.ipv6, &dst->ipType.ipv6, sizeof(struct in6_addr)));
  }
}

/* ****************************************************** */

static FlowHashBucket* allocFlowBucket(u_int8_t proto) {
  FlowHashBucket* bkt;

  bkt = (FlowHashBucket*)calloc(1, sizeof(FlowHashBucket));
  if(bkt == NULL) {
    traceEvent(TRACE_ERROR, "NULL bkt (not enough memory?)\n");
  } else {
    pthread_rwlock_wrlock(&readWriteGlobals->rwGlobalsRwLock);
    readWriteGlobals->bucketsAllocated++;
    pthread_rwlock_unlock(&readWriteGlobals->rwGlobalsRwLock);
#if 0
    traceEvent(TRACE_NORMAL, "[+] bucketsAllocated=%u",
         readWriteGlobals->bucketsAllocated);
#endif
  }
  
  if(readOnlyGlobals.numPcapThreads > 1) pthread_rwlock_wrlock(&readWriteGlobals->statsRwLock);
  if(proto == 1) readWriteGlobals->accumulateStats.icmpFlows++;
  else if(proto == 6) readWriteGlobals->accumulateStats.tcpFlows++;
  else if(proto == 17) readWriteGlobals->accumulateStats.udpFlows++;
  if(readOnlyGlobals.numPcapThreads > 1) pthread_rwlock_unlock(&readWriteGlobals->statsRwLock);
  
  return(bkt);
}

/* ****************************************************** */

inline void updateHostInterface(HostHashBucket *bkt, u_int32_t ifHost, u_int16_t ifIdx) {
  if(ifHost == 0) 
    return;
  else
    bkt->ifHost = ifHost, bkt->ifIdx = ifIdx;
}

/* ****************************************************** */

static HostHashBucket* allocHostHashBucket(int alloc_stats, IpAddress *host, 
             u_int32_t ifHost, u_int16_t ifIdx) {
  HostHashBucket* bkt = (HostHashBucket*)calloc(1, sizeof(HostHashBucket));

  if(bkt == NULL) {
    traceEvent(TRACE_ERROR, "NULL bkt (not enough memory?)");
  } else {
    memcpy(&bkt->host, host, sizeof(IpAddress));
    updateHostInterface(bkt, ifHost, ifIdx);

    if(readOnlyGlobals.enableHostStats && alloc_stats) {
      bkt->stats = (HostStats*)calloc(1, sizeof(HostStats));

      if(bkt->stats != NULL) {
  pthread_rwlock_init(&bkt->stats->host_lock, NULL);
      }
    }
  }

  return(bkt);
}

/* ****************************************************** */

static inline u_int32_t hostHash(IpAddress *host) {
  if(host->ipVersion == 4)
    return(host->ipType.ipv4);
  else
    return(host->ipType.ipv6.s6_addr32[0]
     + host->ipType.ipv6.s6_addr32[1]
     + host->ipType.ipv6.s6_addr32[2]
     + host->ipType.ipv6.s6_addr32[3]);
}

/* ****************************************************** */

HostHashBucket* findHost(IpAddress *host, u_int8_t allocHostIfNecessary,
       u_int32_t ifHost, u_int16_t ifIdx) {
  unsigned short local_host;

  if((host == NULL) || (host->ipVersion == 6))
    local_host = 0;
  else {
    struct in_addr addr;

    addr.s_addr = ntohl(host->ipType.ipv4);
    local_host = isLocalAddress(&addr);
  }

  if(readOnlyGlobals.enableHostStats && local_host) {
    u_int32_t hash_idx = hostHash(host) % readOnlyGlobals.hostHashSize;
    u_int32_t mutex_idx = hash_idx % MAX_HASH_MUTEXES;
    HostHashBucket *prev_bkt = NULL;
    HostHashBucket *bkt = readWriteGlobals->theHostHash[hash_idx];
    
  while_host_search:
    while(bkt != NULL) {
      if(cmpIpAddress(&bkt->host, host)) {
  updateHostInterface(bkt, ifHost, ifIdx);
  return(bkt);
    } else {
  prev_bkt = bkt;
  bkt = bkt->stats->next;
      }
    } /* while */

    if(allocHostIfNecessary == 0) return(NULL);

    // FIX - Use another mutex
    pthread_mutex_lock(&readWriteGlobals->hostHashMutex[mutex_idx]);
    if((prev_bkt != NULL) && (prev_bkt->stats->next != NULL)) {
      bkt = prev_bkt->stats->next;
      pthread_mutex_unlock(&readWriteGlobals->hostHashMutex[mutex_idx]);
      goto while_host_search;
    }

    bkt = allocHostHashBucket(1, host, ifHost, ifIdx);
    if(bkt == NULL) {
      traceEvent(TRACE_ERROR, "NULL bkt (not enough memory?)\n");
      pthread_mutex_unlock(&readWriteGlobals->hostHashMutex[mutex_idx]);
      return(NULL);
    }

    /* Put the bucket at the end of the list */
    if(prev_bkt != NULL)
      prev_bkt->stats->next = bkt;
    else
      readWriteGlobals->theHostHash[hash_idx] = bkt;

    pthread_mutex_unlock(&readWriteGlobals->hostHashMutex[mutex_idx]);
    return(bkt);
  } else {
    if(allocHostIfNecessary == 0)
      return(NULL);
    else {
      return(allocHostHashBucket(0, host, ifHost, ifIdx));
    }
  }
}

/* ****************************************************** */

void printHostStats(HostHashBucket *host) {
  char buf[32];

  traceEvent(TRACE_NORMAL,
       "%s [sent=%u/%u,rcvd=%u/%u]\n",
       _intoa(host->host, buf, sizeof(buf)),
       host->stats ? host->stats->accumulateStats.num_pkts_sent : 0,
       host->stats ? host->stats->accumulateStats.num_bytes_sent : 0,
       host->stats ? host->stats->accumulateStats.num_pkts_rcvd : 0,
       host->stats ? host->stats->accumulateStats.num_bytes_rcvd : 0);
}

/* ****************************************************** */

void checkStatsUpdate(HostStats *stats) {
  if(stats->nextMinUpdate < readWriteGlobals->now) {
    stats->nextMinUpdate = readWriteGlobals->now+60;
    memcpy(&stats->lastMinStats, &stats->accumulateStats, sizeof(HostTraffic));
  }
}

/* ****************************************************** */

void updateFlowHosts(FlowHashBucket *myBucket, 
         const struct pcap_pkthdr *h,
         u_int8_t new_flow,
         u_int8_t final_update) {
  HostStats *stats;
     
  if(myBucket->src->stats != NULL) {
    pthread_rwlock_wrlock(&myBucket->src->stats->host_lock);
    stats = myBucket->src->stats;

    if(h) {
      stats->accumulateStats.num_pkts_sent++, stats->accumulateStats.num_bytes_sent += h->len;
    } else {
      stats->accumulateStats.num_pkts_sent += myBucket->flowCounters.pktSent,
  stats->accumulateStats.num_pkts_rcvd += myBucket->flowCounters.pktRcvd,
  stats->accumulateStats.num_bytes_sent += myBucket->flowCounters.bytesSent,
  stats->accumulateStats.num_bytes_rcvd += myBucket->flowCounters.bytesRcvd;
    }

    if(new_flow) {
      stats->accumulateStats.num_flows_client++;
      switch(myBucket->proto) {
      case 1:  stats->accumulateStats.num_icmp_flows_client++; break;
      case 6:  stats->accumulateStats.num_tcp_flows_client++; break;
      case 17: stats->accumulateStats.num_udp_flows_client++; break;
      }
    }

    if(final_update) myBucket->src->stats->num_references--;
    checkStatsUpdate(myBucket->src->stats);
    pthread_rwlock_unlock(&myBucket->src->stats->host_lock);

    if(readOnlyGlobals.deferredHostUpdate) printHostStats(myBucket->src);
  }

  if(myBucket->dst->stats != NULL) {
    pthread_rwlock_wrlock(&myBucket->dst->stats->host_lock);
    stats = myBucket->dst->stats;

    if(h) {
      stats->accumulateStats.num_pkts_rcvd++, stats->accumulateStats.num_bytes_rcvd += h->len;
    } else {
    stats->accumulateStats.num_pkts_sent += myBucket->flowCounters.pktRcvd,
      stats->accumulateStats.num_pkts_rcvd += myBucket->flowCounters.pktSent,
      stats->accumulateStats.num_bytes_sent += myBucket->flowCounters.bytesRcvd,
      stats->accumulateStats.num_bytes_rcvd += myBucket->flowCounters.bytesSent;
    }

    if(new_flow) {
      stats->accumulateStats.num_flows_server++;
      switch(myBucket->proto) {
      case 1:  stats->accumulateStats.num_icmp_flows_server++; break;
      case 6:  stats->accumulateStats.num_tcp_flows_server++; break;
      case 17: stats->accumulateStats.num_udp_flows_server++; break;
      }
    }

    if(final_update) myBucket->dst->stats->num_references--;
    checkStatsUpdate(myBucket->dst->stats);
    pthread_rwlock_unlock(&myBucket->dst->stats->host_lock);

    if(readOnlyGlobals.deferredHostUpdate) printHostStats(myBucket->dst);
  }
}

/* ****************************************************** */

inline u_int32_t to_msec(struct timeval *tv) {
  return(tv->tv_sec * 1000 + tv->tv_usec/1000);
}

/* ****************************************************** */

void addPktToHash(u_int8_t proto, u_char isFragment,
      u_short numPkts, u_char tos,
      u_short vlanId, u_int32_t tunnel_id,
      struct ether_header *ehdr,
      IpAddress src, u_short sport,
      IpAddress dst, u_short dport,
      u_int len, u_int8_t flags,
      u_int8_t icmpType, u_int8_t icmpCode, struct icmp_hdr *icmpPkt,
      u_short numMplsLabels,
      u_char mplsLabels[MAX_NUM_MPLS_LABELS][MPLS_LABEL_LEN],
      u_int16_t if_input, u_int16_t if_output,
      char *fingerprint,
      struct pcap_pkthdr *h, u_char *p,
      u_int16_t payload_shift, int payloadLen,
      time_t _firstSeen, /* Always set to 0 unless numPkts > 0 */     
      u_int16_t src_as, u_int16_t dst_as,
      u_int16_t src_mask, u_int16_t dst_mask,
      u_int32_t flow_sender_ip) {
  u_char *payload = NULL;
  u_int32_t n=0, mutex_idx;
  FlowHashBucket *bkt, *prev_bkt = NULL;
  u_int32_t srcHost=0, dstHost=0, idx, hash_idx = 0;
  struct timeval firstSeen;
     
  if(readOnlyGlobals.ignoreVlan)     vlanId = 0;
  if(readOnlyGlobals.ignoreProtocol) proto = 0;
  if(readOnlyGlobals.ignoreIP)       src.ipVersion = 4, src.ipType.ipv4 = 0, dst.ipVersion = 4, dst.ipType.ipv4 = 0;
  if(readOnlyGlobals.ignorePorts)    sport = 0, dport = 0;
  if(readOnlyGlobals.ignoreTos)      tos = 0;
  
  if(_firstSeen == 0)
    firstSeen.tv_sec = h->ts.tv_sec, firstSeen.tv_usec = h->ts.tv_usec;
  else
    firstSeen.tv_sec = _firstSeen, firstSeen.tv_usec = 0;
  
  if(src.ipVersion == 4) {
    srcHost = src.ipType.ipv4, dstHost = dst.ipType.ipv4;
  } else {
    srcHost = src.ipType.ipv6.s6_addr32[0]+src.ipType.ipv6.s6_addr32[1]
      +src.ipType.ipv6.s6_addr32[2]+src.ipType.ipv6.s6_addr32[3];
    dstHost = dst.ipType.ipv6.s6_addr32[0]+dst.ipType.ipv6.s6_addr32[1]
      +dst.ipType.ipv6.s6_addr32[2]+dst.ipType.ipv6.s6_addr32[3];
  }
  
  idx = (vlanId+proto+srcHost+dstHost+sport+dport+(tos & 0xfe));
  hash_idx = idx % readOnlyGlobals.numPcapThreads;
  idx %= readOnlyGlobals.flowHashSize; /* Do this after having computed queue_idx */

  if(payload_shift > 0) payload = &p[payload_shift];

  if(readOnlyGlobals.pcapFile == NULL) /* Live capture */
    readWriteGlobals->actTime.tv_sec = h->ts.tv_sec,
      readWriteGlobals->actTime.tv_usec = h->ts.tv_usec;

#if 0
  {
    char buf[256], buf1[256];

    printf("[%4s] %s:%d -> %s:%d [len=%u][payloadLen=%d][idx=%d]\n",
     proto2name(proto),
     _intoa(src, buf, sizeof(buf)), (int)sport,
     _intoa(dst, buf1, sizeof(buf1)), (int)dport,
     len, payloadLen, idx);
  }
#endif

  if(len > 4000000000) {
    traceEvent(TRACE_WARNING, "Internal error: len=%u", len);
  }else {
    // traceEvent(TRACE_INFO, "=> len=%u", len);
  }

  mutex_idx = idx % MAX_HASH_MUTEXES;

  // traceEvent(TRACE_INFO, "mutex_idx=%d", mutex_idx);

  /* The statement below guarantees that packets are serialized */
  pthread_rwlock_wrlock(&readWriteGlobals->flowHashRwLock[hash_idx][mutex_idx]);

  /* traceEvent(TRACE_INFO, "hash_idx=%d/idx=%d", hash_idx, idx); */
  bkt = readWriteGlobals->theFlowHash[hash_idx][idx];

   while(bkt != NULL) {
#ifdef ENABLE_MAGIC
    if(bkt->magic != 67) {
      printf("Error: magic error detected (%d)\n", bkt->magic);
    }
#endif

    if((bkt->proto == proto)
       && (bkt->vlanId == vlanId)
       && (((bkt->sport == sport)
      && (bkt->dport == dport)
      && ((bkt->src2dstTos & 0xfe) == (tos & 0xfe))
      && cmpIpAddress(&bkt->src->host, &src)
      && cmpIpAddress(&bkt->dst->host, &dst)
      )
     || ((bkt->sport == dport)
         && (bkt->dport == sport)
         && ((bkt->dst2srcTos & 0xfe) == (tos & 0xfe))
         && cmpIpAddress(&bkt->src->host, &dst)
         && cmpIpAddress(&bkt->dst->host, &src)
         )
     )
       ) {
      if(!bkt->sampled_flow) {
  /* This flow has not been sampled */
  if(cmpIpAddress(&bkt->src->host, &src)) {
    bkt->flowCounters.bytesSent += len, bkt->flowCounters.pktSent += numPkts;
    bkt->flowTimers.lastSeenSent.tv_sec = h->ts.tv_sec, bkt->flowTimers.lastSeenSent.tv_usec = h->ts.tv_usec;
    if(isFragment) NPROBE_FD_SET(FLAG_FRAGMENTED_PACKET_SRC2DST, &(bkt->flags));

    updateTos(bkt, 0, tos);
    if(proto == IPPROTO_TCP)
      updateTcpFlags(bkt, 0, &h->ts, flags, fingerprint);
    else if((proto == IPPROTO_UDP) || (proto == IPPROTO_ICMP))
      updateApplLatency(proto, bkt, 0, &h->ts, icmpType, icmpCode);

    setPayload(bkt, h, payload, payloadLen, 0);
    bkt->src2dstTcpFlags |= flags; /* Do not move this line before updateTcpFlags(...) */
  } else {
    bkt->flowCounters.bytesRcvd += len, bkt->flowCounters.pktRcvd += numPkts;
    if(((bkt->flowTimers.firstSeenRcvd.tv_sec == 0) && (bkt->flowTimers.firstSeenRcvd.tv_usec == 0)) 
       || (to_msec(&firstSeen) < to_msec(&bkt->flowTimers.firstSeenRcvd)))  
      bkt->flowTimers.firstSeenRcvd.tv_sec = firstSeen.tv_sec, bkt->flowTimers.firstSeenRcvd.tv_usec = firstSeen.tv_usec;

    bkt->flowTimers.lastSeenRcvd.tv_sec = h->ts.tv_sec, bkt->flowTimers.lastSeenRcvd.tv_usec = h->ts.tv_usec;
    if(isFragment) NPROBE_FD_SET(FLAG_FRAGMENTED_PACKET_DST2SRC, &(bkt->flags));

    updateTos(bkt, 1, tos);
    if(proto == IPPROTO_TCP)
      updateTcpFlags(bkt, 1, &h->ts, flags, fingerprint);
    else if((proto == IPPROTO_UDP) || (proto == IPPROTO_ICMP))
      updateApplLatency(proto, bkt, 1, &h->ts, icmpType, icmpCode);

    setPayload(bkt, h, payload, payloadLen, 1);
    bkt->dst2srcTcpFlags |= flags; /* Do not move this line before updateTcpFlags(...) */
  }

  /* Sanity check */
  if(payload == NULL) payloadLen = 0;

  pluginCallback(PACKET_CALLBACK, bkt,
           proto, isFragment, numPkts, tos,
           vlanId, ehdr, &src, sport,
           &dst, dport, len,
           flags, icmpType, icmpPkt, numMplsLabels,
           mplsLabels, fingerprint,
           h, p, payload, payloadLen);
      } else {
  /* traceEvent(TRACE_NORMAL, "--> Sampled flow"); */
      }

      if(!readOnlyGlobals.deferredHostUpdate) updateFlowHosts(bkt, h, 0, 0);

      pthread_rwlock_unlock(&readWriteGlobals->flowHashRwLock[hash_idx][mutex_idx]);
      return;
    } else {
      /* Bucket not found yet */
      n++;
      prev_bkt = bkt;
      bkt = bkt->next;
    }
  } /* while */

  if(n > readWriteGlobals->maxBucketSearch) {
    readWriteGlobals->maxBucketSearch = n;
    /* traceEvent(TRACE_INFO, "maxBucketSearch=%d\n", readWriteGlobals->maxBucketSearch); */
  }

#ifdef DEBUG_EXPORT
  printf("Adding new bucket\n");
#endif

  if(bkt == NULL) {
    if(readWriteGlobals->bucketsAllocated >= readOnlyGlobals.maxNumActiveFlows) {
      static u_char msgSent = 0;

      if(!msgSent) {
  traceEvent(TRACE_WARNING, "WARNING: too many (%u) active flows [limit=%u] (see -M)",
       readWriteGlobals->bucketsAllocated,
       readOnlyGlobals.maxNumActiveFlows);
  msgSent = 1;
      }
      readWriteGlobals->droppedPktsTooManyFlows++;

      pthread_rwlock_unlock(&readWriteGlobals->flowHashRwLock[hash_idx][mutex_idx]);
      return;
    }

    bkt = allocFlowBucket(proto);

    if(bkt == NULL) {
      traceEvent(TRACE_ERROR, "NULL bkt (not enough memory?)\n");
      pthread_rwlock_unlock(&readWriteGlobals->flowHashRwLock[hash_idx][mutex_idx]);
      return;
    }
  }
  memset(bkt, 0, sizeof(FlowHashBucket)); /* Reset bucket */
#ifdef ENABLE_MAGIC
  bkt->magic = 67;
#endif

  if((bkt->src = findHost(&src, 1, flow_sender_ip, if_input)) == NULL) {
    traceEvent(TRACE_ERROR, "NULL host bkt (not enough memory?)\n");
    pthread_rwlock_unlock(&readWriteGlobals->flowHashRwLock[hash_idx][mutex_idx]);
    return;
  } else {
    if(bkt->src->stats) bkt->src->stats->num_references++; // FIX - Missing atomic
  }

  if((bkt->dst = findHost(&dst, 1, 0 /* unknown */, NO_INTERFACE_INDEX)) == NULL) {
    traceEvent(TRACE_ERROR, "NULL host bkt (not enough memory?)\n");
    pthread_rwlock_unlock(&readWriteGlobals->flowHashRwLock[hash_idx][mutex_idx]);
    return;
  } else {
    if(bkt->dst->stats) bkt->dst->stats->num_references++;  // FIX - Missing atomic
  }

  if(readOnlyGlobals.flowSampleRate > 1) {
    pthread_rwlock_wrlock(&readWriteGlobals->rwGlobalsRwLock);

    if(readWriteGlobals->flowsToGo <= 1) {
     readWriteGlobals->flowsToGo = readOnlyGlobals.flowSampleRate;
    } else {
      readWriteGlobals->flowsToGo--;
      bkt->sampled_flow = 1;
    }

    pthread_rwlock_unlock(&readWriteGlobals->rwGlobalsRwLock);
  }

  bkt->proto = proto, bkt->vlanId = vlanId, bkt->tunnel_id = tunnel_id;
  bkt->sport = sport, bkt->dport = dport;
  bkt->src_as = src_as, bkt->dst_as = dst_as;
  bkt->src_mask = src_mask, bkt->dst_mask = dst_mask;

  if(ehdr) {
    memcpy(bkt->srcMacAddress, (char *)ESRC(ehdr), 6);
    memcpy(bkt->dstMacAddress, (char *)EDST(ehdr), 6);
  }

  if((if_input == NO_INTERFACE_INDEX) || (if_output == NO_INTERFACE_INDEX))
    bkt->if_input = ifIdx(bkt, 0, 1), bkt->if_output = ifIdx(bkt, 0, 0);
  else
    bkt->if_input = if_input, bkt->if_output = if_output;

  bkt->flowTimers.firstSeenSent.tv_sec = firstSeen.tv_sec, bkt->flowTimers.lastSeenSent.tv_sec = h->ts.tv_sec,
    bkt->flowTimers.firstSeenSent.tv_usec = firstSeen.tv_usec, bkt->flowTimers.lastSeenSent.tv_usec = h->ts.tv_usec;
  bkt->flowTimers.firstSeenRcvd.tv_sec = bkt->flowTimers.lastSeenRcvd.tv_sec = 0,
    bkt->flowTimers.firstSeenRcvd.tv_usec = bkt->flowTimers.lastSeenRcvd.tv_usec = 0;
  bkt->flowCounters.bytesSent += len, bkt->flowCounters.pktSent += numPkts;
      
  if(isFragment) NPROBE_FD_SET(FLAG_FRAGMENTED_PACKET_SRC2DST, &(bkt->flags));
  if(tos != 0) updateTos(bkt, 0, tos);
  if(proto == IPPROTO_TCP)
    updateTcpFlags(bkt, 0, &h->ts, flags, fingerprint);
  else if((proto == IPPROTO_UDP) || (proto == IPPROTO_ICMP))
    updateApplLatency(proto, bkt, 0, &h->ts, icmpType, icmpCode);

  if(payloadLen > 0) setPayload(bkt, h, payload, payloadLen, 0);
  bkt->src2dstTcpFlags |= flags;

  if(numMplsLabels > 0) {
    bkt->mplsInfo = malloc(sizeof(struct mpls_labels));
    bkt->mplsInfo->numMplsLabels = numMplsLabels;
    memcpy(bkt->mplsInfo->mplsLabels, mplsLabels,
     MAX_NUM_MPLS_LABELS*MPLS_LABEL_LEN);
  }

  pluginCallback(CREATE_FLOW_CALLBACK, bkt,
     proto,  isFragment, numPkts,  tos,
     vlanId, ehdr, &src,  sport,
     &dst,  dport, len,
     flags,  icmpType, icmpPkt, numMplsLabels,
     mplsLabels, fingerprint,
     h, p, payload, payloadLen);

  /* Put the bucket on top of the list */
  addToList(bkt, &readWriteGlobals->theFlowHash[hash_idx][idx]);

  if(!readOnlyGlobals.deferredHostUpdate) updateFlowHosts(bkt, h, 1, 0);

  pthread_rwlock_unlock(&readWriteGlobals->flowHashRwLock[hash_idx][mutex_idx]);

#ifdef DEBUG_EXPORT
  traceEvent(TRACE_INFO, "Bucket addedd");
#endif

  if(readOnlyGlobals.traceMode == 2) {
    char buf[256], buf1[256];

    traceEvent(TRACE_INFO, "New Flow: [%s] %s:%d -> %s:%d",
         proto2name(proto),
         _intoa(src, buf, sizeof(buf)), sport,
         _intoa(dst, buf1, sizeof(buf1)), dport);
  }
}

/* ****************************************************** */

void printICMPflags(u_int32_t flags, char *icmpBuf, int icmpBufLen) {
  snprintf(icmpBuf, icmpBufLen, "%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s",
     NPROBE_FD_ISSET(NPROBE_ICMP_ECHOREPLY, &flags)     ? "[ECHO REPLY]" : "",
     NPROBE_FD_ISSET(NPROBE_ICMP_UNREACH, &flags)       ? "[UNREACH]": "",
     NPROBE_FD_ISSET(NPROBE_ICMP_SOURCEQUENCH, &flags)  ? "[SOURCE_QUENCH]": "",
     NPROBE_FD_ISSET(NPROBE_ICMP_REDIRECT, &flags)      ? "[REDIRECT]": "",
     NPROBE_FD_ISSET(NPROBE_ICMP_ECHO, &flags)          ? "[ECHO]": "",
     NPROBE_FD_ISSET(NPROBE_ICMP_ROUTERADVERT, &flags)  ? "[ROUTERADVERT]": "",
     NPROBE_FD_ISSET(NPROBE_ICMP_ROUTERSOLICIT, &flags) ? "[ROUTERSOLICIT]": "",
     NPROBE_FD_ISSET(NPROBE_ICMP_TIMXCEED, &flags)      ? "[TIMXCEED]": "",
     NPROBE_FD_ISSET(NPROBE_ICMP_PARAMPROB, &flags)     ? "[PARAMPROB]": "",
     NPROBE_FD_ISSET(NPROBE_ICMP_TSTAMP, &flags)        ? "[TIMESTAMP]": "",
     NPROBE_FD_ISSET(NPROBE_ICMP_TSTAMPREPLY, &flags)   ? "[TIMESTAMP REPLY]": "",
     NPROBE_FD_ISSET(NPROBE_ICMP_IREQ, &flags)          ? "[INFO REQ]": "",
     NPROBE_FD_ISSET(NPROBE_ICMP_IREQREPLY, &flags)     ? "[INFO REPLY]": "",
     NPROBE_FD_ISSET(NPROBE_ICMP_MASKREQ , &flags)      ? "[MASK REQ]": "",
     NPROBE_FD_ISSET(NPROBE_ICMP_MASKREPLY, &flags)     ? "[MASK REPLY]": "");
}

/* ****************************************************** */

void printFlow(FlowHashBucket *theFlow, int direction) {
  char buf[256] = { 0 }, buf1[256] = { 0 }, latBuf[48] = { 0 };
  char vlanStr[16] = { 0 }, tunnelStr[32] = { 0 }, *fragmented = "";
  char icmpBuf[128] = {0}, applLatBuf[48] = {0}, jitterStr[64] = {0};

  if(((direction == 0) && fragmentedPacketSrc2Dst(theFlow))
     || ((direction == 1) && fragmentedPacketDst2Src(theFlow)))
    fragmented = " [FRAGMENT]";

  if(nwLatencyComputed(theFlow)
     && ((theFlow->clientNwDelay.tv_sec > 0) || (theFlow->clientNwDelay.tv_usec > 0))) {
    snprintf(latBuf, sizeof(latBuf), " [CND: %.2f ms]",
       (float)(theFlow->clientNwDelay.tv_sec*1000+(float)theFlow->clientNwDelay.tv_usec/1000));
  }

  if(nwLatencyComputed(theFlow)
     && ((theFlow->serverNwDelay.tv_sec > 0) || (theFlow->serverNwDelay.tv_usec > 0))) {
    int len = strlen(latBuf);

    snprintf(&latBuf[len], sizeof(latBuf)-len, " [SND: %.2f ms]",
       (float)(theFlow->serverNwDelay.tv_sec*1000+(float)theFlow->serverNwDelay.tv_usec/1000));
  }

  if(applLatencyComputed(theFlow)) {
    if((direction == 0) && (theFlow->src2dstApplLatency.tv_sec || theFlow->src2dstApplLatency.tv_usec))
      snprintf(applLatBuf, sizeof(applLatBuf), " [A: %.2f ms]",
         (float)(theFlow->src2dstApplLatency.tv_sec*1000
           +(float)theFlow->src2dstApplLatency.tv_usec/1000));
    else if((direction == 1) && (theFlow->dst2srcApplLatency.tv_sec || theFlow->dst2srcApplLatency.tv_usec))
      snprintf(applLatBuf, sizeof(applLatBuf), " [A: %.2f ms]",
         (float)(theFlow->dst2srcApplLatency.tv_sec*1000
           +(float)theFlow->dst2srcApplLatency.tv_usec/1000));
  }

  if(theFlow->proto == IPPROTO_ICMP) {
    if(direction == 0)
      printICMPflags(theFlow->src2dstIcmpFlags, icmpBuf, sizeof(icmpBuf));
    else
      printICMPflags(theFlow->dst2srcIcmpFlags, icmpBuf, sizeof(icmpBuf));
  }

  if(theFlow->vlanId == 0)
    vlanStr[0] = '\0';
  else
    snprintf(vlanStr, sizeof(vlanStr), " [VLAN %u]", theFlow->vlanId);

  if(theFlow->tunnel_id == 0)
    tunnelStr[0] = '\0';
  else
    snprintf(tunnelStr, sizeof(tunnelStr), " [TunnelId %u]", theFlow->tunnel_id);

  if(direction == 0) {
    traceEvent(TRACE_INFO, "Emitting Flow: [->][%s] %s:%d -> %s:%d [%d/%d pkt][%d/%d bytes]%s%s%s%s%s%s%s",
         proto2name(theFlow->proto), _intoa(theFlow->src->host, buf, sizeof(buf)), theFlow->sport,
         _intoa(theFlow->dst->host, buf1, sizeof(buf1)), theFlow->dport,
         (int)theFlow->flowCounters.pktSent, (int)theFlow->flowCounters.pktRcvd,
         (int)theFlow->flowCounters.bytesSent, (int)theFlow->flowCounters.bytesRcvd,
         latBuf, applLatBuf, jitterStr, icmpBuf, fragmented, vlanStr, tunnelStr);
    if(theFlow->src2dstFingerprint[0] != '\0')
      traceEvent(TRACE_INFO, "Fingeprint: '%s'", theFlow->src2dstFingerprint);
  } else {
    traceEvent(TRACE_INFO, "Emitting Flow: [<-][%s] %s:%d -> %s:%d [%d pkt/%d bytes]%s%s%s%s%s%s",
         proto2name(theFlow->proto), _intoa(theFlow->dst->host, buf, sizeof(buf)), theFlow->dport,
         _intoa(theFlow->src->host, buf1, sizeof(buf1)), theFlow->sport,
         (int)theFlow->flowCounters.pktRcvd, (int)theFlow->flowCounters.bytesRcvd, latBuf,
         applLatBuf, jitterStr, icmpBuf, fragmented, vlanStr, tunnelStr);
    if(theFlow->dst2srcFingerprint[0] != '\0')
      traceEvent(TRACE_INFO, "Fingeprint: '%s'", theFlow->dst2srcFingerprint);
  }
}

/* ****************************************************** */

u_int8_t endTcpFlow(unsigned short flags) {
  if(((flags & (TH_FIN | TH_ACK)) == (TH_FIN | TH_ACK))
     || ((flags & TH_RST) == TH_RST))
    return(1);
  else
    return(0);
}

/* ****************************************************** */

int isFlowExpired(FlowHashBucket *myBucket, time_t theTime) {
  if(myBucket->bucket_expired /* Forced expire */
     || (theTime < myBucket->flowTimers.lastSeenSent.tv_sec)
     || (theTime < myBucket->flowTimers.lastSeenRcvd.tv_sec)
     || ((theTime-myBucket->flowTimers.lastSeenSent.tv_sec)  >= readOnlyGlobals.idleTimeout)      /* flow expired: data not sent for a while */
     || ((theTime-myBucket->flowTimers.firstSeenSent.tv_sec) >= readOnlyGlobals.lifetimeTimeout)  /* flow expired: flow active but too old   */
     || ((myBucket->flowCounters.pktRcvd > 0)
   && (((theTime-myBucket->flowTimers.lastSeenRcvd.tv_sec) >= readOnlyGlobals.idleTimeout)  /* flow expired: data not sent for a while */
       || ((theTime-myBucket->flowTimers.firstSeenRcvd.tv_sec) >= readOnlyGlobals.lifetimeTimeout)))  /* flow expired: flow active but too old   */
     || ((myBucket->proto == IPPROTO_TCP) && (theTime-myBucket->flowTimers.lastSeenSent.tv_sec > 10 /* sec */)
   && endTcpFlow(myBucket->src2dstTcpFlags)
   && endTcpFlow(myBucket->dst2srcTcpFlags))     
     ) {
    return(1);
  } else {
    /* if(hashDebug) printBucket(myBucket); */
    return(0);
  }
}

/* ****************************************************** */

int isFlowExpiredSinceTooLong(FlowHashBucket *myBucket, time_t theTime) {
  if(myBucket->bucket_expired /* Forced expire */
     || ((theTime-myBucket->flowTimers.lastSeenSent.tv_sec)  >= 2*readOnlyGlobals.idleTimeout)      /* flow expired: data not sent for a while */
     || ((theTime-myBucket->flowTimers.firstSeenSent.tv_sec) >= 2*readOnlyGlobals.lifetimeTimeout)  /* flow expired: flow active but too old   */
     || ((myBucket->flowCounters.pktRcvd > 0)
   && (((theTime-myBucket->flowTimers.lastSeenRcvd.tv_sec) >= 2*readOnlyGlobals.idleTimeout)  /* flow expired: data not sent for a while */
       || ((theTime-myBucket->flowTimers.firstSeenRcvd.tv_sec) >= 2*readOnlyGlobals.lifetimeTimeout)))  /* flow expired: flow active but too old   */
     ) {
    return(1);
  } else {
    /* if(hashDebug) printBucket(myBucket); */
    return(0);
  }
}

/* ****************************************************** */

void printBucket(FlowHashBucket *myBucket) {
  char str[128], str1[128];
  int a = time(NULL)-myBucket->flowTimers.firstSeenSent.tv_sec;
  int b = time(NULL)-myBucket->flowTimers.lastSeenSent.tv_sec;
  int c = myBucket->flowCounters.bytesRcvd ? time(NULL)-myBucket->flowTimers.firstSeenRcvd.tv_sec : 0;
  int d = myBucket->flowCounters.bytesRcvd ? time(NULL)-myBucket->flowTimers.lastSeenRcvd.tv_sec : 0;

#ifdef DEBUG
  if((a > 30) || (b>30) || (c>30) || (d>30))
#endif
    {
      printf("[%4s] %s:%d [%u pkts] <-> %s:%d [%u pkts] [FsSent=%d][LsSent=%d][FsRcvd=%d][LsRcvd=%d]\n",
       proto2name(myBucket->proto),
       _intoa(myBucket->src->host, str, sizeof(str)), myBucket->sport, myBucket->flowCounters.pktSent,
       _intoa(myBucket->dst->host, str1, sizeof(str1)), myBucket->dport, myBucket->flowCounters.pktRcvd,
       a, b, c, d);
    }
}

/* ******************************************************** */

void walkHash(u_int32_t hash_idx, int flushHash) {
  u_int walkIndex, mutex_idx = 0, old_mutex_idx = mutex_idx+1; /* This to make sure that we lock 
                  the mutex at the first run */
  FlowHashBucket *myPrevBucket, *myBucket, *myNextBucket;
  time_t now = time(NULL);
  u_int num_lock = 0, num_unlock = 0;

#ifdef DEBUG_EXPORT
  printf("Begin walkHash(%d)\n", hash_idx);
#endif

  for(walkIndex=0; walkIndex < readOnlyGlobals.flowHashSize; walkIndex++) {
    /* traceEvent(TRACE_INFO, "walkHash(%d)", walkIndex); */

    old_mutex_idx = mutex_idx;
    mutex_idx = walkIndex % MAX_HASH_MUTEXES;

    if(!readOnlyGlobals.rebuild_hash) {
      if(mutex_idx != old_mutex_idx)
  pthread_rwlock_wrlock(&readWriteGlobals->flowHashRwLock[hash_idx][mutex_idx]), num_lock++;
    } else {
      if(readWriteGlobals->thePrevFlowHash == NULL) return; /* Too early */
    }

    myPrevBucket = NULL;

    if((!readOnlyGlobals.rebuild_hash)
       || flushHash || readOnlyGlobals.pcapFile /* We're reading from a dump file */)
      myBucket = readWriteGlobals->theFlowHash[hash_idx][walkIndex];
    else
      myBucket = readWriteGlobals->thePrevFlowHash[hash_idx][walkIndex];

    while(myBucket != NULL) {
#ifdef ENABLE_MAGIC
      if(myBucket->magic != 67) {
  printf("Error (2): magic error detected (magic=%d)\n", myBucket->magic);
      }
#endif

      if(readWriteGlobals->shutdownInProgress) {
  if(!readOnlyGlobals.rebuild_hash) {
    pthread_rwlock_unlock(&readWriteGlobals->flowHashRwLock[hash_idx][mutex_idx]);
    return;
  }
      }

      if(flushHash
   || readOnlyGlobals.rebuild_hash
   || isFlowExpired(myBucket, now)) {
#ifdef DEBUG_EXPORT
  printf("Found flow to emit (expired)(idx=%d)\n",walkIndex);
#endif

  myNextBucket = myBucket->next;

  if(myPrevBucket != NULL)
    myPrevBucket->next = myNextBucket;
  else {
    if((!readOnlyGlobals.rebuild_hash) || flushHash || readOnlyGlobals.pcapFile /* We're reading from a dump file */)
      readWriteGlobals->theFlowHash[hash_idx][walkIndex] = myNextBucket;
    else
      readWriteGlobals->thePrevFlowHash[hash_idx][walkIndex] = myNextBucket;
  }

  /*
    We've updated the pointers, hence removed this bucket from the active bucket list,
    therefore we now invalidate the next pointer 
  */
  myBucket->next = NULL;

  if(!myBucket->sampled_flow) {
    if(readWriteGlobals->exportBucketsLen < MAX_EXPORT_QUEUE_LEN) {
      /*
        The flow is both expired and we have room in the export
        queue to send it out, hence we can export it
      */
      queueBucketToExport(myBucket);
    } else {
      /* The export queue is full:
         
         The flow is expired and in queue since too long. As there's
         no room left in queue, the only thing we can do is to 
         drop it
      */
      discardBucket(myBucket);
      readWriteGlobals->totFlowDropped++;
    }
  } else {
    /* Free bucket */
    discardBucket(myBucket);
  }

  myBucket = myNextBucket;
      } else {
  /* Move to the next bucket */
  myPrevBucket = myBucket;
  myBucket = myBucket->next;
      }
#ifndef WIN32
  sched_yield();
#endif
    } /* while */

    if(!readOnlyGlobals.rebuild_hash) {
      if(mutex_idx != old_mutex_idx) {
  pthread_rwlock_unlock(&readWriteGlobals->flowHashRwLock[hash_idx][mutex_idx]), num_unlock++;
      }
    }
  } /* for */

#ifdef DEBUG_EXPORT
  printf("end walkHash(%d) [locks=%d][unlocks=%d]\n", hash_idx, num_lock, num_unlock);
  #endif

  if((num_lock != num_unlock) || (num_lock != (readOnlyGlobals.flowHashSize-1)))
    traceEvent(TRACE_WARNING, "Internal error [hash_idx=%d][locks=%d][unlocks=%d]\n", 
         hash_idx, num_lock, num_unlock);
}

/* ****************************************************** */

#ifdef HAVE_SQLITE
void sqlite_exec_sql(char* sql) {
  int rc;
  char *zErrMsg = 0;

  if(readWriteGlobals->sqlite3Handler == NULL) {
    traceEvent(TRACE_ERROR, "NULL sqlite3 handler [%s]", sql);
    return;
  }

  rc = sqlite3_exec(readWriteGlobals->sqlite3Handler, sql, NULL, 0, &zErrMsg);
  if(rc != SQLITE_OK) {
    traceEvent(TRACE_ERROR, "SQL error: %s [%s]", sql, zErrMsg);
    sqlite3_free(zErrMsg);
  }
}
#endif

/* ****************************************************** */


/* Save the specific packet into a pcap file */
void SavePktToPcap(const struct pcap_pkthdr *h, const u_char *p){
  int rc = 0;
  if(readOnlyGlobals.pcapDirPath != NULL) {
    time_t theTime = time(NULL);
    static time_t lastTheTime = 0;
    struct tm *tm;
    char creation_time[256], dir_path[256];

    // theTime -= (theTime % readOnlyGlobals.file_dump_timeout);
    theTime -= (theTime % PCAP_FILE_TIMEOUT);

    if(lastTheTime != theTime) {
      pthread_rwlock_wrlock(&readWriteGlobals->pcapFileLock);
      if(lastTheTime != theTime) {
        ClosePcapFile();
        lastTheTime = theTime;
      }
      pthread_rwlock_unlock(&readWriteGlobals->pcapFileLock);
    }

    if((readWriteGlobals->pcapDumper == NULL)) {
      pthread_rwlock_wrlock(&readWriteGlobals->pcapFileLock);
      if((readWriteGlobals->pcapDumper == NULL)) {

        tm = localtime(&theTime);

        strftime(creation_time, sizeof(creation_time), "%Y%m%d%H", tm);
        snprintf(dir_path, sizeof(dir_path), "mkdir %s %s", 
            "-p", readOnlyGlobals.pcapDirPath);

        rc = system(dir_path);

        snprintf(readWriteGlobals->pcapFilePath,
                 sizeof(readWriteGlobals->pcapFilePath),
                 "%s%c%s%02d.%s%s",
                 readOnlyGlobals.pcapDirPath, '/', creation_time, 
                 tm->tm_min - (tm->tm_min % ((PCAP_FILE_TIMEOUT+59)/60)),
                 // tm->tm_min - (tm->tm_min % ((readOnlyGlobals.file_dump_timeout+59)/60)),
                 "pcap",
                 TEMP_PREFIX);
        if((readWriteGlobals->pcapDumperFile = fopen(readWriteGlobals->pcapFilePath,"w")) != NULL){
          if((readWriteGlobals->pcapDumper = pcap_dump_fopen(readOnlyGlobals.pcapPtr, readWriteGlobals->pcapDumperFile)) != NULL){
            if(readOnlyGlobals.traceMode) traceEvent(TRACE_NORMAL, "Saving pcap into temporary file '%s'", readWriteGlobals->pcapFilePath);
          } else {
            traceEvent(TRACE_WARNING, "WARNING: pcap_dump_fopen() unable to create file '%s' [errno=%d]", readWriteGlobals->pcapFilePath, errno);
            pthread_rwlock_unlock(&readWriteGlobals->pcapFileLock);
            return;
          }
        } else {
          traceEvent(TRACE_WARNING, "WARNING: fopen() unable to create file '%s' [errno=%d]", readWriteGlobals->pcapFilePath, errno);
          pthread_rwlock_unlock(&readWriteGlobals->pcapFileLock);
          return;
        }
      }
      pthread_rwlock_unlock(&readWriteGlobals->pcapFileLock);
    }
    if ( h->caplen <= LONG_SNAPLEN && p != NULL) {

      u_int32_t wlen = 4 * sizeof(u_int32_t) + h->caplen;
      void * pkt = malloc(wlen);
      if (pkt == NULL){
        traceEvent(TRACE_ERROR, "Not enough space for writing pcao file.");
        return;
      }
      void * pkt_p = pkt;
      u_int32_t h_sec    = (u_int32_t)h->ts.tv_sec;
      u_int32_t h_usec   = (u_int32_t)h->ts.tv_usec;
      u_int32_t h_caplen = h->caplen;
      u_int32_t h_len    = h->len;
      memcpy(pkt_p, &h_sec, sizeof(u_int32_t));    pkt_p += sizeof(u_int32_t);
      memcpy(pkt_p, &h_usec, sizeof(u_int32_t));   pkt_p += sizeof(u_int32_t);
      memcpy(pkt_p, &h_caplen, sizeof(u_int32_t)); pkt_p += sizeof(u_int32_t);
      memcpy(pkt_p, &h_len, sizeof(u_int32_t));    pkt_p += sizeof(u_int32_t);
      memcpy(pkt_p, p, h_caplen);

      u_int32_t wlen_r;
      if((wlen_r = fwrite(pkt, wlen, 1, readWriteGlobals->pcapDumperFile)) != wlen)
      free(pkt);

      // pcap_dump((u_char *)readWriteGlobals->pcapDumper, h, p);
    } else {
      traceEvent(TRACE_WARNING, "WARNING: pkt length %d (caplen %d)", h->len, h->caplen);
    }
  }
}

void ClosePcapFile() {
  char newPath[512]; /* same size as pcapFilePath */
  int len = strlen(readWriteGlobals->pcapFilePath)-strlen(TEMP_PREFIX);

  // pthread_rwlock_wrlock(&readWriteGlobals->pcapFileLock);
  if(readWriteGlobals->pcapDumper != NULL) {
    pcap_dump_close(readWriteGlobals->pcapDumper);
    // if(readWriteGlobals->pcapDumperFile != NULL){
    //   traceEvent(TRACE_NORMAL, "fclose");
    //   fclose(readWriteGlobals->pcapDumperFile);
    // }

    if(readWriteGlobals->pcapFilePath[0] != '\0') {
      strncpy(newPath, readWriteGlobals->pcapFilePath, len); newPath[len] = '\0';
      rename(readWriteGlobals->pcapFilePath, newPath);
      traceEvent(TRACE_NORMAL, "Flow file '%s' is now available", newPath);
    }
    readWriteGlobals->pcapDumper = NULL;
    readWriteGlobals->pcapDumperFile = NULL;
  }
  // pthread_rwlock_unlock(&readWriteGlobals->pcapFileLock);
}

/* ****************************************************** */

void close_dump_file() {
  char newPath[512]; /* same size as dumpFilePath */
  int len = strlen(readWriteGlobals->dumpFilePath)-strlen(TEMP_PREFIX);

#ifdef HAVE_SQLITE
  if(readOnlyGlobals.dumpFormat == sqlite_format) {
    if(readWriteGlobals->sqlite3Handler != NULL) {
      sqlite_exec_sql("commit;");
      sqlite3_close(readWriteGlobals->sqlite3Handler);
      readWriteGlobals->sqlite3Handler = NULL;
      traceEvent(TRACE_NORMAL, "Insert %u rows into the saved database",
     readWriteGlobals->sql_row_idx);
    }
  }
#endif

  if((readOnlyGlobals.dumpFormat == binary_format)
     || (readOnlyGlobals.dumpFormat == text_format)) {
    if(readWriteGlobals->flowFd != NULL) {
      fclose(readWriteGlobals->flowFd);
    }
  }

  if(readWriteGlobals->dumpFilePath[0] != '\0') {
    strncpy(newPath, readWriteGlobals->dumpFilePath, len); newPath[len] = '\0';
    rename(readWriteGlobals->dumpFilePath, newPath);
    traceEvent(TRACE_NORMAL, "Flow file '%s' is now available", newPath);
    readWriteGlobals->flowFd = NULL;
  }
}

/* ****************************************************** */

#ifdef HAVE_GEOIP
GeoIPRecord* geoLocate(IpAddress *host) {
  if(readOnlyGlobals.geo_ip_city_db == NULL) return(NULL);

  if(host->ipVersion == 4)
    return(GeoIP_record_by_ipnum(readOnlyGlobals.geo_ip_city_db, host->ipType.ipv4));
#ifdef HAVE_GEOIP_IPv6
  else if(host->ipVersion == 6)
    return(GeoIP_record_by_ipnum_v6(readOnlyGlobals.geo_ip_city_db, host->ipType.ipv6));
#endif
  else
    return(NULL);
}
#endif

/* ****************************************************** */

void exportBucket(FlowHashBucket *myBucket, u_char free_memory) {
  int rc = 0;

  //    pthread_mutex_lock(&buf_mutex);
#ifdef HAVE_GEOIP
  if(readOnlyGlobals.geo_ip_city_db != NULL) {
    /* We need to geo-locate this flow */
    if(myBucket->src) myBucket->geo_src = geoLocate(&myBucket->src->host);
    if(myBucket->dst) myBucket->geo_dst = geoLocate(&myBucket->dst->host);
  }
#endif

  if(readOnlyGlobals.dirPath != NULL) {
    time_t theTime = time(NULL);
    static time_t lastTheTime = 0;
    struct tm *tm;
    char creation_time[256], dir_path[256];

    theTime -= (theTime % readOnlyGlobals.file_dump_timeout);

    if(lastTheTime != theTime) {
      close_dump_file();
      lastTheTime = theTime;
    }

    if((readWriteGlobals->flowFd == NULL)
#ifdef HAVE_SQLITE
       && (readWriteGlobals->sqlite3Handler == NULL)
#endif
       ) {
      tm = localtime(&theTime);

      strftime(creation_time, sizeof(creation_time), "%Y/%m/%d/%H", tm);
      snprintf(dir_path, sizeof(dir_path), "mkdir %s %s%c%s",
#ifdef WIN32
         "",
#else
         "-p",
#endif
         readOnlyGlobals.dirPath,
#ifdef WIN32
         '\\'
#else
         '/'
#endif
         , creation_time);

#ifdef WIN32
      revertSlash(dir_path, 0);
#endif
      rc = system(dir_path);

      snprintf(readWriteGlobals->dumpFilePath,
         sizeof(readWriteGlobals->dumpFilePath),
         "%s%c%s%c%02d.%s%s",
         readOnlyGlobals.dirPath, '/', creation_time, '/',
         tm->tm_min - (tm->tm_min % ((readOnlyGlobals.file_dump_timeout+59)/60)),
#ifdef HAVE_SQLITE
         (readOnlyGlobals.dumpFormat == sqlite_format) ? "sqlite" : "flows",
#else
         "flows",
#endif
         TEMP_PREFIX);

      traceEvent(TRACE_WARNING, "Prepare to create file '%s'", readWriteGlobals->dumpFilePath);

#ifdef WIN32
      revertSlash(readWriteGlobals->dumpFilePath, 0);
#endif

#ifdef HAVE_SQLITE
      if(readOnlyGlobals.dumpFormat == sqlite_format) {
  int rc;

  traceEvent(TRACE_NORMAL, "About to open database %s", readWriteGlobals->dumpFilePath);

  if((rc = sqlite3_open(readWriteGlobals->dumpFilePath, &readWriteGlobals->sqlite3Handler)) != 0) {
    traceEvent(TRACE_WARNING, "WARNING: Unable to create database %s' [%s]",
         readWriteGlobals->dumpFilePath, sqlite3_errmsg(readWriteGlobals->sqlite3Handler));
    sqlite3_close(readWriteGlobals->sqlite3Handler);
    readWriteGlobals->sqlite3Handler = NULL;
  } else {
    int i;
    char sql_buffer[2048] = { '\0' };

    traceEvent(TRACE_NORMAL, "Saving flows into temporary database '%s'",
         readWriteGlobals->dumpFilePath);
    snprintf(sql_buffer, sizeof(sql_buffer), "begin; create table flows (");

    /* Dump header */
    for(i=0; i<TEMPLATE_LIST_LEN; i++) {
      if(readOnlyGlobals.v9TemplateElementList[i] != NULL) {
        if(i > 0) snprintf(&sql_buffer[strlen(sql_buffer)], sizeof(sql_buffer)-strlen(sql_buffer), ", ");
        snprintf(&sql_buffer[strlen(sql_buffer)], sizeof(sql_buffer)-strlen(sql_buffer),
           "%s %s",
           readOnlyGlobals.v9TemplateElementList[i]->templateElementName,
           (readOnlyGlobals.v9TemplateElementList[i]->templateElementLen <= 4) ? "number" : "string");
      } else
        break;
    }
    snprintf(&sql_buffer[strlen(sql_buffer)], sizeof(sql_buffer)-strlen(sql_buffer), ")");

    sqlite_exec_sql(sql_buffer);
  }
      }
#endif

      if((readOnlyGlobals.dumpFormat == text_format)
   || (readOnlyGlobals.dumpFormat == binary_format)) {
  if((readWriteGlobals->flowFd = fopen(readWriteGlobals->dumpFilePath, "w+b")) == NULL) {
    traceEvent(TRACE_WARNING, "WARNING: Unable to create file '%s' [errno=%d]",
         readWriteGlobals->dumpFilePath, errno);
  } else {
    int i;

    traceEvent(TRACE_NORMAL, "Saving flows into temporary file '%s'",
         readWriteGlobals->dumpFilePath);

    /* Dump header */
    if(readOnlyGlobals.dumpFormat == text_format) {
      for(i=0; i<TEMPLATE_LIST_LEN; i++) {
        if(readOnlyGlobals.v9TemplateElementList[i] != NULL) {
    if(i > 0) fprintf(readWriteGlobals->flowFd, "%s",
          readOnlyGlobals.csv_separator);
    fprintf(readWriteGlobals->flowFd, "%s",
      readOnlyGlobals.v9TemplateElementList[i]->templateElementName);
        } else
    break;
      }

      fprintf(readWriteGlobals->flowFd, "\n");
    }
  }
      }

      readWriteGlobals->sql_row_idx = 0;
    }
  }

//pthread_mutex_lock(&buf_mutex);
pthread_rwlock_wrlock(&readWriteGlobals->exportRwLock);
  if((myBucket->proto != TCP_PROTOCOL)
     || (myBucket->flowCounters.bytesSent >= readOnlyGlobals.minFlowSize)) {
    rc = exportBucketToNetflow(myBucket, 0 /* src -> dst */, free_memory);

    if(rc > 0)
      readWriteGlobals->totFlows++;
  }

  if(free_memory && (myBucket->src2dstPayload != NULL)) {
    free(myBucket->src2dstPayload);
    myBucket->src2dstPayload = NULL;
  }

  /* *********************** */

  if((readOnlyGlobals.netFlowVersion == 5)
     || ((readOnlyGlobals.netFlowVersion != 5) && (!readOnlyGlobals.bidirectionalFlows))) {
    if(myBucket->flowCounters.bytesRcvd > 0) {
      /*
  v9 flows do not need to be exported twice, once per direction
  as they are bi-directional. However if the flow format does not
  contain bi-directional info (e.g. IN_BYTES, OUT_BYTES) the two
  flow directions need to be sent anyway. Hence we decide to send
  both flow directions
      */

      if((myBucket->proto != TCP_PROTOCOL)
   || (myBucket->flowCounters.bytesRcvd >= readOnlyGlobals.minFlowSize)) {
  rc = exportBucketToNetflow(myBucket, 1 /* dst -> src */, free_memory);

  if(rc > 0)
    readWriteGlobals->totFlows++;
      }

      if(free_memory && (myBucket->dst2srcPayload != NULL)) {
  free(myBucket->dst2srcPayload);
  myBucket->dst2srcPayload = NULL;
      }
    }
  }

//pthread_mutex_unlock(&buf_mutex);
pthread_rwlock_unlock(&readWriteGlobals->exportRwLock);
  if(free_memory && (myBucket->mplsInfo != NULL)) {
    free(myBucket->mplsInfo);
    myBucket->mplsInfo = NULL;
  }

  if(free_memory) {
    if(readOnlyGlobals.deferredHostUpdate) updateFlowHosts(myBucket, NULL, 0, 1);

    pluginCallback(DELETE_FLOW_CALLBACK, myBucket,
       0, 0,
       0, 0,
       0, NULL,
       NULL, 0,
       NULL, 0,
       0,
       0, 0, NULL, 0, NULL, NULL,
       NULL, NULL, NULL, 0);
  }
    //  pthread_mutex_unlock(&buf_mutex);
}

/* ****************************************************** */

void discardBucket(FlowHashBucket *myBucket) {
  pluginCallback(DELETE_FLOW_CALLBACK, myBucket,
     0, 0,
     0, 0,
     0, NULL,
     NULL, 0,
     NULL, 0,
     0,
     0, 0, NULL, 0, NULL, NULL,
     NULL, NULL, NULL, 0);
  
  purgeBucket(myBucket);
}

/* ****************************************************** */

void queueBucketToExport(FlowHashBucket *myBucket) {
  if(readWriteGlobals->exportBucketsLen > MAX_EXPORT_QUEUE_LEN) {
    static char show_message = 0;

    if(!show_message) {
      traceEvent(TRACE_WARNING,
     "Too many (%u) queued buckets for export: bucket discarded.\n",
     readWriteGlobals->exportBucketsLen);
      traceEvent(TRACE_WARNING, "Please check -e value and decrease it.\n");
      show_message = 1;
    }

    discardBucket(myBucket);
  } else {
    pthread_mutex_lock(&readWriteGlobals->exportMutex);
    addToList(myBucket, &readWriteGlobals->exportQueue);
    readWriteGlobals->exportBucketsLen++;
#ifdef DEBUG
    traceEvent(TRACE_NORMAL, "[+] [exportBucketsLen=%d][myBucket=%p]",
         readWriteGlobals->exportBucketsLen, myBucket);
#endif
    pthread_mutex_unlock(&readWriteGlobals->exportMutex);
    signalCondvar(&readWriteGlobals->exportQueueCondvar, 0);
  }
}

/* ****************************************************** */

void* dequeueBucketToExport(void* notUsed) {
  traceEvent(TRACE_INFO, "Starting bucket dequeue thread");

  dequeueBucketToExport_up = 1;
  while(1) {
    /*
      traceEvent(TRACE_INFO, "dequeueBucketToExport() [exportQueue=%p]",
      readWriteGlobals->exportQueue);
    */

    if(readWriteGlobals->exportQueue == NULL) {
      if(!readWriteGlobals->shutdownInProgress) {
  /* traceEvent(TRACE_INFO, "About to call waitCondvar()"); */
  waitCondvar(&readWriteGlobals->exportQueueCondvar);
  /* traceEvent(TRACE_INFO, "waitCondvar() called"); */
      } else
  break;
    }

    if(readWriteGlobals->exportQueue != NULL) {
      FlowHashBucket *myBucket;

      /* Remove bucket from list */
      pthread_mutex_lock(&readWriteGlobals->exportMutex);
      if(readWriteGlobals->exportQueue != NULL) {
  myBucket = getListHead(&readWriteGlobals->exportQueue);
  if(myBucket != NULL) {
    if(readWriteGlobals->exportBucketsLen == 0)
      traceEvent(TRACE_WARNING, "Internal error (exportBucketsLen == 0)");
    else
      readWriteGlobals->exportBucketsLen--;
  }
#ifdef DEBUG
  traceEvent(TRACE_NORMAL, "[-] [exportBucketsLen=%d][myBucket=%p]",
       readWriteGlobals->exportBucketsLen, myBucket);
#endif
      } else
  myBucket = NULL;

      pthread_mutex_unlock(&readWriteGlobals->exportMutex);

      if(myBucket != NULL) {
  exportBucket(myBucket, 1);
  purgeBucket(myBucket);
      }
    }
  }

  traceEvent(TRACE_INFO, "Export thread terminated [exportQueue=%x]",
       readWriteGlobals->exportQueue);
  signalCondvar(&readWriteGlobals->termCondvar, 0);
  return(NULL);
}

/* ****************************************************** */

void purgeBucket(FlowHashBucket *myBucket) {
  PluginInformation *next_info, *info = myBucket->plugin;

  if(myBucket->mplsInfo)       free(myBucket->mplsInfo);
  if(myBucket->src2dstPayload) free(myBucket->src2dstPayload);
  if(myBucket->dst2srcPayload) free(myBucket->dst2srcPayload);

  /* These pointers should have been already freed by plugins */
  while(info != NULL) {
    if(info->pluginData) free(info->pluginData);
    next_info = info->next;
    free(info);
    info = next_info;
  }

#ifdef HAVE_GEOIP
  if(myBucket->geo_src) GeoIPRecord_delete(myBucket->geo_src);
  if(myBucket->geo_dst) GeoIPRecord_delete(myBucket->geo_dst);
#endif

  if(myBucket->src->stats == NULL) free(myBucket->src);
  if(myBucket->dst->stats == NULL) free(myBucket->dst);

  free(myBucket);

  pthread_rwlock_wrlock(&readWriteGlobals->rwGlobalsRwLock);
  readWriteGlobals->bucketsAllocated--;
  pthread_rwlock_unlock(&readWriteGlobals->rwGlobalsRwLock);

#if 0
  traceEvent(TRACE_NORMAL, "[-] bucketsAllocated=%u",
       readWriteGlobals->bucketsAllocated);
#endif
}

