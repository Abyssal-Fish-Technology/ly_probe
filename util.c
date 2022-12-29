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

#ifdef sun
extern char *strtok_r(char *, const char *, char **);
#endif

#ifdef WIN32
#define strtok_r(a, b, c) strtok(a, b)
#endif

#ifdef HAVE_SQLITE
extern void sqlite_exec_sql(char* sql);
#endif

/* ********************** */

static char *port_mapping[0xFFFF] = { NULL };
static char *proto_mapping[0xFF] = { NULL };

static u_int32_t localNetworks[MAX_NUM_NETWORKS][CONST_NETWORK_SIZE];
static u_int32_t blacklistNetworks[MAX_NUM_NETWORKS][CONST_NETWORK_SIZE];

/* ********************** */

#define CUSTOM_FIELD_LEN  16

/* ************************************ */

void traceEvent(const int eventTraceLevel, const char* file,
		const int line, const char * format, ...) {
  va_list va_ap;

  if(eventTraceLevel <= readOnlyGlobals.traceLevel) {
    char buf[2048], out_buf[640];
    char theDate[32], *extra_msg = "";
    time_t theTime = time(NULL);

    va_start (va_ap, format);

    /* We have two paths - one if we're logging, one if we aren't
     *   Note that the no-log case is those systems which don't support it (WIN32),
     *                                those without the headers !defined(USE_SYSLOG)
     *                                those where it's parametrically off...
     */

    memset(buf, 0, sizeof(buf));
    strftime(theDate, 32, "%d/%b/%Y %H:%M:%S", localtime(&theTime));

    vsnprintf(buf, sizeof(buf)-1, format, va_ap);

    if(eventTraceLevel == 0 /* TRACE_ERROR */)
      extra_msg = "ERROR: ";
    else if(eventTraceLevel == 1 /* TRACE_WARNING */)
      extra_msg = "WARNING: ";

    while(buf[strlen(buf)-1] == '\n') buf[strlen(buf)-1] = '\0';

    snprintf(out_buf, sizeof(out_buf), "%s [%s:%d] %s%s", theDate,
#ifdef WIN32
	     strrchr(file, '\\')+1,
#else
	     file,
#endif
	     line, extra_msg, buf);

#ifndef WIN32
    if(readOnlyGlobals.useSyslog) {
      if(!readWriteGlobals->syslog_opened) {
	openlog(readOnlyGlobals.nprobeId, LOG_PID, LOG_DAEMON);
	readWriteGlobals->syslog_opened = 1;
      }

      syslog(LOG_INFO, "%s", out_buf);
    } else
      printf("%s\n", out_buf);
#else
    printf("%s\n", out_buf);
#endif
  }

  fflush(stdout);
  va_end(va_ap);
}


/* ************************************ */

#ifdef WIN32
unsigned long waitForNextEvent(unsigned long ulDelay /* ms */) {
  unsigned long ulSlice = 1000L; /* 1 Second */

  while(ulDelay > 0L) {
    if(ulDelay < ulSlice)
      ulSlice = ulDelay;
    Sleep(ulSlice);
    ulDelay -= ulSlice;
  }

  return ulDelay;
}

/* ******************************* */

void initWinsock32() {
  WORD wVersionRequested;
  WSADATA wsaData;
  int err;

  wVersionRequested = MAKEWORD(2, 0);
  err = WSAStartup( wVersionRequested, &wsaData );
  if( err != 0 ) {
    /* Tell the user that we could not find a usable */
    /* WinSock DLL.                                  */
    traceEvent(TRACE_ERROR, "FATAL ERROR: unable to initialise Winsock 2.x.");
    exit(-1);
  }
}

/* ******************************** */

short isWinNT() {
  DWORD dwVersion;
  DWORD dwWindowsMajorVersion;

  dwVersion=GetVersion();
  dwWindowsMajorVersion =  (DWORD)(LOBYTE(LOWORD(dwVersion)));
  if(!(dwVersion >= 0x80000000 && dwWindowsMajorVersion >= 4))
    return 1;
  else
    return 0;
}

/* ****************************************************** */
/*
  int snprintf(char *string, size_t maxlen, const char *format, ...) {
  int ret=0;
  va_list args;

  va_start(args, format);
  vsprintf(string,format,args);
  va_end(args);
  return ret;
  }
*/
#endif /* Win32 */

/* ****************************************************** */

void checkHostFingerprint(char *fingerprint, char *osName, int osNameLen) {
  FILE *fd = NULL;
  char *WIN, *MSS, *WSS, *ttl, *flags;
  int S, N, D, T, done = 0;
  char *strtokState;

  osName[0] = '\0';
  strtokState = NULL;
  WIN = strtok_r(fingerprint, ":", &strtokState);
  MSS = strtok_r(NULL, ":", &strtokState);
  ttl = strtok_r(NULL, ":", &strtokState);
  WSS = strtok_r(NULL, ":", &strtokState);
  S = atoi(strtok_r(NULL, ":", &strtokState));
  N = atoi(strtok_r(NULL, ":", &strtokState));
  D = atoi(strtok_r(NULL, ":", &strtokState));
  T = atoi(strtok_r(NULL, ":", &strtokState));
  flags = strtok_r(NULL, ":", &strtokState);

  fd = fopen("etter.passive.os.fp", "r");

  if(fd) {
    char line[384];
    char *b, *d, *ptr;

    while((!done) && fgets(line, sizeof(line)-1, fd)) {
      if((line[0] == '\0') || (line[0] == '#') || (strlen(line) < 30)) continue;
      line[strlen(line)-1] = '\0';

      strtokState = NULL;
      ptr = strtok_r(line, ":", &strtokState); if(ptr == NULL) continue;
      if(strcmp(ptr, WIN)) continue;
      b = strtok_r(NULL, ":", &strtokState); if(b == NULL) continue;
      if(strcmp(MSS, "_MSS") != 0) {
	if(strcmp(b, "_MSS") != 0) {
	  if(strcmp(b, MSS)) continue;
	}
      }

      ptr = strtok_r(NULL, ":", &strtokState); if(ptr == NULL) continue;
      if(strcmp(ptr, ttl)) continue;

      d = strtok_r(NULL, ":", &strtokState); if(d == NULL) continue;
      if(strcmp(WSS, "WS") != 0) {
	if(strcmp(d, "WS") != 0) {
	  if(strcmp(d, WSS)) continue;
	}
      }

      ptr = strtok_r(NULL, ":", &strtokState); if(ptr == NULL) continue;
      if(atoi(ptr) != S) continue;
      ptr = strtok_r(NULL, ":", &strtokState); if(ptr == NULL) continue;
      if(atoi(ptr) != N) continue;
      ptr = strtok_r(NULL, ":", &strtokState); if(ptr == NULL) continue;
      if(atoi(ptr) != D) continue;
      ptr = strtok_r(NULL, ":", &strtokState); if(ptr == NULL) continue;
      if(atoi(ptr) != T) continue;
      ptr = strtok_r(NULL, ":", &strtokState); if(ptr == NULL) continue;
      if(strcmp(ptr, flags)) continue;

      /* NOTE
	 strlen(srcHost->fingerprint) is 29 as the fingerprint length is so
	 Example: 0212:_MSS:80:WS:0:1:0:0:A:LT
      */

      snprintf(osName, osNameLen, "%s", &line[29]);
      done = 1;
    }

    fclose(fd);
  }
}

/* ******************************************************************* */

u_int8_t ip2mask(IpAddress ip) {
  if((readOnlyGlobals.numLocalNetworks == 0) || (ip.ipVersion != 4))
    return(0);
  else {
    int i;
    u_int32_t addr = htonl(ip.ipType.ipv4);

    for(i=0; i<readOnlyGlobals.numLocalNetworks; i++) {
      if((addr & localNetworks[i][CONST_NETMASK_ENTRY]) == localNetworks[i][CONST_NETWORK_ENTRY]) {
	// traceEvent(TRACE_INFO, "--> %d", localNetworks[i][CONST_NETMASK_V6_ENTRY]);
	return(localNetworks[i][CONST_NETMASK_V6_ENTRY]);
      }
    }
  }

  return(0); /* Unknown */
}

/* ******************************************************************* */

u_int16_t ip2AS(IpAddress ip) {
#ifdef HAVE_GEOIP
  if((readOnlyGlobals.geo_ip_asn_db == NULL)
#ifdef WIN32
     || (ip.ipVersion == 6)
#endif
     )
    return(0);
  else {
    char *rsp = NULL;
    short as;

    if(ip.ipVersion == 4)
      rsp = GeoIP_name_by_ipnum(readOnlyGlobals.geo_ip_asn_db, ip.ipType.ipv4);
    else {
#ifdef INET6
#ifndef WIN32
      rsp = GeoIP_name_by_ipnum_v6(readOnlyGlobals.geo_ip_asn_db, ip.ipType.ipv6);
#endif
#endif
    }

    as = rsp ? atoi(&rsp[2]) : 0;
    free(rsp);
    /* traceEvent(TRACE_WARNING, "--> %s (%d)", rsp, as); */
    return(as);
  }
#else
  return(0);
#endif
}

/* ************************************ */

void readASs(char *path) {
#ifdef HAVE_GEOIP
  if(path == NULL)
    return;
  else {
    if((readOnlyGlobals.geo_ip_asn_db = GeoIP_open(path, GEOIP_CHECK_CACHE)) != NULL) {
      traceEvent(TRACE_NORMAL, "GeoIP: loaded AS config file %s", path);
    } else
      traceEvent(TRACE_WARNING, "Unable to load AS file %s. AS support disabled", path);
  }
#endif
}

/* ************************************ */

void readCities(char *path) {
#ifdef HAVE_GEOIP
  if(path == NULL)
    return;
  else {
    if((readOnlyGlobals.geo_ip_city_db = GeoIP_open(path, GEOIP_CHECK_CACHE)) != NULL) {
      traceEvent(TRACE_NORMAL, "GeoIP: loaded cities config file %s", path);
    } else
      traceEvent(TRACE_WARNING, "Unable to load cities file %s. IP geolocation disabled", path);
  }
#endif
}

/* ********* NetFlow v9/IPFIX ***************************** */

/*
  Cisco Systems NetFlow Services Export Version 9

  http://www.faqs.org/rfcs/rfc3954.html
*/

V9V10TemplateElementId ver9_templates[] = {
  { FLOW_TEMPLATE, STANDARD_ENTERPRISE_ID,   1,  4, numeric_format, dump_as_formatted_uint,  "IN_BYTES", "Incoming flow bytes" },
  { OPTION_TEMPLATE, STANDARD_ENTERPRISE_ID, 1,  4, numeric_format, dump_as_uint,  "SYSTEM_ID", "" }, /* Hack for options template */
  { FLOW_TEMPLATE, STANDARD_ENTERPRISE_ID,   2,  4, numeric_format, dump_as_formatted_uint,  "IN_PKTS", "Incoming flow packets" },
  { OPTION_TEMPLATE, STANDARD_ENTERPRISE_ID, 2,  4, numeric_format, dump_as_uint,  "INTERFACE_ID", "" }, /* Hack for options template */
  { FLOW_TEMPLATE, STANDARD_ENTERPRISE_ID,   3,  4, numeric_format, dump_as_formatted_uint,  "FLOWS", "Number of flows" },
  { OPTION_TEMPLATE, STANDARD_ENTERPRISE_ID, 3,  2, numeric_format, dump_as_uint,  "LINE_CARD", "" }, /* Hack for options template */
  { FLOW_TEMPLATE, STANDARD_ENTERPRISE_ID,   4,  1, numeric_format, dump_as_uint,  "PROTOCOL", "IP protocol byte" },
  { FLOW_TEMPLATE, STANDARD_ENTERPRISE_ID,   0xA0+4, CUSTOM_FIELD_LEN, numeric_format, dump_as_ip_proto,  "PROTOCOL_MAP", "IP protocol name" },
  { OPTION_TEMPLATE, STANDARD_ENTERPRISE_ID, 4,  2, numeric_format, dump_as_uint,  "NETFLOW_CACHE", "" }, /* Hack for options template */
  { FLOW_TEMPLATE, STANDARD_ENTERPRISE_ID,   5,  1, numeric_format, dump_as_uint,  "SRC_TOS", "Type of service byte" },
  { OPTION_TEMPLATE, STANDARD_ENTERPRISE_ID, 5,  2, numeric_format, dump_as_uint,  "TEMPLATE_ID", "" }, /* Hack for options template */
  { FLOW_TEMPLATE, STANDARD_ENTERPRISE_ID,   6,  1, numeric_format, dump_as_uint,  "TCP_FLAGS", "Cumulative of all flow TCP flags" },
  { FLOW_TEMPLATE, STANDARD_ENTERPRISE_ID,   7,  2, numeric_format, dump_as_uint,  "L4_SRC_PORT", "IPv4 source port" },
  { FLOW_TEMPLATE, STANDARD_ENTERPRISE_ID,   0xA0+7, CUSTOM_FIELD_LEN, numeric_format, dump_as_ip_port,  "L4_SRC_PORT_MAP", "IPv4 source port symbolic name" },
  { FLOW_TEMPLATE, STANDARD_ENTERPRISE_ID,   8,  4, numeric_format, dump_as_ipv4_address,  "IPV4_SRC_ADDR", "IPv4 source address" },
  { FLOW_TEMPLATE, STANDARD_ENTERPRISE_ID,   9,  1, numeric_format, dump_as_ipv6_address,  "SRC_MASK", "Source subnet mask (/<bits>)" },
  { FLOW_TEMPLATE, STANDARD_ENTERPRISE_ID,   10,  2, numeric_format, dump_as_uint,  "INPUT_SNMP", "Input interface SNMP idx" },
  { FLOW_TEMPLATE, STANDARD_ENTERPRISE_ID,   11,  2, numeric_format, dump_as_uint,  "L4_DST_PORT", "IPv4 destination port" },
  { FLOW_TEMPLATE, STANDARD_ENTERPRISE_ID,   0xA0+11, CUSTOM_FIELD_LEN, numeric_format, dump_as_ip_port,  "L4_DST_PORT_MAP", "IPv4 destination port symbolic name" },
  { FLOW_TEMPLATE, STANDARD_ENTERPRISE_ID,   12,  4, numeric_format, dump_as_ipv4_address,  "IPV4_DST_ADDR", "IPv4 destination address" },
  { FLOW_TEMPLATE, STANDARD_ENTERPRISE_ID,   13,  1, numeric_format, dump_as_uint,  "DST_MASK", "Dest subnet mask (/<bits>)" },
  { FLOW_TEMPLATE, STANDARD_ENTERPRISE_ID,   14,  2, numeric_format, dump_as_uint,  "OUTPUT_SNMP", "Output interface SNMP idx" },
  { FLOW_TEMPLATE, STANDARD_ENTERPRISE_ID,   15,  4, numeric_format, dump_as_ipv4_address,  "IPV4_NEXT_HOP", "IPv4 next hop address" },
  { FLOW_TEMPLATE, STANDARD_ENTERPRISE_ID,   16,  2, numeric_format, dump_as_uint,  "SRC_AS", "Source BGP AS" },
  { FLOW_TEMPLATE, STANDARD_ENTERPRISE_ID,   17,  2, numeric_format, dump_as_uint,  "DST_AS", "Destination BGP AS" },
  /*
    { FLOW_TEMPLATE, STANDARD_ENTERPRISE_ID,   18,  4, numeric_format, dump_as_uint,  "BGP_IPV4_NEXT_HOP", "" },
    { FLOW_TEMPLATE, STANDARD_ENTERPRISE_ID,   19,  4, numeric_format, dump_as_uint,  "MUL_DST_PKTS", "" },
    { FLOW_TEMPLATE, STANDARD_ENTERPRISE_ID,   20,  4, numeric_format, dump_as_uint,  "MUL_DST_BYTES", "" },
  */
  { FLOW_TEMPLATE, STANDARD_ENTERPRISE_ID,   21,  4, numeric_format, dump_as_uint,  "LAST_SWITCHED", "SysUptime (msec) of the last flow pkt" },
  { FLOW_TEMPLATE, STANDARD_ENTERPRISE_ID,   22,  4, numeric_format, dump_as_uint,  "FIRST_SWITCHED", "SysUptime (msec) of the first flow pkt" },
  { FLOW_TEMPLATE, STANDARD_ENTERPRISE_ID,   23,  4, numeric_format, dump_as_formatted_uint,  "OUT_BYTES", "Outgoing flow bytes" },
  { FLOW_TEMPLATE, STANDARD_ENTERPRISE_ID,   24,  4, numeric_format, dump_as_formatted_uint,  "OUT_PKTS", "Outgoing flow packets" },
  /* { FLOW_TEMPLATE, STANDARD_ENTERPRISE_ID,   25,  0, numeric_format, dump_as_uint,  "RESERVED", "" }, */
  /* { FLOW_TEMPLATE, STANDARD_ENTERPRISE_ID,   26,  0, numeric_format, dump_as_uint,  "RESERVED", "" }, */
  { FLOW_TEMPLATE, STANDARD_ENTERPRISE_ID,   27,  16, ipv6_address_format, dump_as_ipv6_address,  "IPV6_SRC_ADDR", "IPv6 source address" },
  { FLOW_TEMPLATE, STANDARD_ENTERPRISE_ID,   28,  16, ipv6_address_format, dump_as_ipv6_address,  "IPV6_DST_ADDR", "IPv6 destination address" },
  { FLOW_TEMPLATE, STANDARD_ENTERPRISE_ID,   29,  1, numeric_format, dump_as_uint,  "IPV6_SRC_MASK", "IPv6 source mask" },
  { FLOW_TEMPLATE, STANDARD_ENTERPRISE_ID,   30,  1, numeric_format, dump_as_uint,  "IPV6_DST_MASK", "IPv6 destination mask" },
  /* { FLOW_TEMPLATE, STANDARD_ENTERPRISE_ID,   31,  3, numeric_format, dump_as_uint,  "IPV6_FLOW_LABEL", "" }, */
  { FLOW_TEMPLATE, STANDARD_ENTERPRISE_ID,   32,  2, numeric_format, dump_as_uint,  "ICMP_TYPE", "ICMP Type * 256 + ICMP code" },
  /* { FLOW_TEMPLATE, STANDARD_ENTERPRISE_ID,   33,  1, numeric_format, dump_as_uint,  "MUL_IGMP_TYPE", "" }, */
  { FLOW_TEMPLATE, STANDARD_ENTERPRISE_ID,   34,  4, numeric_format, dump_as_uint,  "SAMPLING_INTERVAL", "Sampling rate" },
  { FLOW_TEMPLATE, STANDARD_ENTERPRISE_ID,   35,  1, numeric_format, dump_as_uint,  "SAMPLING_ALGORITHM", "Sampling type (deterministic/random)" },
  { FLOW_TEMPLATE, STANDARD_ENTERPRISE_ID,   36,  2, numeric_format, dump_as_uint,  "FLOW_ACTIVE_TIMEOUT", "Activity timeout of flow cache entries" },
  { FLOW_TEMPLATE, STANDARD_ENTERPRISE_ID,   37,  2, numeric_format, dump_as_uint,  "FLOW_INACTIVE_TIMEOUT", "Inactivity timeout of flow cache entries" },
  { FLOW_TEMPLATE, STANDARD_ENTERPRISE_ID,   38,  1, numeric_format, dump_as_uint,  "ENGINE_TYPE", "Flow switching engine" },
  { FLOW_TEMPLATE, STANDARD_ENTERPRISE_ID,   39,  1, numeric_format, dump_as_uint,  "ENGINE_ID", "Id of the flow switching engine" },
  { FLOW_TEMPLATE, STANDARD_ENTERPRISE_ID,   40,  4, numeric_format, dump_as_formatted_uint,  "TOTAL_BYTES_EXP", "Total bytes exported" },
  { FLOW_TEMPLATE, STANDARD_ENTERPRISE_ID,   41,  4, numeric_format, dump_as_formatted_uint,  "TOTAL_PKTS_EXP", "Total flow packets exported" },
  { FLOW_TEMPLATE, STANDARD_ENTERPRISE_ID,   42,  4, numeric_format, dump_as_formatted_uint,  "TOTAL_FLOWS_EXP", "Total number of exported flows" },
  /* { FLOW_TEMPLATE, STANDARD_ENTERPRISE_ID,   43,  0, numeric_format, dump_as_uint,  "RESERVED", "" }, */
  /* { FLOW_TEMPLATE, STANDARD_ENTERPRISE_ID,   44,  0, numeric_format, dump_as_uint,  "RESERVED", "" }, */
  /* { FLOW_TEMPLATE, STANDARD_ENTERPRISE_ID,   45,  0, numeric_format, dump_as_uint,  "RESERVED", "" }, */
  /* { FLOW_TEMPLATE, STANDARD_ENTERPRISE_ID,   46,  0, numeric_format, dump_as_uint,  "RESERVED", "" }, i*/
  /* { FLOW_TEMPLATE, STANDARD_ENTERPRISE_ID,   47,  0, numeric_format, dump_as_uint,  "RESERVED", "" }, */
  /* { FLOW_TEMPLATE, STANDARD_ENTERPRISE_ID,   48,  0, numeric_format, dump_as_uint,  "RESERVED", "" }, */
  /* { FLOW_TEMPLATE, STANDARD_ENTERPRISE_ID,   49,  0, numeric_format, dump_as_uint,  "RESERVED", "" }, */
  /* { FLOW_TEMPLATE, STANDARD_ENTERPRISE_ID,   50,  0, numeric_format, dump_as_uint,  "RESERVED", "" }, */
  /* { FLOW_TEMPLATE, STANDARD_ENTERPRISE_ID,   51,  0, numeric_format, dump_as_uint,  "RESERVED", "" }, */
  /* { FLOW_TEMPLATE, STANDARD_ENTERPRISE_ID,   52,  0, numeric_format, dump_as_uint,  "RESERVED", "" }, */
  /* { FLOW_TEMPLATE, STANDARD_ENTERPRISE_ID,   53,  0, numeric_format, dump_as_uint,  "RESERVED", "" }, */
  /* { FLOW_TEMPLATE, STANDARD_ENTERPRISE_ID,   54,  0, numeric_format, dump_as_uint,  "RESERVED", "" }, */
  /* { FLOW_TEMPLATE, STANDARD_ENTERPRISE_ID,   55,  0, numeric_format, dump_as_uint,  "RESERVED", "" }, */
  { FLOW_TEMPLATE, STANDARD_ENTERPRISE_ID,   56,  6, hex_format, dump_as_mac_address,  "IN_SRC_MAC", "Source MAC Address" }, /* new */
  { FLOW_TEMPLATE, STANDARD_ENTERPRISE_ID,   57,  6, hex_format, dump_as_mac_address,  "OUT_DST_MAC", "Destination MAC Address" }, /* new */
  { FLOW_TEMPLATE, STANDARD_ENTERPRISE_ID,   58,  2, numeric_format, dump_as_uint,  "SRC_VLAN", "Source VLAN" },
  { FLOW_TEMPLATE, STANDARD_ENTERPRISE_ID,   59,  2, numeric_format, dump_as_uint,  "DST_VLAN", "Destination VLAN" },
  { FLOW_TEMPLATE, STANDARD_ENTERPRISE_ID,   60,  1, numeric_format, dump_as_uint,  "IP_PROTOCOL_VERSION", "[4=IPv4][6=IPv6]" },
  { FLOW_TEMPLATE, STANDARD_ENTERPRISE_ID,   61,  1, numeric_format, dump_as_uint,  "DIRECTION", "[0=ingress][1=egress] flow" },
  /*
    { FLOW_TEMPLATE, STANDARD_ENTERPRISE_ID,   62,  1, numeric_format, dump_as_uint,  "IPV6_NEXT_HOP", "IPv4 next hop address" },
    { FLOW_TEMPLATE, STANDARD_ENTERPRISE_ID,   63,  16, ipv6_address_format, dump_as_uint,  "BPG_IPV6_NEXT_HOP", "" },
    { FLOW_TEMPLATE, STANDARD_ENTERPRISE_ID,   64,  16, ipv6_address_format, dump_as_uint,  "IPV6_OPTION_HEADERS", "" },
  */
  /* { FLOW_TEMPLATE, STANDARD_ENTERPRISE_ID,   65,  0, numeric_format, dump_as_uint,  "RESERVED", "" }, */
  /* { FLOW_TEMPLATE, STANDARD_ENTERPRISE_ID,   66,  0, numeric_format, dump_as_uint,  "RESERVED", "" }, */
  /* { FLOW_TEMPLATE, STANDARD_ENTERPRISE_ID,   67,  0, numeric_format, dump_as_uint,  "RESERVED", "" }, */
  /* { FLOW_TEMPLATE, STANDARD_ENTERPRISE_ID,   68,  0, numeric_format, dump_as_uint,  "RESERVED", "" }, */
  /* { FLOW_TEMPLATE, STANDARD_ENTERPRISE_ID,   69,  0, numeric_format, dump_as_uint,  "RESERVED", "" }, */
  { FLOW_TEMPLATE, STANDARD_ENTERPRISE_ID,   70,  3, numeric_format, dump_as_uint,  "MPLS_LABEL_1",  "MPLS label at position 1" },
  { FLOW_TEMPLATE, STANDARD_ENTERPRISE_ID,   71,  3, numeric_format, dump_as_uint,  "MPLS_LABEL_2",  "MPLS label at position 2" },
  { FLOW_TEMPLATE, STANDARD_ENTERPRISE_ID,   72,  3, numeric_format, dump_as_uint,  "MPLS_LABEL_3",  "MPLS label at position 3" },
  { FLOW_TEMPLATE, STANDARD_ENTERPRISE_ID,   73,  3, numeric_format, dump_as_uint,  "MPLS_LABEL_4",  "MPLS label at position 4" },
  { FLOW_TEMPLATE, STANDARD_ENTERPRISE_ID,   74,  3, numeric_format, dump_as_uint,  "MPLS_LABEL_5",  "MPLS label at position 5" },
  { FLOW_TEMPLATE, STANDARD_ENTERPRISE_ID,   75,  3, numeric_format, dump_as_uint,  "MPLS_LABEL_6",  "MPLS label at position 6" },
  { FLOW_TEMPLATE, STANDARD_ENTERPRISE_ID,   76,  3, numeric_format, dump_as_uint,  "MPLS_LABEL_7",  "MPLS label at position 7" },
  { FLOW_TEMPLATE, STANDARD_ENTERPRISE_ID,   77,  3, numeric_format, dump_as_uint,  "MPLS_LABEL_8",  "MPLS label at position 8" },
  { FLOW_TEMPLATE, STANDARD_ENTERPRISE_ID,   78,  3, numeric_format, dump_as_uint,  "MPLS_LABEL_9",  "MPLS label at position 9" },
  { FLOW_TEMPLATE, STANDARD_ENTERPRISE_ID,   79,  3, numeric_format, dump_as_uint,  "MPLS_LABEL_10", "MPLS label at position 10" },

  /*
    ntop Extensions

    IMPORTANT
    if you change/add constants here/below make sure
    you change them into ntop too.
  */

  { FLOW_TEMPLATE, STANDARD_ENTERPRISE_ID,   NTOP_BASE_ID+80,  1, numeric_format, dump_as_bool,  "FRAGMENTED", "1=some flow packets are fragmented" },
  { FLOW_TEMPLATE, STANDARD_ENTERPRISE_ID,   NTOP_BASE_ID+81,  FINGERPRINT_LEN, ascii_format, dump_as_hex,  "FINGERPRINT", "TCP fingerprint" },
  { FLOW_TEMPLATE, STANDARD_ENTERPRISE_ID,   NTOP_BASE_ID+82,  4, numeric_format, dump_as_uint,  "CLIENT_NW_DELAY_SEC",  "Network latency client <-> nprobe (sec)" },
  { FLOW_TEMPLATE, STANDARD_ENTERPRISE_ID,   NTOP_BASE_ID+83,  4, numeric_format, dump_as_uint,  "CLIENT_NW_DELAY_USEC", "Network latency client <-> nprobe (usec)" },
  { FLOW_TEMPLATE, STANDARD_ENTERPRISE_ID,   NTOP_BASE_ID+84,  4, numeric_format, dump_as_uint,  "SERVER_NW_DELAY_SEC",  "Network latency nprobe <-> server (sec)" },
  { FLOW_TEMPLATE, STANDARD_ENTERPRISE_ID,   NTOP_BASE_ID+85,  4, numeric_format, dump_as_uint,  "SERVER_NW_DELAY_USEC", "Network latency nprobe <-> server (usec)" },
  { FLOW_TEMPLATE, STANDARD_ENTERPRISE_ID,   NTOP_BASE_ID+86,  4, numeric_format, dump_as_uint,  "APPL_LATENCY_SEC", "Application latency (sec)" },
  { FLOW_TEMPLATE, STANDARD_ENTERPRISE_ID,   NTOP_BASE_ID+87,  4, numeric_format, dump_as_uint,  "APPL_LATENCY_USEC", "Application latency (usec)" },

  { FLOW_TEMPLATE, STANDARD_ENTERPRISE_ID,   NTOP_BASE_ID+IN_PAYLOAD_ID,  0 /* The length is set at runtime */, ascii_format, dump_as_hex,  "IN_PAYLOAD", "Initial payload bytes" },
  { FLOW_TEMPLATE, STANDARD_ENTERPRISE_ID,   NTOP_BASE_ID+OUT_PAYLOAD_ID,  0 /* The length is set at runtime */, ascii_format, dump_as_ascii,  "OUT_PAYLOAD", "Initial payload bytes" },
  { FLOW_TEMPLATE, STANDARD_ENTERPRISE_ID,   NTOP_BASE_ID+98,  4, numeric_format, dump_as_uint,  "ICMP_FLAGS", "Cumulative of all flow ICMP types" },
  /* 99+100 are available */
  { FLOW_TEMPLATE, STANDARD_ENTERPRISE_ID,   NTOP_BASE_ID+101, 2,  ascii_format, dump_as_ascii,  "SRC_IP_COUNTRY", "Country where the src IP is located" },
  { FLOW_TEMPLATE, STANDARD_ENTERPRISE_ID,   NTOP_BASE_ID+102, 16, ascii_format, dump_as_ascii,  "SRC_IP_CITY", "City where the src IP is located" },
  { FLOW_TEMPLATE, STANDARD_ENTERPRISE_ID,   NTOP_BASE_ID+103, 2,  ascii_format, dump_as_ascii,  "DST_IP_COUNTRY", "Country where the dst IP is located" },
  { FLOW_TEMPLATE, STANDARD_ENTERPRISE_ID,   NTOP_BASE_ID+104, 16, ascii_format, dump_as_ascii,  "DST_IP_CITY", "City where the dst IP is located" },
  { FLOW_TEMPLATE, STANDARD_ENTERPRISE_ID,   NTOP_BASE_ID+105,  2, numeric_format, dump_as_uint, "FLOW_PROTO_PORT", "L7 port that identifies the flow protocol or 0 if unknown" },
  { FLOW_TEMPLATE, STANDARD_ENTERPRISE_ID,   NTOP_BASE_ID+106,  4, numeric_format, dump_as_uint, "TUNNEL_ID", "Tunnel identifier (e.g. GTP tunnel Id) or 0 if unknown" },

  /*
    { FLOW_TEMPLATE, STANDARD_ENTERPRISE_ID,   NTOP_BASE_ID+0,  1, numeric_format, dump_as_uint,  "PAD1", "" },
    { FLOW_TEMPLATE, STANDARD_ENTERPRISE_ID,   NTOP_BASE_ID+0,  2, numeric_format, dump_as_uint,  "PAD2", "" },
  */
  { FLOW_TEMPLATE, STANDARD_ENTERPRISE_ID,   0,  0, 0, 0, NULL, NULL }
};


/* ******************************************** */

void printTemplateInfo(V9V10TemplateElementId *templates,
		       u_char show_private_elements) {
  int j = 0;

  while(templates[j].templateElementName != NULL) {
    if(((!show_private_elements)
	&& ((templates[j].templateElementLen > 0)
	    || (templates[j].templateElementId == IN_PAYLOAD_ID)
	    || (templates[j].templateElementId == OUT_PAYLOAD_ID)))
       || (show_private_elements && (templates[j].templateElementId >= 0xFF))) {
      printf("[%3d] %%%-22s\t%s\n",
	     templates[j].templateElementId,
	     templates[j].templateElementName,
	     templates[j].templateElementDescr);
    }

    j++;
  }
}

/* ******************************************** */

void setPayloadLength(int len) {
  int i = 0;

  while(ver9_templates[i].templateElementName != NULL) {
    if((ver9_templates[i].templateElementId == IN_PAYLOAD_ID)
       || (ver9_templates[i].templateElementId == OUT_PAYLOAD_ID)) {
      ver9_templates[i].templateElementLen = len;

      if(0)
	traceEvent(TRACE_ERROR, "--> Setting payload length for element %s",
		   ver9_templates[i].templateElementName);
    }

    i++;
  }
}

/* ******************************************** */

void copyInt8(u_int8_t t8, char *outBuffer,
	      u_int *outBufferBegin, u_int *outBufferMax) {
  if((*outBufferBegin)+sizeof(t8) < (*outBufferMax)) {
    memcpy(&outBuffer[(*outBufferBegin)], &t8, sizeof(t8));
    (*outBufferBegin) += sizeof(t8);
  }
}

/* ******************************************** */

void copyInt16(u_int16_t _t16, char *outBuffer,
	       u_int *outBufferBegin, u_int *outBufferMax) {
  u_int16_t t16 = htons(_t16);

  if((*outBufferBegin)+sizeof(t16) < (*outBufferMax)) {
    memcpy(&outBuffer[(*outBufferBegin)], &t16, sizeof(t16));
    (*outBufferBegin) += sizeof(t16);
  }
}

/* ******************************************** */

void copyInt32(u_int32_t _t32, char *outBuffer,
	       u_int *outBufferBegin, u_int *outBufferMax) {
  u_int32_t t32 = htonl(_t32);

  if((*outBufferBegin)+sizeof(t32) < (*outBufferMax)) {
#ifdef DEBUG
    char buf1[32];

    printf("(8) %s\n", _intoaV4(_t32, buf1, sizeof(buf1)));
#endif

    memcpy(&outBuffer[(*outBufferBegin)], &t32, sizeof(t32));
    (*outBufferBegin) += sizeof(t32);
  }
}

/* *************u_int64_t********************** */
u_int64_t hton64(u_int64_t host){
  u_int64_t ret = 0; 
  u_int32_t high, low;

  low = host & 0xFFFFFFFF;
  high =  (host >> 32) & 0xFFFFFFFF;

  low = htonl(low); 
  high = htonl(high); 

  ret = low;
  ret <<= 32; 
  ret |= high; 

  return ret;
}

void copyInt64(u_int64_t _t64, char *outBuffer, u_int *outBufferBegin, u_int *outBufferMax) {
  u_int64_t t64 = hton64(_t64);

  if((*outBufferBegin)+sizeof(t64) < (*outBufferMax)) {
    memcpy(&outBuffer[(*outBufferBegin)], &t64, sizeof(t64));
    (*outBufferBegin) += sizeof(t64);
  }
}

/* ******************************************** */

void copyLen(u_char *str, int strLen, char *outBuffer,
	     u_int *outBufferBegin, u_int *outBufferMax) {
  if((*outBufferBegin)+strLen < (*outBufferMax)) {
    memcpy(&outBuffer[(*outBufferBegin)], str, strLen);
    (*outBufferBegin) += strLen;
  }
}

/* ******************************************** */

static void copyIpV6(struct in6_addr ipv6, char *outBuffer,
		     u_int *outBufferBegin, u_int *outBufferMax) {
  copyLen((u_char*)&ipv6, sizeof(ipv6), outBuffer,
	  outBufferBegin, outBufferMax);
}

/* ******************************************** */

static void copyMac(u_char *macAddress, char *outBuffer,
		    u_int *outBufferBegin, u_int *outBufferMax) {
  copyLen(macAddress, 6 /* lenght of mac address */,
	  outBuffer, outBufferBegin, outBufferMax);
}

/* ******************************************** */

static void copyMplsLabel(struct mpls_labels *mplsInfo, int labelId,
			  char *outBuffer, u_int *outBufferBegin,
			  u_int *outBufferMax) {
  if(mplsInfo == NULL) {
    int i;

    for(i=0; (i < 3) && (*outBufferBegin < *outBufferMax); i++) {
      outBuffer[*outBufferBegin] = 0;
      (*outBufferBegin)++;
    }
  } else {
    if(((*outBufferBegin)+MPLS_LABEL_LEN) < (*outBufferMax)) {
      memcpy(outBuffer, mplsInfo->mplsLabels[labelId-1], MPLS_LABEL_LEN);
      (*outBufferBegin) += MPLS_LABEL_LEN;
    }
  }
}

/* ****************************************************** */

static void exportPayload(FlowHashBucket *myBucket, int direction,
			  V9V10TemplateElementId *theTemplate,
			  char *outBuffer, u_int *outBufferBegin,
			  u_int *outBufferMax) {
  if(readOnlyGlobals.maxPayloadLen > 0) {
    u_char thePayload[MAX_PAYLOAD_LEN];
    int len;

    if(direction == 0)
      len = myBucket->src2dstPayloadLen;
    else
      len = myBucket->dst2srcPayloadLen;

    /*
      u_int16_t t16;

      t16 = theTemplate->templateId;
      copyInt16(t16, outBuffer, outBufferBegin, outBufferMax);
      t16 = maxPayloadLen;
      copyInt16(t16, outBuffer, outBufferBegin, outBufferMax);
    */

    memset(thePayload, 0, readOnlyGlobals.maxPayloadLen);
    if(len > readOnlyGlobals.maxPayloadLen) len = readOnlyGlobals.maxPayloadLen;
    memcpy(thePayload, direction == 0 ? myBucket->src2dstPayload : myBucket->dst2srcPayload, len);

    copyLen(thePayload, readOnlyGlobals.maxPayloadLen, outBuffer, outBufferBegin, outBufferMax);
  }
}

/* ******************************************** */

u_int16_t ifIdx(FlowHashBucket *myBucket, int direction, int inputIf) {
  u_char *mac;
  u_int16_t idx;

  if(readOnlyGlobals.use_vlanId_as_ifId) {
    return(myBucket->vlanId);
  } else if(readOnlyGlobals.setLocalTrafficDirection) {
    struct in_addr addr;

    if(direction == 0 /* src -> dst */) {
      /* Source */
      if(inputIf) {
	addr.s_addr = htonl(myBucket->src->host.ipType.ipv4);
	if(isLocalAddress(&addr)) return(readOnlyGlobals.inputInterfaceIndex); else return(readOnlyGlobals.outputInterfaceIndex);
      } else {
	addr.s_addr = htonl(myBucket->dst->host.ipType.ipv4);
	if(isLocalAddress(&addr)) return(readOnlyGlobals.inputInterfaceIndex); else return(readOnlyGlobals.outputInterfaceIndex);
      }
    } else {
      /* Destination */
      if(inputIf) {
	addr.s_addr = htonl(myBucket->dst->host.ipType.ipv4);
	if(isLocalAddress(&addr)) return(readOnlyGlobals.inputInterfaceIndex); else return(readOnlyGlobals.outputInterfaceIndex);
      } else {
	addr.s_addr = htonl(myBucket->src->host.ipType.ipv4);
	if(isLocalAddress(&addr)) 
	  return(readOnlyGlobals.inputInterfaceIndex); 
	else 
	  return(readOnlyGlobals.outputInterfaceIndex);
      }
    }
  }

  if(readWriteGlobals->num_src_mac_export > 0) {
    int i = 0;

    for(i = 0; i<readWriteGlobals->num_src_mac_export; i++)
      if((((inputIf == 1) && (direction == 0)) || ((inputIf == 0) && (direction == 1)))
	 && (memcmp(myBucket->srcMacAddress,
		    readOnlyGlobals.mac_if_match[i].mac_address, 6) == 0))
        return(readOnlyGlobals.mac_if_match[i].interface_id);
      else if((((inputIf == 0) && (direction == 0)) || ((inputIf == 1) && (direction == 1)))
	      && (memcmp(myBucket->dstMacAddress,
			 readOnlyGlobals.mac_if_match[i].mac_address, 6) == 0))
        return(readOnlyGlobals.mac_if_match[i].interface_id);
  }

#if 1
  if(inputIf) {
    if(readOnlyGlobals.inputInterfaceIndex != NO_INTERFACE_INDEX)
      return(readOnlyGlobals.inputInterfaceIndex);
  } else {
    if(readOnlyGlobals.outputInterfaceIndex != NO_INTERFACE_INDEX)
      return(readOnlyGlobals.outputInterfaceIndex);
  }
#else
  /* non-mirror mode */
  if(direction == 0 /* src -> dst */) {
    /* Source */
    if(inputIf) {
      if(readOnlyGlobals.inputInterfaceIndex != NO_INTERFACE_INDEX)
	return(readOnlyGlobals.inputInterfaceIndex);
    } else {
      if(readOnlyGlobals.outputInterfaceIndex != NO_INTERFACE_INDEX)
	return(readOnlyGlobals.outputInterfaceIndex);
    }
    /* else dynamic */
  } else {
    /* Destination */
    if(inputIf) {
      if(readOnlyGlobals.outputInterfaceIndex != (u_int16_t)-1)
	return(readOnlyGlobals.outputInterfaceIndex);
    } else {
      if(readOnlyGlobals.inputInterfaceIndex != (u_int16_t)-1)
	return(readOnlyGlobals.inputInterfaceIndex);
    }
  }
#endif

  /* ...else dynamic */

  /* Calculate the input/output interface using
     the last two MAC address bytes */
  if(direction == 0 /* src -> dst */) {
    if(inputIf)
      mac = &(myBucket->srcMacAddress[4]);
    else
      mac = &(myBucket->dstMacAddress[4]);
  } else {
    if(inputIf)
      mac = &(myBucket->dstMacAddress[4]);
    else
      mac = &(myBucket->srcMacAddress[4]);
  }

  idx = (mac[0] * 256) + mac[1];

  return(idx);
}

/* ******************************************** */

static char* port2name(u_int16_t port, u_int8_t proto) {
#if 0
  struct servent *svt;

  if((svt = getservbyport(htons(port), proto2name(proto))) != NULL)
    return(svt->s_name);
  else {
    static char the_port[8];

    snprintf(the_port, sizeof(the_port), "%d", port);
    return(the_port);
  }
#else
  if(port_mapping[port] != NULL)
    return(port_mapping[port]);
  else if(proto == 6)  return("tcp_other");
  else if(proto == 17) return("udp_other");
  else return("<unknown>"); /* Not reached */
#endif
}

/* **************************************************************** */

void reset_bitmask(bitmask_selector *selector) {
  memset((char*)selector->bits_memory, 0, selector->num_bits/8);
}

/* **************************************************************** */

int alloc_bitmask(u_int32_t tot_bits, bitmask_selector *selector) {
  u_int tot_mem = 1 + (tot_bits >> 3); /* /= 8 */

  if((selector->bits_memory = malloc(tot_mem)) != NULL) {
  } else {
    selector->num_bits = 0;
    return(-1);
  }

  selector->num_bits = tot_bits;
  reset_bitmask(selector);
  return(0);
}

/* ********************************** */

void free_bitmask(bitmask_selector *selector) {
  if(selector->bits_memory > 0) {
    free(selector->bits_memory);
    selector->bits_memory = 0;
  }
}

/* ******************************************** */

void bitmask_set(u_int32_t n, bitmask_selector* p)       { (((char*)p->bits_memory)[n >> 3] |=  (1 << (n & 7))); }
void bitmask_clr(u_int32_t n, bitmask_selector* p)       { (((char*)p->bits_memory)[n >> 3] &= ~(1 << (n & 7))); }
u_int8_t bitmask_isset(u_int32_t n, bitmask_selector* p) { return(((char*)p->bits_memory)[n >> 3] &   (1 << (n & 7))); }

/* ******************************************** */

void loadApplProtocols(void) {
  struct servent *s;

  alloc_bitmask(65536, &readOnlyGlobals.udpProto);
  alloc_bitmask(65536, &readOnlyGlobals.tcpProto);

#ifndef WIN32
  setservent(1);
#endif

  while((s = getservent()) != NULL) {
    s->s_port = ntohs(s->s_port);

    // traceEvent(TRACE_ERROR, "==> loadApplProtocols(%u/%s)", s->s_port, s->s_proto);

    if(s->s_proto[0] == 'u')
      bitmask_set(s->s_port, &readOnlyGlobals.udpProto);
    else
      bitmask_set(s->s_port, &readOnlyGlobals.tcpProto);
  }

  endservent();
}

/* ******************************************** */

u_int16_t port2ApplProtocol(u_int8_t proto, u_int16_t port) {
  u_int16_t value;
  
  if(proto == IPPROTO_TCP) 
    value = bitmask_isset(port, &readOnlyGlobals.tcpProto);
  else if(proto == IPPROTO_UDP) 
    value = bitmask_isset(port, &readOnlyGlobals.udpProto);
  else
    value = 0;

  return(value ? port : 0);
}

/* ******************************************** */

u_int16_t getFlowApplProtocol(FlowHashBucket *theFlow) {
  u_int16_t value;
  u_int16_t proto_sport = port2ApplProtocol(theFlow->proto, theFlow->sport);
  u_int16_t proto_dport = port2ApplProtocol(theFlow->proto, theFlow->dport);
  
  if((theFlow->proto == IPPROTO_TCP) || (theFlow->proto == IPPROTO_UDP)) {
    if(proto_sport == 0) value = proto_dport;
    else if(proto_dport == 0) value = proto_sport;
    else {
      if(theFlow->sport < theFlow->dport) value = proto_sport;
      else value = proto_dport;
    }
  } else
    value = 0;
  
  // traceEvent(TRACE_ERROR, "[%u/%u] -> %u", theFlow->sport, theFlow->dport, value);
  
  return(value);
}

/* ******************************************** */

static void handleTemplate(V9V10TemplateElementId *theTemplateElement,
			   char *outBuffer, u_int *outBufferBegin,
			   u_int *outBufferMax,
			   char buildTemplate, int *numElements,
			   FlowHashBucket *theFlow, int direction,
			   int addTypeLen, int optionTemplate) {
#ifdef HAVE_GEOIP  
  GeoIPRecord *geo;
#endif
  u_char null_data[128] = { 0 };
  u_int16_t t16;
  
  if(buildTemplate || addTypeLen) {
    t16 = theTemplateElement->templateElementId;

    if((readOnlyGlobals.netFlowVersion == 10)
       && (theTemplateElement->templateElementEnterpriseId != STANDARD_ENTERPRISE_ID))
      t16 = t16 | 0xA000;

    copyInt16(t16, outBuffer, outBufferBegin, outBufferMax);
    t16 = theTemplateElement->templateElementLen;
    copyInt16(t16, outBuffer, outBufferBegin, outBufferMax);

    if((readOnlyGlobals.netFlowVersion == 10)
       && (theTemplateElement->templateElementEnterpriseId != STANDARD_ENTERPRISE_ID))
      copyInt32(theTemplateElement->templateElementEnterpriseId, outBuffer, outBufferBegin, outBufferMax);
  }

  if(!buildTemplate) {
    if(theTemplateElement->templateElementLen == 0)
      ; /* Nothing to do: all fields have zero length */
    else {
      u_char custom_field[CUSTOM_FIELD_LEN];

#ifdef DEBUG
	traceEvent(TRACE_INFO, "[%d][%s][%d]",
		   theTemplateElement->templateElementId,
		   theTemplateElement->templateElementName,
		   theTemplateElement->templateElementLen);
#endif

      if(theTemplateElement->isOptionTemplate) {
	copyLen(null_data, theTemplateElement->templateElementLen,
		outBuffer, outBufferBegin, outBufferMax);
      } else {
	/*
	 * IMPORTANT
	 *
	 * Any change below need to be ported also in printRecordWithTemplate()
	 *
	 */
	switch(theTemplateElement->templateElementId) {
	case 1:
	  //copyInt32(direction == 0 ? theFlow->flowCounters.bytesRcvd : theFlow->flowCounters.bytesSent,
		  //  outBuffer, outBufferBegin, outBufferMax);
	  copyInt32(direction == 0 ? theFlow->flowCounters.bytesSent : theFlow->flowCounters.bytesRcvd,
		    outBuffer, outBufferBegin, outBufferMax);
	  break;
	case 2:
	  //copyInt32(direction == 0 ? theFlow->flowCounters.pktRcvd : theFlow->flowCounters.pktSent,
		  //  outBuffer, outBufferBegin, outBufferMax);
		copyInt32(direction == 0 ? theFlow->flowCounters.pktSent : theFlow->flowCounters.pktRcvd,
        outBuffer, outBufferBegin, outBufferMax);
	  break;
	case 4:
	  copyInt8((u_int8_t)theFlow->proto, outBuffer, outBufferBegin, outBufferMax);
	  break;
	case 5:
	  copyInt8(direction == 0 ? theFlow->src2dstTos : theFlow->dst2srcTos,
		   outBuffer, outBufferBegin, outBufferMax);
	  break;
	case 6:
	  copyInt8(direction == 0 ? theFlow->src2dstTcpFlags : theFlow->dst2srcTcpFlags,
		   outBuffer, outBufferBegin, outBufferMax);
	  break;
	case 7:
	  copyInt16(direction == 0 ? theFlow->sport : theFlow->dport,
		    outBuffer, outBufferBegin, outBufferMax);
	  break;
	case 8:
	  if((theFlow->src->host.ipVersion == 4) && (theFlow->dst->host.ipVersion == 4))
	    copyInt32(direction == 0 ? theFlow->src->host.ipType.ipv4 : theFlow->dst->host.ipType.ipv4,
		      outBuffer, outBufferBegin, outBufferMax);
	  else
	    copyInt32(0, outBuffer, outBufferBegin, outBufferMax);
	  break;
	case 9: /* SRC_MASK */
	  copyInt8(ip2mask((direction == 0) ? theFlow->src->host: theFlow->dst->host),
		   outBuffer, outBufferBegin, outBufferMax);
	  break;
	case 10: /* INPUT_SNMP */
	  copyInt16(theFlow->if_input, outBuffer, outBufferBegin, outBufferMax);
	  break;
	case 11:
	  copyInt16(direction == 0 ? theFlow->dport : theFlow->sport,
		    outBuffer, outBufferBegin, outBufferMax);
	  break;
	case 12:
	  if((theFlow->src->host.ipVersion == 4) && (theFlow->dst->host.ipVersion == 4))
	    copyInt32(direction == 0 ? theFlow->dst->host.ipType.ipv4 : theFlow->src->host.ipType.ipv4,
		      outBuffer, outBufferBegin, outBufferMax);
	  else
	    copyInt32(0, outBuffer, outBufferBegin, outBufferMax);
	  break;
	case 13: /* DST_MASK */
	  copyInt8(ip2mask((direction == 1) ? theFlow->src->host: theFlow->dst->host),
		   outBuffer, outBufferBegin, outBufferMax);
	  break;
	case 14: /* OUTPUT_SNMP */
	  copyInt16(theFlow->if_output, outBuffer, outBufferBegin, outBufferMax);
	  break;
	case 15: /* IPV4_NEXT_HOP */
	  copyInt32(0, outBuffer, outBufferBegin, outBufferMax);
	  break;
	case 16:
	  copyInt16(direction == 0 ? ip2AS(theFlow->src->host) : ip2AS(theFlow->dst->host),
		    outBuffer, outBufferBegin, outBufferMax);
	  break;
	case 17:
	  copyInt16(direction == 0 ? ip2AS(theFlow->dst->host) : ip2AS(theFlow->src->host),
		    outBuffer, outBufferBegin, outBufferMax);
	  break;
	case 21:
	  copyInt32(direction == 0 ? msTimeDiff(theFlow->flowTimers.lastSeenSent,
						readOnlyGlobals.initialSniffTime)
		    : msTimeDiff(theFlow->flowTimers.lastSeenRcvd,
				 readOnlyGlobals.initialSniffTime),
		    outBuffer, outBufferBegin, outBufferMax);
	  break;
	case 22:
	  copyInt32(direction == 0 ? msTimeDiff(theFlow->flowTimers.firstSeenSent,
						readOnlyGlobals.initialSniffTime)
		    : msTimeDiff(theFlow->flowTimers.firstSeenRcvd,
				 readOnlyGlobals.initialSniffTime),
		    outBuffer, outBufferBegin, outBufferMax);
	  break;
	case 23:
	  //copyInt32(direction == 0 ? theFlow->flowCounters.bytesSent : theFlow->flowCounters.bytesRcvd,
		  //  outBuffer, outBufferBegin, outBufferMax);
	  copyInt32(direction == 0 ? theFlow->flowCounters.bytesRcvd : theFlow->flowCounters.bytesSent,
		    outBuffer, outBufferBegin, outBufferMax);
	  break;
	case 24:
	  //copyInt32(direction == 0 ? theFlow->flowCounters.pktSent : theFlow->flowCounters.pktRcvd,
		  //  outBuffer, outBufferBegin, outBufferMax);
	  copyInt32(direction == 0 ? theFlow->flowCounters.pktRcvd : theFlow->flowCounters.pktSent,
		    outBuffer, outBufferBegin, outBufferMax);
	  break;
	case 27:
	  if((theFlow->src->host.ipVersion == 6) && (theFlow->dst->host.ipVersion == 6))
	    copyIpV6(direction == 0 ? theFlow->src->host.ipType.ipv6 : theFlow->dst->host.ipType.ipv6,
		     outBuffer, outBufferBegin, outBufferMax);
	  else {
	    struct in6_addr _ipv6;

	    memset(&_ipv6, 0, sizeof(struct in6_addr));
	    copyIpV6(_ipv6, outBuffer, outBufferBegin, outBufferMax);
	  }
	  break;
	case 28:
	  if((theFlow->src->host.ipVersion == 6) && (theFlow->dst->host.ipVersion == 6))
	    copyIpV6(direction == 0 ? theFlow->dst->host.ipType.ipv6 : theFlow->src->host.ipType.ipv6,
		     outBuffer, outBufferBegin, outBufferMax);
	  else {
	    struct in6_addr _ipv6;

	    memset(&_ipv6, 0, sizeof(struct in6_addr));
	    copyIpV6(_ipv6, outBuffer, outBufferBegin, outBufferMax);
	  }
	  break;
	case 29:
	case 30:
	  {
	    IpAddress addr;

	    memset(&addr, 0, sizeof(addr));
	    copyIpV6(addr.ipType.ipv6, outBuffer, outBufferBegin, outBufferMax);
	  }
	  break;
	case 32:
	  copyInt16(direction == 0 ? theFlow->src2dstIcmpType : theFlow->dst2srcIcmpType,
		    outBuffer, outBufferBegin, outBufferMax);
	  break;
	case 34: /* SAMPLING INTERVAL */
	  copyInt32(1 /* 1:1 = no sampling */, outBuffer, outBufferBegin, outBufferMax);
	  break;
	case 35: /* SAMPLING ALGORITHM */
	  copyInt8(0x01 /* 1=Deterministic Sampling, 0x02=Random Sampling */,
		   outBuffer, outBufferBegin, outBufferMax);
	  break;
	case 36: /* FLOW ACTIVE TIMEOUT */
	  copyInt16(readOnlyGlobals.lifetimeTimeout, outBuffer, outBufferBegin, outBufferMax);
	  break;
	case 37: /* FLOW INACTIVE TIMEOUT */
	  copyInt16(readOnlyGlobals.idleTimeout, outBuffer, outBufferBegin, outBufferMax);
	  break;
	case 38:
	  copyInt8((u_int8_t)readOnlyGlobals.engineType, outBuffer, outBufferBegin, outBufferMax);
	  break;
	case 39:
	  copyInt8((u_int8_t)readOnlyGlobals.engineId, outBuffer, outBufferBegin, outBufferMax);
	  break;
	case 40: /* TOTAL_BYTES_EXP */
	  copyInt32(readWriteGlobals->totBytesExp, outBuffer, outBufferBegin, outBufferMax);
	  break;
	case 41: /* TOTAL_PKTS_EXP */
	  copyInt32(readWriteGlobals->totExpPktSent, outBuffer, outBufferBegin, outBufferMax);
	  break;
	case 42: /* TOTAL_FLOWS_EXP */
	  copyInt32(readWriteGlobals->totFlowExp, outBuffer, outBufferBegin, outBufferMax);
	  break;
	case 56: /* IN_SRC_MAC */
	  copyMac(direction == 0 ? theFlow->srcMacAddress : theFlow->dstMacAddress, outBuffer, outBufferBegin, outBufferMax);
	  break;
	case 57: /* OUT_DST_MAC */
	  copyMac(direction == 0 ? theFlow->dstMacAddress : theFlow->srcMacAddress, outBuffer, outBufferBegin, outBufferMax);
	  break;
	case 58: /* SRC_VLAN */
	  /* no break */
	case 59: /* DST_VLAN */
	  copyInt16(theFlow->vlanId, outBuffer, outBufferBegin, outBufferMax);
	  break;
	case 60: /* IP_PROTOCOL_VERSION */
	  copyInt8((theFlow->src->host.ipVersion == 4) && (theFlow->dst->host.ipVersion == 4) ? 4 : 6, outBuffer, outBufferBegin, outBufferMax);
	  break;
	case 61: /* Direction */
	  copyInt8(direction, outBuffer, outBufferBegin, outBufferMax);
	  break;
	case 70: /* MPLS: label 1 */
	  copyMplsLabel(theFlow->mplsInfo, 1, outBuffer, outBufferBegin, outBufferMax);
	  break;
	case 71: /* MPLS: label 2 */
	  copyMplsLabel(theFlow->mplsInfo, 2, outBuffer, outBufferBegin, outBufferMax);
	  break;
	case 72: /* MPLS: label 3 */
	  copyMplsLabel(theFlow->mplsInfo, 3, outBuffer, outBufferBegin, outBufferMax);
	  break;
	case 73: /* MPLS: label 4 */
	  copyMplsLabel(theFlow->mplsInfo, 4, outBuffer, outBufferBegin, outBufferMax);
	  break;
	case 74: /* MPLS: label 5 */
	  copyMplsLabel(theFlow->mplsInfo, 5, outBuffer, outBufferBegin, outBufferMax);
	  break;
	case 75: /* MPLS: label 6 */
	  copyMplsLabel(theFlow->mplsInfo, 6, outBuffer, outBufferBegin, outBufferMax);
	  break;
	case 76: /* MPLS: label 7 */
	  copyMplsLabel(theFlow->mplsInfo, 7, outBuffer, outBufferBegin, outBufferMax);
	  break;
	case 77: /* MPLS: label 8 */
	  copyMplsLabel(theFlow->mplsInfo, 8, outBuffer, outBufferBegin, outBufferMax);
	  break;
	case 78: /* MPLS: label 9 */
	  copyMplsLabel(theFlow->mplsInfo, 9, outBuffer, outBufferBegin, outBufferMax);
	  break;
	case 79: /* MPLS: label 10 */
	  copyMplsLabel(theFlow->mplsInfo, 10, outBuffer, outBufferBegin, outBufferMax);
	  break;

	  /* ************************************ */

	  /* nProbe Extensions */
	case NTOP_BASE_ID+80:
	  copyInt8(direction == 0 ? fragmentedPacketSrc2Dst(theFlow) :
		   fragmentedPacketSrc2Dst(theFlow),
		   outBuffer, outBufferBegin, outBufferMax);
	  break;
	case NTOP_BASE_ID+81:
	  copyLen(direction == 0 ? theFlow->src2dstFingerprint : theFlow->dst2srcFingerprint,
		  FINGERPRINT_LEN,
		  outBuffer, outBufferBegin, outBufferMax);
	  break;
	case NTOP_BASE_ID+82:
	  copyInt32(nwLatencyComputed(theFlow) ? theFlow->clientNwDelay.tv_sec : 0,
		    outBuffer, outBufferBegin, outBufferMax);
	  break;
	case NTOP_BASE_ID+83:
	  copyInt32(nwLatencyComputed(theFlow) ? theFlow->clientNwDelay.tv_usec : 0,
		    outBuffer, outBufferBegin, outBufferMax);
	  break;
	case NTOP_BASE_ID+84:
	  copyInt32(nwLatencyComputed(theFlow) ? theFlow->serverNwDelay.tv_sec : 0,
		    outBuffer, outBufferBegin, outBufferMax);
	  break;
	case NTOP_BASE_ID+85:
	  copyInt32(nwLatencyComputed(theFlow) ? theFlow->serverNwDelay.tv_usec : 0,
		    outBuffer, outBufferBegin, outBufferMax);
	  break;
	case NTOP_BASE_ID+86:
	  copyInt32(applLatencyComputed(theFlow) ? (direction == 0 ? theFlow->src2dstApplLatency.tv_sec
						    : theFlow->dst2srcApplLatency.tv_sec) : 0,
		    outBuffer, outBufferBegin, outBufferMax);
	  break;
	case NTOP_BASE_ID+87:
	  copyInt32(applLatencyComputed(theFlow) ?
		    (direction == 0 ? theFlow->src2dstApplLatency.tv_usec :
		     theFlow->dst2srcApplLatency.tv_usec) : 0,
		    outBuffer, outBufferBegin, outBufferMax);
	  break;
	case NTOP_BASE_ID+IN_PAYLOAD_ID:
	  exportPayload(theFlow, 0, theTemplateElement, outBuffer, outBufferBegin, outBufferMax);
	  break;
	case NTOP_BASE_ID+OUT_PAYLOAD_ID:
	  exportPayload(theFlow, 1, theTemplateElement, outBuffer, outBufferBegin, outBufferMax);
	  break;
	case NTOP_BASE_ID+98:
	  copyInt32(direction == 0 ? theFlow->src2dstIcmpFlags : theFlow->dst2srcIcmpFlags,
		    outBuffer, outBufferBegin, outBufferMax);
	  break;

	case NTOP_BASE_ID+101: /* SRC_IP_COUNTRY */
#ifdef HAVE_GEOIP
	  geo = (direction == 0) ? theFlow->geo_src : theFlow->geo_dst;
#endif

	  //if(geo) traceEvent(TRACE_ERROR, "SRC_IP_COUNTRY -> %s", (geo && geo->country_code) ? geo->country_code : "???");

	  copyLen((u_char*)(
#ifdef HAVE_GEOIP
			    (geo && geo->country_code) ? geo->country_code : 
#endif
			    "  "), 2,
		  outBuffer, outBufferBegin, outBufferMax);
	  break;

	case NTOP_BASE_ID+102: /* SRC_IP_CITY */
#ifdef HAVE_GEOIP
	  geo = (direction == 0) ? theFlow->geo_src : theFlow->geo_dst;
#endif

	  // if(geo) traceEvent(TRACE_ERROR, "-> %s [%s]", geo->region, geo->country_code);

	  copyLen((u_char*)(
#ifdef HAVE_GEOIP
			    (geo && geo->city) ? geo->city :
#endif
			    "                "), 16,
		  outBuffer, outBufferBegin, outBufferMax);
	  break;

	case NTOP_BASE_ID+103: /* DST_IP_COUNTRY */
#ifdef HAVE_GEOIP
	  geo = (direction == 0) ? theFlow->geo_dst : theFlow->geo_src;
#endif

	  // if(geo) traceEvent(TRACE_ERROR, "DST_IP_COUNTRY -> %s", (geo && geo->country_code) ? geo->country_code : "???");
	  copyLen((u_char*)(
#ifdef HAVE_GEOIP
			    (geo && geo->country_code) ? geo->country_code :
#endif
			    "  "), 2,
		  outBuffer, outBufferBegin, outBufferMax);
	  break;

	case NTOP_BASE_ID+104: /* DST_IP_CITY */
#ifdef HAVE_GEOIP
	  geo = (direction == 0) ? theFlow->geo_dst : theFlow->geo_src;
#endif
	  copyLen((u_char*)(
#ifdef HAVE_GEOIP
			    (geo && geo->city) ? geo->city : 
#endif
			    "                "), 16,
		  outBuffer, outBufferBegin, outBufferMax);
	  break;

	case NTOP_BASE_ID+105: /* FLOW_PROTO_PORT */
	  t16 = getFlowApplProtocol(theFlow);
	  copyInt16(t16, outBuffer, outBufferBegin, outBufferMax);
	  break;

	case NTOP_BASE_ID+106: /* TUNNEL_ID */
	  copyInt32(theFlow->tunnel_id, outBuffer, outBufferBegin, outBufferMax);
	  break;

	  /* Custom fields */
	case 0xA0+4:
	  snprintf((char*)custom_field, sizeof(custom_field), "%s", proto2name(theFlow->proto));
	  copyLen(custom_field, sizeof(custom_field), outBuffer, outBufferBegin, outBufferMax);
	  break;
	case 0xA0+7:
	  snprintf((char*)custom_field, sizeof(custom_field), "%s", port2name(direction == 0 ? theFlow->sport : theFlow->dport, theFlow->proto));
	  copyLen(custom_field, sizeof(custom_field), outBuffer, outBufferBegin, outBufferMax);
	  break;
	case 0xA0+11:
	  snprintf((char*)custom_field, sizeof(custom_field), "%s", port2name(direction == 0 ? theFlow->dport : theFlow->sport, theFlow->proto));
	  copyLen(custom_field, sizeof(custom_field), outBuffer, outBufferBegin, outBufferMax);
	  break;

	default:
	  if(checkPluginExport(theTemplateElement, direction, theFlow,
			       outBuffer, outBufferBegin, outBufferMax) == -1) {
	    /*
	      This flow is the one we like, however we need
	      to store some values anyway, so we put an empty value
	    */

	    copyLen(null_data, theTemplateElement->templateElementLen,
		    outBuffer, outBufferBegin, outBufferMax);
	  }
	}
      }
    }

#ifdef DEBUG
    traceEvent(TRACE_INFO, "name=%s/Id=%d/len=%d [len=%d][outBufferMax=%d]\n",
	       theTemplateElement->templateElementName,
	       theTemplateElement->templateElementId,
	       theTemplateElement->templateElementLen,
	       *outBufferBegin, *outBufferMax);
#endif
  }

  (*numElements) = (*numElements)+1;

  return;
}

/* ******************************************** */

void load_mappings() {
  struct servent *sv;
#if !defined(WIN32)
  struct protoent *pe;
#endif

  while((sv = getservent()) != NULL) {
    u_short port = ntohs(sv->s_port);
    if(port_mapping[port] == NULL)
      port_mapping[port] = strdup(sv->s_name);
  }

#if !defined(WIN32)
  endservent();
#endif

  /* ******************** */

#if !defined(WIN32)
  while((pe = getprotoent()) != NULL) {
    if(proto_mapping[pe->p_proto] == NULL) {
      proto_mapping[pe->p_proto] = strdup(pe->p_name);
      // traceEvent(TRACE_INFO, "[%d][%s]", pe->p_proto, pe->p_name);
    }
  }

  endprotoent();
#else
  proto_mapping[0] = strdup("ip");
  proto_mapping[1] = strdup("icmp");
  proto_mapping[2] = strdup("igmp");
  proto_mapping[6] = strdup("tcp");
  proto_mapping[17] = strdup("udp");
#endif
}

/* ******************************************** */

void unload_mappings() {
  int i;

  for(i=0; i<0xFFFF; i++) if(port_mapping[i])  free(port_mapping[i]);
  for(i=0; i<0xFF; i++)   if(proto_mapping[i]) free(proto_mapping[i]);
}

/* ******************************************** */

/* FIX: improve performance */
char* proto2name(u_int8_t proto) {
#if 0
  struct protoent *svt;

  if(proto == 6)       return("tcp");
  else if(proto == 17) return("udp");
  else if(proto == 1)  return("icmp");
  else if(proto == 2)  return("igmp");
  else if((svt = getprotobynumber(proto)) != NULL)
    return(svt->p_name);
  else {
    static char the_proto[8];

    snprintf(the_proto, sizeof(the_proto), "%d", proto);
    return(the_proto);
  }
#else
  if(proto_mapping[proto] != NULL) {
    // traceEvent(TRACE_INFO, "[%d][%s]", proto, proto_mapping[proto]);
    return(proto_mapping[proto]);
  } else
    return("unknown");
#endif
}

/* ******************************************** */

static int mplsLabel2int(struct mpls_labels *mplsInfo, int labelId) {
  if(mplsInfo == NULL)
    return(0);
  else
    return((mplsInfo->mplsLabels[labelId][0] << 16)
	   + (mplsInfo->mplsLabels[labelId][1] << 8)
	   + mplsInfo->mplsLabels[labelId][2]);
}

/* ******************************************** */

static void printRecordWithTemplate(V9V10TemplateElementId *theTemplateElement,
				    char *line_buffer, u_int line_buffer_len,
				    FlowHashBucket *theFlow, int direction) {
  char buf[128], *dst;
#ifdef HAVE_GEOIP  
  GeoIPRecord *geo;
#endif
  u_int len;

  /* traceEvent(TRACE_INFO, "[%s][%d]",
     theTemplate->templateElementName, theTemplate->templateElementLen);
  */

  len = strlen(line_buffer);
  dst = &line_buffer[len];

  switch(theTemplateElement->templateElementId) {
  case 1:
    snprintf(dst, (line_buffer_len-len), "%u",
	     direction == 0 ? theFlow->flowCounters.bytesSent : theFlow->flowCounters.bytesRcvd);
    break;
  case 2:
    //snprintf(dst, (line_buffer_len-len), "%u",
	    // direction == 0 ? theFlow->flowCounters.pktRcvd : theFlow->flowCounters.pktSent);
    snprintf(dst, (line_buffer_len-len), "%u",
	     direction == 0 ? theFlow->flowCounters.pktSent : theFlow->flowCounters.pktRcvd);
    break;
  case 4:
    snprintf(dst, (line_buffer_len-len), "%d",
	     theFlow->proto);
    break;
  case 0xFF+4:
    snprintf(dst, (line_buffer_len-len), "%s",
	     proto2name(theFlow->proto));
    break;
  case 5:
    snprintf(dst, (line_buffer_len-len), "%d",
	     direction == 0 ? theFlow->src2dstTos : theFlow->dst2srcTos);
    break;
  case 6:
    snprintf(dst, (line_buffer_len-len), "%d",
	     direction == 0 ? theFlow->src2dstTcpFlags : theFlow->dst2srcTcpFlags);
    break;
  case 7:
    snprintf(dst, (line_buffer_len-len), "%d",
	     direction == 0 ? theFlow->sport : theFlow->dport);
    break;
  case 0xFF+7:
    snprintf(dst, (line_buffer_len-len), "%s",
	     port2name(direction == 0 ? theFlow->sport : theFlow->dport, theFlow->proto));
    break;
  case 8:
  case 27:
    snprintf(dst, (line_buffer_len-len), "%s",
	     _intoa(direction == 0 ? theFlow->src->host : theFlow->dst->host, buf, sizeof(buf)));
    break;
  case 9: /* SRC_MASK */
    snprintf(dst, (line_buffer_len-len), "%d",
	     ip2mask((direction == 0) ? theFlow->src->host : theFlow->dst->host));
    break;
  case 10: /* INPUT_SNMP */
    snprintf(dst, (line_buffer_len-len), "%d",
	     theFlow->if_input);
    break;
  case 11:
    snprintf(dst, (line_buffer_len-len), "%d",
	     direction == 0 ? theFlow->dport : theFlow->sport);
    break;
  case 0xFF+11:
    snprintf(dst, (line_buffer_len-len), "%s",
	     port2name(direction == 0 ? theFlow->dport : theFlow->sport, theFlow->proto));
    break;
  case 12:
  case 28:
    snprintf(dst, (line_buffer_len-len), "%s",
	     _intoa(direction == 0 ? theFlow->dst->host : theFlow->src->host, buf, sizeof(buf)));
    break;
  case 13: /* DST_MASK */
    snprintf(dst, (line_buffer_len-len), "%d",
	     ip2mask((direction == 1) ? theFlow->src->host : theFlow->dst->host));
    break;
  case 14: /* OUTPUT_SNMP */
    snprintf(dst, (line_buffer_len-len), "%d",
	     theFlow->if_output);
    break;
  case 15: /* IPV4_NEXT_HOP */
    snprintf(dst, (line_buffer_len-len), "%d", 0);
    break;
  case 16:
    snprintf(dst, (line_buffer_len-len), "%d",
	     direction == 0 ? ip2AS(theFlow->src->host) : ip2AS(theFlow->dst->host));
    break;
  case 17:
    snprintf(dst, (line_buffer_len-len), "%d",
	     direction == 0 ? ip2AS(theFlow->dst->host) : ip2AS(theFlow->src->host));
    break;
    case 21:
      snprintf(dst, (line_buffer_len-len), "%u",
	       (unsigned int)(direction == 0 ? theFlow->flowTimers.lastSeenSent.tv_sec :
			      theFlow->flowTimers.lastSeenRcvd.tv_sec));
    break;
  case 22:
    snprintf(dst, (line_buffer_len-len), "%u",
	     (unsigned int)(direction == 0 ? theFlow->flowTimers.firstSeenSent.tv_sec :
			    theFlow->flowTimers.firstSeenRcvd.tv_sec));
    break;
  case 23:
    snprintf(dst, (line_buffer_len-len), "%u",
	     direction == 0 ? theFlow->flowCounters.bytesRcvd : theFlow->flowCounters.bytesSent);
    //snprintf(dst, (line_buffer_len-len), "%u",
	    // direction == 0 ? theFlow->flowCounters.bytesSent : theFlow->flowCounters.bytesRcvd);
    break;
  case 24:
    snprintf(dst, (line_buffer_len-len), "%u",
	     direction == 0 ? theFlow->flowCounters.pktRcvd : theFlow->flowCounters.pktSent);
    //snprintf(dst, (line_buffer_len-len), "%u",
	    // direction == 0 ? theFlow->flowCounters.pktSent : theFlow->flowCounters.pktRcvd);
    break;
  case 29:
  case 30:
    snprintf(dst, (line_buffer_len-len), "%d", 0);
    break;
  case 32:
    snprintf(dst, (line_buffer_len-len), "%d",
	     direction == 0 ? theFlow->src2dstIcmpType : theFlow->dst2srcIcmpType);
    break;
  case 34: /* SAMPLING INTERVAL */
    snprintf(dst, (line_buffer_len-len), "%d",
	     1 /* 1:1 = no sampling */);
    break;
  case 35: /* SAMPLING ALGORITHM */
    snprintf(dst, (line_buffer_len-len), "%d",
	     0x01 /* 1=Deterministic Sampling, 0x02=Random Sampling */);
    break;
  case 36: /* FLOW ACTIVE TIMEOUT */
    snprintf(dst, (line_buffer_len-len), "%d",
	     readOnlyGlobals.lifetimeTimeout);
    break;
  case 37: /* FLOW INACTIVE TIMEOUT */
    snprintf(dst, (line_buffer_len-len), "%d",
	     readOnlyGlobals.idleTimeout);
    break;
  case 38:
    snprintf(dst, (line_buffer_len-len), "%d",
	     readOnlyGlobals.engineType);
    break;
  case 39:
    snprintf(dst, (line_buffer_len-len), "%d",
	     readOnlyGlobals.engineId);
    break;
  case 40: /* TOTAL_BYTES_EXP */
    snprintf(dst, (line_buffer_len-len), "%d",
	     readWriteGlobals->totBytesExp);
    break;
  case 41: /* TOTAL_PKTS_EXP */
    snprintf(dst, (line_buffer_len-len), "%d",
	     readWriteGlobals->totExpPktSent);
    break;
  case 42: /* TOTAL_FLOWS_EXP */
    snprintf(dst, (line_buffer_len-len), "%d",
	     readWriteGlobals->totFlowExp);
    break;
  case 56: /* IN_SRC_MAC */
    snprintf(dst, (line_buffer_len-len), "%s",
	     direction == 0 ? etheraddr_string(theFlow->srcMacAddress, buf)
	     : etheraddr_string(theFlow->dstMacAddress, buf));
    break;
  case 57: /* OUT_DST_MAC */
    snprintf(dst, (line_buffer_len-len), "%s",
	     direction == 0 ? etheraddr_string(theFlow->dstMacAddress, buf)
	     : etheraddr_string(theFlow->srcMacAddress, buf));
    break;
  case 58: /* SRC_VLAN */
  case 59: /* DST_VLAN */
    snprintf(dst, (line_buffer_len-len), "%d",
	     theFlow->vlanId);
    break;
  case 60: /* IP_PROTOCOL_VERSION */
    snprintf(dst, (line_buffer_len-len), "%d",
	     (theFlow->src->host.ipVersion == 4) && (theFlow->dst->host.ipVersion == 4) ? 4 : 6);
    break;
  case 61: /* Direction */
    snprintf(dst, (line_buffer_len-len), "%d",
	     direction);
    break;
  case 70: /* MPLS: label 1 */
    snprintf(dst, (line_buffer_len-len), "%u",
	     mplsLabel2int(theFlow->mplsInfo, 0));
    break;
  case 71: /* MPLS: label 2 */
    snprintf(dst, (line_buffer_len-len), "%u",
	     mplsLabel2int(theFlow->mplsInfo, 1));
    break;
  case 72: /* MPLS: label 3 */
    snprintf(dst, (line_buffer_len-len), "%u",
	     mplsLabel2int(theFlow->mplsInfo, 2));
    break;
  case 73: /* MPLS: label 4 */
    snprintf(dst, (line_buffer_len-len), "%u",
	     mplsLabel2int(theFlow->mplsInfo, 3));
    break;
  case 74: /* MPLS: label 5 */
    snprintf(dst, (line_buffer_len-len), "%u",
	     mplsLabel2int(theFlow->mplsInfo, 4));
    break;
  case 75: /* MPLS: label 6 */
    snprintf(dst, (line_buffer_len-len), "%u",
	     mplsLabel2int(theFlow->mplsInfo, 5));
    break;
  case 76: /* MPLS: label 7 */
    snprintf(dst, (line_buffer_len-len), "%u",
	     mplsLabel2int(theFlow->mplsInfo, 6));
    break;
  case 77: /* MPLS: label 8 */
    snprintf(dst, (line_buffer_len-len), "%u",
	     mplsLabel2int(theFlow->mplsInfo, 7));
    break;
  case 78: /* MPLS: label 9 */
    snprintf(dst, (line_buffer_len-len), "%u",
	     mplsLabel2int(theFlow->mplsInfo, 8));
    break;
  case 79: /* MPLS: label 10 */
    snprintf(dst, (line_buffer_len-len), "%u",
	     mplsLabel2int(theFlow->mplsInfo, 9));
    break;

    /* ************************************ */

    /* nProbe Extensions */
  case NTOP_BASE_ID+80:
    snprintf(dst, (line_buffer_len-len), "%d",
	     direction == 0 ? fragmentedPacketSrc2Dst(theFlow) : fragmentedPacketSrc2Dst(theFlow));
    break;
  case NTOP_BASE_ID+81:
    {
      int idx;

      for(idx=0; idx<FINGERPRINT_LEN; idx++)
	snprintf(dst, (line_buffer_len-len), "%c",
		 direction == 0 ? theFlow->src2dstFingerprint[idx] : theFlow->dst2srcFingerprint[idx]);
    }
    break;
  case NTOP_BASE_ID+82:
    snprintf(dst, (line_buffer_len-len), "%d",
	     (int)(nwLatencyComputed(theFlow) ? theFlow->clientNwDelay.tv_sec : 0));
    break;
  case NTOP_BASE_ID+83:
    snprintf(dst, (line_buffer_len-len), "%u",
	     nwLatencyComputed(theFlow) ? (u_int32_t)theFlow->clientNwDelay.tv_usec : 0);
    break;
  case NTOP_BASE_ID+84:
    snprintf(dst, (line_buffer_len-len), "%u",
	     (int)(nwLatencyComputed(theFlow) ? (u_int32_t)theFlow->serverNwDelay.tv_sec : 0));
    break;
  case NTOP_BASE_ID+85:
    snprintf(dst, (line_buffer_len-len), "%u",
	     nwLatencyComputed(theFlow) ? (u_int32_t)theFlow->serverNwDelay.tv_usec : 0);
    break;

  case NTOP_BASE_ID+86:
    snprintf(dst, (line_buffer_len-len), "%u",
	     (u_int32_t)(applLatencyComputed(theFlow) ?
			 (direction == 0 ? theFlow->src2dstApplLatency.tv_sec
			  : theFlow->dst2srcApplLatency.tv_sec) : 0));
    break;
  case NTOP_BASE_ID+87:
    snprintf(dst, (line_buffer_len-len), "%d",
	     (u_int32_t)(applLatencyComputed(theFlow) ?
			 (direction == 0 ? theFlow->src2dstApplLatency.tv_usec
			  : theFlow->dst2srcApplLatency.tv_usec) : 0));
    break;
  case NTOP_BASE_ID+IN_PAYLOAD_ID:
  case NTOP_BASE_ID+OUT_PAYLOAD_ID:
    {
      int idx, len;

      if((theTemplateElement->templateElementId == IN_PAYLOAD_ID)
	 || (theTemplateElement->templateElementId == OUT_PAYLOAD_ID))
	len = theFlow->src2dstPayloadLen;
      else
	len = theFlow->dst2srcPayloadLen;

      for(idx=0; idx<len; idx++)
	snprintf(dst, (line_buffer_len-len), "%c",
		 ((theTemplateElement->templateElementId == IN_PAYLOAD_ID)
		  || (theTemplateElement->templateElementId == OUT_PAYLOAD_ID))
		 ? theFlow->src2dstPayload[idx] : theFlow->dst2srcPayload[idx]);
    }
    break;
  case NTOP_BASE_ID+98:
    snprintf(dst, (line_buffer_len-len), "%d",
	     direction == 0 ? theFlow->src2dstIcmpFlags : theFlow->dst2srcIcmpFlags);
    break;

  case NTOP_BASE_ID+101: /* SRC_IP_COUNTRY */
#ifdef HAVE_GEOIP
    geo = (direction == 0) ? theFlow->geo_src : theFlow->geo_dst;
#endif
    snprintf(dst, (line_buffer_len-len), "%s",
#ifdef HAVE_GEOIP
	     (geo && geo->country_code) ? geo->country_code : 
#endif
	     "");
    break;

  case NTOP_BASE_ID+102: /* SRC_IP_CITY */
#ifdef HAVE_GEOIP
    geo = (direction == 0) ? theFlow->geo_src : theFlow->geo_dst;
#endif
    snprintf(dst, (line_buffer_len-len), "%s",
#ifdef HAVE_GEOIP
	     (geo && geo->city) ? geo->city : 
#endif
	     "");
    break;

  case NTOP_BASE_ID+103: /* DST_IP_COUNTRY */
#ifdef HAVE_GEOIP
    geo = (direction == 0) ? theFlow->geo_dst : theFlow->geo_src;
#endif
    snprintf(dst, (line_buffer_len-len), "%s",
#ifdef HAVE_GEOIP
	     (geo && geo->country_code) ? geo->country_code : 
#endif
	     "");
    break;

  case NTOP_BASE_ID+104: /* DST_IP_CITY */
#ifdef HAVE_GEOIP
    geo = (direction == 0) ? theFlow->geo_dst : theFlow->geo_src;
#endif
    snprintf(dst, (line_buffer_len-len), "%s",
#ifdef HAVE_GEOIP
	     (geo && geo->city) ? geo->city : 
#endif
	     "");
    break;

  case NTOP_BASE_ID+105: /* FLOW_PROTO_PORT */
    snprintf(dst, (line_buffer_len-len), "%u", getFlowApplProtocol(theFlow));
    break;

  case NTOP_BASE_ID+106: /* TUNNEL_ID */
    snprintf(dst, (line_buffer_len-len), "%u", theFlow->tunnel_id);
    break;

  default:
    checkPluginPrint(theTemplateElement, direction, theFlow, line_buffer, line_buffer_len);
  }

#ifdef DEBUG
  traceEvent(TRACE_INFO, "name=%s/Id=%d\n",
	     theTemplateElement->templateElementName,
	     theTemplateElement->templateElementId);
#endif
}

/* ******************************************** */

void flowPrintf(V9V10TemplateElementId **templateList, char *outBuffer,
		u_int *outBufferBegin, u_int *outBufferMax,
		int *numElements, char buildTemplate,
		FlowHashBucket *theFlow, int direction,
		int addTypeLen, int optionTemplate) {
  int idx = 0;

  (*numElements) = 0;

  while(templateList[idx] != NULL) {
    handleTemplate(templateList[idx], outBuffer, outBufferBegin, outBufferMax,
		   buildTemplate, numElements,
		   theFlow, direction, addTypeLen,
		   optionTemplate);
    idx++;
  }
}

/* ******************************************** */

void flowFilePrintf(V9V10TemplateElementId **templateList,
		    FILE *stream, FlowHashBucket *theFlow, int direction) {
  int idx = 0;
  char line_buffer[2048] = { '\0' };

  readWriteGlobals->sql_row_idx++;
  if(readOnlyGlobals.dumpFormat == sqlite_format)
    snprintf(&line_buffer[strlen(line_buffer)],
	     sizeof(line_buffer), "insert into flows values ('");

  while(templateList[idx] != NULL) {
    if(idx > 0) {
      if(readOnlyGlobals.dumpFormat == sqlite_format)
	snprintf(&line_buffer[strlen(line_buffer)], sizeof(line_buffer), "','");
      else
	snprintf(&line_buffer[strlen(line_buffer)], sizeof(line_buffer), "%s",
		 readOnlyGlobals.csv_separator);
    }

    printRecordWithTemplate(templateList[idx], line_buffer,
			    sizeof(line_buffer), theFlow, direction);
    idx++;
  }

  if(readOnlyGlobals.dumpFormat == sqlite_format) {
    snprintf(&line_buffer[strlen(line_buffer)], sizeof(line_buffer), "');");
#ifdef HAVE_SQLITE
    sqlite_exec_sql(line_buffer);
#endif
  } else
    fprintf(stream, "%s\n", line_buffer);
}

/* ******************************************** */

void compileTemplate(char *_fmt, V9V10TemplateElementId **templateList, int templateElements) {
  int idx=0, endIdx, i, templateIdx, len = strlen(_fmt);
  char fmt[1024], tmpChar, found;
  u_int8_t ignored;

  templateIdx = 0;
  snprintf(fmt, sizeof(fmt), "%s", _fmt);

  while((idx < len) && (fmt[idx] != '\0')) {	/* scan format string characters */
    switch(fmt[idx]) {
    case '%':	        /* special format follows */
      endIdx = ++idx;
      while(fmt[endIdx] != '\0') {
	if((fmt[endIdx] == ' ') || (fmt[endIdx] == '%'))
	  break;
	else
	  endIdx++;
      }

      if((endIdx == (idx+1)) && (fmt[endIdx] == '\0')) return;
      tmpChar = fmt[endIdx]; fmt[endIdx] = '\0';

      ignored = 0;

      if(strstr(&fmt[idx], "_COUNTRY") || strstr(&fmt[idx], "_CITY")) {
#ifdef HAVE_GEOIP
	if(readOnlyGlobals.geo_ip_city_db == NULL) {
	  traceEvent(TRACE_WARNING, "Geo-location requires --city-list to be specified: ignored %s", &fmt[idx]);
	  ignored = 1;
	}
#else
	ignored = 1;
#endif
      }

      /* traceEvent(TRACE_INFO, "Checking '%s' [ignored=%d]", &fmt[idx], ignored); */

      if(!ignored) {
	i = 0, found = 0;

	while(ver9_templates[i].templateElementName != NULL) {
	  if(strcmp(&fmt[idx], ver9_templates[i].templateElementName) == 0) {
	    templateList[templateIdx++] = &ver9_templates[i];
	    found = 1;
	    break;
	  }

	  i++;
	}

	if(!found) {
	  if((templateList[templateIdx] = getPluginTemplate(&fmt[idx])) != NULL)
	    templateIdx++;
	  else
	    traceEvent(TRACE_WARNING, "Unable to locate template '%s'. Discarded.", &fmt[idx]);
	}

	if(templateIdx >= (templateElements-1)) {
	  traceEvent(TRACE_WARNING, "Unable to add further template elements (%d).", templateIdx);
	  break;
	}
      }

      fmt[endIdx] = tmpChar;
      if(tmpChar == '%')
	idx = endIdx;
      else
	idx = endIdx+1;
      break;

    default:
      idx++;
      break;
    }
  }

  templateList[templateIdx] = NULL;
}

/* ******************************************** */

double toMs(struct timeval theTime) {
  return(theTime.tv_sec+(float)theTime.tv_usec/1000000);
}

/* ****************************************************** */

u_int32_t msTimeDiff(struct timeval end, struct timeval begin) {
  if((end.tv_sec == 0) && (end.tv_usec == 0))
    return(0);
  else
    return((end.tv_sec-begin.tv_sec)*1000+(end.tv_usec-begin.tv_usec)/1000);
}

/* ****************************************************** */

#ifndef __TILECC__
#ifndef WIN32
int createCondvar(ConditionalVariable *condvarId) {
  int rc;

  rc = pthread_mutex_init(&condvarId->mutex, NULL);
  rc = pthread_cond_init(&condvarId->condvar, NULL);
  condvarId->predicate = 0;

  return(rc);
}

/* ************************************ */

void deleteCondvar(ConditionalVariable *condvarId) {
  pthread_mutex_destroy(&condvarId->mutex);
  pthread_cond_destroy(&condvarId->condvar);
}

/* ************************************ */

int waitCondvar(ConditionalVariable *condvarId) {
  int rc;

  if((rc = pthread_mutex_lock(&condvarId->mutex)) != 0)
    return rc;

  while(condvarId->predicate <= 0) {
    rc = pthread_cond_wait(&condvarId->condvar, &condvarId->mutex);
  }

  condvarId->predicate--;

  rc = pthread_mutex_unlock(&condvarId->mutex);

  return rc;
}
/* ************************************ */

int signalCondvar(ConditionalVariable *condvarId, int broadcast) {
  int rc;

  rc = pthread_mutex_lock(&condvarId->mutex);

  condvarId->predicate++;

  rc = pthread_mutex_unlock(&condvarId->mutex);
  if(broadcast)
    rc = pthread_cond_broadcast(&condvarId->condvar);
  else
    rc = pthread_cond_signal(&condvarId->condvar);

  return rc;
}

#undef sleep /* Used by ntop_sleep */

#else /* WIN32 */

/* ************************************ */

int createCondvar(ConditionalVariable *condvarId) {
  condvarId->condVar = CreateEvent(NULL,  /* no security */
				   TRUE , /* auto-reset event (FALSE = single event, TRUE = broadcast) */
				   FALSE, /* non-signaled initially */
				   NULL); /* unnamed */
  InitializeCriticalSection(&condvarId->criticalSection);
  return(1);
}

/* ************************************ */

void deleteCondvar(ConditionalVariable *condvarId) {
  CloseHandle(condvarId->condVar);
  DeleteCriticalSection(&condvarId->criticalSection);
}

/* ************************************ */

int waitCondvar(ConditionalVariable *condvarId) {
  int rc;
#ifdef DEBUG
  traceEvent(CONST_TRACE_INFO, "Wait (%x)...", condvarId->condVar);
#endif
  EnterCriticalSection(&condvarId->criticalSection);
  rc = WaitForSingleObject(condvarId->condVar, INFINITE);
  LeaveCriticalSection(&condvarId->criticalSection);

#ifdef DEBUG
  traceEvent(CONST_TRACE_INFO, "Got signal (%d)...", rc);
#endif

  return(rc);
}

/* ************************************ */

/* NOTE: broadcast is currently ignored */
int signalCondvar(ConditionalVariable *condvarId, int broadcast) {
#ifdef DEBUG
  traceEvent(CONST_TRACE_INFO, "Signaling (%x)...", condvarId->condVar);
#endif
  return((int)PulseEvent(condvarId->condVar));
}

#define sleep(a /* sec */) waitForNextEvent(1000*a /* ms */)

#endif /* WIN32 */
#endif /* __TILECC__ */

/* ******************************************* */

unsigned int ntop_sleep(unsigned int secs) {
  unsigned int unsleptTime = secs, rest;

  while((rest = sleep(unsleptTime)) > 0)
    unsleptTime = rest;

  return(secs);
}

/* ******************************************* */

FlowHashBucket* getListHead(FlowHashBucket **list) {
  FlowHashBucket *bkt = *list;

  if(bkt == NULL)
    traceEvent(TRACE_ERROR, "INTERNAL ERROR: getListHead is empty");
  else
    (*list) = bkt->next;

  return(bkt);
}

/* ******************************************* */

void addToList(FlowHashBucket *bkt, FlowHashBucket **list) {
  bkt->next = *list;
  (*list) = bkt;
}

/* **************************************** */

#ifndef WIN32

void detachFromTerminal(int doChdir) {
  if(doChdir) {
    int rc = chdir("/");
    if(rc != 0) traceEvent(TRACE_ERROR, "Error while moving to / directory");
  }

  setsid();  /* detach from the terminal */

  fclose(stdin);
  fclose(stdout);
  /* fclose(stderr); */

  /*
   * clear any inherited file mode creation mask
   */
  umask (0);

  /*
   * Use line buffered stdout
   */
  /* setlinebuf (stdout); */
  setvbuf(stdout, (char *)NULL, _IOLBF, 0);
}

/* **************************************** */

void daemonize(void) {
  int childpid;

  signal(SIGHUP, SIG_IGN);
  signal(SIGCHLD, SIG_IGN);
  signal(SIGQUIT, SIG_IGN);

  if((childpid = fork()) < 0)
    traceEvent(TRACE_ERROR, "INIT: Occurred while daemonizing (errno=%d)", errno);
  else {
#ifdef DEBUG
    traceEvent(TRACE_INFO, "DEBUG: after fork() in %s (%d)",
	       childpid ? "parent" : "child", childpid);
#endif
    if(!childpid) { /* child */
      traceEvent(TRACE_INFO, "INIT: Bye bye: I'm becoming a daemon...");
      detachFromTerminal(1);
    } else { /* father */
      traceEvent(TRACE_INFO, "INIT: Parent process is exiting (this is normal)");
      exit(0);
    }
  }
}

#endif /* WIN32 */

/* ****************************************

   Address management

   **************************************** */

static int int2bits(int number) {
  int bits = 8;
  int test;

  if((number > 255) || (number < 0))
    return(CONST_INVALIDNETMASK);
  else {
    test = ~number & 0xff;
    while (test & 0x1)
      {
	bits --;
	test = test >> 1;
      }
    if(number != ((~(0xff >> bits)) & 0xff))
      return(CONST_INVALIDNETMASK);
    else
      return(bits);
  }
}

/* ********************** */

static int dotted2bits(char *mask) {
  int		fields[4];
  int		fields_num, field_bits;
  int		bits = 0;
  int		i;

  fields_num = sscanf(mask, "%d.%d.%d.%d",
		      &fields[0], &fields[1], &fields[2], &fields[3]);
  if((fields_num == 1) && (fields[0] <= 32) && (fields[0] >= 0))
    {
#ifdef DEBUG
      traceEvent(CONST_TRACE_INFO, "DEBUG: dotted2bits (%s) = %d", mask, fields[0]);
#endif
      return(fields[0]);
    }
  for (i=0; i < fields_num; i++)
    {
      /* We are in a dotted quad notation. */
      field_bits = int2bits (fields[i]);
      switch (field_bits)
	{
	case CONST_INVALIDNETMASK:
	  return(CONST_INVALIDNETMASK);

	case 0:
	  /* whenever a 0 bits field is reached there are no more */
	  /* fields to scan                                       */
	  /* In this case we are in a bits (not dotted quad) notation */
	  return(bits /* fields[0] - L.Deri 08/2001 */);

	default:
	  bits += field_bits;
	}
    }
  return(bits);
}

/* ********************************* */

static char* read_file(char* path, char* buf, u_int buf_len) {
  FILE *fd = fopen(&path[1], "r");

  if(fd == NULL) {
    traceEvent(TRACE_WARNING, "Unable to read file %s", path);
    return(NULL);
  } else {
    char line[256];
    int idx = 0;

    while(!feof(fd) && (fgets(line, sizeof(line), fd) != NULL)) {
      if((line[0] == '#') || (line[0] == '\n')) continue;
      while(strlen(line) && (line[strlen(line)-1] == '\n')) {
	line[strlen(line)-1] = '\0';
      }

      snprintf(&buf[idx], buf_len-idx-2, "%s%s", (idx > 0) ? "," : "", line);
      idx = strlen(buf);
    }

    fclose(fd);
    return(buf);
  }
}

/* ********************************* */

static u_int8_t num_network_bits(u_int32_t addr) {
  u_int8_t i, j, bits = 0, fields[4];

  memcpy(fields, &addr, 4);

  for(i = 8; i <= 8; i--)
    for(j=0; j<4; j++)
      if ((fields[j] & (1 << i)) != 0) bits++;

  return(bits);
}

/* ********************** */

typedef struct {
  u_int32_t network;
  u_int32_t networkMask;
  u_int32_t broadcast;
} netAddress_t;

int parseAddress(char * address, netAddress_t * netaddress) {
  u_int32_t network, networkMask, broadcast;
  int bits, a, b, c, d;
  char *mask = strchr(address, '/');

  mask[0] = '\0';
  mask++;
  bits = dotted2bits (mask);

  if(sscanf(address, "%d.%d.%d.%d", &a, &b, &c, &d) != 4)
    return -1;

  if(bits == CONST_INVALIDNETMASK) {
    traceEvent(TRACE_WARNING, "netmask '%s' not valid - ignoring entry", mask);
    /* malformed netmask specification */
    return -1;
  }

  network = ((a & 0xff) << 24) + ((b & 0xff) << 16) + ((c & 0xff) << 8) + (d & 0xff);
  /* Special case the /32 mask - yeah, we could probably do it with some fancy
     u long long stuff, but this is simpler...
     Burton Strauss <Burton@ntopsupport.com> Jun2002
  */
  if(bits == 32) {
    networkMask = 0xffffffff;
  } else {
    networkMask = 0xffffffff >> bits;
    networkMask = ~networkMask;
  }

  if((network & networkMask) != network)  {
    /* malformed network specification */

    traceEvent(TRACE_WARNING, "%d.%d.%d.%d/%d is not a valid network - correcting mask",
	       a, b, c, d, bits);
    /* correcting network numbers as specified in the netmask */
    network &= networkMask;

    /*
      a = (int) ((network >> 24) & 0xff);
      b = (int) ((network >> 16) & 0xff);
      c = (int) ((network >>  8) & 0xff);
      d = (int) ((network >>  0) & 0xff);


      traceEvent(CONST_TRACE_NOISY, "Assuming %d.%d.%d.%d/%d [0x%08x/0x%08x]",
      a, b, c, d, bits, network, networkMask);
    */
  }

  broadcast = network | (~networkMask);

  a = (int) ((network >> 24) & 0xff);
  b = (int) ((network >> 16) & 0xff);
  c = (int) ((network >>  8) & 0xff);
  d = (int) ((network >>  0) & 0xff);

  traceEvent(TRACE_INFO, "Adding %d.%d.%d.%d/%d to the local network list",
	     a, b, c, d, bits);

  netaddress->network     = network;
  netaddress->networkMask = networkMask;
  netaddress->broadcast   = broadcast;

  return 0;
}

/* ********************** */

void parseLocalAddressLists(char* _addresses) {
  char *address, *addresses, *strTokState = NULL, buf[2048];

  readOnlyGlobals.numLocalNetworks = 0;

  if((_addresses == NULL) || (_addresses[0] == '\0'))
    return;
  else if(_addresses[0] == '@') {
    addresses = strdup(read_file(_addresses, buf, sizeof(buf)));
  } else
    addresses = strdup(_addresses);

  address = strtok_r(addresses, ",", &strTokState);

  while(address != NULL) {
    char *mask = strchr(address, '/');

    if(mask == NULL) {
      traceEvent(TRACE_WARNING, "Empty mask '%s' - ignoring entry", address);
    } else {
      netAddress_t netaddress;

      if(readOnlyGlobals.numLocalNetworks >= MAX_NUM_NETWORKS) {
	traceEvent(TRACE_WARNING, "Too many networks defined (-L): skipping further networks");
	break;
      }

      if(parseAddress(address, &netaddress)==-1) {
	address = strtok_r(NULL, ",", &strTokState);
	continue;
      }

      /* NOTE: entries are saved in network byte order for performance reasons */
      localNetworks[readOnlyGlobals.numLocalNetworks][CONST_NETWORK_ENTRY]    = htonl(netaddress.network);
      localNetworks[readOnlyGlobals.numLocalNetworks][CONST_NETMASK_ENTRY]    = htonl(netaddress.networkMask);
      localNetworks[readOnlyGlobals.numLocalNetworks][CONST_BROADCAST_ENTRY]  = htonl(netaddress.broadcast);
      localNetworks[readOnlyGlobals.numLocalNetworks][CONST_NETMASK_V6_ENTRY] = num_network_bits(netaddress.networkMask); /* Host byte-order */
      readOnlyGlobals.numLocalNetworks++;
    }

    address = strtok_r(NULL, ",", &strTokState);
  }

  free(addresses);
}

/* ************************************************ */

void parseBlacklistNetworks(char* _addresses) {
  char *address, *addresses, buf[2048], *strTokState = NULL;

  readOnlyGlobals.numBlacklistNetworks = 0;

  if((_addresses == NULL) || (_addresses[0] == '\0'))
    return;
  else if(_addresses[0] == '@') {
    addresses = strdup(read_file(_addresses, buf, sizeof(buf)));
  } else
    addresses = strdup(_addresses);

  address = strtok_r(addresses, ",", &strTokState);

  while(address != NULL) {
    char *mask = strchr(address, '/');

    if(mask == NULL) {
      traceEvent(TRACE_WARNING, "Empty mask '%s' - ignoring entry", address);
    } else {
      netAddress_t netaddress;

      if(readOnlyGlobals.numBlacklistNetworks >= MAX_NUM_NETWORKS) {
	traceEvent(TRACE_WARNING, "Too many networks defined (--black-list): skipping further networks");
	break;
      }

      if (parseAddress(address,&netaddress)==-1) {
	address = strtok_r(NULL, ",", &strTokState);
	continue;
      }

      /* NOTE: entries are saved in network byte order for performance reasons */
      blacklistNetworks[readOnlyGlobals.numBlacklistNetworks][CONST_NETWORK_ENTRY]    = htonl(netaddress.network);
      blacklistNetworks[readOnlyGlobals.numBlacklistNetworks][CONST_NETMASK_ENTRY]    = htonl(netaddress.networkMask);
      blacklistNetworks[readOnlyGlobals.numBlacklistNetworks][CONST_BROADCAST_ENTRY]  = htonl(netaddress.broadcast);
      blacklistNetworks[readOnlyGlobals.numBlacklistNetworks][CONST_NETMASK_V6_ENTRY] = num_network_bits(netaddress.networkMask); /* Host byte-order */
      readOnlyGlobals.numBlacklistNetworks++;
    }

    address = strtok_r(NULL, ",", &strTokState);
  }

  free(addresses);
}


/* ************************************************ */

//#define DEBUG
#undef DEBUG

unsigned short isLocalAddress(struct in_addr *addr) {
  int i;
#ifdef DEBUG
  char buf[64];
#endif

#ifdef DEBUG
  traceEvent(TRACE_INFO, "isLocalAddress(%s)",
	     _intoaV4(ntohl(addr->s_addr), buf, sizeof(buf)));
#endif

  /* If unset all the addresses are local */
  if(readOnlyGlobals.numLocalNetworks == 0) return(1);

  for(i=0; i<readOnlyGlobals.numLocalNetworks; i++)
    if((addr->s_addr & localNetworks[i][CONST_NETMASK_ENTRY])
       == localNetworks[i][CONST_NETWORK_ENTRY]) {
#ifdef DEBUG
      traceEvent(TRACE_INFO, "%s is local",
		 _intoaV4(ntohl(addr->s_addr), buf, sizeof(buf)));
#endif
      return 1;
    }

#ifdef DEBUG
  traceEvent(TRACE_INFO, "%s is NOT local",
	     _intoaV4(ntohl(addr->s_addr), buf, sizeof(buf)));
#endif
  return(0);
}

/* ************************************************ */

u_short isBlacklistedAddress(struct in_addr *addr) {
  int i;
#ifdef DEBUG
  char buf[64];
#endif

  /* If unset is not blacklisted */
  if(readOnlyGlobals.numBlacklistNetworks == 0) return(0);

  for(i=0; i<readOnlyGlobals.numBlacklistNetworks; i++)
    if((addr->s_addr & blacklistNetworks[i][CONST_NETMASK_ENTRY])
       == blacklistNetworks[i][CONST_NETWORK_ENTRY]) {

#ifdef DEBUG
      traceEvent(TRACE_INFO, "%s is blacklisted",
		 _intoaV4(ntohl(addr->s_addr), buf, sizeof(buf)));
#endif
      return 1;
    }

#ifdef DEBUG
  traceEvent(TRACE_INFO, "%s is NOT blacklisted",
	     _intoaV4(ntohl(addr->s_addr), buf, sizeof(buf)));
#endif
  return(0);
}

/* ************************************************ */

/* Utility function */
uint32_t str2addr(char *address) {
  int a, b, c, d;

  if(sscanf(address, "%d.%d.%d.%d", &a, &b, &c, &d) != 4) {
    return(0);
  } else
    return(((a & 0xff) << 24) + ((b & 0xff) << 16) + ((c & 0xff) << 8) + (d & 0xff));
}

/* ************************************************ */

static char hex[] = "0123456789ABCDEF";

char* etheraddr_string(const u_char *ep, char *buf) {
  u_int i, j;
  char *cp;

  cp = buf;
  if ((j = *ep >> 4) != 0)
    *cp++ = hex[j];
  else
    *cp++ = '0';

  *cp++ = hex[*ep++ & 0xf];

  for(i = 5; (int)--i >= 0;) {
    *cp++ = ':';
    if ((j = *ep >> 4) != 0)
      *cp++ = hex[j];
    else
      *cp++ = '0';

    *cp++ = hex[*ep++ & 0xf];
  }

  *cp = '\0';
  return (buf);
}

/* ************************************ */

void resetBucketStats(FlowHashBucket* bkt,
		      const struct pcap_pkthdr *h,
		      u_int len,
		      u_short sport, u_short dport,
		      u_char *payload, int payloadLen) {
  if(bkt->sport == sport) {
    bkt->flowCounters.bytesSent = len, bkt->flowCounters.pktSent = 1, bkt->flowCounters.bytesRcvd = bkt->flowCounters.pktRcvd = 0;
    memcpy(&bkt->flowTimers.firstSeenSent, &h->ts, sizeof(struct timeval));
    memcpy(&bkt->flowTimers.lastSeenSent, &h->ts, sizeof(struct timeval));
    memset(&bkt->flowTimers.firstSeenRcvd, 0, sizeof(struct timeval));
    memset(&bkt->flowTimers.lastSeenRcvd, 0, sizeof(struct timeval));
  } else {
    bkt->flowCounters.bytesSent = bkt->flowCounters.pktSent = 0, bkt->flowCounters.bytesRcvd = len, bkt->flowCounters.pktRcvd = 1;
    memset(&bkt->flowTimers.firstSeenRcvd, 0, sizeof(struct timeval));
    memset(&bkt->flowTimers.lastSeenRcvd, 0, sizeof(struct timeval));
    memcpy(&bkt->flowTimers.firstSeenSent, &h->ts, sizeof(struct timeval));
    memcpy(&bkt->flowTimers.lastSeenRcvd, &h->ts, sizeof(struct timeval));
  }

  if(bkt->src2dstPayload) { free(bkt->src2dstPayload);  bkt->src2dstPayload = NULL;  }
  if(bkt->dst2srcPayload) { free(bkt->dst2srcPayload); bkt->dst2srcPayload = NULL; }
  setPayload(bkt, h, payload, payloadLen, bkt->sport == sport ? 0 : 1);
}

/* ****************************************** */

/*
  UNIX was not designed to stop you from doing stupid things, because that
  would also stop you from doing clever things.
  -- Doug Gwyn
*/
void maximize_socket_buffer(int sock_fd, int buf_type) {
  int i, rcv_buffsize_base, rcv_buffsize, max_buf_size = 1024 * 2 * 1024 /* 2 MB */, debug = 0;
  socklen_t len = sizeof(rcv_buffsize_base);

  if(getsockopt(sock_fd, SOL_SOCKET, buf_type, &rcv_buffsize_base, &len) < 0) {
    traceEvent(TRACE_ERROR, "Unable to read socket receiver buffer size [%s]",
	       strerror(errno));
    return;
  } else {
    if(debug) traceEvent(TRACE_INFO, "Default socket %s buffer size is %d",
			 buf_type == SO_RCVBUF ? "receive" : "send",
			 rcv_buffsize_base);
  }

  for(i=2;; i++) {
    rcv_buffsize = i * rcv_buffsize_base;
    if(rcv_buffsize > max_buf_size) break;

    if(setsockopt(sock_fd, SOL_SOCKET, buf_type, &rcv_buffsize, sizeof(rcv_buffsize)) < 0) {
      if(debug) traceEvent(TRACE_ERROR, "Unable to set socket %s buffer size [%s]",
			   buf_type == SO_RCVBUF ? "receive" : "send",
			   strerror(errno));
      break;
    } else
      if(debug) traceEvent(TRACE_INFO, "%s socket buffer size set %d",
			   buf_type == SO_RCVBUF ? "Receive" : "Send",
			   rcv_buffsize);
  }
}

/* ****************************************** */

#ifdef linux

/* /usr/local/bin/setethcore <eth2> <core Id> */
#define SET_NETWORK_CARD_AFFINITY   "/usr/local/bin/setethcore"

void setCpuAffinity(char *dev_name, int cpuId) {
  pid_t p = 0; /* current process */
  int ret;
  cpu_set_t cpu_set;
  int numCpus = sysconf(_SC_NPROCESSORS_CONF);

  if(cpuId < 0) return; /* No affinity */

  traceEvent(TRACE_INFO, "This computer has %d processor(s)\n", numCpus);

  if(cpuId > numCpus) {
    traceEvent(TRACE_ERROR, "The CPU id you selected (%d) is greather than the", cpuId);
    traceEvent(TRACE_ERROR, "number of available processor(s) [%d]", numCpus);
    return;
  }

  CPU_ZERO(&cpu_set);
  CPU_SET(cpuId, &cpu_set);

  ret = sched_setaffinity(p, sizeof(cpu_set_t), &cpu_set);

  if(ret == 0) {
    traceEvent(TRACE_NORMAL, "CPU affinity successfully set (CPU Id %d)",
	       cpuId);

    if(dev_name != NULL) {
      struct stat stats;
      
      if(stat(SET_NETWORK_CARD_AFFINITY, &stats) == 0) {
	char affinity_buf[256];
	int ret;
	
	snprintf(affinity_buf, sizeof(affinity_buf), "%s %s %d",
		 SET_NETWORK_CARD_AFFINITY,
		 dev_name,
		 cpuId);
	
	ret = system(affinity_buf);
	traceEvent(TRACE_NORMAL, "Executed %s (ret: %d)", affinity_buf, ret);
      } else {
	traceEvent(TRACE_NORMAL, "Missing %s: unable to set %s affinity", 
		   SET_NETWORK_CARD_AFFINITY, dev_name);
      }
    } else {
      traceEvent(TRACE_NORMAL, "Unspecified card (-i missing): not setting card affinity");
    }
  } else
    traceEvent(TRACE_ERROR, "Unable to set CPU affinity to %08lx [ret: %d]",
	       cpu_set, ret);
}
#endif
