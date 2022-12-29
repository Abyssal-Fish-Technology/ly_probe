/*
 *  Contact Us: abyssalfish <opensource@abyssalfish.com.cn>
 *
 *             http://www.abyssalfish.com.cn/
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
#include "pcre.h"
#include "cJSON.h"

#if defined(HAVE_PCRE_H) && defined(HAVE_LIBPCRE)

#define GET_URL         "GET /"
#define POST_URL        "POST /"
#define HTTP_1          "HTTP/1"

#define BASE_ID         NTOP_BASE_ID+220

#define SRV_TYPE_LEN    32
#define SRV_NAME_LEN    32
#define SRV_VERS_LEN    16
#define DEV_TYPE_LEN    32
#define DEV_NAME_LEN    32
#define DEV_VEND_LEN    32
#define DEV_VERS_LEN    16
#define OS_TYPE_LEN     32
#define OS_NAME_LEN     32
#define OS_VERS_LEN     16
#define MID_TYPE_LEN    32
#define MID_NAME_LEN    32
#define MID_VERS_LEN    16
#define THREAT_TYPE_LEN 32
#define THREAT_NAME_LEN 32
#define THREAT_VERS_LEN 16
#define FP_TIME_LEN     8
#define FP_INDEX_LEN    16

#define VER_ARGS_NUM    2
#define SKIP_PKT_COUNT  10
#define PCAP_FILE_TIMEOUT 300

static V9V10TemplateElementId SrvPlugin_template[] = {
  { FLOW_TEMPLATE, NTOP_ENTERPRISE_ID, BASE_ID+0,  SRV_TYPE_LEN, ascii_format, dump_as_ascii, "SRV_TYPE", "Type of SERVICE." },
  { FLOW_TEMPLATE, NTOP_ENTERPRISE_ID, BASE_ID+1,  SRV_NAME_LEN, ascii_format, dump_as_ascii, "SRV_NAME", "Name of SERVICE." },
  { FLOW_TEMPLATE, NTOP_ENTERPRISE_ID, BASE_ID+2,  SRV_VERS_LEN, ascii_format, dump_as_ascii, "SRV_VERS", "extract version information from packet." },

  { FLOW_TEMPLATE, NTOP_ENTERPRISE_ID, BASE_ID+3,  DEV_TYPE_LEN, ascii_format, dump_as_ascii, "DEV_TYPE", "Type of DEVICE." },
  { FLOW_TEMPLATE, NTOP_ENTERPRISE_ID, BASE_ID+4,  DEV_NAME_LEN, ascii_format, dump_as_ascii, "DEV_NAME", "Name of DEVICE." },
  { FLOW_TEMPLATE, NTOP_ENTERPRISE_ID, BASE_ID+5,  DEV_VEND_LEN, ascii_format, dump_as_ascii, "DEV_VEND", "Vendor of DEVICE." },
  { FLOW_TEMPLATE, NTOP_ENTERPRISE_ID, BASE_ID+6,  DEV_VERS_LEN, ascii_format, dump_as_ascii, "DEV_VERS", "extract version information from packet." },

  { FLOW_TEMPLATE, NTOP_ENTERPRISE_ID, BASE_ID+7,  OS_TYPE_LEN,  ascii_format, dump_as_ascii, "OS_TYPE", "Type of OS." },
  { FLOW_TEMPLATE, NTOP_ENTERPRISE_ID, BASE_ID+8,  OS_NAME_LEN,  ascii_format, dump_as_ascii, "OS_NAME", "Name of OS." },
  { FLOW_TEMPLATE, NTOP_ENTERPRISE_ID, BASE_ID+9,  OS_VERS_LEN,  ascii_format, dump_as_ascii, "OS_VERS", "extract version information from packet." },

  { FLOW_TEMPLATE, NTOP_ENTERPRISE_ID, BASE_ID+10, MID_TYPE_LEN, ascii_format, dump_as_ascii, "MID_TYPE", "Type of MIDDLEWARE." },
  { FLOW_TEMPLATE, NTOP_ENTERPRISE_ID, BASE_ID+11, MID_NAME_LEN, ascii_format, dump_as_ascii, "MID_NAME", "Name of MIDDLEWARE." },
  { FLOW_TEMPLATE, NTOP_ENTERPRISE_ID, BASE_ID+12, MID_VERS_LEN, ascii_format, dump_as_ascii, "MID_VERS", "extract version information from packet." },

  { FLOW_TEMPLATE, NTOP_ENTERPRISE_ID, BASE_ID+13, THREAT_TYPE_LEN, ascii_format, dump_as_ascii, "THREAT_TYPE", "Type of THREAT." },
  { FLOW_TEMPLATE, NTOP_ENTERPRISE_ID, BASE_ID+14, THREAT_NAME_LEN, ascii_format, dump_as_ascii, "THREAT_NAME", "Name of THREAT." },
  { FLOW_TEMPLATE, NTOP_ENTERPRISE_ID, BASE_ID+15, THREAT_VERS_LEN, ascii_format, dump_as_ascii, "THREAT_VERS", "extract version information from packet." },

  { FLOW_TEMPLATE, NTOP_ENTERPRISE_ID, BASE_ID+16, FP_TIME_LEN, numeric_format, dump_as_uint, "SRV_TIME", "Timestamp of SERVICE," },
  { FLOW_TEMPLATE, NTOP_ENTERPRISE_ID, BASE_ID+17, FP_TIME_LEN, numeric_format, dump_as_uint, "DEV_TIME", "Timestamp of DEVICE," },
  { FLOW_TEMPLATE, NTOP_ENTERPRISE_ID, BASE_ID+18, FP_TIME_LEN, numeric_format, dump_as_uint, "OS_TIME", "Timestamp of OS," },
  { FLOW_TEMPLATE, NTOP_ENTERPRISE_ID, BASE_ID+19, FP_TIME_LEN, numeric_format, dump_as_uint, "MID_TIME", "Timestamp of MIDDLEWARE," },
  { FLOW_TEMPLATE, NTOP_ENTERPRISE_ID, BASE_ID+20, FP_TIME_LEN, numeric_format, dump_as_uint, "THREAT_TIME", "Timestamp of THREAT," },

  { FLOW_TEMPLATE, NTOP_ENTERPRISE_ID, BASE_ID+28, FP_INDEX_LEN, ascii_format, dump_as_ascii, "THREAT_INDEX", "INDEX of Threat Match." },

  { FLOW_TEMPLATE, NTOP_ENTERPRISE_ID, 0, 0, 0, 0, NULL, NULL }
};

/* netflow 中 pluginData 所存储的数据结构 */
#define TYPE_SERVICE    1 
#define TYPE_DEVICE     2 
#define TYPE_OS         3 
#define TYPE_MIDDLEWARE 4
#define TYPE_THREAT     5

struct pkt_time_t{
  u_int64_t pkt_sec;
  u_int64_t pkt_usec;
};

struct plugin_info {
  u_int32_t conf_type; 
  // u_int32_t pat_type_priority; //数值大的优先级高，优先级相同时，以第一次命中为准

  // service类规则命中结果
  char *srv_type;
  char *srv_name;
  char srv_vers[SRV_VERS_LEN];
  u_int64_t srv_time;

  // device类规则命中结果
  char *dev_type;
  char *dev_name;
  char *dev_vendor;
  char dev_vers[DEV_VERS_LEN];
  u_int64_t dev_time;

  // os类规则命中结果
  char *os_type;
  char *os_name;
  char os_vers[OS_VERS_LEN];
  u_int64_t os_time;

  // middleware类规则命中结果
  char *mid_type;
  char *mid_name;
  char mid_vers[MID_VERS_LEN];
  u_int64_t mid_time;

  // threat类规则命中结果
  char *threat_type;
  char *threat_name;
  char threat_vers[THREAT_VERS_LEN];
  u_int64_t threat_time;
  char threat_index[FP_INDEX_LEN];

  u_short pkt_count;      // 一条flow累计匹配的数据包数量
  u_int8_t flow_checked;  // 标识是否已命中规则，srv: 0x01;dev: 0x02
  IpAddress srcip;        // 识别结果标签标记在目标为src的flow上

  u_int64_t src_time;
  u_int64_t dst_time;
};

/* 配置文件中，规则的存储结构 */
struct common_pat_info {
  char *type;
  u_int id;
  char *name;           /* pattern name */
  char *vendor;           /* pattern vendor */
  u_int protocol;       /* using protocol & port to filtering packets */
#define  PAT_TCP    6
#define  PAT_UDP    17
// #define  PAT_HTTP   255
  u_int port;
  u_int is_http;
  u_int part;
#define  HTTP_HEAD  1
#define  HTTP_BODY  2
#define  HTTP_TOTAL 3
  // u_int reverse;
  char *version;
  char *os;
  pcre *pat_regex;      /* result of pcre_compile*/
  pcre_extra *pat_extra;/* result of pcre_study */
  struct common_pat_info *next;/* pointer to next pattern */
};

/* 用于传递给线程函数的参数 */
struct pthread_argv_t{
  u_int8_t type;
  u_int is_http;
  u_short protocol;
  IpAddress *src;
  IpAddress *dst;
  u_short sport;
  u_short dport;
  u_int subject_length;
  u_int head_length;
  struct pkt_time_t pkt_time;
  u_char **subject_string;
  struct plugin_info **pinfo;
};

/* *********************************************** */
#define PAT_TYPE_NUM  5

static char *patDirs[] = { 
            "./fp-patterns",
            "/bin/plugins/fp-patterns",
            "/usr/local/lib/lyprobe/plugins/fp-patterns",
            "/usr/local/lyprobe/lib/lyprobe/plugins/fp-patterns",
            "/bin/plugins/service-patterns",
            NULL };
static char *patterns_name[PAT_TYPE_NUM] = {"service", "device", "os", "midware","threat"};
static u_int32_t patterns_priority[PAT_TYPE_NUM];
static struct common_pat_info *patterns[PAT_TYPE_NUM];

const char* os_type = "OS";

/* ******************************************** */

static PluginInfo SrvPlugin; /* Forward */

// extern int cmpIpAddress(IpAddress *src, IpAddress *dst);
extern void SavePktToPcap(const struct pcap_pkthdr *h, const u_char *p);
extern void ClosePcapFile(void);

/* ******************************************* */
bool cmpIpAddress_s(IpAddress IPA, IpAddress IPB) {
  if(IPA.ipVersion == IPB.ipVersion){
    if(IPA.ipVersion == 4){
      if( !memcmp((void *)&IPA.ipType, (void *)&IPB.ipType, sizeof(u_int32_t)) )
        return 1;
    } else if(IPA.ipVersion == 6){
      if( !memcmp((void *)&IPA.ipType, (void *)&IPB.ipType, sizeof(struct in6_addr)) )
        return 1;
    }
  }
  return 0;
}

void PrintLoadedPatterns(){
  int i=0;
  for(; i < PAT_TYPE_NUM; i++){
    struct common_pat_info *pat = patterns[i];
    int j = 0;
    while(pat){
      j++;
      traceEvent(TRACE_INFO, "type %d, num %d, name: %s", i, j, pat->name);
      pat = pat->next;  
    }
  }
}

/* Read config file */
char *readTextFile(char *file_path) {
  char *file_string;
  if(readOnlyGlobals.traceMode) traceEvent(TRACE_INFO, "Read config file from %s.", file_path);
  FILE *pf = fopen(file_path,"r");
  if (!pf){
    traceEvent(TRACE_WARNING, "Can't open file %s.", file_path);
    return NULL;
  }

  fseek(pf,0,SEEK_END);
  long lSize = ftell(pf);
  file_string = (char *)malloc(lSize+1);
  if (file_string == NULL){
    traceEvent(TRACE_ERROR, "Not enough space for read config file.");
    return NULL;
  }

  rewind(pf);
  size_t count = fread(file_string,sizeof(char),lSize,pf);
  if (count < 1) {
    traceEvent(TRACE_ERROR, "Can't read config file of ServicePlugin.");
    return NULL;
  }
  file_string[lSize] = '\0';

  // traceEvent(TRACE_INFO, "config file total(%d) read(%d):\n%s", lSize, count, file_string);

  fclose(pf);
  return file_string;
}

/* Parse the config file, using cJSON */
static int loadPattern(const char *file_string, u_int32_t pattern_type) {
  cJSON *file_obj, *class_obj, *pat_obj, *priority_obj, *rules_obj;
  cJSON *type_obj, *is_http_obj, /* *reverse_obj, */ *version_obj, *os_obj;
  cJSON *name_obj, *proto_obj, *port_obj, *part_obj, *regex_obj, *vendor_obj;
  cJSON *del_obj;
  int port_num = 0, part_num = 0, /* reverse = 0, */ is_http = 0;
  char *type_string, *name_string, *proto_string, *regex_string, *part_string, *vendor_string, *version_string, *os_string;
  int num_patterns = 0;

  //读取整个json文件
  file_obj = cJSON_Parse(file_string);
  if (file_obj == NULL){
    const char *cjson_error = cJSON_GetErrorPtr();
    traceEvent(TRACE_ERROR, "cJSON_Parse return NULL. Error msg: %s", cjson_error);
    return -1;
  }
  if(readOnlyGlobals.traceMode) traceEvent(TRACE_INFO, "pattern_type %d: %s", pattern_type, patterns_name[pattern_type]);
  class_obj = file_obj->child;

  if (cJSON_IsInvalid(class_obj) || cJSON_IsNull(class_obj)){
  // if (cJSON_GetArraySize(class_obj) == 0){
    traceEvent(TRACE_WARNING, "type:[%s] is empty.", class_obj->string);
    return -1;
  }

  //每类规则的优先级
  priority_obj = cJSON_GetObjectItem(class_obj, "priority");
  if ( cJSON_IsNumber(priority_obj)) {
    patterns_priority[pattern_type] = cJSON_GetNumberValue(priority_obj);
  }
  if(readOnlyGlobals.traceMode) traceEvent(TRACE_INFO, "%s pattern priority: %d", class_obj->string, patterns_priority[pattern_type]);

  rules_obj = cJSON_GetObjectItem(class_obj, "rules");

  //循环逐条处理每类规则中的匹配规则
  struct common_pat_info *pat_head = (struct common_pat_info*)malloc(sizeof(struct common_pat_info));
  struct common_pat_info *pat_rear = NULL;
  pat_head->next = NULL;
  pat_rear = pat_head;
  int pat_num = 0;
  cJSON_ArrayForEach(pat_obj, rules_obj){
    if (cJSON_IsInvalid(pat_obj) ||  cJSON_IsNull(pat_obj)){
      traceEvent(TRACE_INFO, "Pattern Invalid or is Empty.");
      break;
    }

    // 若配置该字段，则跳过此条规则
    if (del_obj = cJSON_GetObjectItem(pat_obj, "deleted")){
      if (cJSON_IsNumber(del_obj)) {
        if((int)cJSON_GetNumberValue(del_obj))
          continue;
      }
    }

    // 为新建pattern分配空间
    struct common_pat_info *new_pat = (struct common_pat_info*)malloc(sizeof(struct common_pat_info));
    if(new_pat == NULL) {
      traceEvent(TRACE_WARNING, "Not enough memory while loading pattern");
      return num_patterns;
    }
    memset(new_pat, 0, sizeof(struct common_pat_info));
    new_pat->type = NULL; new_pat->name = NULL; new_pat->vendor = NULL;
    new_pat->version = NULL; new_pat->os = NULL;
    new_pat->pat_regex = NULL; new_pat->pat_extra = NULL;
    new_pat->id = atoi(pat_obj->string);
    

    // pattern的类型
    if (type_obj = cJSON_GetObjectItem(pat_obj, "type")){
      if (cJSON_IsString(type_obj)) {
        type_string = cJSON_GetStringValue(type_obj);
        new_pat->type = strdup(type_string);
      } else {
        traceEvent(TRACE_WARNING, "[%s]Pattern `type` is not String.", pat_obj->string);
        free(new_pat);
        continue;
      }
    } else {
      /* 必须配置type选项 */
      traceEvent(TRACE_WARNING, "[%s]Not config pattern `type`.", pat_obj->string);
      free(new_pat);
      continue;
    }

    // pattern的名称
    if (name_obj = cJSON_GetObjectItem(pat_obj, "name")){
      if (cJSON_IsString(name_obj)) {
        name_string = cJSON_GetStringValue(name_obj);
        new_pat->name = strdup(name_string);
        if(readOnlyGlobals.traceMode)
          traceEvent(TRACE_INFO, "loading pattern %d %s.", new_pat->id, new_pat->name);
      } else {
        traceEvent(TRACE_WARNING, "[%s]Pattern `name` is not String.", pat_obj->string);
        free(new_pat);
        continue;
      }
    } else {
      /* 必须配置name选项 */
      traceEvent(TRACE_WARNING, "[%s]Not config pattern `name`.", pat_obj->string);
      free(new_pat);
      continue;
    }

    // pattern的厂商
    if (vendor_obj = cJSON_GetObjectItem(pat_obj, "vendor")){
      if (cJSON_IsString(vendor_obj)) {
        vendor_string = cJSON_GetStringValue(vendor_obj);
        new_pat->vendor = strdup(vendor_string);
      } else {
        traceEvent(TRACE_WARNING, "[%s]Pattern `vendor` is not String.", pat_obj->string);
        new_pat->vendor = NULL;
      }
    }

    // 配置 协议对数据包进行预先分类
    if (proto_obj = cJSON_GetObjectItem(pat_obj, "protocol")){
      if (cJSON_IsString(proto_obj)) {
        proto_string = cJSON_GetStringValue(proto_obj);
        if (!strcasecmp(proto_string, "TCP"))
          new_pat->protocol = PAT_TCP;
        else if (!strcasecmp(proto_string, "UDP"))
          new_pat->protocol = PAT_UDP;
        else
          traceEvent(TRACE_WARNING, "[%s]Unknown protocol `%s`, match all protocols", pat_obj->string, proto_string);
      }
    }
    
    // 指定仅识别HTTP协议内容
    if (is_http_obj = cJSON_GetObjectItem(pat_obj, "is_http")){
      if (cJSON_IsNumber(is_http_obj)) {
        is_http = (int)cJSON_GetNumberValue(is_http_obj);
        new_pat->is_http = is_http;
      }
    }

    // 指定识别HTTP数据包的Header或Body
    if (part_obj = cJSON_GetObjectItem(pat_obj, "part")){
      if (cJSON_IsString(part_obj)) {
        part_string = cJSON_GetStringValue(part_obj);

        if (strcmp(part_string, "head")==0)
          new_pat->part = 1;
        else if (!strcmp(part_string, "body"))
          new_pat->part = 2;
        else if (!strcmp(part_string, "total"))
          new_pat->part = 3;
        else{
          traceEvent(TRACE_WARNING, "[%s]Unknown part of http '%s', match the whole packet.", pat_obj->string, part_string);
          new_pat->part = 3;
        }
      }
    }
    
    // 指定识别端口
    if (port_obj = cJSON_GetObjectItem(pat_obj, "port")){
      if (cJSON_IsNumber(port_obj)) {
        port_num = (int)cJSON_GetNumberValue(port_obj);
        new_pat->port = port_num;
      }
    }
    
    // 指定规则方向（弃用，默认所有规则均匹配识别目标所发出数据）
    /*if (reverse_obj = cJSON_GetObjectItem(pat_obj, "reverse")){
      if (cJSON_IsNumber(reverse_obj)) {
        reverse = (int)cJSON_GetNumberValue(reverse_obj);
        new_pat->reverse = reverse;
      }
    }*/

    // pattern的版本型号信息，若配置则为固定字符串，未配置则通过规则提取第一个子匹配
    if (version_obj = cJSON_GetObjectItem(pat_obj, "version")){
      if (cJSON_IsString(version_obj)) {
        version_string = cJSON_GetStringValue(version_obj);
        new_pat->version = strdup(version_string);
        // traceEvent(TRACE_INFO, "new_pat->version: %s; position: %d", new_pat->version, new_pat->ver_vars[0]);
      } else {
        traceEvent(TRACE_WARNING, "[%s]Pattern `version` is not String.", pat_obj->string);
        new_pat->version = NULL;
      }
    }

    // 附加的OS字段，其他类型规则推定的OS
    if (os_obj = cJSON_GetObjectItem(pat_obj, "os")){
      if (cJSON_IsString(os_obj)) {
        os_string = cJSON_GetStringValue(os_obj);
        new_pat->os = strdup(os_string);
        // if(readOnlyGlobals.traceMode) traceEvent(TRACE_INFO, "new_pat->os: %s; position: %d", new_pat->os, new_pat->os_vars[0]);
      }
    }

    // pattern的正则表达式
    if (regex_obj = cJSON_GetObjectItem(pat_obj, "regex")){
      if ( cJSON_IsString(regex_obj)) {
        regex_string = cJSON_GetStringValue(regex_obj);
        // traceEvent(TRACE_INFO, "regex_string '%s'", regex_string);

        const char *error;
        int erroffset;

        // traceEvent(TRACE_INFO, "[%s][%s]: \"%s\"", class_obj->string, new_pat->name, regex_string);
        new_pat->pat_regex = pcre_compile(regex_string,               /* the pattern */
                PCRE_CASELESS,        /* default options */
                &error,               /* for error message */
                &erroffset,           /* for error offset */
                NULL);                /* use default character tables */
        
        if(new_pat->pat_regex == NULL) {
          if(new_pat->name != NULL) free(new_pat->name);
          traceEvent(TRACE_WARNING, "[%s]Invalid pattern \"%s\". Skipped.", pat_obj->string, regex_string);
          free(new_pat);
          continue;
          // return(NULL);
        } else {
          // traceEvent(TRACE_INFO, "Service: [%s][%s]", pat_head->pat_type, regex_string); 
          new_pat->pat_extra = pcre_study(new_pat->pat_regex, PCRE_STUDY_JIT_COMPILE, &error);
          if(new_pat->pat_extra == NULL)
            traceEvent(TRACE_WARNING, "Could not find additional information, or there was an error.[%d]", part_num);
          // pcre_assign_jit_stack(new_pat->pat_extra, NULL, jit_stack);
        }
      } else {
        traceEvent(TRACE_WARNING, "[%s]Pattern `regex` is not String.", pat_obj->string);
        free(new_pat);
        continue;
      }
    } else {
      traceEvent(TRACE_WARNING, "[%s]Not config pattern `regex`.", pat_obj->string);
      free(new_pat);
      continue;
    }

    pat_num ++;
    new_pat->next = NULL;
    pat_rear->next = new_pat;
    pat_rear = new_pat;
  }
  pat_rear->next = NULL;
  traceEvent(TRACE_NORMAL, ">load %d %s patterns.", pat_num, class_obj->string);

  if(pat_head){
    patterns[pattern_type] = pat_head;
    num_patterns += pat_num;
  } else {
    free(pat_head);
    patterns[pattern_type] = NULL;
  }

  //free space
  cJSON_Delete(file_obj);

  return(num_patterns);
}

/* Match regex rules */
bool RegexFunc1(u_int8_t argv_type, struct pthread_argv_t *p){

  int output[30] = {0};
  int head_length = p->head_length;
  int subject_length = p->subject_length;
  u_char *subject_string = *(p->subject_string);
  struct plugin_info *pinfo = *(p->pinfo);
  u_int8_t argv_type_index;
  argv_type_index = argv_type - 1;

  // traceEvent(TRACE_INFO, "pkt: protocol %d, sport %d, dport %d", p->protocol, p->sport, p->dport);
  if(readOnlyGlobals.traceMode==2)
    traceEvent(TRACE_INFO, "pkt: subject_length %d, head_length %d, subject_string :\n%s", p->subject_length, p->head_length, *(p->subject_string));
  if(patterns[argv_type_index] == NULL)
    return;
  struct common_pat_info *pat = patterns[argv_type_index]->next;
  while(pat){
    if( !(pinfo->flow_checked & (1 << argv_type_index)) ) {
      // traceEvent(TRACE_INFO, "pat %s:%s, protocol %d, port %d", pat->type, pat->name, pat->protocol, pat->port);
      //跳过不适合的pat0
      
      u_char* subject_string_tmp = subject_string;
      int subject_length_tmp = subject_length;

      if (pat->port != 0 && (pat->port != p->sport && pat->port != p->dport)) { pat = pat->next; continue; }
      if (pat->protocol == PAT_UDP && p->protocol != IPPROTO_UDP) { pat = pat->next; continue; }
      if (pat->protocol == PAT_TCP && p->protocol != IPPROTO_TCP) { pat = pat->next; continue; }
      if (pat->is_http && !p->is_http) { pat = pat->next; continue; }
      
      if (pat->is_http){
        switch(pat->part){
          case HTTP_HEAD:
            subject_length_tmp = head_length;
            break;
          case HTTP_BODY:
            subject_length_tmp = subject_length - head_length;
            subject_string_tmp = subject_string + subject_length + 4;
            break;
          case HTTP_TOTAL:
          default:
            break;
        }
        if(subject_length_tmp <= 0){
          pat = pat->next;
          continue;
        }
      }

      // traceEvent(TRACE_INFO, "Done escape specific protocol/port, subject_length %d.", subject_length);
      // traceEvent(TRACE_INFO, "payload(%d): %s", subject_length, subject_string);
      int rc = pcre_exec(pat->pat_regex,    /* the compiled pattern */
                       pat->pat_extra,      /* extra data - study the pattern */
                       subject_string_tmp,  /* the subject string */
                       subject_length_tmp,  /* the length of the subject */
                       0,                   /* start at offset 0 in the subject */
                       0 /*PCRE_PARTIAL*/,  /* default options */
                       output,              /* output vector for substring information */
                       30);                 /* number of elements in the output vector */
      
      // traceEvent(TRACE_NORMAL, "pcre_exec() return %d.", rc);
      if(rc>=0){
        // traceEvent(TRACE_NORMAL, "---> Flow matched pattern %d:%s:%s(%s)", pat->id, pat->type, pat->name, pat->version); 
        pinfo->srcip = *(p->src);

        switch(argv_type){
          case TYPE_SERVICE:{
            pinfo->srv_time = p->pkt_time.pkt_sec*1000000 + p->pkt_time.pkt_usec;
            pinfo->srv_type = pat->type;
            pinfo->srv_name = pat->name;
            pinfo->flow_checked = pinfo->flow_checked | 0x01;

            if (pat->os){
              pinfo->os_time = pinfo->srv_time;
              pinfo->os_type = (char*)os_type;
              pinfo->os_name = pat->os;
              pinfo->flow_checked = pinfo->flow_checked | 0x04;
            }

            memset(pinfo->srv_vers, 0, sizeof(char) * SRV_VERS_LEN);
            if (pat->version == NULL && rc >= 2) {
              pcre_copy_substring(subject_string_tmp, output, rc, 1, pinfo->srv_vers, SRV_VERS_LEN);
            } else if (pat->version != NULL && rc >= 1) {
              int val_len = min(strlen(pat->version), SRV_VERS_LEN-1);
              memcpy(pinfo->srv_vers, (char *)pat->version, val_len);
              pinfo->srv_vers[SRV_VERS_LEN-1] = '\0';
            }

            if(readOnlyGlobals.traceMode)
              traceEvent(TRACE_NORMAL, "---> Flow matched %s => %d:%s:%s(%s)", patterns_name[argv_type_index], pat->id, pinfo->srv_type, pinfo->srv_name, pinfo->srv_vers); 
            break;
          }
          case TYPE_DEVICE:{
            pinfo->dev_time = p->pkt_time.pkt_sec*1000000 + p->pkt_time.pkt_usec;
            pinfo->dev_type = pat->type;
            pinfo->dev_name = pat->name;
            if (pat->vendor){
              pinfo->dev_vendor = pat->vendor;
            }
            pinfo->flow_checked = pinfo->flow_checked | 0x02;

            if (pat->os){
              pinfo->os_time = pinfo->dev_time;
              pinfo->os_type = (char*)os_type;
              pinfo->os_name = pat->os;
              pinfo->flow_checked = pinfo->flow_checked | 0x04;
            }

            memset(pinfo->dev_vers, 0, sizeof(char) * DEV_VERS_LEN);
            if (pat->version == NULL && rc >= 2) {
              pcre_copy_substring(subject_string_tmp, output, rc, 1, pinfo->dev_vers, DEV_VERS_LEN);
            } else if (pat->version != NULL && rc >= 1) {
              int val_len = min(strlen(pat->version), DEV_VERS_LEN-1);
              memcpy(pinfo->dev_vers, (char *)pat->version, val_len);
              pinfo->dev_vers[DEV_VERS_LEN-1] = '\0';
            }

            if(readOnlyGlobals.traceMode)
                traceEvent(TRACE_NORMAL, "---> Flow matched %s => %d:%s:%s:%s(%s)", patterns_name[argv_type_index], pat->id, pinfo->dev_type, pinfo->dev_vendor, pinfo->dev_name, pinfo->dev_vers); 
            break;
          }
          case TYPE_OS:{
            pinfo->os_time = p->pkt_time.pkt_sec*1000000 + p->pkt_time.pkt_usec;
            pinfo->os_type = pat->type;
            pinfo->os_name = pat->name;
            pinfo->flow_checked = pinfo->flow_checked | 0x04;

            memset(pinfo->os_vers, 0, sizeof(char) * OS_VERS_LEN);
            if (pat->version == NULL && rc >= 2) {
              pcre_copy_substring(subject_string_tmp, output, rc, 1, pinfo->os_vers, OS_VERS_LEN);
            } else if (pat->version != NULL && rc >= 1) {
              int val_len = min(strlen(pat->version), OS_VERS_LEN-1);
              memcpy(pinfo->os_vers, (char *)pat->version, val_len);
              pinfo->os_vers[OS_VERS_LEN-1] = '\0';
            }

            if(readOnlyGlobals.traceMode)
              traceEvent(TRACE_NORMAL, "---> Flow matched %s => %d:%s:%s", patterns_name[argv_type_index], pat->id, pinfo->os_type, pinfo->os_name); 
            break;
          }
          case TYPE_MIDDLEWARE:{
            pinfo->mid_time = p->pkt_time.pkt_sec*1000000 + p->pkt_time.pkt_usec;
            pinfo->mid_type = pat->type;
            pinfo->mid_name = pat->name;
            pinfo->flow_checked = pinfo->flow_checked | 0x08;

            if (pat->os){
              pinfo->os_time = pinfo->mid_time;
              pinfo->os_type = (char*)os_type;
              pinfo->os_name = pat->os;
              pinfo->flow_checked = pinfo->flow_checked | 0x04;
            }

            memset(pinfo->mid_vers, 0, sizeof(char) * MID_VERS_LEN);
            if (pat->version == NULL && rc >= 2) {
              pcre_copy_substring(subject_string_tmp, output, rc, 1, pinfo->mid_vers, MID_VERS_LEN);
            } else if (pat->version != NULL && rc >= 1) {
              int val_len = min(strlen(pat->version), MID_VERS_LEN-1);
              memcpy(pinfo->mid_vers, (char *)pat->version, val_len);
              pinfo->mid_vers[MID_VERS_LEN-1] = '\0';
            }

            if(readOnlyGlobals.traceMode)
              traceEvent(TRACE_NORMAL, "---> Flow matched %s => %d:%s:%s(%s)", patterns_name[argv_type_index], pat->id, pinfo->mid_type, pinfo->mid_name, pinfo->mid_vers); 
            break;
          }
          case TYPE_THREAT:{
            pinfo->src_time = p->pkt_time.pkt_sec*1000000 + p->pkt_time.pkt_usec;
            pinfo->dst_time = 0;

            pinfo->threat_time = pinfo->src_time;
            pinfo->threat_type = pat->type;
            pinfo->threat_name = pat->name;
            pinfo->flow_checked = pinfo->flow_checked | 0x10;

            if (pat->os){
              pinfo->os_time = pinfo->threat_time;
              pinfo->os_type = (char*)os_type;
              pinfo->os_name = pat->os;
              pinfo->flow_checked = pinfo->flow_checked | 0x04;
            }

            memset(pinfo->threat_index, 0, sizeof(char) * FP_INDEX_LEN);

            if (output[3]!=0) {
              snprintf(pinfo->threat_index, FP_INDEX_LEN, "%d,%d", output[2], output[3]);
            } else {
              snprintf(pinfo->threat_index, FP_INDEX_LEN, "%d,%d", output[0], output[1]);
            }
            // traceEvent(TRACE_WARNING, "pinfo->threat_index: %s", pinfo->threat_index);
            
            memset(pinfo->threat_vers, 0, sizeof(char) * THREAT_VERS_LEN);
            if (pat->version == NULL && rc >= 2) {
              pcre_copy_substring(subject_string_tmp, output, rc, 1, pinfo->threat_vers, THREAT_VERS_LEN);
            } else if (pat->version != NULL && rc >= 1) {
              int val_len = min(strlen(pat->version), THREAT_VERS_LEN-1);
              memcpy(pinfo->threat_vers, (char *)pat->version, val_len);
              pinfo->threat_vers[THREAT_VERS_LEN-1] = '\0';
            }

            if(readOnlyGlobals.traceMode)
              traceEvent(TRACE_NORMAL, "---> Flow matched %s => %d:%s:%s(%s)", patterns_name[argv_type_index], pat->id, pinfo->threat_type, pinfo->threat_name, pinfo->threat_vers); 
            pinfo->flow_checked = pinfo->flow_checked | 0x10;
            break;
          }
          default:{
            traceEvent(TRACE_ERROR, "Invalid pattern type %d ", argv_type);
            break;
          }
        }
        // break;
        return 1;
      } else {
        // traceEvent(TRACE_INFO, "pattern(%s) unmatched %d ", pat->name, rc);
      }

      //not matched, turn to next pat.
      pat = pat->next;
    } else {
      break;
    }
  }
  return 0;
}

/* *********************************************** */

void SrvPlugin_init(int argc, char *argv[]) {
  int num_patterns = 0;
  char *file_string;

  if(readOnlyGlobals.traceMode) traceEvent(TRACE_NORMAL, "Initialized servicePlugin");
  
  int idp = 0;
  char dirPath[256];
  DIR* directoryPointer=NULL;

  for(idp = 0; patDirs[idp] != NULL; idp++) {
    snprintf(dirPath, sizeof(dirPath), "%s", patDirs[idp]);
    directoryPointer = opendir(dirPath);

    if(directoryPointer != NULL){
      traceEvent(TRACE_NORMAL, "Load pattern in %s", dirPath);
      break;
    }else{
      traceEvent(TRACE_NORMAL, "No pattern found in %s", dirPath);
      memset(dirPath, 0, sizeof(dirPath));
    }
  }

  if (patDirs[idp] == NULL) return;

  int i = 0;
  for (; i < PAT_TYPE_NUM; i++) {

    char *file_path = (char *)malloc(128 * sizeof(char));
    sprintf(file_path, "%s/%s.json", patDirs[idp], patterns_name[i]);
    file_string = readTextFile(file_path);
    if (file_string == NULL){
      if(readOnlyGlobals.traceMode) traceEvent(TRACE_WARNING, ">>No pattern Loaded.");
      continue; 
    }

    num_patterns += loadPattern(file_string, i);

    free(file_path);
    free(file_string);
  }

  // PrintLoadedPatterns();

  traceEvent(TRACE_NORMAL, ">>Loaded %d patterns totally.", num_patterns); 
}

/* *********************************************** */

/* Handler called whenever an incoming packet is received */

static void SrvPlugin_packet(u_char new_bucket, void *pluginData,
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
  // int output[30];

  // traceEvent(TRACE_INFO, "SrvPlugin_packet(%d)", payloadLen);
  if(new_bucket) {
    info = (PluginInformation*)malloc(sizeof(PluginInformation));
    if(info == NULL) {
      traceEvent(TRACE_ERROR, "Not enough memory?");
      return; /* Not enough memory */
    }

    info->pluginPtr  = (void*)&SrvPlugin;
    pluginData = info->pluginData = malloc(sizeof(struct plugin_info));
    if(info->pluginData == NULL) {
      traceEvent(TRACE_ERROR, "Not enough memory?");
      free(info);
      return; /* Not enough memory */
    } else{
      memset(info->pluginData, 0, sizeof(struct plugin_info));
    }

    info->next = bkt->plugin;
    bkt->plugin = info;
  }

  struct plugin_info *pinfo = (struct plugin_info*)pluginData;

  if (payloadLen > 0 && payloadLen  < 1500) {

    if(readOnlyGlobals.traceMode) traceEvent(TRACE_INFO, "Catched packet size %d.", payloadLen);
    // traceEvent(TRACE_INFO, "argv proto %d, isFragment 0x%02x, numPkts %d, tos 0x%02x, src %d..%d, sport %d, dst %d..%d, dport %d, len %d, flags 0x%02x, icmpType 0x%02x.",
    //     proto, isFragment, numPkts, tos, src[0], src[4], sport, dst[0], dst[4], dport, len, flags, icmpType);
    //traceEvent(TRACE_INFO, "Match packet %d (%s)", payloadLen, payload);
    //若已有命中的结果，则return；
    if(pinfo->flow_checked == 0x1F ) return;

    //若同一数据流检测的数据包数量超出设置的阈值，结束匹配，return；
    if( ++ pinfo->pkt_count > SKIP_PKT_COUNT ) {
      if(readOnlyGlobals.traceMode) traceEvent(TRACE_INFO, "After %d packets, still not recognized service. Skipping...", SKIP_PKT_COUNT); 
      pinfo->flow_checked = 0x1F;
      return;
    }

    //初始化一系列辅助变量，用于指向将要匹配的数据包以及匹配长度
    // int subject_length = (proto == IPPROTO_UDP) ? (len - sizeof(struct udphdr)) : payloadLen;
    int subject_length = payloadLen;
    int head_length = subject_length;
    u_char *subject_string, *body;

    subject_string = payload;
    body = payload;

    int has_save_pkt = 0;
    if(readOnlyGlobals.isSavePcapFile > 1 && pinfo->src_time == 0){
      pinfo->srcip = *src;
      SavePktToPcap(h, p);
      has_save_pkt = 1;
      pinfo->src_time = h->ts.tv_sec*1000000 + h->ts.tv_usec;
      // traceEvent(TRACE_WARNING, "pinfo->src_time(%u.%u)", h->ts.tv_sec, h->ts.tv_usec);
    } else if(readOnlyGlobals.isSavePcapFile > 1 && pinfo->dst_time == 0 && cmpIpAddress_s(pinfo->srcip, *dst)){
      SavePktToPcap(h, p);
      has_save_pkt = 1;
      pinfo->dst_time = h->ts.tv_sec*1000000 + h->ts.tv_usec;
      // traceEvent(TRACE_WARNING, "pinfo->dst_time(%u.%u)", h->ts.tv_sec, h->ts.tv_usec);
    }

    int is_http = 0;
    if (payloadLen > 10 ) {
      if( (!strncmp((char*)payload, GET_URL, strlen(GET_URL))) || (!strncmp((char*)payload, POST_URL, strlen(POST_URL))) || (!strncmp((char*)payload, HTTP_1, strlen(HTTP_1))) ){
        is_http = 1;
        if ((body = strstr((char *)payload, "\r\n\r\n")) != NULL)
          head_length = body - payload;
      } 
    }

    // bulid a argument struct for threads.
    struct pthread_argv_t *pthread_argv = malloc(sizeof(struct pthread_argv_t));

    pthread_argv->sport            =   sport;            // pkt sport,
    pthread_argv->dport            =   dport;            // pkt dport,
    pthread_argv->protocol         =   proto;            // pkt sport,
    pthread_argv->is_http          =   is_http;          // is http pkt or not, use for filtering pats.
    pthread_argv->subject_length   =   subject_length;   // str length for pcre_exec.
    pthread_argv->head_length      =   head_length;      // http pkt header length.
    pthread_argv->subject_string   =   &subject_string;  // pkt payload string, use for pcre_exec.
    pthread_argv->pinfo            =   &pinfo;           // pointer which point to pluginData.
    pthread_argv->src              =   src;              // ip address.
    pthread_argv->dst              =   dst;              // ip address.

    pthread_argv->pkt_time.pkt_sec  = h->ts.tv_sec;      // 用于证据留存，定位数据包
    pthread_argv->pkt_time.pkt_usec = h->ts.tv_usec;     //

    int save_pkt = 0;
    int i;
    for(i = 1; i <= PAT_TYPE_NUM; i++){
      if(RegexFunc1(i, pthread_argv) && readOnlyGlobals.isSavePcapFile){
        save_pkt = i;
      }
    }
    if(save_pkt > 0 && has_save_pkt ==0){
      SavePktToPcap(h, p);
    }

    free(pthread_argv);
  }

}

/* *********************************************** */

/* Handler called when the flow is deleted (after export) */

static void SrvPlugin_delete(FlowHashBucket* bkt, void *pluginData) {
  if(pluginData != NULL)
    free(pluginData);
}

/* *********************************************** */

/* Handler called at startup when the template is read */

static V9V10TemplateElementId* SrvPlugin_get_template(char* template_name) {
  int i;

  for(i=0; SrvPlugin_template[i].templateElementId != 0; i++) {
    if(!strcmp(template_name, SrvPlugin_template[i].templateElementName)) {
      return(&SrvPlugin_template[i]);
    }
  }

  return(NULL); /* Unknown */
}

/* *********************************************** */

/* Handler called whenever a flow attribute needs to be exported */

static int SrvPlugin_export(void *pluginData, V9V10TemplateElementId *theTemplate,
         int direction /* 0 = src->dst, 1 = dst->src */,
         FlowHashBucket *bkt, char *outBuffer,
         u_int* outBufferBegin, u_int* outBufferMax) {

  if(pluginData) {
    struct plugin_info *pinfo = (struct plugin_info *)pluginData;

    bool is_target = 0;
    is_target = direction ? cmpIpAddress_s(pinfo->srcip, bkt->dst->host) : cmpIpAddress_s(pinfo->srcip, bkt->src->host);

    // char buf[256], buf1[256], buf2[256];
    // traceEvent(TRACE_INFO, "->direction %d IP target: %s, src: %s, dst: %s, is_target:%d", 
    //       direction,
    //       _intoa(pinfo->srcip, buf, sizeof(buf)), 
    //       _intoa(bkt->src->host, buf1, sizeof(buf1)),
    //       _intoa(bkt->dst->host, buf2, sizeof(buf2)), is_target);

    if(is_target){

      int i;
      for(i=0; SrvPlugin_template[i].templateElementId != 0; i++) {

        if(theTemplate->templateElementId == SrvPlugin_template[i].templateElementId) {
          if((*outBufferBegin)+SrvPlugin_template[i].templateElementLen > (*outBufferMax))
            return(-2); /* Too long */

          switch(SrvPlugin_template[i].templateElementId) {
            // service
            case BASE_ID+0:
              memset(&outBuffer[*outBufferBegin], 0, SRV_TYPE_LEN);
              if(pinfo->srv_type) {
                int len = strlen(pinfo->srv_type);
                if(len > SRV_TYPE_LEN) len = SRV_TYPE_LEN;
                memcpy(&outBuffer[*outBufferBegin], pinfo->srv_type, len);
                // copyLen(pinfo->srv_type, SRV_TYPE_LEN, outBuffer, outBufferBegin, outBufferMax);
                if(readOnlyGlobals.traceMode) 
                  traceEvent(TRACE_INFO, "-> SRV_TYPE: %s", pinfo->srv_type);
              }
              (*outBufferBegin) += SrvPlugin_template[i].templateElementLen;
              break;
            case BASE_ID+1:
              memset(&outBuffer[*outBufferBegin], 0, SRV_NAME_LEN);
              if(pinfo->srv_name) {
                int len = strlen(pinfo->srv_name);
                if(len > SRV_NAME_LEN) len = SRV_NAME_LEN;
                memcpy(&outBuffer[*outBufferBegin], pinfo->srv_name, len);
                // copyLen(pinfo->srv_name, SRV_NAME_LEN, outBuffer, outBufferBegin, outBufferMax);
                if(readOnlyGlobals.traceMode) 
                  traceEvent(TRACE_INFO, "-> SRV_NAME: %s", pinfo->srv_name);
              }
              (*outBufferBegin) += SrvPlugin_template[i].templateElementLen;
              break;
            case BASE_ID+2:
              memset(&outBuffer[*outBufferBegin], 0, SRV_VERS_LEN);
              if(pinfo->srv_vers) {
                int len = strlen(pinfo->srv_vers);
                if(len > SRV_VERS_LEN) len = SRV_VERS_LEN;
                memcpy(&outBuffer[*outBufferBegin], pinfo->srv_vers, len);
                // copyLen(pinfo->srv_vers, SRV_VERS_LEN, outBuffer, outBufferBegin, outBufferMax);
                if(readOnlyGlobals.traceMode) 
                  traceEvent(TRACE_INFO, "-> SRV_VERS: %s", pinfo->srv_vers);
              }
              (*outBufferBegin) += SrvPlugin_template[i].templateElementLen;
              break;
            // device
            case BASE_ID+3:
              memset(&outBuffer[*outBufferBegin], 0, DEV_TYPE_LEN);
              
              if(pinfo->dev_type) {
                int len = strlen(pinfo->dev_type);
                if(len > DEV_TYPE_LEN) len = DEV_TYPE_LEN;
                memcpy(&outBuffer[*outBufferBegin], pinfo->dev_type, len);
                // copyLen(pinfo->dev_type, DEV_TYPE_LEN, outBuffer, outBufferBegin, outBufferMax);
                if(readOnlyGlobals.traceMode) 
                  traceEvent(TRACE_INFO, "-> DEV_TYPE: %s", pinfo->dev_type);
              }
              (*outBufferBegin) += SrvPlugin_template[i].templateElementLen;
              break;
            case BASE_ID+4:
              memset(&outBuffer[*outBufferBegin], 0, DEV_NAME_LEN);
              
              if(pinfo->dev_name) {
                int len = strlen(pinfo->dev_name);
                if(len > DEV_NAME_LEN) len = DEV_NAME_LEN;
                memcpy(&outBuffer[*outBufferBegin], pinfo->dev_name, len);
                // copyLen(pinfo->dev_name, DEV_NAME_LEN, outBuffer, outBufferBegin, outBufferMax);
                if(readOnlyGlobals.traceMode) 
                  traceEvent(TRACE_INFO, "-> DEV_NAME: %s", pinfo->dev_name);
              }
              (*outBufferBegin) += SrvPlugin_template[i].templateElementLen;
              break;
            case BASE_ID+5:
              memset(&outBuffer[*outBufferBegin], 0, DEV_VEND_LEN);
              
              if(pinfo->dev_vendor) {
                int len = strlen(pinfo->dev_vendor);
                if(len > DEV_VEND_LEN) len = DEV_VEND_LEN;
                memcpy(&outBuffer[*outBufferBegin], pinfo->dev_vendor, len);
                // copyLen(pinfo->dev_vendor, DEV_VEND_LEN, outBuffer, outBufferBegin, outBufferMax);
                if(readOnlyGlobals.traceMode) 
                  traceEvent(TRACE_INFO, "-> DEV_VEND: %s", pinfo->dev_vendor);
              }
              (*outBufferBegin) += SrvPlugin_template[i].templateElementLen;
              break;
            case BASE_ID+6:
              memset(&outBuffer[*outBufferBegin], 0, DEV_VERS_LEN);
              
              if(pinfo->dev_vers) {
                int len = strlen(pinfo->dev_vers);
                if(len > DEV_VERS_LEN) len = DEV_VERS_LEN;
                memcpy(&outBuffer[*outBufferBegin], pinfo->dev_vers, len);
                // copyLen(pinfo->dev_vers, DEV_VERS_LEN, outBuffer, outBufferBegin, outBufferMax);
                if(readOnlyGlobals.traceMode) 
                  traceEvent(TRACE_INFO, "-> DEV_VERS: %s", pinfo->dev_vers);
              }
              (*outBufferBegin) += SrvPlugin_template[i].templateElementLen;
              break;
            // os
            case BASE_ID+7:
              memset(&outBuffer[*outBufferBegin], 0, OS_TYPE_LEN);
              
              if(pinfo->os_type) {
                int len = strlen(pinfo->os_type);
                if(len > OS_TYPE_LEN) len = OS_TYPE_LEN;
                memcpy(&outBuffer[*outBufferBegin], pinfo->os_type, len);
                // copyLen(pinfo->os_type, OS_TYPE_LEN, outBuffer, outBufferBegin, outBufferMax);
                if(readOnlyGlobals.traceMode) 
                  traceEvent(TRACE_INFO, "-> OS_TYPE: %s", pinfo->os_type);
              }
              (*outBufferBegin) += SrvPlugin_template[i].templateElementLen;
              break;
            case BASE_ID+8:
              memset(&outBuffer[*outBufferBegin], 0, OS_NAME_LEN);
              
              if(pinfo->os_name) {
                int len = strlen(pinfo->os_name);
                if(len > OS_NAME_LEN) len = OS_NAME_LEN;
                memcpy(&outBuffer[*outBufferBegin], pinfo->os_name, len);
                // copyLen(pinfo->os_name, OS_NAME_LEN, outBuffer, outBufferBegin, outBufferMax);
                if(readOnlyGlobals.traceMode) 
                  traceEvent(TRACE_INFO, "-> OS_NAME: %s", pinfo->os_name);
              }
              (*outBufferBegin) += SrvPlugin_template[i].templateElementLen;
              break;
            case BASE_ID+9:
              memset(&outBuffer[*outBufferBegin], 0, OS_VERS_LEN);
              
              if(pinfo->os_vers) {
                int len = strlen(pinfo->os_vers);
                if(len > OS_VERS_LEN) len = OS_VERS_LEN;
                memcpy(&outBuffer[*outBufferBegin], pinfo->os_vers, len);
                // copyLen(pinfo->os_vers, OS_VERS_LEN, outBuffer, outBufferBegin, outBufferMax);
                if(readOnlyGlobals.traceMode) 
                  traceEvent(TRACE_INFO, "-> OS_VERS: %s", pinfo->os_vers);
              }
              (*outBufferBegin) += SrvPlugin_template[i].templateElementLen;
              break;
            // middleware
            case BASE_ID+10:
              memset(&outBuffer[*outBufferBegin], 0, MID_TYPE_LEN);
              
              if(pinfo->mid_type) {
                int len = strlen(pinfo->mid_type);
                if(len > MID_TYPE_LEN) len = MID_TYPE_LEN;
                memcpy(&outBuffer[*outBufferBegin], pinfo->mid_type, len);
                // copyLen(pinfo->mid_type, MID_TYPE_LEN, outBuffer, outBufferBegin, outBufferMax);
                if(readOnlyGlobals.traceMode) 
                  traceEvent(TRACE_INFO, "-> MID_TYPE: %s", pinfo->mid_type);
              }
              (*outBufferBegin) += SrvPlugin_template[i].templateElementLen;
              break;
            case BASE_ID+11:
              memset(&outBuffer[*outBufferBegin], 0, MID_NAME_LEN);
              
              if(pinfo->mid_name) {
                int len = strlen(pinfo->mid_name);
                if(len > MID_NAME_LEN) len = MID_NAME_LEN;
                memcpy(&outBuffer[*outBufferBegin], pinfo->mid_name, len);
                // copyLen(pinfo->mid_name, MID_NAME_LEN, outBuffer, outBufferBegin, outBufferMax);
                if(readOnlyGlobals.traceMode) 
                  traceEvent(TRACE_INFO, "-> MID_NAME: %s", pinfo->mid_name);
              }
              (*outBufferBegin) += SrvPlugin_template[i].templateElementLen;
              break;
            case BASE_ID+12:
              memset(&outBuffer[*outBufferBegin], 0, MID_VERS_LEN);
              
              if(pinfo->mid_vers) {
                int len = strlen(pinfo->mid_vers);
                if(len > MID_VERS_LEN) len = MID_VERS_LEN;
                memcpy(&outBuffer[*outBufferBegin], pinfo->mid_vers, len);
                // copyLen(pinfo->mid_vers, MID_VERS_LEN, outBuffer, outBufferBegin, outBufferMax);
                if(readOnlyGlobals.traceMode) 
                  traceEvent(TRACE_INFO, "-> MID_VERS: %s", pinfo->mid_vers);
              }
              (*outBufferBegin) += SrvPlugin_template[i].templateElementLen;
              break;
            // threat
            case BASE_ID+13:
              memset(&outBuffer[*outBufferBegin], 0, THREAT_TYPE_LEN);
              
              if(pinfo->threat_type) {
                int len = strlen(pinfo->threat_type);
                if(len > THREAT_TYPE_LEN) len = THREAT_TYPE_LEN;
                memcpy(&outBuffer[*outBufferBegin], pinfo->threat_type, len);
                // copyLen(pinfo->threat_type, THREAT_TYPE_LEN, outBuffer, outBufferBegin, outBufferMax);
                if(readOnlyGlobals.traceMode) 
                  traceEvent(TRACE_INFO, "-> THREAT_TYPE: %s", pinfo->threat_type);
              }
              (*outBufferBegin) += SrvPlugin_template[i].templateElementLen;
              break;
            case BASE_ID+14:
              memset(&outBuffer[*outBufferBegin], 0, THREAT_NAME_LEN);
              
              if(pinfo->threat_name) {
                int len = strlen(pinfo->threat_name);
                if(len > THREAT_NAME_LEN) len = THREAT_NAME_LEN;
                memcpy(&outBuffer[*outBufferBegin], pinfo->threat_name, len);
                // copyLen(pinfo->threat_name, THREAT_NAME_LEN, outBuffer, outBufferBegin, outBufferMax);
                if(readOnlyGlobals.traceMode) 
                  traceEvent(TRACE_INFO, "-> THREAT_NAME: %s", pinfo->threat_name);
              }
              (*outBufferBegin) += SrvPlugin_template[i].templateElementLen;
              break;
            case BASE_ID+15:
              memset(&outBuffer[*outBufferBegin], 0, THREAT_VERS_LEN);
              
              if(pinfo->threat_vers) {
                int len = strlen(pinfo->threat_vers);
                if(len > THREAT_VERS_LEN) len = THREAT_VERS_LEN;
                memcpy(&outBuffer[*outBufferBegin], pinfo->threat_vers, len);
                // copyLen(pinfo->threat_vers, THREAT_VERS_LEN, outBuffer, outBufferBegin, outBufferMax);
                if(readOnlyGlobals.traceMode) 
                  traceEvent(TRACE_INFO, "-> THREAT_VERS: %s", pinfo->threat_vers);
              }
              (*outBufferBegin) += SrvPlugin_template[i].templateElementLen;
              break;

            // fingerprint timestamp
            case BASE_ID+16:
              memset(&outBuffer[*outBufferBegin], 0, FP_TIME_LEN);
              
              if(pinfo->srv_time) {
                copyInt64(pinfo->srv_time, outBuffer, outBufferBegin, outBufferMax);
                if(readOnlyGlobals.traceMode) {
                  traceEvent(TRACE_INFO, "-> SRV_TIME: %lu", pinfo->srv_time);
                }
              } else
                (*outBufferBegin) += SrvPlugin_template[i].templateElementLen;
              break;
            case BASE_ID+17:
              memset(&outBuffer[*outBufferBegin], 0, FP_TIME_LEN);
              
              if(pinfo->dev_time) {
                copyInt64(pinfo->dev_time, outBuffer, outBufferBegin, outBufferMax);
                if(readOnlyGlobals.traceMode) {
                  traceEvent(TRACE_INFO, "-> DEV_TIME: %lu", pinfo->dev_time);
                }
              } else
                (*outBufferBegin) += SrvPlugin_template[i].templateElementLen;
              break;
            case BASE_ID+18:
              memset(&outBuffer[*outBufferBegin], 0, FP_TIME_LEN);
              
              if(pinfo->os_time) {
                copyInt64(pinfo->os_time, outBuffer, outBufferBegin, outBufferMax);
                if(readOnlyGlobals.traceMode) {
                  traceEvent(TRACE_INFO, "-> OS_TIME: %lu", pinfo->os_time);
                }
              } else
                (*outBufferBegin) += SrvPlugin_template[i].templateElementLen;
              break;
            case BASE_ID+19:
              memset(&outBuffer[*outBufferBegin], 0, FP_TIME_LEN);
              
              if(pinfo->mid_time) {
                copyInt64(pinfo->mid_time, outBuffer, outBufferBegin, outBufferMax);
                if(readOnlyGlobals.traceMode) {
                  traceEvent(TRACE_INFO, "-> MID_TIME: %lu", pinfo->mid_time);
                }
              } else
                (*outBufferBegin) += SrvPlugin_template[i].templateElementLen;
              break;
            case BASE_ID+20:
              memset(&outBuffer[*outBufferBegin], 0, FP_TIME_LEN);
              
              if(pinfo->src_time) {
                copyInt64(pinfo->src_time, outBuffer, outBufferBegin, outBufferMax);
                if(readOnlyGlobals.traceMode) {
                  traceEvent(TRACE_INFO, "-> THREAT_TIME: %lu", pinfo->src_time);
                }
              } else
                (*outBufferBegin) += SrvPlugin_template[i].templateElementLen;
              break;

            case BASE_ID+28:
              memset(&outBuffer[*outBufferBegin], 0, FP_INDEX_LEN);
              
              if(pinfo->threat_index) {
                int len = strlen(pinfo->threat_index);
                if(len > FP_INDEX_LEN) len = FP_INDEX_LEN;
                memcpy(&outBuffer[*outBufferBegin], pinfo->threat_index, len);
                // copyLen(pinfo->threat_index, FP_INDEX_LEN, outBuffer, outBufferBegin, outBufferMax);
                if(readOnlyGlobals.traceMode) 
                  traceEvent(TRACE_INFO, "-> THREAT_INDEX: %s", pinfo->threat_index);
              }
              (*outBufferBegin) += SrvPlugin_template[i].templateElementLen;
              break;
            default:
              return(-1); /* Not handled */
          } // end of switch

          return(0);          
        }
      } // end of for
    } else {
      int i;
      for(i=0; SrvPlugin_template[i].templateElementId != 0; i++) {

        if(theTemplate->templateElementId == SrvPlugin_template[i].templateElementId) {
          if((*outBufferBegin)+SrvPlugin_template[i].templateElementLen > (*outBufferMax))
            return(-2); /* Too long */

          switch(SrvPlugin_template[i].templateElementId) {
            case BASE_ID+16:
              memset(&outBuffer[*outBufferBegin], 0, FP_TIME_LEN);
              
              if(pinfo->dst_time) {
                copyInt64(pinfo->dst_time, outBuffer, outBufferBegin, outBufferMax);
                if(readOnlyGlobals.traceMode) {
                  traceEvent(TRACE_INFO, "-> REVERSE_TIME: %lu", pinfo->dst_time);
                }
              } else
                (*outBufferBegin) += SrvPlugin_template[i].templateElementLen;
              break;

            default:
              return(-1); /* Not handled */
          } // end of switch

          return(0);          
        }
      } // end of for
    } // is_target
  }
  return(-1); /* Not handled */
}

/* *********************************************** */

static int SrvPlugin_print(void *pluginData, V9V10TemplateElementId *theTemplate,
        int direction /* 0 = src->dst, 1 = dst->src */,
        FlowHashBucket *bkt, char *line_buffer, u_int line_buffer_len) {

  if(pluginData) {
    struct plugin_info *pinfo = (struct plugin_info *)pluginData;

    bool is_target = 0;
    is_target = direction ? cmpIpAddress_s(pinfo->srcip, bkt->dst->host) : cmpIpAddress_s(pinfo->srcip, bkt->src->host);

    if(is_target){
      int i;
      for(i=0; SrvPlugin_template[i].templateElementId != 0; i++) {
        if(theTemplate->templateElementId == SrvPlugin_template[i].templateElementId) {

          switch(SrvPlugin_template[i].templateElementId) {
            case BASE_ID+1:
              snprintf(&line_buffer[strlen(line_buffer)], 
                 (line_buffer_len-strlen(line_buffer)),
                 "%s", pinfo->srv_name ? pinfo->srv_name : "");
              break;
            case BASE_ID+4:
              snprintf(&line_buffer[strlen(line_buffer)], 
                 (line_buffer_len-strlen(line_buffer)),
                 "%s", pinfo->dev_name ? pinfo->dev_name : "");
              break;
            case BASE_ID+8:
              snprintf(&line_buffer[strlen(line_buffer)], 
                 (line_buffer_len-strlen(line_buffer)),
                 "%s", pinfo->os_name ? pinfo->os_name : "");
              break;
            case BASE_ID+11:
              snprintf(&line_buffer[strlen(line_buffer)], 
                 (line_buffer_len-strlen(line_buffer)),
                 "%s", pinfo->mid_name ? pinfo->mid_name : "");
              break;
            case BASE_ID+14:
              snprintf(&line_buffer[strlen(line_buffer)], 
                 (line_buffer_len-strlen(line_buffer)),
                 "%s", pinfo->threat_name ? pinfo->threat_name : "");
              break;
            // fp time
            case BASE_ID+16:
              snprintf(&line_buffer[strlen(line_buffer)], 
                 (line_buffer_len-strlen(line_buffer)),
                 "%lu", pinfo->srv_time ? pinfo->srv_time : 0);
              break;
            case BASE_ID+17:
              snprintf(&line_buffer[strlen(line_buffer)], 
                 (line_buffer_len-strlen(line_buffer)),
                 "%lu", pinfo->dev_time ? pinfo->dev_time : 0);
              break;
            case BASE_ID+18:
              snprintf(&line_buffer[strlen(line_buffer)], 
                 (line_buffer_len-strlen(line_buffer)),
                 "%lu", pinfo->os_time ? pinfo->os_time : 0);
              break;
            case BASE_ID+19:
              snprintf(&line_buffer[strlen(line_buffer)], 
                 (line_buffer_len-strlen(line_buffer)),
                 "%lu", pinfo->mid_time ? pinfo->mid_time : 0);
              break;
            case BASE_ID+20:
              snprintf(&line_buffer[strlen(line_buffer)], 
                 (line_buffer_len-strlen(line_buffer)),
                 "%lu", pinfo->threat_time ? pinfo->threat_time : 0);
              break;
            default:
              return(-1); /* Not handled */
          } // end of switch

          return(0);
        }
      } // end of for
    } //is_target
  }
  return(-1); /* Not handled */
}

/* *********************************************** */

static V9V10TemplateElementId* SrvPlugin_conf(void) {
  return(SrvPlugin_template);
}

/* *********************************************** */

/* Plugin entrypoint */
static PluginInfo SrvPlugin = {
  NPROBE_REVISION,
  "Services Recognition",
  "0.1",
  "Handle Services",
  "abyssalfish <opensource@abyssalfish.com.cn>",
  0 /* not always enabled */, 1, /* enabled */
  SrvPlugin_init,
  NULL, /* Term */
  SrvPlugin_conf,
  SrvPlugin_delete,
  1, /* call packetFlowFctn for each packet */
  SrvPlugin_packet,
  SrvPlugin_get_template,
  SrvPlugin_export,
  SrvPlugin_print,
  NULL,
  NULL
};

/* *********************************************** */
#endif

/* Plugin entry fctn */
#ifdef MAKE_STATIC_PLUGINS
PluginInfo* servicePluginEntryFctn(void)
#else
   PluginInfo* PluginEntryFctn(void)
#endif
{
#if defined(HAVE_PCRE_H) && defined(HAVE_LIBPCRE)
  return(&SrvPlugin);
#else
  traceEvent(TRACE_INFO, "Services plugin disabled (missing 'pcre' library)");
  return(NULL);
#endif
}
