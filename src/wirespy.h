/****
 *
 * Headers for all wirespy tools
 * 
 * Copyright (c) 2006-2018, Ron Dilley
 * All rights reserved.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 ****/

#ifndef WIRESPY_DOT_H
#define WIRESPY_DOT_H

/****
 *
 * defines
 *
 ****/

/* arg len boundary */
#define MAX_ARG_LEN 1024

#define MAX_IP_ADDR_LEN 46

#define MAX_LOG_LINE 2048
#define MAX_SYSLOG_LINE 1024
#define SYSLOG_SOCKET "/dev/log"
#define MAX_FILE_DESC 256

/* user and group defaults */
#define MAX_USER_LEN 16
#define MAX_GROUP_LEN 16

/****
 *
 * includes
 *
 ****/

/****
 *
 * consts & enums
 *
 ****/

/****
 *
 * typedefs & structs
 *
 ****/

/* traffic address record */
struct trafficAddressRecord {
  u_char sMac[ETHER_ADDR_LEN];
  u_char dMac[ETHER_ADDR_LEN];
  u_short ethProto;    
  struct in_addr sIp;
  struct in_addr dIp;
  u_char ipProto;
  u_short sPort; /* or icmp type */
  u_short dPort; /* or icmp code */
};

/* traffic record */
struct trafficRecord {
  time_t wire_sec;
  time_t wire_usec;
  struct trafficAddressRecord aRec;
  u_int32_t seq;
  u_int32_t ack;
  u_int16_t win;
  u_int16_t size;
  struct trafficRecord *next;
  struct trafficRecord *prev;
};

#define TCP_FLOW_IGNORE 0
#define TCP_FLOW_SYN    1
#define TCP_FLOW_SYNACK 2
#define TCP_FLOW_EST    3
#define TCP_FLOW_FIN1   4
#define TCP_FLOW_FIN2   5
#define TCP_FLOW_CLOSED 6

/* tcp flows */
struct tcpFlow {
  time_t firstUpdate;
  time_t lastUpdate;
  int status;
  u_int32_t clientIsn;
  u_int32_t serverIsn;
  size_t packetsOut;
  size_t packetsIn;
  size_t bytesOut;
  size_t bytesIn;
  size_t recordCount;
  struct trafficAddressRecord aRecOut;
  struct trafficAddressRecord aRecIn;
  struct tcpFlow *prev;
  struct tcpFlow *next;
  struct trafficRecord *head;
  struct trafficRecord *tail;
};

/* flow cache record */
struct tcpFlowCache {
  time_t firstUpdate;
  time_t lastUpdate;
  int status;
  u_int32_t clientIsn;
  u_int32_t serverIsn;
  size_t packetsOut;
  size_t packetsIn;
  size_t bytesOut;
  size_t bytesIn;    
  size_t recordCount;
  struct trafficAddressRecord aRecOut;
  struct trafficAddressRecord aRecIn;
};

/* traffic cache record */
struct trafficRecordCache {
  time_t wire_sec;
  time_t wire_usec;
  struct trafficAddressRecord aRec;
  u_int32_t seq;
  u_int32_t ack;
  u_int16_t win;
  u_int16_t size;    
};

/* acl record */
struct accessControlList {
  struct accessControlList *prev;
  struct accessControlList *next;
  struct trafficRecord *head;
  struct trafficRecord *tail;
  struct in_addr sIp;
  struct in_addr dIp;
  u_char ipProto;
  u_short sPort;
  u_short dPort;
  double count;
};

/* prog config */
typedef struct {
  uid_t starting_uid;
  uid_t uid;
  gid_t gid;
  char *home_dir;
  char *pid_file;
  char *chroot_dir;
  char *log_dir;
  char *log_fName;
  char *pcap_fName;
  char *wFlow_fName;
  char *rFlow_fName;
  int display_to_pipe;
  FILE *log_st;
  FILE *syslog_st;
  char *hostname;
  char *domainname;
  char *in_iface;
  char *in_dev_ip_addr_str;
  char *in_dev_net_addr_str;
  char *in_dev_net_mask_str;
  struct in_addr in_dev_ip_addr;
  struct in_addr in_dev_net_addr;
  struct in_addr in_dev_net_mask;
  pcap_t *pcap_handle;
  int debug;
  int verbose;
  int mode;
  int write_fd;
  int pruneCounter;
  unsigned long pktcount;
  unsigned long pcap_rec;
  unsigned long pcap_drop;
  time_t current_time;
  pid_t cur_pid;
  /* traffic specific items */
  struct tcpFlow *tfHead;
  struct tcpFlow *tfTail;
  struct hash_s *tcpFlowHash;
  size_t flowCount;
} Config_t;

#endif /* WIRESPY_DOT_H */