/****
 *
 * Headers for Wirespy Daemon
 * 
 * Copyright (c) 2006-2017, Ron Dilley
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

#ifndef WSD_DOT_H
#define WSD_DOT_H

/****
 *
 * defines
 *
 ****/

#define PROGNAME "wsd"
#define MODE_DAEMON 0
#define MODE_INTERACTIVE 1
#define MODE_DEBUG 2

/* arg len boundary */
#define MAX_ARG_LEN 1024

/* packet count */
#define LOOP_PACKET_COUNT 16
#define LOOP_PACKET_TIME 5 /* seconds */

#define MAX_IP_ADDR_LEN 46

#define LOGDIR "/var/log/wsd"
#define MAX_LOG_LINE 2048
#define PID_FILE "/var/run/wsd.pid"
#define MAX_SYSLOG_LINE 1024
#define SYSLOG_SOCKET "/dev/log"
#define MAX_FILE_DESC 256

/* user and group defaults */
#define MAX_USER_LEN 16
#define MAX_GROUP_LEN 16

/* header length defs */
#define PPP_HDRLEN 4
#define NULL_HDRLEN 4

/* alarm interval */
#define CTIME_SYNC_INTERVAL 5

/****
 *
 * includes
 *
 ****/

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <sysdep.h>

#ifndef SYSDEP_DOT_H
#error something is messed up
#endif

#include <common.h>
#include "util.h"
#include "mem.h"
#include "hash.h"

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
  struct trafficRecord *next;
  struct trafficRecord *prev;
  time_t wire_sec;
  time_t wire_usec;
  u_char sMac[ETHER_ADDR_LEN];
  u_char dMac[ETHER_ADDR_LEN];
  u_short ethProto;
  struct trafficAddressRecord aRec;
  u_int32_t seq;
  u_int32_t ack;
  u_int16_t win;
  u_int16_t size;
};


/* tcp flows */
struct tcpFlow {
  struct tcpFlow *prev;
  struct tcpFlow *next;
  time_t firstUpdate;
  time_t lastUpdate;
  int status;
#define TCP_FLOW_IGNORE 0
#define TCP_FLOW_SYN    1
#define TCP_FLOW_SYNACK 2
#define TCP_FLOW_EST    3
#define TCP_FLOW_FIN1   4
#define TCP_FLOW_FIN2   5
#define TCP_FLOW_CLOSED 6
  u_int32_t clientIsn;
  u_int32_t serverIsn;
  int recordCount;
  size_t packetsOut;
  size_t packetsIn;
  size_t bytesOut;
  size_t bytesIn;
  struct trafficAddressRecord aRecOut;
  struct trafficAddressRecord aRecIn;
  struct trafficRecord *head;
  struct trafficRecord *tail;
};

/* btree traffic record index */
struct trafficRecordIndex {
  struct trafficRecordIndex *left;
  struct trafficRecordIndex *right;
  struct trafficRecord *ptr;
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
  //struct trafficRecord *trHead;
  //struct trafficRecord *trTail;
  struct tcpFlow *tfHead;
  struct tcpFlow *tfTail;
  struct hash_s *tcpFlowHash;
  size_t flowCount;
  struct trafficRecordIndex *sEthHead;
  struct trafficRecordIndex *dEthHead;
  struct trafficRecordIndex *sIpHead;
  struct trafficRecordIndex *dIpHead;
} Config_t;

/****
 *
 * function prototypes
 *
 ****/

int main(int argc, char *argv[]);
PRIVATE void cleanup( void );
PRIVATE void cleanupTrafficReports( void );
PRIVATE void cleanupTcpFlows( void );
PRIVATE void show_info( void );
void sigint_handler( int signo );
void sighup_handler( int signo );
void sigterm_handler( int signo );
void sigfpe_handler( int signo );
void sigbus_handler( int signo );
void sigsegv_handler( int signo );
void sigill_handler( int signo );
void ctime_prog( int signo );
PRIVATE void print_version( void );
PRIVATE void print_help( void );
PRIVATE int start_collecting( void );
PRIVATE int process_pcap( char *fName );
PRIVATE int show_interfaces( void );
pcap_handler get_handler( int datalink_type, char *device );
void dl_ppp(u_char *args, const struct pcap_pkthdr *header, const u_char *packet );
void dl_raw(u_char *args, const struct pcap_pkthdr *header, const u_char *packet );
void dl_null( u_char *args, const struct pcap_pkthdr *header, const u_char *packet );
void dl_ethernet( u_char *args, const struct pcap_pkthdr *header, const u_char *packet );
void processIpPacket( const struct pcap_pkthdr *header, u_int transportSize, struct trafficRecord *tr, const u_char *packet );
PRIVATE int avg_loop_count( int cur_loop_count );
bpf_u_int32 get_iface_info( char *device );
int writeFlowState( char *outFile );
int readFlowState( char *inFile );

#endif /* WSD_DOT_H */
