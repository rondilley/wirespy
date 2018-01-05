/****
 *
 * Process TELNET Packets
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

/****
 *
 * includes
 *
 ****/

#include "process_telnet.h"

/****
 *
 * local variables
 *
 ****/

/****
 *
 * global variables
 *
 ****/

extern int quit;
extern Config_t *config;

/****
 *
 * functions
 *
 ****/

/****
 *
 * process ip packet
 *
 ****/

void processTelnetFlow( struct tcpFlow *tf, struct trafficRecord *tr, const u_char *packet ) {
  const struct tcphdr *tcp_ptr;
  const char *payload;
  const char *tmp_ptr;
  const int size_tcp = sizeof( struct tcphdr );
  PRIVATE int bytes_sent;
  PRIVATE u_int ip_hlen, ip_ver, ip_off, ip_offidx;
  PRIVATE int ip_len;
  PRIVATE struct in_addr addr;
  PRIVATE struct tm pkt_time;
  PRIVATE int payload_size;
  PRIVATE struct trafficRecord *tr_tmp, *tmpTrPtr;
  PRIVATE struct tcpFlow *tfPtr, *tmpTfPtr;
  time_t currentTime = time( NULL );
  int flowDirection;
  struct hashRec_s *tmpHashRec;
  struct trafficAddressRecord revAddrRec;
#ifdef DEBUG
  PRIVATE char s_eth_addr_str[(ETHER_ADDR_LEN*2)+ETHER_ADDR_LEN];
  PRIVATE char d_eth_addr_str[(ETHER_ADDR_LEN*2)+ETHER_ADDR_LEN];
  PRIVATE char s_ip_addr_str[MAX_IP_ADDR_LEN+2];
  PRIVATE char d_ip_addr_str[MAX_IP_ADDR_LEN+2];
#endif
 
  return; 
}