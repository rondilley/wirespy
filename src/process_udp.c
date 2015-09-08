/****
 *
 * Process UDP Packets
 * 
 * Copyright (c) 2006-2015, Ron Dilley
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

/*****
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 *****/

/****
 *
 * includes
 *
 ****/

#include "wsd.h"
#include "process_udp.h"

/****
 *
 * local variables
 *
 ****/

PRIVATE char *months[] = { "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec" };

/****
 *
 * global variables
 *
 ****/

extern int quit;
extern Config_t *config;

/* md5 stuff */
extern struct MD5Context md5_ctx;
extern unsigned char md5_digest[16];

/* sha1 suff */
extern struct SHA1Context sha1_ctx;
extern unsigned char sha1_digest[20];

/****
 *
 * functions
 *
 ****/

/****
 *
 * process udp packet
 *
 ****/

void processUdpPacket( struct trafficRecord *tr, const u_char *packet ) {
  const struct udphdr *udp_ptr;
  const char *payload;
  const char *tmp_ptr;
  const int size_udp = sizeof( struct udphdr );

  PRIVATE int bytes_sent;
  PRIVATE u_int ip_hlen, ip_ver, ip_off, ip_offidx;
  PRIVATE int ip_len;
  PRIVATE char s_ip_addr_str[MAX_IP_ADDR_LEN+1];
  PRIVATE char d_ip_addr_str[MAX_IP_ADDR_LEN+1];
  PRIVATE struct in_addr addr;
  PRIVATE struct tm pkt_time;
  PRIVATE int payload_size;
  /* pre-allocated traffic record */
  PRIVATE struct trafficRecord *tr_tmp, *tmpTrPtr;
  PRIVATE struct tcpFlow *tf_ptr;
  time_t currentTime = time( NULL );

  /* process packet */

  /*
   * udp decode
   */

#ifdef DEBUG
  if ( config->debug >= 5 ) {
    display( LOG_DEBUG, "UDP packet" );
  }
#endif

  /* pointers are fun */
  udp_ptr = (struct udphdr*)( packet );

#ifdef BSD_DERIVED
  tr->sPort = ntohs( udp_ptr->uh_sport );
  tr->dPort = ntohs( udp_ptr->uh_dport );
#else
  tr->sPort = ntohs( udp_ptr->source );
  tr->dPort = ntohs( udp_ptr->dest );
#endif

#ifdef DEBUG
  if ( config->debug >= 3 ) {
    display( LOG_INFO, "UDP: S: %d D: %d", ntohs( tr->sPort ), ntohs( tr->dPort ) );
  }
#endif

  /*
   * write to log
   */
    
  XSTRNCPY( s_ip_addr_str, inet_ntoa( tr->sIp ), MAX_IP_ADDR_LEN );
  XSTRNCPY( d_ip_addr_str, inet_ntoa( tr->dIp ), MAX_IP_ADDR_LEN );
  fprintf( config->log_st, "[%04d/%02d/%02d %02d:%02d:%02d] %16s:%-5u -> %16s:%-5u UDP\n",
	   tr->wireTime.tm_year+1900,
	   tr->wireTime.tm_mon+1,
	   tr->wireTime.tm_mday,
	   tr->wireTime.tm_hour,
	   tr->wireTime.tm_min,
	   tr->wireTime.tm_sec,
	   s_ip_addr_str,
	   tr->sPort,
	   d_ip_addr_str,
	   tr->dPort
	   );

  /*
   * done with packet, fall through
   */
  
  /* cleanup, we will do nothing with this packet */
  return;
}

