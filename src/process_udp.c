/****
 *
 * Process UDP Packets
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
  PRIVATE char s_eth_addr_str[(ETHER_ADDR_LEN*2)+ETHER_ADDR_LEN];
  PRIVATE char d_eth_addr_str[(ETHER_ADDR_LEN*2)+ETHER_ADDR_LEN];
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
  tr->aRec.sPort = ntohs( udp_ptr->uh_sport );
  tr->aRec.dPort = ntohs( udp_ptr->uh_dport );
#else
  tr->aRec.sPort = ntohs( udp_ptr->source );
  tr->aRec.dPort = ntohs( udp_ptr->dest );
#endif

#ifdef DEBUG
  if ( config->debug >= 3 ) {
    display( LOG_INFO, "UDP: S: %u D: %u", ntohs( tr->aRec.sPort ), ntohs( tr->aRec.dPort ) );
  }
#endif

  if ( ! config->verbose )
      return;
  
  /*
   * write to log
   */
  XSTRNCPY( s_eth_addr_str, ether_ntoa((struct ether_addr *)tr->aRec.sMac), ((ETHER_ADDR_LEN*2)+ETHER_ADDR_LEN)-1 );
  XSTRNCPY( d_eth_addr_str, ether_ntoa((struct ether_addr *)tr->aRec.dMac), ((ETHER_ADDR_LEN*2)+ETHER_ADDR_LEN)-1 );    
  XSTRNCPY( s_ip_addr_str, inet_ntoa( tr->aRec.sIp ), MAX_IP_ADDR_LEN );
  XSTRNCPY( d_ip_addr_str, inet_ntoa( tr->aRec.dIp ), MAX_IP_ADDR_LEN );

#if SIZEOF_SIZE_T == 8
  fprintf( config->log_st, "[%lu.%06lu] %17s->%-17s %16s:%-5u -> %16s:%-5u UDP\n",
           tr->wire_sec,
           tr->wire_usec,
#else
#ifdef OPENBSD
  fprintf( config->log_st, "[%lu.",
	   tr->wire_sec );
  fprintf( config->log_st, "%06lu] ",
	   tr->wire_usec );
  fprintf( config->log_st, "%17s->%-17s %16s:%-5u -> %16s:%-5u UDP\n",
#else
  fprintf( config->log_st, "[%lu.%06lu] %17s->%-17s %16s:%-5u -> %16s:%-5u UDP\n",
           tr->wire_sec,
           tr->wire_usec,
#endif
#endif
           s_eth_addr_str,
           d_eth_addr_str,
	   s_ip_addr_str,
	   tr->aRec.sPort,
	   d_ip_addr_str,
	   tr->aRec.dPort
	   );
  
  /*
   * done with packet, fall through
   */
  
  /* cleanup, we will do nothing with this packet */
  
  return;
}

