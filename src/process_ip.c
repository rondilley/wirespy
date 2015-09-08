/****
 *
 * Process IP Packets
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
#include "process_ip.h"

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
 * process ip packet
 *
 ****/

void processIpPacket( const struct pcap_pkthdr *header, u_int transportSize, struct trafficRecord *tr, const u_char *packet ) {
  const struct ip *ip_ptr;
  const struct tcphdr *tcp_ptr;
  const struct udphdr *udp_ptr;
#ifdef BSD_DERIVED
  const struct icmp *icmp_ptr;
#else
  const struct icmphdr *icmp_ptr;
#endif
  const char *payload;
  const char *tmp_ptr;
  const int size_ip = sizeof( struct ip );
  const int size_tcp = sizeof( struct tcphdr );
  const int size_udp = sizeof( struct udphdr );
#ifdef BSD_DERIVED
  const int size_icmp = sizeof( struct icmp );
#else
  const int size_icmp = sizeof( struct icmphdr );
#endif
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
#ifdef DEBUG
  PRIVATE char tmpBuf[4096];
  PRIVATE char tcpFlags[9];
#endif

  /* process packet */

  ip_ptr = (struct ip*)(packet);

  /* get ip source/dest */

  /* check to see we have a packet of valid length */
  if ( ( header->len - transportSize ) < size_ip ) {
    /* can't do much with this packet, bail */
    display( LOG_WARNING, "IP: truncated packet %d", ( header->len - transportSize ) );
    return;
  }

  ip_len = ntohs( ip_ptr->ip_len );
  ip_hlen = ( ip_ptr->ip_hl * 4 );
#ifdef DEBUG
  if ( config->debug >= 7 ) {
    display( LOG_DEBUG, "IP: header length [%d]", ip_hlen );
  }
#endif
  ip_ver = ip_ptr->ip_v;

  /* check version */
  if ( ip_ver != IPVERSION ) {
    /* can't do much with this packet, bail */
    display( LOG_WARNING, "IP: unknown version %d", ip_ver );
    return;
  }

  /* check header len */
  if ( ip_hlen < 5 ) {
    /* should not touch this packet, bail */
    display( LOG_WARNING, "IP: bad-hlen %d", ip_hlen );
    return;
  }
  if ( ip_hlen > size_ip ) {
    /* there are ip options on the packet */
#ifdef DEBUG
    if ( config->debug >= 4 ) {
      display( LOG_DEBUG, "IP: ip_options present" );
    }
#endif
  }

  /* is the packet all there */
  if ( ( header->len - transportSize ) < ip_len ) {
    /* can't do much with this packet, bail */
    display( LOG_WARNING, "IP: truncated packet - %d bytes missing", ip_len - ( header->len - transportSize ) );
    return;
  }

#ifdef DEBUG
  if ( config->debug >= 6 ) {
    /* is the packet all there */
    if ( ( header->len - transportSize ) > ip_len ) {
      display( LOG_DEBUG, "IP: oversized packet - %d bytes over/padded", ( header->len - transportSize ) - ip_len );
    }
  }
#endif
      
  /* is the packet too big */
  if ( ( header->len - transportSize ) > IP_MAXPACKET ) {
    /* should not touch this packet, bail */
    display( LOG_WARNING, "IP: way oversized packet - %d bytes over", IP_MAXPACKET - ( header->len - transportSize ) );
    return;
  }

  /*
   * ip fragmentation
   */

  /* Check to see if we have the first fragment */
  ip_off = ntohs( ip_ptr->ip_off );
  ip_offidx = ( ip_off << 3 ) & 0xffff;
        
  /* display ip packet flags */
#ifdef DEBUG
  if ( config->debug >= 5 ) {
    if ( ip_off & IP_DF ) {
      display( LOG_INFO, "IP: don't frag set" );
    }
  }
#endif

  /* if the packet is part of a fragment */
  if ( (( ip_off << 2 ) & 0xffff ) != 0) {
    /* can't do much with this packet in this version, bail */
#ifdef DEBUG
    if ( config->debug >= 3 ) {
      display( LOG_DEBUG, "IP: Fragment offset: %d", ip_offidx );
    }
#endif
    return;
  }

  XMEMCPY( &tr->sIp, &ip_ptr->ip_src, sizeof( struct in_addr ) );
  XMEMCPY( &tr->dIp, &ip_ptr->ip_dst, sizeof( struct in_addr ) );
  tr->ipProto = ip_ptr->ip_p;

#ifdef DEBUG
  XSTRNCPY( s_ip_addr_str, inet_ntoa( ip_ptr->ip_src ), MAX_IP_ADDR_LEN );
  XSTRNCPY( d_ip_addr_str, inet_ntoa( ip_ptr->ip_dst ), MAX_IP_ADDR_LEN );

  /* display source and dest */
  if ( config->debug >= 3 ) {
    display( LOG_DEBUG, "IP: %s -> %s", s_ip_addr_str, d_ip_addr_str );
  }

  if ( config->debug >= 8 ) {
    display( LOG_DEBUG, "IP: id [%d]", ip_ptr->ip_id );
  }
#endif

  tr->size = ip_len - ip_hlen;

  /*
   * process the IP packet
   */

  if ( tr->ipProto EQ IPPROTO_UDP ) {

    /*
     * udp decode
     */

    processUdpPacket( tr, ( packet + ip_hlen ) );

    /*
     * done with packet, fall through
     */
  } else if ( tr->ipProto EQ IPPROTO_TCP) {

    /*
     * tcp decode
     */

    processTcpPacket( tr, ( packet + ip_hlen ) );
    
    /*
     * done with packet, fall through
     */
  
  } else if ( tr->ipProto EQ IPPROTO_ICMP ) {
    /* icmp decode */
    if ( config->debug >= 5 ) {
      display( LOG_DEBUG, "ICMP packet" );
    }

    /* pointers are fun */
#ifdef BSD_DERIVED
    icmp_ptr = (struct icmp*)(packet+ip_hlen);
#else
    icmp_ptr = (struct icmphdr*)(packet+ip_hlen);
#endif

#ifdef BSD_DERIVED
    tr->sPort = icmp_ptr->icmp_code;
    tr->dPort = icmp_ptr->icmp_type;
#else
    tr->sPort = icmp_ptr->code;
    tr->dPort = icmp_ptr->type;
#endif

    /*
     * done with packet, fall through
     */
  } else {
    /* unknown protocol */
    if ( config->debug >= 4 ) {
      display( LOG_DEBUG, "Unknown:" );
    }
  }

  /* XXX  we need to save all non-tcp traffic someplace */
  //if ( config->trHead EQ NULL ) {
  /* first traffic record */
  //config->trHead = config->trTail = tr_tmp;
  //} else {
  //config->trTail->next = tr_tmp;
  //tr_tmp->prev = config->trTail;
  //config->trTail = tr_tmp;
  //}

  /* XXX add a timer check and purge tcp flow linked list of dead flows */

  /* cleanup, we will do nothing with this packet */
  return;
}

