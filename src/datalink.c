/****
 *
 * libpcap based packet processor
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
 * return a pcap handler for the interface datalink type
 *
 ****/

pcap_handler get_handler(int datalink_type, char *device) {
  int i;
  PRIVATE struct {
    pcap_handler handler;
    int type;
  } handlers[] = {
    { dl_null, DLT_NULL },
    { dl_raw, DLT_RAW },
    { dl_ethernet, DLT_EN10MB },
    { dl_ethernet, DLT_IEEE802 },
    { dl_ppp, DLT_PPP },
    { NULL, 0 },
  };

#ifdef DEBUG
  if ( config->debug >= 3 ) {
    display( LOG_DEBUG, "Need handler for [%d] on [%s]", datalink_type, device );
  }
#endif

  for (i = 0; handlers[i].handler != NULL; i++) {
    if (handlers[i].type EQ datalink_type) {
      return handlers[i].handler;
    }
  }

  /* no handler for this link type */
  display( LOG_ERR, "Unsupported link type [%d] on [%s]", datalink_type, device );
  return NULL;
}

/****
 *
 * pcap packet handler for ppp link-layer
 *
 ****/

void dl_ppp(u_char *args, const struct pcap_pkthdr *header, const u_char *packet ) {
  u_int caplen = header->caplen;
  u_int length = header->len;

#ifdef DEBUG
  if ( length != caplen ) {
    display( LOG_WARNING, "PPP: [%d] bytes expected in frame, got [%d]", caplen, length );
  }
#endif

  if ( caplen < PPP_HDRLEN ) {
    display( LOG_WARNING, "PPP: Incomplete frame" );
    return;
  }


  return;
}

/****
 *
 * pcap packet handler with no encapsulation or link-layer headers
 *
 ****/

void dl_raw(u_char *args, const struct pcap_pkthdr *header, const u_char *packet ) {
  u_int caplen = header->caplen;
  u_int length = header->len;

#ifdef DEBUG
  if ( length != caplen ) {
    display( LOG_WARNING, "RAW: [%d] bytes expected in frame, got [%d]", caplen, length );
  }
#endif

  return;
}

/****
 *
 * pcap packet handler for the null interface (localhost)
 *
 ****/

void dl_null( u_char *args, const struct pcap_pkthdr *header, const u_char *packet ) {
  const u_int length = header->len;
  const u_int caplen = header->caplen;
  u_int family;
  const char *payload;
  const char *tmp_ptr;
  PRIVATE int bytes_sent;
  PRIVATE struct tm pkt_time;
  PRIVATE int payload_size;
  /* pre-allocated traffic record */
  PRIVATE struct trafficRecord tr;
  PRIVATE struct trafficRecord *tr_tmp;
  PRIVATE struct tcpFlow *tf_ptr;

#ifdef DEBUG
  if ( length != caplen ) {
    display( LOG_WARNING, "NULL: [%d] bytes expected in frame, got [%d]", caplen, length );
  }
#endif

  if ( caplen < NULL_HDRLEN ) {
    display( LOG_WARNING, "NULL: Incomplete frame" );
    return;
  }

#ifndef DLT_NULL_BROKEN
  /* make sure this is AF_INET */
  XMEMCPY((char *)&family, (char *)packet, sizeof(family));
  family = ntohl(family);
  if (family != AF_INET) {
    display( LOG_WARNING, "NULL: [%d] frame is not AF_INET", family );
    return;
  }
#endif


#ifdef DEBUG
  if ( config->debug >= 4 ) {
    display( LOG_DEBUG, "Packet of length [%d - %d]", header->caplen, header->len );
  }
#endif

  /* convert packet time into something usable */
  localtime_r((const time_t*)&header->ts.tv_sec, &pkt_time);

#ifdef DEBUG
  if ( config->debug >= 5 ) {
    display( LOG_DEBUG, "Received at [%04d/%02d/%02d %02d:%02d:%02d.%06d]",
	     pkt_time.tm_year+1900,
	     pkt_time.tm_mon+1,
	     pkt_time.tm_mday,
	     pkt_time.tm_hour,
	     pkt_time.tm_min,
	     pkt_time.tm_sec,
	     header->ts.tv_usec );
  }
#endif

  /* clear traffic report */
  XMEMSET( &tr, 0, sizeof( tr ) );

  XMEMCPY( &tr.wireTime, &pkt_time, sizeof( pkt_time ) );
  tr.next = NULL;
  tr.prev = NULL;

  if ( family EQ AF_INET ) { /* IP */

    processIpPacket( header, NULL_HDRLEN, &tr, packet + NULL_HDRLEN );
  } else { /* Unknown */
#ifdef DEBUG
    if ( config->debug >= 7 ) {
      display( LOG_DEBUG, "NULL Family Unknown [%d]", family );
    }
#endif
  }

  /* XXX add a timer check and purge tcp flow linked list of dead flows */

  /* cleanup, we will do nothing with this packet */

  return;
}

/****
 *
 * pcap packet handler for ethernet (10/100mbit)
 *
 ****/

void dl_ethernet( u_char *args, const struct pcap_pkthdr *header, const u_char *packet ) {
  const struct ether_header *ethernet_ptr;
  const char *payload;
  const char *tmp_ptr;
  const int size_ethernet = sizeof( struct ether_header );
  PRIVATE int bytes_sent;
  /* this is easier to read */
  PRIVATE char s_eth_addr_str[(ETHER_ADDR_LEN*2)+ETHER_ADDR_LEN];
  PRIVATE char d_eth_addr_str[(ETHER_ADDR_LEN*2)+ETHER_ADDR_LEN];
  /* libnet uses this format */
  PRIVATE u_char s_eth_addr[ETHER_ADDR_LEN];
  PRIVATE u_char d_eth_addr[ETHER_ADDR_LEN];
  PRIVATE struct tm pkt_time;
  PRIVATE int payload_size;
  /* pre-allocated traffic record */
  PRIVATE struct trafficRecord tr;
  PRIVATE struct trafficRecord *tr_tmp;
  PRIVATE struct tcpFlow *tf_ptr;

#ifdef DEBUG
  if ( config->debug >= 4 ) {
    display( LOG_DEBUG, "Packet of length [%d - %d]", header->caplen, header->len );
  }
#endif

  /* proto decode */
  ethernet_ptr = (struct ether_header*)(packet);

  /* convert packet time into something usable */
  localtime_r((const time_t*)&header->ts.tv_sec, &pkt_time);

#ifdef DEBUG
  if ( config->debug >= 5 ) {
    display( LOG_DEBUG, "Received at [%04d/%02d/%02d %02d:%02d:%02d.%06d]",
	     pkt_time.tm_year+1900,
	     pkt_time.tm_mon+1,
	     pkt_time.tm_mday,
	     pkt_time.tm_hour,
	     pkt_time.tm_min,
	     pkt_time.tm_sec,
	     header->ts.tv_usec );
  }

  /* ether_ntoa issue */
  XSTRNCPY( s_eth_addr_str, ether_ntoa((struct ether_addr *)ethernet_ptr->ether_shost), ((ETHER_ADDR_LEN*2)+ETHER_ADDR_LEN)-1 );
  XSTRNCPY( d_eth_addr_str, ether_ntoa((struct ether_addr *)ethernet_ptr->ether_dhost), ((ETHER_ADDR_LEN*2)+ETHER_ADDR_LEN)-1 );

  /* parse ether source/dest */
  if ( config->debug >= 3 ) {
    display( LOG_INFO, "ETHER: %s -> %s", s_eth_addr_str, d_eth_addr_str );
  }
#endif

  /* clear traffic report */
  XMEMSET( &tr, 0, sizeof( tr ) );

  XMEMCPY( &tr.wireTime, &pkt_time, sizeof( pkt_time ) );
  tr.next = NULL;
  tr.prev = NULL;
  XMEMCPY( &tr.sMac, ethernet_ptr->ether_shost, ETHER_ADDR_LEN );
  XMEMCPY( &tr.dMac, ethernet_ptr->ether_dhost, ETHER_ADDR_LEN );
  tr.ethProto = ethernet_ptr->ether_type;

  if (ntohs( ethernet_ptr->ether_type ) EQ ETHERTYPE_IP ) { /* IP */

#ifdef DEBUG
    if ( config->debug >= 7 ) {
      display( LOG_DEBUG, "ETHER: type 0x%04x is an IP packet", ntohs( ethernet_ptr->ether_type ) );
    }
#endif
    /* process packet */
    processIpPacket( header, size_ethernet, &tr, packet + size_ethernet );

    /* done with the packet, fall through */
  } else if ( ntohs( ethernet_ptr->ether_type ) EQ ETHERTYPE_ARP ) { /* ARP */
#ifdef DEBUG
    if ( config->debug >= 7 ) {
      display( LOG_DEBUG, "Ethernet type 0x%04x is an ARP packet", ntohs( ethernet_ptr->ether_type ) );
    }
#endif
    /*
     * done with packet, fall through
     */
  } else if ( ntohs( ethernet_ptr->ether_type ) EQ ETHERTYPE_REVARP ) { /* RARP */
#ifdef DEBUG
    if ( config->debug >= 7 ) {
      display( LOG_DEBUG, "Ethernet type 0x%04x is an RARP packet", ntohs( ethernet_ptr->ether_type ) );
    }
#endif
    /*
     * done with packet, fall through
     */
  } else if ( ntohs( ethernet_ptr->ether_type ) EQ ETHERTYPE_PUP ) { /* PUP */
#ifdef DEBUG
    if ( config->debug >= 7 ) {
      display( LOG_DEBUG, "Ethernet type 0x%04x is a Xerox PUP packet", ntohs( ethernet_ptr->ether_type ) );
    }
#endif
    /*
     * done with packet, fall through
     */
  } else if ( ntohs( ethernet_ptr->ether_type ) EQ ETHERTYPE_TRAIL ) { /* Trailer */
#ifdef DEBUG
    if ( config->debug >= 7 ) {
      display( LOG_DEBUG, "Ethernet type 0x%04x is a trailer packet", ntohs( ethernet_ptr->ether_type ) );
    }
#endif
    /*
     * done with packet, fall through
     */
  } else if ( ntohs( ethernet_ptr->ether_type ) EQ 50 ) { /* ipSec */
#ifdef DEBUG
    if ( config->debug >= 7 ) {
      display( LOG_DEBUG, "Ethernet type 0x%04x is an ipSec packet", ntohs( ethernet_ptr->ether_type ) );
    }
#endif
    /*
     * done with packet, fall through
     */
  } else { /* Unknown */
#ifdef DEBUG
    if ( config->debug >= 7 ) {
      display( LOG_DEBUG, "Ethernet type 0x%04x unknown", ntohs( ethernet_ptr->ether_type ) );
    }
#endif
  }

  /* XXX add a timer check and purge tcp flow linked list of dead flows */

  /* cleanup, we will do nothing with this packet */
  return;
}
