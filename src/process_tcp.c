/****
 *
 * Process TCP Packets
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

/****
 *
 * includes
 *
 ****/

#include "wsd.h"
#include "process_tcp.h"

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

void processTcpPacket( struct trafficRecord *tr, const u_char *packet ) {
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
  /* pre-allocated traffic record */
  PRIVATE struct trafficRecord *tr_tmp, *tmpTrPtr;
  PRIVATE struct tcpFlow *tfPtr, *tmpTfPtr;
  time_t currentTime = time( NULL );
  int flowDirection;

  /* process packet */

  /*
   * tcp decode
   */

  if ( config->debug >= 7 ) {
    display( LOG_DEBUG, "TCP packet" );
  }

  /* pointers are fun */
  tcp_ptr = (struct tcphdr*)( packet );

#ifdef BSD_DERIVED
  tr->sPort = ntohs( tcp_ptr->th_sport );
  tr->dPort = ntohs( tcp_ptr->th_dport );
  tr->seq = ntohl( tcp_ptr->th_seq );
  tr->ack = ntohl( tcp_ptr->th_ack );
  tr->win = ntohs( tcp_ptr->th_win );
#else
  tr->sPort = ntohs( tcp_ptr->source );
  tr->dPort = ntohs( tcp_ptr->dest );
  tr->seq = ntohl( tcp_ptr->seq );
  tr->ack = ntohl( tcp_ptr->ack_seq );
  tr->win = ntohs( tcp_ptr->window );
#endif

#ifdef DEBUG
  if ( config->debug >= 3 ) {
    display( LOG_INFO, "TCP: S: %d D: %d", tr->sPort, tr->dPort );
  }

  if ( config->debug >= 5 ) {
    display( LOG_INFO, "TCP: Window [%u]", tr->win );
    display( LOG_INFO, "TCP: Seq [%u]", tr->seq );
    display( LOG_INFO, "TCP: Ack [%u]", tr->ack );
    display( LOG_DEBUG, "TCP: Payload Size: %u", tr->size - size_tcp );
  }
#endif

  /* XXX only add traffic record when we start a new tcp flow */

  /****
   *
   * assemble the packets
   *
   ****/

  if ( tcp_ptr->syn & ! tcp_ptr->ack ) {

    /*
     * initial SYN
     */

    /* create new tcp flow record */
    tfPtr = (struct tcpFlow *)XMALLOC( sizeof( struct tcpFlow ) );
    XMEMSET( tfPtr, 0, sizeof( struct tcpFlow ) );

    /* set state to SYN */
    tfPtr->status = TCP_FLOW_SYN;

    /* copy source and dest addresses into flow */
    XMEMCPY( &tfPtr->sIp, &tr->sIp, sizeof( struct in_addr ) );
    XMEMCPY( &tfPtr->dIp, &tr->dIp, sizeof( struct in_addr ) );

    /* copy source and dest ports into flow */
    tfPtr->sPort = tr->sPort;
    tfPtr->dPort = tr->dPort;

    /* update out size */
    tfPtr->clientIsn = tr->seq;

    /* mark time, for scrubbing */
    tfPtr->lastUpdate = time( NULL );
      
    /* insert traffic record into linked list */
    insertTrafficRecord( tfPtr, tr );
 
    /* insert tcp flow into linked list */

    /* XXX needs to be a binary tree */

    if ( config->tfHead EQ NULL ) {
      config->tfHead = config->tfTail = tfPtr;
    } else {
      config->tfTail->next = tfPtr;
      tfPtr->prev = config->tfTail;
      config->tfTail = tfPtr;
    }
    flowDirection = FLOW_OUTBOUND;

    /* log the packet */
    logTcpPacket( tfPtr, tcp_ptr, tr, FLOW_OUTBOUND );

    return;

  } else {
      
    /*
     * everything else
     */
      
    /* look for a ip/port match */

    /* search for existing tcp flow */
    tfPtr = config->tfHead;
    while( tfPtr != NULL ) {
      /* test for ip and port matching */
      if (
	  ( tr->dPort EQ tfPtr->dPort ) &
	  ( tr->dIp.s_addr EQ tfPtr->dIp.s_addr ) &
	  ( tr->sIp.s_addr EQ tfPtr->sIp.s_addr ) &
	  ( tr->sPort EQ tfPtr->sPort )
	  ) {

	/****
	 *
	 * packet from client to server
	 *
	 ****/

	flowDirection = FLOW_OUTBOUND;

	if ( tcp_ptr->fin & ! tcp_ptr->ack ) {
	  if ( tfPtr->status != TCP_FLOW_EST ) {
	    /* FIN packet received outside of flow */
	    display( LOG_DEBUG, "FIN outside of flow" );
	  } else {

	    tfPtr->status = TCP_FLOW_FIN1;

	    /* update flow timestamp */
	    tfPtr->lastUpdate = time( NULL );

	    /* insert traffic record */
	    insertTrafficRecord( tfPtr, tr );

	    /* log packet */
	    logTcpPacket( tfPtr, tcp_ptr, tr, flowDirection );

	    return;
	  }
	} else if ( tcp_ptr->fin & tcp_ptr->ack ) {
	  if ( tfPtr->status != TCP_FLOW_EST ) {
	    /* FIN packet received outside of flow */
	    display( LOG_DEBUG, "Short FIN+ACK outside of flow" );
	  } else {

	    tfPtr->status = TCP_FLOW_FIN2;
	    tfPtr->lastUpdate = time( NULL );

	    insertTrafficRecord( tfPtr, tr );

	    /* log packet */
	    logTcpPacket( tfPtr, tcp_ptr, tr, flowDirection );

	    return;
	  }
	} else if ( tcp_ptr->ack ) {
	  if ( ( tfPtr->status != TCP_FLOW_SYNACK ) &
	       ( tfPtr->status != TCP_FLOW_EST ) &
	       ( tfPtr->status != TCP_FLOW_FIN1 ) &
	       ( tfPtr->status != TCP_FLOW_FIN2 )
	       ) {
	    /* ack packet received outside of a flow */
	    display( LOG_DEBUG, "ACK outside of flow" );
	  } else {

	    if ( tfPtr->status EQ TCP_FLOW_FIN1 ) {
	      /* flow closed */
	      tfPtr->status = TCP_FLOW_CLOSED;
	    } else if ( tfPtr->status EQ TCP_FLOW_FIN2 ) {
	      /* flow closed */
	      tfPtr->status = TCP_FLOW_CLOSED;
	    } else {
	      tfPtr->status = TCP_FLOW_EST;
	    }
	    tfPtr->lastUpdate = time( NULL );

	    insertTrafficRecord( tfPtr, tr );

	    /* log packet */
	    logTcpPacket( tfPtr, tcp_ptr, tr, flowDirection );

	    return;
	  }
	} else if ( tcp_ptr->rst ) {
	  tfPtr->status = TCP_FLOW_CLOSED;

	  insertTrafficRecord( tfPtr, tr );

	  /* log packet */
	  logTcpPacket( tfPtr, tcp_ptr, tr, flowDirection );

	  return;
	}

      } else if (
		 ( tr->dPort EQ tfPtr->sPort ) &
		 ( tr->dIp.s_addr EQ tfPtr->sIp.s_addr ) &
		 ( tr->sIp.s_addr EQ tfPtr->dIp.s_addr ) &
		 ( tr->sPort EQ tfPtr->dPort )
		 ) {

	/****
	 *
	 * packet from server to client
	 *
	 ****/

	flowDirection = FLOW_INBOUND;

	if ( tcp_ptr->syn & tcp_ptr->ack ) {

	  if ( tfPtr->status != TCP_FLOW_SYN ) {
	    /* out of order syn+ack */
	    display( LOG_DEBUG, "SYN+ACK outside of flow" );
	  } else {
	    /*
	     * search for ack in flow
	     */

	    tfPtr->serverIsn = tr->seq;

	    tfPtr->status = TCP_FLOW_SYNACK;
	    tfPtr->lastUpdate = time( NULL );

	    insertTrafficRecord( tfPtr, tr );

	    /* log packet */
	    logTcpPacket( tfPtr, tcp_ptr, tr, flowDirection );

	    return;
	  }
	} else if ( tcp_ptr->fin & tcp_ptr->ack ) {
	  if ( tfPtr->status != TCP_FLOW_FIN1 ) {
	    /* FIN packet received outside of flow */
	    display( LOG_DEBUG, "FIN+ACK outside of flow" );
	  } else {

	    tfPtr->status = TCP_FLOW_FIN2;
	    tfPtr->lastUpdate = time( NULL );

	    insertTrafficRecord( tfPtr, tr );

	    /* log packet */
	    logTcpPacket( tfPtr, tcp_ptr, tr, flowDirection );

	    return;
	  }
	} else if ( tcp_ptr->ack ) {
	  if ( ( tfPtr->status != TCP_FLOW_EST )
	       ) {
	    /* ack packet received outside of a flow */
	    display( LOG_DEBUG, "ACK outside of flow" );
	  } else {

	    tfPtr->lastUpdate = time( NULL );

	    insertTrafficRecord( tfPtr, tr );

	    /* log packet */
	    logTcpPacket( tfPtr, tcp_ptr, tr, flowDirection );

	    return;
	  }
	} else if ( tcp_ptr->rst ) {
	  tfPtr->status = TCP_FLOW_CLOSED;

	  insertTrafficRecord( tfPtr, tr );

	  /* log packet */
	  logTcpPacket( tfPtr, tcp_ptr, tr, flowDirection );

	  return;
	}

      } else {
#ifdef DEBUG
	if ( config->debug >= 3 )
	  display( LOG_DEBUG, "Flow not found" );
#endif
	flowDirection = FLOW_FALSE;
      }

      if ( ( ( ( tfPtr->lastUpdate + 60 ) < currentTime ) ) |
	   ( tfPtr->status EQ TCP_FLOW_CLOSED )
	   ) {
	/* old traffic flow, remove it */

#ifdef DEBUG
	if ( config->debug >= 4 )
	  display( LOG_DEBUG, "Removing records in old flow" );
#endif

	/* empty the traffic records related to this flow */
	while( tfPtr->tail != NULL ) {
#ifdef DEBUG
	  if ( config->debug >= 5 )
	    display( LOG_DEBUG, "Removing traffic record [%d]", tfPtr->recordCount );
#endif
	  tmpTrPtr = tfPtr->tail;
	  tfPtr->tail = tfPtr->tail->prev;
	  XFREE( tmpTrPtr );
	  tfPtr->recordCount--;
	}

#ifdef DEBUG
	if ( config->debug >= 4 ) 
	  display( LOG_DEBUG, "Removing old flow" );
#endif

	tmpTfPtr = tfPtr;

	if ( tfPtr EQ config->tfHead ) {
	  config->tfHead = tfPtr->next;
	} else {
	  tfPtr->prev->next = tfPtr->next;
	}

	if ( tfPtr EQ config->tfTail ) {
	  config->tfTail = tfPtr->prev;
	} else {
	  tfPtr->next->prev = tfPtr->prev;
	}

	tfPtr = tfPtr->next;
	XFREE( tmpTfPtr );

      } else
	tfPtr = tfPtr->next;
    }

    /* log packet */
    logTcpPacket( NULL, tcp_ptr, tr, FLOW_UNKNOWN );
  }

  /* cleanup, we will do nothing with this packet */
  return;
}

/****
 *
 * insert traffic record into flow
 *
 ****/

int insertTrafficRecord( struct tcpFlow *tfPtr, struct trafficRecord *trPtr ) {
  struct trafficRecord *tmpTrPtr;

  /* insert traffic record into linked list */
  tmpTrPtr = ( struct trafficRecord *)XMALLOC( sizeof ( struct trafficRecord ) );
  XMEMSET( tmpTrPtr, 0, sizeof( struct trafficRecord ) );
  XMEMCPY( tmpTrPtr, trPtr, sizeof( struct trafficRecord ) );

  /* insert record into flow traffic list */

  /* add the traffic record to the flow record */
  if ( tfPtr->head EQ NULL ) {
    /* first record in the flow */
    tfPtr->head = tfPtr->tail = tmpTrPtr;
  } else {
    tfPtr->tail->next = tmpTrPtr;
    tmpTrPtr->prev = tfPtr->tail;
    tfPtr->tail = tmpTrPtr;
  }

  tfPtr->recordCount++;

  return TRUE;
}

/****
 *
 * log packet
 *
 ****/

void logTcpPacket( struct tcpFlow *tfPtr, struct tcphdr *tcpPtr, struct trafficRecord *tr, int flowDir ) {
  PRIVATE char s_ip_addr_str[MAX_IP_ADDR_LEN+1];
  PRIVATE char d_ip_addr_str[MAX_IP_ADDR_LEN+1];
  char tcpFlags[9];
  char flowString[3];
  int tmpSentCount;
  int tmpAckCount;

#ifdef BSD_DERIVED
  if ( tcpPtr->th_flags & TH_FIN )
#else
  if ( tcpPtr->fin )
#endif
    tcpFlags[0] = 'F';
  else
    tcpFlags[0] = '.';

#ifdef BSD_DERIVED
  if ( tcpPtr->th_flags & TH_SYN )
#else
  if ( tcpPtr->syn )
#endif
    tcpFlags[1] = 'S';
  else
    tcpFlags[1] = '.';

#ifdef BSD_DERIVED
  if ( tcpPtr->th_flags & TH_RST )
#else
  if ( tcpPtr->rst )
#endif
    tcpFlags[2] = 'R';
  else
    tcpFlags[2] = '.';

#ifdef BSD_DERIVED
  if ( tcpPtr->th_flags & TH_PUSH )
#else
  if ( tcpPtr->psh )
#endif
    tcpFlags[3] = 'P';
  else
    tcpFlags[3] = '.';

#ifdef BSD_DERIVED
  if ( tcpPtr->th_flags & TH_ACK )
#else
  if ( tcpPtr->ack )
#endif
    tcpFlags[4] = 'A';
  else
    tcpFlags[4] = '.';

#ifdef BSD_DERIVED
  if ( tcpPtr->th_flags & TH_URG )
#else
  if ( tcpPtr->urg )
#endif
    tcpFlags[5] = 'U';
  else
    tcpFlags[5] = '.';
  
#ifdef BSD_DERIVED
  if ( tcpPtr->th_flags & TH_ECE )
    tcpFlags[6] = 'E';
  else
    tcpFlags[6] = '.';

  if ( tcpPtr->th_flags & TH_CWR )
    tcpFlags[7] = 'C';
  else
    tcpFlags[7] = '.';
  tcpFlags[8] = 0;
#else
  tcpFlags[6] = 0;
#endif

#ifdef DEBUG
  if ( config->debug >= 6 ) {
    display( LOG_DEBUG, "TCP: Flags [%s]", tcpFlags );
  }
#endif

  /*
   * write packet to log
   */ 
  XSTRNCPY( s_ip_addr_str, inet_ntoa( tr->sIp ), MAX_IP_ADDR_LEN );
  XSTRNCPY( d_ip_addr_str, inet_ntoa( tr->dIp ), MAX_IP_ADDR_LEN );
  if ( flowDir EQ FLOW_OUTBOUND ) {
    XSTRCPY( flowString, "->" );
    tmpSentCount = tr->seq - tfPtr->clientIsn;
    tmpAckCount = tr->ack - tfPtr->serverIsn;
  } else if ( flowDir EQ FLOW_INBOUND ) {
    XSTRCPY( flowString, "<-" );
    tmpSentCount = tr->seq - tfPtr->serverIsn;
    tmpAckCount = tr->ack - tfPtr->clientIsn;
  } else if ( flowDir EQ FLOW_FALSE ) {
    XSTRCPY( flowString, "X" );
    tmpSentCount = tmpAckCount = 0;
  } else {
    XSTRCPY( flowString, "??" );
    tmpSentCount = tmpAckCount = 0;
  }

  fprintf( config->log_st, "[%04d/%02d/%02d %02d:%02d:%02d] %16s:%-5u %s %16s:%-5u TCP [%s] win: %u seq: %-10u (+%u) ack: %-10u (+%u)\n",
	   tr->wireTime.tm_year+1900,
	   tr->wireTime.tm_mon+1,
	   tr->wireTime.tm_mday,
	   tr->wireTime.tm_hour,
	   tr->wireTime.tm_min,
	   tr->wireTime.tm_sec,
	   d_ip_addr_str,
	   tr->dPort,
	   flowString,
	   s_ip_addr_str,
	   tr->sPort,
	   tcpFlags,
	   tr->win,
	   tr->seq,
	   tmpSentCount,
	   tr->ack,
	   tmpAckCount
	   );

#ifdef DEBUG
  if ( config->debug >= 1 )
    display( LOG_DEBUG, "[%04d/%02d/%02d %02d:%02d:%02d] %16s:%-5u %s %16s:%-5u TCP [%s] win: %u seq: %-10u (+%u) ack: %-10u (+%u)\n",
	     tr->wireTime.tm_year+1900,
	     tr->wireTime.tm_mon+1,
	     tr->wireTime.tm_mday,
	     tr->wireTime.tm_hour,
	     tr->wireTime.tm_min,
	     tr->wireTime.tm_sec,
	     d_ip_addr_str,
	     tr->dPort,
	     flowString,
	     s_ip_addr_str,
	     tr->sPort,
	     tcpFlags,
	     tr->win,
	     tr->seq,
	     tmpSentCount,
	     tr->ack,
	     tmpAckCount
	     );
#endif

  return;
}
