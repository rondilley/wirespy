/****
 *
 * Process TCP Packets
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

/****
 *
 * external functions
 *
 ****/

/****
 *
 * functions
 *
 ****/

/****
 * 
 * flow garbage collector
 * 
 ****/

void pruneFlows( void ) {
    PRIVATE char s_ip_addr_str[MAX_IP_ADDR_LEN+1];
    PRIVATE char d_ip_addr_str[MAX_IP_ADDR_LEN+1];
    PRIVATE struct tcpFlow *tfPtr, *tmpTfPtr;
    struct tm *tmpTm;
    PRIVATE struct trafficRecord *tr_tmp, *tmpTrPtr;
    char tmpBuf[4096];
    int r = 0;

    /* grow hash if needed */
    config->tcpFlowHash = dyGrowHash( config->tcpFlowHash );
    
#ifdef DEBUG
    if ( config->debug >= 1 )
      display( LOG_DEBUG, "TCP Flows [%u]", config->flowCount );
#endif
    
    tfPtr = config->tfHead;
    while ( tfPtr != NULL ) {
      if ( ( ( ( tfPtr->lastUpdate + 30 ) < config->last_packet_time ) ) && ( tfPtr->status EQ TCP_FLOW_CLOSED ) ) { // flow closed and no traffic for too long
	/* old traffic flow, remove it */
        tmpTfPtr = tfPtr;
        tfPtr = tfPtr->next;
        reportTcpFlow( tmpTfPtr );
      } else if ( ( tfPtr->lastUpdate + 600 ) < config->last_packet_time ) { // flow not closed but no traffic for too long
        /* old traffic flow, remove it */
        tmpTfPtr = tfPtr;
        tfPtr = tfPtr->next;
        reportTcpFlow( tmpTfPtr );
      } else
        tfPtr = tfPtr->next;
    }
}

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
  
  /* check prune counter */
  if ( config->pruneCounter > 12 ) {
      config->pruneCounter = 0;
      pruneFlows();
  }
  
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
  tr->aRec.sPort = ntohs( tcp_ptr->th_sport );
  tr->aRec.dPort = ntohs( tcp_ptr->th_dport );
  tr->seq = ntohl( tcp_ptr->th_seq );
  tr->ack = ntohl( tcp_ptr->th_ack );
  tr->win = ntohs( tcp_ptr->th_win );
#else
  tr->aRec.sPort = ntohs( tcp_ptr->source );
  tr->aRec.dPort = ntohs( tcp_ptr->dest );
  tr->seq = ntohl( tcp_ptr->seq );
  tr->ack = ntohl( tcp_ptr->ack_seq );
  tr->win = ntohs( tcp_ptr->window );
#endif

#ifdef DEBUG
  if ( config->debug >= 3 ) {
    display( LOG_INFO, "TCP: S: %d D: %d", tr->aRec.sPort, tr->aRec.dPort );
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

#ifdef BSD_DERIVED
  if ( ( tcp_ptr->th_flags & TH_SYN ) && ! ( tcp_ptr->th_flags & TH_ACK ) ) {
#else
  if ( tcp_ptr->syn & ! tcp_ptr->ack ) {
#endif

    /*
     * initial SYN
     */

    /* create new tcp flow record */
    tfPtr = (struct tcpFlow *)XMALLOC( sizeof( struct tcpFlow ) );
    XMEMSET( tfPtr, 0, sizeof( struct tcpFlow ) );

    /* set state to SYN */
    tfPtr->status = TCP_FLOW_SYN;

    /* copy source and dest addresses into flow */
    XMEMCPY( &tfPtr->aRecOut, &tr->aRec, sizeof( struct trafficAddressRecord ) );
    
    XMEMCPY( &tfPtr->aRecIn.sMac, &tr->aRec.dMac, ETHER_ADDR_LEN );
    XMEMCPY( &tfPtr->aRecIn.dMac, &tr->aRec.sMac, ETHER_ADDR_LEN );
    tfPtr->aRecIn.ethProto = tr->aRec.ethProto;
    XMEMCPY( &tfPtr->aRecIn.sIp, &tr->aRec.dIp, sizeof( struct in_addr ) );
    XMEMCPY( &tfPtr->aRecIn.dIp, &tr->aRec.sIp, sizeof( struct in_addr ) );
    tfPtr->aRecIn.ipProto = tr->aRec.ipProto;
    tfPtr->aRecIn.sPort = tr->aRec.dPort;
    tfPtr->aRecIn.dPort = tr->aRec.sPort;
     
    /* update out size */
    tfPtr->clientIsn = tr->seq;

    /* mark time, for scrubbing */
    tfPtr->firstUpdate = tfPtr->lastUpdate = tr->wire_sec;

    /* XXX should check for duplicates */
    
    /* increment outbound packet count */
    tfPtr->packetsOut++;
    
    /* increment outbound byte count */
    tfPtr->bytesOut += tr->size;

    /* insert tcp flow into linked list */

#ifdef DEBUG
    if ( config->debug >= 3 )
        display( LOG_DEBUG, "Inserting outbound address record into hash\n" );
#endif
    
    /* insert new traffic flow into hash */
    if ( addUniqueHashRec( config->tcpFlowHash, (char *)&tfPtr->aRecOut, sizeof( struct trafficAddressRecord ), tfPtr ) != TRUE ) {
#ifdef DEBUG
      XSTRNCPY( s_eth_addr_str, ether_ntoa((struct ether_addr *)&tfPtr->aRecOut.sMac), ((ETHER_ADDR_LEN*2)+ETHER_ADDR_LEN)-1 );
      XSTRNCPY( d_eth_addr_str, ether_ntoa((struct ether_addr *)&tfPtr->aRecOut.dMac), ((ETHER_ADDR_LEN*2)+ETHER_ADDR_LEN)-1 );
      XSTRNCPY( s_ip_addr_str, inet_ntoa( tfPtr->aRecOut.sIp ), MAX_IP_ADDR_LEN );
      XSTRNCPY( d_ip_addr_str, inet_ntoa( tfPtr->aRecOut.dIp ), MAX_IP_ADDR_LEN );
      display( LOG_DEBUG, "Problem inserting inbound address record [%s:%s:%u-%s:%s:%u]",
               s_eth_addr_str,
               s_ip_addr_str,
               tfPtr->aRecOut.sPort,
               d_eth_addr_str,
               d_ip_addr_str,
               tfPtr->aRecOut.dPort
	     );
#endif

      XFREE( tfPtr );
      /* log the packet */
      if( config->verbose )
        logTcpPacket( tfPtr, tcp_ptr, tr, FLOW_OUTBOUND );

      return;
        
    } else {
#ifdef DEBUG
      if ( config->debug >= 3 )
          display( LOG_DEBUG, "Inserting inbound address record into hash\n" );
#endif

      if ( addUniqueHashRec( config->tcpFlowHash, (char *)&tfPtr->aRecIn, sizeof( struct trafficAddressRecord ), tfPtr ) != TRUE ) {
#ifdef DEBUG
        XSTRNCPY( s_eth_addr_str, ether_ntoa((struct ether_addr *)&tfPtr->aRecIn.sMac), ((ETHER_ADDR_LEN*2)+ETHER_ADDR_LEN)-1 );
        XSTRNCPY( d_eth_addr_str, ether_ntoa((struct ether_addr *)&tfPtr->aRecIn.dMac), ((ETHER_ADDR_LEN*2)+ETHER_ADDR_LEN)-1 );
        XSTRNCPY( s_ip_addr_str, inet_ntoa( tfPtr->aRecIn.sIp ), MAX_IP_ADDR_LEN );
        XSTRNCPY( d_ip_addr_str, inet_ntoa( tfPtr->aRecIn.dIp ), MAX_IP_ADDR_LEN );
        display( LOG_DEBUG, "Problem inserting inbound address record [%s:%s:%u-%s:%s:%u]",
                 s_eth_addr_str,
                 s_ip_addr_str,
                 tfPtr->aRecIn.sPort,
                 d_eth_addr_str,
                 d_ip_addr_str,
                 tfPtr->aRecIn.dPort
               );
#endif

        XFREE( tfPtr );
        /* log the packet */
        if( config->verbose )
            logTcpPacket( tfPtr, tcp_ptr, tr, FLOW_OUTBOUND );

        return;
      }
    }
    
        
    /* insert traffic record into linked list */
    //insertTrafficRecord( tfPtr, tr );
 
    if ( config->tfHead EQ NULL ) {
      config->tfHead = config->tfTail = tfPtr;
    } else {
      config->tfTail->next = tfPtr;
      tfPtr->prev = config->tfTail;
      config->tfTail = tfPtr;
    }
    config->flowCount++;
    flowDirection = FLOW_OUTBOUND;

    /* log the packet */
    if( config->verbose )
      logTcpPacket( tfPtr, tcp_ptr, tr, FLOW_OUTBOUND );

    return;
  };
  
  /*
   * everything else
   */

  /* search for existing tcp flow */
  if ( ( tmpHashRec = snoopHashRecord( config->tcpFlowHash, (char *)&tr->aRec, sizeof( struct trafficAddressRecord ) ) ) EQ NULL ) {
    /* no match, flow data without syn */
#ifdef DEBUG
    if ( config->debug >= 3 )
      display( LOG_DEBUG, "Flow not found" );
#endif
    flowDirection = FLOW_FALSE;

    /* log packet */
    if ( config->verbose )
      logTcpPacket( NULL, tcp_ptr, tr, FLOW_UNKNOWN );

        
  } else {
    tfPtr = tmpHashRec->data;

    if ( XMEMCMP( &tr->aRec, &tfPtr->aRecOut, sizeof( struct trafficAddressRecord ) ) EQ 0 ) { // matches the outbound side

      /****
       *
       * packet from client to server
       *
       ****/

      flowDirection = FLOW_OUTBOUND;

#ifdef BSD_DERIVED
      if ( ( tcp_ptr->th_flags & TH_FIN ) && ! ( tcp_ptr->th_flags & TH_ACK ) ) {
#else
      if ( tcp_ptr->fin && ! tcp_ptr->ack ) {
#endif

        if ( tfPtr->status != TCP_FLOW_EST ) {
	  /* FIN packet received outside of flow */
	  display( LOG_DEBUG, "FIN outside of flow" );
	  /* log packet */
          if ( config->verbose )
            logTcpPacketErr( tfPtr, tcp_ptr, tr, flowDirection, "FIN outside of flow" );
        } else {

	  tfPtr->status = TCP_FLOW_FIN1;

	  /* update flow timestamp */
	  tfPtr->lastUpdate = tr->wire_sec;

          /* increment outbound packet count */
          tfPtr->packetsOut++;
    
          /* increment outbound byte count */
          tfPtr->bytesOut += tr->size;
          
          /* insert traffic record */
          //insertTrafficRecord( tfPtr, tr );
          
	  /* log packet */
          if ( config->verbose )
            logTcpPacket( tfPtr, tcp_ptr, tr, flowDirection );
 
	  return;
	}
	  
#ifdef BSD_DERIVED
      } else if ( ( tcp_ptr->th_flags & TH_FIN ) && ( tcp_ptr->th_flags & TH_ACK ) ) {
#else
      } else if ( tcp_ptr->fin && tcp_ptr->ack ) {
#endif
	if ( ( tfPtr->status != TCP_FLOW_EST ) &&
             ( tfPtr->status != TCP_FLOW_FIN1 ) &&
             ( tfPtr->status != TCP_FLOW_FIN2 ) ) {
	  /* FIN packet received outside of flow */
	  display( LOG_DEBUG, "Short FIN+ACK outside of flow" );
          /* log packet */
          if ( config->verbose )
            logTcpPacketErr( tfPtr, tcp_ptr, tr, flowDirection, "Short FIN+ACK outside of flow" );
	} else {

	  tfPtr->status = TCP_FLOW_FIN2;
	  tfPtr->lastUpdate = tr->wire_sec;

          /* increment outbound packet count */
          tfPtr->packetsOut++;
    
          /* increment outbound byte count */
          tfPtr->bytesOut += tr->size;
    
	  //insertTrafficRecord( tfPtr, tr );

	  /* log packet */
          if ( config->verbose )
	    logTcpPacket( tfPtr, tcp_ptr, tr, flowDirection );

	  return;
	}
#ifdef BSD_DERIVED
      } else if ( tcp_ptr->th_flags & TH_ACK ) {
#else
      } else if ( tcp_ptr->ack ) {
#endif
	if ( ( tfPtr->status != TCP_FLOW_SYNACK ) &&
	     ( tfPtr->status != TCP_FLOW_EST ) &&
	     ( tfPtr->status != TCP_FLOW_FIN1 ) &&
	     ( tfPtr->status != TCP_FLOW_FIN2 )
	     ) {
	  /* ack packet received outside of a flow */
	  display( LOG_DEBUG, "ACK outside of flow" );
	  /* log packet */
          if ( config->verbose )
            logTcpPacketErr( tfPtr, tcp_ptr, tr, flowDirection, "ACK outside of flow" );
	} else {

	  if ( ( tfPtr->status EQ TCP_FLOW_FIN1 ) || ( tfPtr->status EQ TCP_FLOW_FIN2 ) )
	    tfPtr->status = TCP_FLOW_CLOSED;
	  else
	    tfPtr->status = TCP_FLOW_EST;

	  tfPtr->lastUpdate = tr->wire_sec;

          /* increment outbound packet count */
          tfPtr->packetsOut++;
    
          /* increment outbound byte count */
          tfPtr->bytesOut += tr->size;
         
	  /* log packet */
          if ( config->verbose )
            logTcpPacket( tfPtr, tcp_ptr, tr, flowDirection );

          if ( tfPtr->status EQ TCP_FLOW_EST ) {
            /* process specific established flows */
            if ( tfPtr->aRecOut.dPort EQ 23 ) { // telnet
              /* insert traffic record */
              insertTrafficRecord( tfPtr, tr );
              processTelnetFlow( tfPtr, tr, packet );
            } else if ( tfPtr->aRecOut.dPort EQ 25 ) { // smtp
              /* insert traffic record */
              insertTrafficRecord( tfPtr, tr );
              processSmtpFlow( tfPtr, tr, packet );
            } else if ( tfPtr->aRecOut.dPort EQ 80 ) { // http
              /* insert traffic record */
              insertTrafficRecord( tfPtr, tr );
              processHttpFlow( tfPtr, tr, packet );
            }            
          } else if ( tfPtr->status EQ TCP_FLOW_CLOSED ) {
            /* report and delete flow */
            reportTcpFlow( tfPtr );
          }
          
          return;
        }
#ifdef BSD_DERIVED
      } else if ( tcp_ptr->th_flags & TH_RST ) {
#else
      } else if ( tcp_ptr->rst ) {
#endif
	tfPtr->status = TCP_FLOW_CLOSED;

        /* increment outbound packet count */
        tfPtr->packetsOut++;
    
        /* increment outbound byte count */
        tfPtr->bytesOut += tr->size;
    
	//insertTrafficRecord( tfPtr, tr );

	/* log packet */
        if ( config->verbose )
          logTcpPacket( tfPtr, tcp_ptr, tr, flowDirection );

        /* report flow and delete */
        reportTcpFlow( tfPtr );
        
	return;
      }

    } else { // must match the inbound instead

      /****
       *
       * packet from server to client
       *
       ****/

      flowDirection = FLOW_INBOUND;
#ifdef BSD_DERIVED
      if ( ( tcp_ptr->th_flags & TH_SYN ) && ( tcp_ptr->th_flags & TH_ACK ) ) {
#else
      if ( tcp_ptr->syn && tcp_ptr->ack ) {
#endif
        if ( tfPtr->status != TCP_FLOW_SYN ) {
          /* out of order syn+ack */
	  display( LOG_DEBUG, "SYN+ACK outside of flow" );
	  /* log packet */
          if ( config->verbose )
            logTcpPacketErr( tfPtr, tcp_ptr, tr, flowDirection, "SYN+ACK outside of flow" );
        } else {
	  /*
	   * search for ack in flow
	   */

	  tfPtr->serverIsn = tr->seq;

	  tfPtr->status = TCP_FLOW_SYNACK;
	  tfPtr->lastUpdate = tr->wire_sec;

          /* increment outbound packet count */
          tfPtr->packetsIn++;
    
          /* increment outbound byte count */
          tfPtr->bytesIn += tr->size;
    
	  //insertTrafficRecord( tfPtr, tr );

	  /* log packet */
          if ( config->verbose )
            logTcpPacket( tfPtr, tcp_ptr, tr, flowDirection );

	  return;
	}
#ifdef BSD_DERIVED
      } else if ( ( tcp_ptr->th_flags & TH_FIN ) && ( tcp_ptr->th_flags & TH_ACK ) ) {
#else
      } else if ( tcp_ptr->fin && tcp_ptr->ack ) {
#endif
  	if ( ( tfPtr->status != TCP_FLOW_FIN1 ) &&
             ( tfPtr->status != TCP_FLOW_FIN2 ) &&
             ( tfPtr->status != TCP_FLOW_EST ) ) {
	  /* FIN packet received outside of flow */
	  display( LOG_DEBUG, "FIN+ACK outside of flow" );
	  /* log packet */
          if ( config->verbose )
            logTcpPacketErr( tfPtr, tcp_ptr, tr, flowDirection, "FIN+ACK outside of flow" );
	} else {

	  tfPtr->status = TCP_FLOW_FIN2;
	  tfPtr->lastUpdate = tr->wire_sec;

          /* increment outbound packet count */
          tfPtr->packetsIn++;
    
          /* increment outbound byte count */
          tfPtr->bytesIn += tr->size;
    
	  //insertTrafficRecord( tfPtr, tr );

	  /* log packet */
          if ( config->verbose )
            logTcpPacket( tfPtr, tcp_ptr, tr, flowDirection );

	  return;
	}
#ifdef BSD_DERIVED
      } else if ( tcp_ptr->th_flags & TH_ACK ) {
#else
      } else if ( tcp_ptr->ack ) {
#endif
	if ( ( tfPtr->status != TCP_FLOW_EST ) &&
	     ( tfPtr->status != TCP_FLOW_FIN1 ) &&
	     ( tfPtr->status != TCP_FLOW_FIN2 )
	     ) {
	  /* ack packet received outside of a flow */
	  display( LOG_DEBUG, "ACK outside of flow" );
	  /* log packet */
          if ( config->verbose )
            logTcpPacketErr( tfPtr, tcp_ptr, tr, flowDirection, "ACK outside of flow" );
	} else {
	  if ( ( tfPtr->status EQ TCP_FLOW_FIN1 ) || ( tfPtr->status EQ TCP_FLOW_FIN2 ) )
	    tfPtr->status = TCP_FLOW_CLOSED;
          
          tfPtr->lastUpdate = tr->wire_sec;

          /* increment outbound packet count */
          tfPtr->packetsIn++;
    
          /* increment outbound byte count */
          tfPtr->bytesIn += tr->size;
    
	  //insertTrafficRecord( tfPtr, tr );

	  /* log packet */
          if ( config->verbose )
            logTcpPacket( tfPtr, tcp_ptr, tr, flowDirection );

          if ( tfPtr->status EQ TCP_FLOW_EST ) {
            /* process specific established flows */
            if ( tfPtr->aRecOut.sPort EQ 23 ) { // telnet
              /* insert traffic record */
              insertTrafficRecord( tfPtr, tr );
              processTelnetFlow( tfPtr, tr, packet );
            } else if ( tfPtr->aRecOut.sPort EQ 25 ) { // smtp
              /* insert traffic record */
              insertTrafficRecord( tfPtr, tr );
              processSmtpFlow( tfPtr, tr, packet );
            } else if ( tfPtr->aRecOut.sPort EQ 80 ) { // http
              /* insert traffic record */
              insertTrafficRecord( tfPtr, tr );
              processHttpFlow( tfPtr, tr, packet );
            }            
          } else if ( tfPtr->status EQ TCP_FLOW_CLOSED ) {
            /* report and delete flow */
            reportTcpFlow( tfPtr );
          }
          
	  return;
	}
#ifdef BSD_DERIVED
      } else if ( tcp_ptr->th_flags & TH_RST ) {
#else
      } else if ( tcp_ptr->rst ) {
#endif
  	tfPtr->status = TCP_FLOW_CLOSED;

        /* increment outbound packet count */
        tfPtr->packetsIn++;
    
        /* increment outbound byte count */
        tfPtr->bytesIn += tr->size;
    
	//insertTrafficRecord( tfPtr, tr );

	/* log packet */
        if ( config->verbose )
          logTcpPacket( tfPtr, tcp_ptr, tr, flowDirection );

        /* report and delete flow */
        reportTcpFlow( tfPtr );
        
	return;
      }
    }
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
  if ( ( tmpTrPtr = ( struct trafficRecord *)XMALLOC( sizeof ( struct trafficRecord ) ) ) EQ NULL ) {
    display( LOG_ERR, "Unable to allocate memory for traffic record" );
    quit = TRUE;
    exit( 1 );
  }
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

void logTcpPacket( struct tcpFlow *tfPtr, const struct tcphdr *tcpPtr, struct trafficRecord *tr, int flowDir ) {
  PRIVATE char s_eth_addr_str[(ETHER_ADDR_LEN*2)+ETHER_ADDR_LEN];
  PRIVATE char d_eth_addr_str[(ETHER_ADDR_LEN*2)+ETHER_ADDR_LEN];
  PRIVATE char s_ip_addr_str[MAX_IP_ADDR_LEN+2];
  PRIVATE char d_ip_addr_str[MAX_IP_ADDR_LEN+2];
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
  XSTRNCPY( s_eth_addr_str, ether_ntoa((struct ether_addr *)tr->aRec.sMac), ((ETHER_ADDR_LEN*2)+ETHER_ADDR_LEN)-1 );
  XSTRNCPY( d_eth_addr_str, ether_ntoa((struct ether_addr *)tr->aRec.dMac), ((ETHER_ADDR_LEN*2)+ETHER_ADDR_LEN)-1 );
  XSTRNCPY( s_ip_addr_str, inet_ntoa( tr->aRec.sIp ), MAX_IP_ADDR_LEN );
  XSTRNCPY( d_ip_addr_str, inet_ntoa( tr->aRec.dIp ), MAX_IP_ADDR_LEN );
  if ( flowDir EQ FLOW_OUTBOUND ) {
    XSTRCPY( flowString, "->" );
    tmpSentCount = tr->seq - tfPtr->clientIsn;
    tmpAckCount = tr->ack - tfPtr->serverIsn;
  } else if ( flowDir EQ FLOW_INBOUND ) {
    XSTRCPY( flowString, "<-" );
    tmpSentCount = tr->seq - tfPtr->serverIsn;
    tmpAckCount = tr->ack - tfPtr->clientIsn;
  } else if ( flowDir EQ FLOW_FALSE ) {
    XSTRCPY( flowString, "XX" );
    tmpSentCount = tmpAckCount = 0;
  } else {
    XSTRCPY( flowString, "??" );
    tmpSentCount = tmpAckCount = 0;
  }

#if SIZEOF_SIZE_T == 8
  fprintf( config->log_st, "[%lu.%06lu] %17s->%-17s %16s:%-5u %s %16s:%-5u TCP [%s] win: %u seq: %-10u (+%u) ack: %-10u (+%u)\n",
	   tr->wire_sec,
           tr->wire_usec,
#else
#ifdef OPENBSD
  fprintf( config->log_st, "[%lu.",
	   tr->wire_sec );
  fprintf( config->log_st, "%06lu] ",
	   tr->wire_usec );
  fprintf( config->log_st, "%17s->%-17s %16s:%-5u %s %16s:%-5u TCP [%s] win: %u seq: %-10u (+%u) ack: %-10u (+%u)\n",
#else
  fprintf( config->log_st, "[%lu.%06lu] %17s->%-17s %16s:%-5u %s %16s:%-5u TCP [%s] win: %u seq: %-10u (+%u) ack: %-10u (+%u)\n",
	   tr->wire_sec,
           tr->wire_usec,
#endif
#endif
	   s_eth_addr_str,
           d_eth_addr_str,
           s_ip_addr_str,
	   tr->aRec.sPort,
	   flowString,
           d_ip_addr_str,
	   tr->aRec.dPort,
	   tcpFlags,
	   tr->win,
	   tr->seq,
	   tmpSentCount,
	   tr->ack,
	   tmpAckCount
	   );
  
  return;
}

/****
 *
 * log packet with error
 *
 ****/

void logTcpPacketErr( struct tcpFlow *tfPtr, const struct tcphdr *tcpPtr, struct trafficRecord *tr, int flowDir, char *errStr ) {
  PRIVATE char s_eth_addr_str[(ETHER_ADDR_LEN*2)+ETHER_ADDR_LEN];
  PRIVATE char d_eth_addr_str[(ETHER_ADDR_LEN*2)+ETHER_ADDR_LEN];
  PRIVATE char s_ip_addr_str[MAX_IP_ADDR_LEN+2];
  PRIVATE char d_ip_addr_str[MAX_IP_ADDR_LEN+2];
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
  XSTRNCPY( s_eth_addr_str, ether_ntoa((struct ether_addr *)tr->aRec.sMac), ((ETHER_ADDR_LEN*2)+ETHER_ADDR_LEN)-1 );
  XSTRNCPY( d_eth_addr_str, ether_ntoa((struct ether_addr *)tr->aRec.dMac), ((ETHER_ADDR_LEN*2)+ETHER_ADDR_LEN)-1 );
  XSTRNCPY( s_ip_addr_str, inet_ntoa( tr->aRec.sIp ), MAX_IP_ADDR_LEN );
  XSTRNCPY( d_ip_addr_str, inet_ntoa( tr->aRec.dIp ), MAX_IP_ADDR_LEN );
  if ( flowDir EQ FLOW_OUTBOUND ) {
    XSTRCPY( flowString, "->" );
    tmpSentCount = tr->seq - tfPtr->clientIsn;
    tmpAckCount = tr->ack - tfPtr->serverIsn;
  } else if ( flowDir EQ FLOW_INBOUND ) {
    XSTRCPY( flowString, "<-" );
    tmpSentCount = tr->seq - tfPtr->serverIsn;
    tmpAckCount = tr->ack - tfPtr->clientIsn;
  } else if ( flowDir EQ FLOW_FALSE ) {
    XSTRCPY( flowString, "XX" );
    tmpSentCount = tmpAckCount = 0;
  } else {
    XSTRCPY( flowString, "??" );
    tmpSentCount = tmpAckCount = 0;
  }

#if SIZEOF_SIZE_T == 8
  fprintf( config->log_st, "[%lu.%06lu] %17s->%-17s %16s:%-5u %s %16s:%-5u TCP [%s] win: %u seq: %-10u (+%u) ack: %-10u (+%u) - %s\n",
	   tr->wire_sec,
           tr->wire_usec,
#else
#ifdef OPENBSD
  fprintf( config->log_st, "[%lu.",
	   tr->wire_sec );
  fprintf( config->log_st, "%06lu] ",
	   tr->wire_usec );
  fprintf( config->log_st, "%17s->%-17s %16s:%-5u %s %16s:%-5u TCP [%s] win: %u seq: %-10u (+%u) ack: %-10u (+%u) - %s\n",
#else
  fprintf( config->log_st, "[%lu.%06lu] %17s->%-17s %16s:%-5u %s %16s:%-5u TCP [%s] win: %u seq: %-10u (+%u) ack: %-10u (+%u) - %s\n",
	   tr->wire_sec,
           tr->wire_usec,
#endif
#endif
	   s_eth_addr_str,
           d_eth_addr_str,
           s_ip_addr_str,
	   tr->aRec.sPort,
	   flowString,
           d_ip_addr_str,
	   tr->aRec.dPort,
	   tcpFlags,
	   tr->win,
	   tr->seq,
	   tmpSentCount,
	   tr->ack,
	   tmpAckCount,
           errStr
	   );
  
  return;
}

/****
 *
 * traverse traffic records
 * 
 ****/

int traverseTrafficRecords ( struct tcpFlow *tfPtr ) {
    // clientIsn
    // serverIsn
    // currentTrSeq
    // currentTrAck
    // currnetTrSize
}
  
/****
 * 
 * show flow record
 * 
 ****/

int showTcpFlow( struct tcpFlow *tfPtr ) {
    PRIVATE char s_eth_addr_str[(ETHER_ADDR_LEN*2)+ETHER_ADDR_LEN];
    PRIVATE char d_eth_addr_str[(ETHER_ADDR_LEN*2)+ETHER_ADDR_LEN];
    PRIVATE char s_ip_addr_str[MAX_IP_ADDR_LEN+2];
    PRIVATE char d_ip_addr_str[MAX_IP_ADDR_LEN+2];
    struct tm *tmpTm;
    char tmpBuf[4096];

    /*
     * report on flow
     */

    XSTRNCPY( s_eth_addr_str, ether_ntoa((struct ether_addr *)&tfPtr->aRecOut.sMac), ((ETHER_ADDR_LEN*2)+ETHER_ADDR_LEN)-1 );
    XSTRNCPY( d_eth_addr_str, ether_ntoa((struct ether_addr *)&tfPtr->aRecOut.dMac), ((ETHER_ADDR_LEN*2)+ETHER_ADDR_LEN)-1 );
    XSTRNCPY( s_ip_addr_str, inet_ntoa( tfPtr->aRecOut.sIp ), MAX_IP_ADDR_LEN );
    XSTRNCPY( d_ip_addr_str, inet_ntoa( tfPtr->aRecOut.dIp ), MAX_IP_ADDR_LEN );

    tmpTm = localtime( &tfPtr->firstUpdate );

#if SIZEOF_SIZE_T == 8
    snprintf( tmpBuf, sizeof( tmpBuf ), "TCPFLOW startTime=%04d/%02d/%02d %02d:%02d:%02d sourceMac=%s sourceIp=%s sourcePort=%u destMac=%s destIp=%s destPort=%u duration=%lu packetsIn=%lu packetsOut=%lu bytesIn=%lu bytesOut=%lu records=%lu\n",
#else
    snprintf( tmpBuf, sizeof( tmpBuf ), "TCPFLOW startTime=%04d/%02d/%02d %02d:%02d:%02d sourceMac=%s sourceIp=%s sourcePort=%u destMac=%s destIp=%s destPort=%u duration=%u packetsIn=%u packetsOut=%u bytesIn=%u bytesOut=%u records=%u\n",
#endif
              tmpTm->tm_year+1900,
              tmpTm->tm_mon+1,
              tmpTm->tm_mday,
              tmpTm->tm_hour,
              tmpTm->tm_min,
              tmpTm->tm_sec,
              s_eth_addr_str,
              s_ip_addr_str,
              tfPtr->aRecOut.sPort,
              d_eth_addr_str,
              d_ip_addr_str,
              tfPtr->aRecOut.dPort,
              tfPtr->lastUpdate - tfPtr->firstUpdate,
              tfPtr->packetsIn,
              tfPtr->packetsOut,
              tfPtr->bytesIn,
              tfPtr->bytesOut,
              tfPtr->recordCount
            );

    display( LOG_INFO, "%s", tmpBuf );
    
    return TRUE;  
}

/****
 * 
 * show traffic record
 * 
 ****/

int showTrafficRecord( struct trafficRecord *trPtr ) {
    
}

/****
 *
 * report and delete flow
 * 
 ****/

int reportTcpFlow( struct tcpFlow *tfPtr ) {
    PRIVATE char s_eth_addr_str[(ETHER_ADDR_LEN*2)+ETHER_ADDR_LEN];
    PRIVATE char d_eth_addr_str[(ETHER_ADDR_LEN*2)+ETHER_ADDR_LEN];
    PRIVATE char s_ip_addr_str[MAX_IP_ADDR_LEN+2];
    PRIVATE char d_ip_addr_str[MAX_IP_ADDR_LEN+2];
    struct tm *tmpTm;
    struct tcpFlow *tmpTfPtr;
    PRIVATE struct trafficRecord *tmpTrPtr;
    char tmpBuf[4096];

    while( tfPtr->head != NULL ) {
        if ( tfPtr->head EQ tfPtr->tail ) {
            XFREE( tfPtr->head );
            tfPtr->head = NULL;
        } else {
            tfPtr->tail = tfPtr->tail->prev;
            XFREE( tfPtr->tail->next );
        }
    }
    tfPtr->head = tfPtr->tail = NULL;
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

    /* remove hash flow records */
    deleteHashRecord( config->tcpFlowHash, (char *)&tfPtr->aRecOut, sizeof( struct trafficAddressRecord ) );
    deleteHashRecord( config->tcpFlowHash, (char *)&tfPtr->aRecIn, sizeof( struct trafficAddressRecord ) );

    /*
     * report on flow
     */

    XSTRNCPY( s_eth_addr_str, ether_ntoa((struct ether_addr *)&tfPtr->aRecOut.sMac), ((ETHER_ADDR_LEN*2)+ETHER_ADDR_LEN)-1 );
    XSTRNCPY( d_eth_addr_str, ether_ntoa((struct ether_addr *)&tfPtr->aRecOut.dMac), ((ETHER_ADDR_LEN*2)+ETHER_ADDR_LEN)-1 );
    XSTRNCPY( s_ip_addr_str, inet_ntoa( tfPtr->aRecOut.sIp ), MAX_IP_ADDR_LEN );
    XSTRNCPY( d_ip_addr_str, inet_ntoa( tfPtr->aRecOut.dIp ), MAX_IP_ADDR_LEN );

    tmpTm = localtime( &tfPtr->firstUpdate );

#if SIZEOF_SIZE_T == 8
    snprintf( tmpBuf, sizeof( tmpBuf ), "TCPFLOW startTime=%04d/%02d/%02d %02d:%02d:%02d sourceMac=%s sourceIp=%s sourcePort=%u destMac=%s destIp=%s destPort=%u duration=%lu packetsIn=%lu packetsOut=%lu bytesIn=%lu bytesOut=%lu records=%lu\n",
#else
    snprintf( tmpBuf, sizeof( tmpBuf ), "TCPFLOW startTime=%04d/%02d/%02d %02d:%02d:%02d sourceMac=%s sourceIp=%s sourcePort=%u destMac=%s destIp=%s destPort=%u duration=%u packetsIn=%u packetsOut=%u bytesIn=%u bytesOut=%u records=%u\n",
#endif
              tmpTm->tm_year+1900,
              tmpTm->tm_mon+1,
              tmpTm->tm_mday,
              tmpTm->tm_hour,
              tmpTm->tm_min,
              tmpTm->tm_sec,
              s_eth_addr_str,
              s_ip_addr_str,
              tfPtr->aRecOut.sPort,
              d_eth_addr_str,
              d_ip_addr_str,
              tfPtr->aRecOut.dPort,
              tfPtr->lastUpdate - tfPtr->firstUpdate,
              tfPtr->packetsIn,
              tfPtr->packetsOut,
              tfPtr->bytesIn,
              tfPtr->bytesOut,
              tfPtr->recordCount
            );

    fprintf( config->log_st, "%s", tmpBuf ); 

#ifdef DEBUG
    if ( config->debug >= 2 )
        display( LOG_DEBUG, "%s", tmpBuf );
#endif

    XFREE( tmpTfPtr );
    config->flowCount--;
    
    return TRUE;
}

/****
 * 
 * save flow state to disk
 * 
 ****/

int writeFlowState( char *out_fName ) {
  struct tcpFlow *tfPtr, *tmpTfPtr;
  FILE *outFile = NULL;
  size_t f = 0, r = 0, rCount;
  
  pruneFlows();
  
#ifdef DEBUG
  if ( config->debug >= 1 )
    display( LOG_DEBUG, "Writing flow cache to [%s]", out_fName );
#endif

  if ( ( outFile = fopen( out_fName, "w" ) ) EQ NULL ) {
    display( LOG_ERR, "Unable top open cache file for write [%s]\n", out_fName );
    return FAILED;
  }
  
  tfPtr = config->tfHead;
  while ( tfPtr != NULL ) {
#ifdef DEBUG
    if ( config->debug >= 4 )
      display( LOG_DEBUG, "Removing records in flow" );
#endif
    
#ifdef DEBUG
        if ( config->debug >= 4 )
            showTcpFlow( tfPtr );
#endif

    /* write flow record */
    fwrite( tfPtr, sizeof( struct tcpFlowCache ), 1, outFile );
    f++;
    
    /* empty the traffic records related to this flow */
    rCount = 0;    
    while( tfPtr->head != NULL ) {

        if ( tfPtr->head EQ tfPtr->tail ) {
        fwrite( tfPtr->head, sizeof( struct trafficRecordCache ), 1, outFile );
        XFREE( tfPtr->head );
        r++;
        rCount++;
        tfPtr->head = NULL;
      } else {
        tfPtr->tail = tfPtr->tail->prev;
        fwrite( tfPtr->tail->next, sizeof( struct trafficRecordCache ), 1, outFile );
        r++;
        rCount++;
        XFREE( tfPtr->tail->next );
      }
    }
    tfPtr->head = tfPtr->tail = NULL;

    if ( tfPtr->recordCount != rCount ) {
        display( LOG_ERR, "Flow reported [%d] records but only saved [%d] records", tfPtr->recordCount, rCount );
    }
    
#ifdef DEBUG
    if ( config->debug >= 4 ) 
      display( LOG_DEBUG, "Removing flow" );
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

    /* remove hash flow records */
    deleteHashRecord( config->tcpFlowHash, (char *)&tmpTfPtr->aRecOut, sizeof( struct trafficAddressRecord ) );
    deleteHashRecord( config->tcpFlowHash, (char *)&tmpTfPtr->aRecIn, sizeof( struct trafficAddressRecord ) );

    /* next flow record */
    tfPtr = tfPtr->next;
    XFREE( tmpTfPtr );
    config->flowCount--;
  }
  
  fclose( outFile );

#ifdef DEBUG
  if ( config->debug >= 1 )
    display( LOG_DEBUG, "[%d] tcp flow records and [%d] tcp traffic records cached", f, r );
#endif
  return TRUE;
}

/****
 *
 * read flow state from disk
 * 
 ****/

int readFlowState( char *in_fName ) {
    struct tcpFlowCache tmpFlowBuf;
    struct trafficRecord tmpRecBuf;
    struct tcpFlow *tfPtr;
    FILE *inFile = NULL;
    size_t f = 0, r = 0, i, ret;
#ifdef DEBUG
    PRIVATE char s_eth_addr_str[(ETHER_ADDR_LEN*2)+ETHER_ADDR_LEN];
    PRIVATE char d_eth_addr_str[(ETHER_ADDR_LEN*2)+ETHER_ADDR_LEN];
    PRIVATE char s_ip_addr_str[MAX_IP_ADDR_LEN+2];
    PRIVATE char d_ip_addr_str[MAX_IP_ADDR_LEN+2];
#endif
  
    XMEMSET( &tmpRecBuf, 0, sizeof( struct trafficRecord ) );
    
#ifdef DEBUG
    if ( config->debug >= 1 )
        display( LOG_DEBUG, "Reading flow cache from [%s]", in_fName );
#endif
    
    if ( ( inFile = fopen( in_fName, "r" ) ) EQ NULL ) {
        display( LOG_ERR, "Unable to open flow cache [%s]", in_fName );
        return FAILED;
    }
    
    while( ( ret = fread( &tmpFlowBuf, sizeof( struct tcpFlowCache ), 1, inFile ) ) EQ 1 ) {
    
        /* grow the hash if needed */
        config->tcpFlowHash = dyGrowHash( config->tcpFlowHash );
        
        /* create new tcp flow record */
        tfPtr = (struct tcpFlow *)XMALLOC( sizeof( struct tcpFlow ) );
        XMEMSET( tfPtr, 0, sizeof( struct tcpFlow ) );
        XMEMCPY( tfPtr, &tmpFlowBuf, sizeof( struct tcpFlowCache ) );
        tfPtr->recordCount = 0;
        
        /* insert new traffic flow into hash */
        if ( addUniqueHashRec( config->tcpFlowHash, (char *)&tfPtr->aRecOut, sizeof( struct trafficAddressRecord ), tfPtr ) != TRUE ) {
#ifdef DEBUG
            XSTRNCPY( s_eth_addr_str, ether_ntoa((struct ether_addr *)tfPtr->aRecOut.sMac), ((ETHER_ADDR_LEN*2)+ETHER_ADDR_LEN)-1 );
            XSTRNCPY( d_eth_addr_str, ether_ntoa((struct ether_addr *)tfPtr->aRecOut.dMac), ((ETHER_ADDR_LEN*2)+ETHER_ADDR_LEN)-1 );
            XSTRNCPY( s_ip_addr_str, inet_ntoa( tfPtr->aRecOut.sIp ), MAX_IP_ADDR_LEN );
            XSTRNCPY( d_ip_addr_str, inet_ntoa( tfPtr->aRecOut.dIp ), MAX_IP_ADDR_LEN );
            display( LOG_DEBUG, "Problem inserting outbound address record [%s->%s(%u)-%s->%s(%u)-%u->%u]",
                     s_eth_addr_str,
                     d_eth_addr_str,
                     tfPtr->aRecOut.ethProto,
                     s_ip_addr_str,
                     d_ip_addr_str,
                     tfPtr->aRecOut.ipProto,
                     tfPtr->aRecOut.sPort,
                     tfPtr->aRecOut.dPort
                );
#endif  
        }
        
        if ( addUniqueHashRec( config->tcpFlowHash, (char *)&tfPtr->aRecIn, sizeof( struct trafficAddressRecord ), tfPtr ) != TRUE ) {
#ifdef DEBUG
            XSTRNCPY( s_eth_addr_str, ether_ntoa((struct ether_addr *)tfPtr->aRecIn.sMac), ((ETHER_ADDR_LEN*2)+ETHER_ADDR_LEN)-1 );
            XSTRNCPY( d_eth_addr_str, ether_ntoa((struct ether_addr *)tfPtr->aRecIn.dMac), ((ETHER_ADDR_LEN*2)+ETHER_ADDR_LEN)-1 );
            XSTRNCPY( s_ip_addr_str, inet_ntoa( tfPtr->aRecIn.sIp ), MAX_IP_ADDR_LEN );
            XSTRNCPY( d_ip_addr_str, inet_ntoa( tfPtr->aRecIn.dIp ), MAX_IP_ADDR_LEN );
            display( LOG_DEBUG, "Problem inserting inbound address record [%s->%s(%u)-%s->%s(%u)-%u->%u]",
                    s_eth_addr_str,
                    d_eth_addr_str,
                    tfPtr->aRecIn.ethProto,
                    s_ip_addr_str,
                    d_ip_addr_str,
                    tfPtr->aRecIn.ipProto,
                    tfPtr->aRecIn.sPort,
                    tfPtr->aRecIn.dPort
                );
#endif            
        } 
        
        if ( config->tfHead EQ NULL ) {
            config->tfHead = config->tfTail = tfPtr;
        } else {
            config->tfTail->next = tfPtr;
            tfPtr->prev = config->tfTail;
            config->tfTail = tfPtr;
        }
        config->flowCount++;
        f++;
        
        for( i = 0; i < tmpFlowBuf.recordCount; i++, r++ ) {
            if ( ( ret = fread( &tmpRecBuf, sizeof( struct trafficRecordCache ), 1, inFile ) ) EQ 0 ) {
                display( LOG_ERR, "Problem while reading record cache" );
                return FAILED;
            }
            
            /* insert traffic record into linked list */
            insertTrafficRecord( tfPtr, &tmpRecBuf );
        }

        if ( ( config->pid_file EQ NULL ) || ( config->debug >= 4 ) )
            showTcpFlow( tfPtr );
    }
    
#ifdef DEBUG
  if ( config->debug >= 1 )
    display( LOG_DEBUG, "[%d] tcp flow records and [%d] tcp traffic records read from cache", f, r );
#endif  
    
    return TRUE;
}

/****
 *
 * cleanup tcp flow linked lists
 *
 ****/

void cleanupTcpFlows( void ) {
  struct tcpFlow *tfPtr, *tmpTfPtr;
  int f = 0;
  int r = 0;

  tfPtr = config->tfHead;
  while ( tfPtr != NULL ) {
#ifdef DEBUG
    if ( config->debug >= 4 )
      display( LOG_DEBUG, "Removing records in flow" );
#endif

    /* empty the traffic records related to this flow */
        
    while( tfPtr->head != NULL ) {
#ifdef DEBUG
      r++;
#endif
      if ( tfPtr->head EQ tfPtr->tail ) {
        XFREE( tfPtr->head );
        tfPtr->head = NULL;
      } else {
        tfPtr->tail = tfPtr->tail->prev;
        XFREE( tfPtr->tail->next );
      }
    }
    tfPtr->head = tfPtr->tail = NULL;

#ifdef DEBUG
    if ( config->debug >= 4 ) 
      display( LOG_DEBUG, "Removing flow" );
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

    /* remove hash flow records */
    deleteHashRecord( config->tcpFlowHash, (char *)&tmpTfPtr->aRecOut, sizeof( struct trafficAddressRecord ) );
    deleteHashRecord( config->tcpFlowHash, (char *)&tmpTfPtr->aRecIn, sizeof( struct trafficAddressRecord ) );

    /* next flow record */
    f++;
    tfPtr = tfPtr->next;
    XFREE( tmpTfPtr );
    config->flowCount--;
  }

#ifdef DEBUG
  if ( config->debug >= 1 )
    display( LOG_DEBUG, "[%d] tcp flow records and [%d] tcp traffic records deleted", f, r );
#endif
}
