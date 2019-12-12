/****
 *
 * Process HTTP Packets
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

#include "process_http.h"

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

void processHttpFlow( struct tcpFlow *tf, struct trafficRecord *tr, const u_char *packet, int flowDirection ) {
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
  int i, line_pos;
  char lineBuf[8192];
  struct hashRec_s *tmpHashRec;
  struct trafficAddressRecord revAddrRec;
  struct httpSession_s *httpPtr;
#ifdef DEBUG
  PRIVATE char s_eth_addr_str[(ETHER_ADDR_LEN*2)+ETHER_ADDR_LEN];
  PRIVATE char d_eth_addr_str[(ETHER_ADDR_LEN*2)+ETHER_ADDR_LEN];
  PRIVATE char s_ip_addr_str[MAX_IP_ADDR_LEN+2];
  PRIVATE char d_ip_addr_str[MAX_IP_ADDR_LEN+2];
#endif

  if ( ( payload_size = tr->size - size_tcp ) EQ 0 )
    return;

  /* initialize http record */
  if ( tf->data EQ NULL ) {
    if ( ( tf->data = XMALLOC( sizeof( struct httpSession_s ) ) ) EQ NULL ) {
        display( LOG_ERR, "Unable to allocate memory for http record" );
        quit = TRUE;
        exit( 1 );
    }
    XMEMSET( tf->data, 0, sizeof( struct httpSession_s ) );
  }

  httpPtr = (struct httpSession_s *)tf->data;
  
    if ( flowDirection EQ FLOW_OUTBOUND ) {

        if ( httpPtr->outBuf EQ NULL ) {
            httpPtr->outBuf = XMALLOC( payload_size );
            httpPtr->oBuf_len = payload_size;
            httpPtr->oBuf_pos = 0;
        } else {
            httpPtr->oBuf_len += payload_size;
            /* need to wrap realloc */
            httpPtr->outBuf = realloc( httpPtr->outBuf, httpPtr->oBuf_len );
        }
        XMEMCPY( httpPtr->outBuf+httpPtr->oBuf_pos, packet+size_tcp, payload_size );

        line_pos = 0;
        for( i = httpPtr->oBuf_pos; i < httpPtr->oBuf_len; i++ ) {
            if ( httpPtr->outBuf[i] EQ '\n' ) {
                if ( line_pos > 0 ) {
                    lineBuf[line_pos] = '\0';
                    if ( httpPtr->requestMethodStr EQ NULL ) {
                        httpPtr->requestMethodStr = XMALLOC( strlen( lineBuf ) + 1 );
                        XSTRCPY( httpPtr->requestMethodStr, lineBuf );
                        printf( "> %s\n", httpPtr->requestMethodStr );
                        line_pos = 0;
                    } else {
                    
                    }
                } else {
                    /* end of request header */
                    XFREE( httpPtr->outBuf );
                    httpPtr->outBuf = NULL;
                    httpPtr->oBuf_len = httpPtr->oBuf_pos = 0;
                }
            } else if ( httpPtr->outBuf[i] EQ '\r' ) {
                /* do nothing */
            } else {
                lineBuf[line_pos++] = httpPtr->outBuf[i];
            }
        }
    
  } else {
      
        if ( httpPtr->inBuf EQ NULL ) {
            httpPtr->inBuf = XMALLOC( payload_size );
            httpPtr->iBuf_len = payload_size;
            httpPtr->iBuf_pos = 0;
        } else {
            httpPtr->iBuf_len += payload_size;
            /* need to wrap realloc */
            httpPtr->inBuf = realloc( httpPtr->inBuf, httpPtr->iBuf_len );
        }
        XMEMCPY( httpPtr->inBuf+httpPtr->iBuf_pos, packet+size_tcp, payload_size );

        line_pos = 0;
        if ( memcmp( httpPtr->inBuf, "HTTP", 4 ) EQ 0 ) {
        for( i = httpPtr->iBuf_pos; i < httpPtr->iBuf_len; i++ ) {
            if ( httpPtr->inBuf[i] EQ '\n' ) {
                if ( line_pos > 0 ) {
                    lineBuf[line_pos] = '\0';
                    if ( httpPtr->responseStr EQ NULL ) {
                        httpPtr->responseStr = XMALLOC( strlen( lineBuf ) + 1 );
                        XSTRCPY( httpPtr->responseStr, lineBuf );
                        printf( "< %s\n", httpPtr->responseStr );
                        line_pos = 0;
                    } else {
                        line_pos = 0;
                    }
                } else {
                    /* end of request header */
                    XFREE( httpPtr->inBuf );
                    httpPtr->inBuf = NULL;
                    httpPtr->iBuf_len = httpPtr->iBuf_pos = 0;
                }
            } else if ( httpPtr->inBuf[i] EQ '\r' ) {
                /* do nothing */
            } else {
                lineBuf[line_pos++] = httpPtr->inBuf[i];
            }
        }
        }
  }

  
    //> GET /bcn?fe=1516318218837&y=2.0.980&elg=199164585&flg=328&x=zzz.fqq.frp%2F&vqwo=1&deo=1&g0=vg%3A%3Aer%2Cxd%3A%3Aqexd%3A%3Aqsu%7Cvg%3A//%3Ask%3A%3Aqsk%3A%3Aqsu%7Clq%3A%3Adm%2Clp%2Clqi%2Cqh%3A%3Aqoe%3A%3Aqsu%3A%3Axuo%3D%2F%2F0914.joredo.vvo.idvwob.qhw%2Fdg2%2Flpj%2Fa.jli%3Ffe%3D1516318216502%7Clq%3A%3Adm%2Clqi%2Cqh%2Cvf%3A%3Aqoe%3A%3Aqsu%3A%3Axuo%3D%2F%2F0914.joredo.vvo.idvwob.qhw%2Fdg2%2Fvfulsw%2Fa.mv%3Ffe%3D1516318216503%7Clq%3A%3Adm%2Clqi%2Cqh%2Cvf%3A%3Adoe%2Coe%3A%3Asu%3A%3Avw%3D0%2Cwv%3D2.000%2Cxuo%3D%2F%2Ffgq3.rswlplchob.frp%2Fmv%2Fjhr2.mv%3Ffe%3D1516318218729%7Cgisl%3A%3Alp%2Clqi%2Cqh%3A%3Aoe%3A%3Asu%3A%3Axuo%3D%2F%2Fdg.grxeohfolfn.qhw%2Fggp%2Fdg%2Fcrug%2Fpphko%2F%3Brug%3D1516318218467%3F%7Cjdg%3A%3Aho%2Ckl%2Cklg%2Clqi%3A%3Ahk%3A%3Asu%3A%3Avho%3D.sodlqDg%7Cjdg%3A%3Akl%2Clp%2Clqi%3A%3Aqoe%3A%3Aqsu%3A%3Axuo%3D%2F%2F0914.joredo.vvo.idvwob.qhw%2Fdg2%2Flpj%2Fa.jli%3Ffe%3D1516318216724%7Cjdg%3A%3Aho%2Ckl%2Cklg%2Clqi%3A%3Ahk%3A%3Asu%3A%3Avho%3D.sodlqDg%7Cddg%2Cjdg%3A%3Aho%2Ckl%2Cklg%2Clqi%3A%3Ahk%3A%3Asu%3A%3Avho%3D.des_re_halvw%7Cdg%3A%3Adu%2Cklg%2Cvv%3A%3Avvs%3A%3Ade%7Cdg%3A%3Adu%2Cklg%2Cvv%3A%3Avvs%3A%3Ades%7Cdg%3A%3Adu%2Cklg%2Cvv%3A%3Aqvvs%3A%3Aqsu%7Cdg%3A%3Adu%2Cklg%2Cvv%3A%3Aqvvs%3A%3Aqsu%7Cdg%3A%3Adu%2Cklg%2Cvv%3A%3Aqvvs%3A%3Aqsu%7Csu%3A%3Aid%3A%3Auivv%3A%3Aqsu&hu=1&g1=de%2Cdes&g2=1%3A%3A1%3A%3A0%3A%3A0%3A%3A1 HTTP/1.1\r\n
    //> Host: www.summerhamster.com\r\n
    //> Connection: keep-alive\r\n
    //> User-Agent: Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebK
    //> it/537.36 (KHTML, like Gecko) Chrome/63.0.3239.132 Safari/537.36\r\n
    //> Accept: image/webp,image/apng,image/*,*/*;q=0.8\r\n
    //> DNT: 1\r\n
    //> Referer: http://www.cnn.com/?refresh=1\r\n
    //> Accept-Encoding: gzip, deflate\r\n
    //> Accept-Language: en-US,en;q=0.9\r\n
    //> \r\n
    //> 
    //< 
    //< HTTP/1.1 200 OK\r\n
    //< Server: openresty\r\n
    //< Date: Thu, 18 Jan 2018 23:30:19 GMT\r\n
    //< Content-Type: image/gif\r\n
    //< Content-Length: 43\r\n
    //< Connection: keep-alive\r\n
    //< Access-Control-Allow-Origin: *\r\n
    //< Access-Control-Allow-Methods: *\r\n
    //< \r\n
    //< GIF89a.............!.......,...........D..;
    //> 
    //< HTTP/1.1 200 OK\r\n
    //< Server: openresty\r\n
    //< Date: Thu, 18 Jan 2018 23:30:19 GMT\r\n
    //< Content-Type: image/gif\r\n
    //< Content-Length: 43\r\n
    //< Connection: keep-alive\r\n
    //< Access-Control-Allow-Origin: *\r\n
    //< Access-Control-Allow-Methods: *\r\n
    //< \r\n
    //< GIF89a.............!.......,...........D..;

  return; 
}

/****
 * 
 * cleanup http http session 
 * 
 ****/

void cleanupHttpSession( struct httpSession_s *httpSessionPtr ) {
    if ( httpSessionPtr != NULL ) {
        if ( httpSessionPtr->outBuf != NULL )
            XFREE( httpSessionPtr->outBuf );
        if ( httpSessionPtr->inBuf != NULL )
            XFREE( httpSessionPtr->inBuf );
        if ( httpSessionPtr->requestMethodStr != NULL )
            XFREE( httpSessionPtr->requestMethodStr );
        if ( httpSessionPtr->requestHeader != NULL )
            XFREE( httpSessionPtr->requestHeader );
        if ( httpSessionPtr->responseStr != NULL )
            XFREE( httpSessionPtr->responseStr );
        if ( httpSessionPtr->responseHeader != NULL )
            XFREE( httpSessionPtr->responseHeader );
    }
}

/****
 *
 * hexdump
 *
 ****/

void hexDump( size_t bPos, uint8_t buf[], size_t len ) {
  size_t y, i = 0;

#ifdef DEBUG
  if ( config->debug >= 7 )
    display( LOG_DEBUG, "%d %d", bPos, len );
#endif

  while ( i < len ) {
    printf( "%08x ", (uint32_t)(bPos + i) );
    for ( y = 0; y < 16 & i + y < len; y++ ) {

      printf( "%02x", (uint8_t)buf[i+y] );
      printf( " " );
    }
    while( y < 16 ) {
      printf( "   " );
      y++;
    }
    printf( " " );
    for ( y = 0; y < 16 & i + y < len; y++ ) {
      if ( ( buf[i+y] < 32 ) | ( buf[i+y] > 127 ) )
        printf( "." );
      else
        printf( "%c", buf[i+y] );
    }
    i += y;

    printf( "\n" );
  }
}

/****
 *
 * extract HTTP method
 *
 * ripped from modules/http/http_protocol.c
 *
 ****/

int lookupHTTPMethod( const char *method, size_t len ) {
  int i;

  for( i = 0; i < len && method[i] != ' '; i++ );

  switch (i) {
  case 3:
    switch (method[0]) {
    case 'P':
      return (method[1] == 'U' && method[2] == 'T' ? M_PUT : UNKNOWN_METHOD);
    case 'G':
      return (method[1] == 'E' && method[2] == 'T' ? M_GET : UNKNOWN_METHOD);
    default:
      return UNKNOWN_METHOD;
    }
    
  case 4:
    switch (method[0]) {
    case 'H':
      return (method[1] == 'E' && method[2] == 'A' && method[3] == 'D' ? M_GET : UNKNOWN_METHOD);
    case 'P':
      return (method[1] == 'O' && method[2] == 'S' && method[3] == 'T' ? M_POST : UNKNOWN_METHOD);
    case 'M':
      return (method[1] == 'O' && method[2] == 'V' && method[3] == 'E' ? M_MOVE : UNKNOWN_METHOD);
    case 'L':
      return (method[1] == 'O' && method[2] == 'C' && method[3] == 'K' ? M_LOCK : UNKNOWN_METHOD);
    case 'C':
      return (method[1] == 'O' && method[2] == 'P' && method[3] == 'Y' ? M_COPY : UNKNOWN_METHOD);
    default:
      return UNKNOWN_METHOD;
    }
    
  case 5:
    switch (method[2]) {
    case 'T':
      return (memcmp(method, "PATCH", 5) == 0 ? M_PATCH : UNKNOWN_METHOD);
    case 'R':
      return (memcmp(method, "MERGE", 5) == 0 ? M_MERGE : UNKNOWN_METHOD);
    case 'C':
      return (memcmp(method, "MKCOL", 5) == 0 ? M_MKCOL : UNKNOWN_METHOD);
    case 'B':
      return (memcmp(method, "LABEL", 5) == 0 ? M_LABEL : UNKNOWN_METHOD);
    case 'A':
      return (memcmp(method, "TRACE", 5) == 0 ? M_TRACE : UNKNOWN_METHOD);
    default:
      return UNKNOWN_METHOD;
    }
    
  case 6:
    switch (method[0]) {
    case 'U':
      switch (method[5]) {
      case 'K':
	return (memcmp(method, "UNLOCK", 6) == 0 ? M_UNLOCK : UNKNOWN_METHOD);
      case 'E':
	return (memcmp(method, "UPDATE", 6) == 0 ? M_UPDATE : UNKNOWN_METHOD);
      default:
	return UNKNOWN_METHOD;
      }
    case 'R':
      return (memcmp(method, "REPORT", 6) == 0 ? M_REPORT : UNKNOWN_METHOD);
    case 'D':
      return (memcmp(method, "DELETE", 6) == 0 ? M_DELETE : UNKNOWN_METHOD);
    default:
      return UNKNOWN_METHOD;
    }
    
  case 7:
    switch (method[1]) {
    case 'P':
      return (memcmp(method, "OPTIONS", 7) == 0 ? M_OPTIONS : UNKNOWN_METHOD);
    case 'O':
      return (memcmp(method, "CONNECT", 7) == 0 ? M_CONNECT : UNKNOWN_METHOD);
    case 'H':
      return (memcmp(method, "CHECKIN", 7) == 0 ? M_CHECKIN : UNKNOWN_METHOD);
    default:
      return UNKNOWN_METHOD;
    }
    
  case 8:
    switch (method[0]) {
    case 'P':
      return (memcmp(method, "PROPFIND", 8) == 0 ? M_PROPFIND : UNKNOWN_METHOD);
    case 'C':
      return (memcmp(method, "CHECKOUT", 8) == 0 ? M_CHECKOUT : UNKNOWN_METHOD);
    default:
      return UNKNOWN_METHOD;
    }
    
  case 9:
    return (memcmp(method, "PROPPATCH", 9) == 0 ? M_PROPPATCH : UNKNOWN_METHOD);
    
  case 10:
    switch (method[0]) {
    case 'U':
      return (memcmp(method, "UNCHECKOUT", 10) == 0 ? M_UNCHECKOUT : UNKNOWN_METHOD);
    case 'M':
      return (memcmp(method, "MKACTIVITY", 10) == 0 ? M_MKACTIVITY : UNKNOWN_METHOD);
    default:
      return UNKNOWN_METHOD;
    }
    
  case 11:
    return (memcmp(method, "MKWORKSPACE", 11) == 0 ? M_MKWORKSPACE : UNKNOWN_METHOD);
    
  case 15:
    return (memcmp(method, "VERSION-CONTROL", 15) == 0 ? M_VERSION_CONTROL : UNKNOWN_METHOD);
    
  case 16:
    return (memcmp(method, "BASELINE-CONTROL", 16) == 0 ? M_BASELINE_CONTROL : UNKNOWN_METHOD);
  }

  return UNKNOWN_METHOD;
}