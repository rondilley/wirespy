/****
 *
 * Headers for Process HTTP Packets
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

#ifndef PROCESS_HTTP_DOT_H
#define PROCESS_HTTP_DOT_H

/****
 *
 * defines
 *
 ****/

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
#include "wirespy.h"
#include "process_tcp.h"

/****
 *
 * ripped from httpd.h
 *
 ****/

#define M_GET                   0       /** RFC 2616: HTTP */
#define M_PUT                   1       /* : */
#define M_POST                  2
#define M_DELETE                3
#define M_CONNECT               4
#define M_OPTIONS               5
#define M_TRACE                 6       /** RFC 2616: HTTP */
#define M_PATCH                 7       /** no rfc(!)  ### remove this one? */
#define M_PROPFIND              8       /** RFC 2518: WebDAV */
#define M_PROPPATCH             9       /* : */
#define M_MKCOL                 10
#define M_COPY                  11
#define M_MOVE                  12
#define M_LOCK                  13
#define M_UNLOCK                14      /** RFC 2518: WebDAV */
#define M_VERSION_CONTROL       15      /** RFC 3253: WebDAV Versioning */
#define M_CHECKOUT              16      /* : */
#define M_UNCHECKOUT            17
#define M_CHECKIN               18
#define M_UPDATE                19
#define M_LABEL                 20
#define M_REPORT                21
#define M_MKWORKSPACE           22
#define M_MKACTIVITY            23
#define M_BASELINE_CONTROL      24
#define M_MERGE                 25
#define M_INVALID               26      /** RFC 3253: WebDAV Versioning */
#define UNKNOWN_METHOD (-1)

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

struct proxyData {
  char *reqStr;
  char *respStr;
  int respCode;
  char *userAgentStr;
  char *hostStr;
  char *cTypeStr;
  unsigned long clientBytes;
  long startTime;
  long startUTime;
  long endTime;
  long endUTime;
};

struct httpSession_s {
  uint8_t *outBuf;
  size_t oBuf_pos;
  size_t oBuf_len;
  uint8_t *inBuf;
  size_t iBuf_pos;
  size_t iBuf_len;
  int method;
  size_t content_len;
  int status;
  char *requestMethodStr;
  char *requestHeader;
  // XXX should be a linked list of fields
  char *responseStr;
  char *responseHeader;
};

/****
 *
 * function prototypes
 *
 ****/

void processHttpFlow( struct tcpFlow *tf, struct trafficRecord *tr, const u_char *packet, int flowDirection );
void hexDump( size_t bPos, uint8_t buf[], size_t len );
int lookupHTTPMethod( const char *method, size_t len );
void cleanupHttpSession( struct httpSession_s *httpSessionPtr );

#endif /* PROCESS_HTTP_DOT_H */
