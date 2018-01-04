/****
 *
 * Headers for Process TCP Packets
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

#ifndef PROCESS_TCP_DOT_H
#define PROCESS_TCP_DOT_H

/****
 *
 * defines
 *
 ****/

#define FLOW_OUTBOUND 2
#define FLOW_INBOUND 1
#define FLOW_FALSE 0
#define FLOW_UNKNOWN (-1)

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

/****
 *
 * function prototypes
 *
 ****/

void processTcpPacket( struct trafficRecord *tr, const u_char *packet );
void logTcpPacket( struct tcpFlow *tfPtr, const struct tcphdr *tcpPtr, struct trafficRecord *tr, int flowDir );
int insertTrafficRecord( struct tcpFlow *tfPtr, struct trafficRecord *trPtr );
void pruneFlows( void );
int reportTcpFlow( struct tcpFlow *tfPtr );
int writeFlowState( char *out_fName );
int readFlowState( char *in_fName );
void cleanupTcpFlows( void );

#endif /* PROCESS_TCP_DOT_H */
