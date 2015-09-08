/****
 *
 * Headers for Process IP Packets
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

#ifndef PROCESS_IP_DOT_H
#define PROCESS_IP_DOT_H

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

#ifndef SYSDEP_H
#error something is messed up
#endif

#include <common.h>
#include "process_udp.h"
#include "process_tcp.h"
#include "util.h"
#include "mem.h"
#include "md5.h"
#include "sha1.h"

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

void processIpPacket( const struct pcap_pkthdr *header, u_int transportSize, struct trafficRecord *tr, const u_char *packet );

#endif /* PROCESS_IP_DOT_H */
