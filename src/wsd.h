/****
 *
 * Headers for Wirespy Daemon
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

#ifndef WSD_DOT_H
#define WSD_DOT_H

/****
 *
 * defines
 *
 ****/

#define PROGNAME "wsd"
#define WSD 1
#define MODE_DAEMON 0
#define MODE_INTERACTIVE 1
#define MODE_DEBUG 2

/* packet count */
#define LOOP_PACKET_COUNT 16
#define LOOP_PACKET_TIME 5 /* seconds */

#define LOGDIR "/var/log/wsd"
#define PID_FILE "/var/run/wsd.pid"

/* header length defs */
#define PPP_HDRLEN 4
#define NULL_HDRLEN 4

/* alarm interval */
#define CTIME_SYNC_INTERVAL 5

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
#include "wirespy.h"
#include "util.h"
#include "mem.h"
#include "hash.h"

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

int main(int argc, char *argv[]);
PRIVATE void cleanup( void );
PRIVATE void show_info( void );
void sigint_handler( int signo );
void sighup_handler( int signo );
void sigterm_handler( int signo );
void sigfpe_handler( int signo );
void sigbus_handler( int signo );
void sigsegv_handler( int signo );
void sigill_handler( int signo );
void ctime_prog( int signo );
PRIVATE void print_version( void );
PRIVATE void print_help( void );
PRIVATE int start_collecting( void );
PRIVATE int process_pcap( char *fName );
PRIVATE int show_interfaces( void );
pcap_handler get_handler( int datalink_type, char *device );
void dl_ppp(u_char *args, const struct pcap_pkthdr *header, const u_char *packet );
void dl_raw(u_char *args, const struct pcap_pkthdr *header, const u_char *packet );
void dl_null( u_char *args, const struct pcap_pkthdr *header, const u_char *packet );
void dl_ethernet( u_char *args, const struct pcap_pkthdr *header, const u_char *packet );
void processIpPacket( const struct pcap_pkthdr *header, u_int transportSize, struct trafficRecord *tr, const u_char *packet );
PRIVATE int avg_loop_count( int cur_loop_count );
bpf_u_int32 get_iface_info( char *device );

#endif /* WSD_DOT_H */
