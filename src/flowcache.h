/****
 *
 * Headers for flow cache
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

#ifndef FLOWCACHE_DOT_H
#define FLOWCACHE_DOT_H

/****
 *
 * defines
 *
 ****/

#define PROGNAME "flowcache"
#define MODE_DAEMON 0
#define MODE_INTERACTIVE 1
#define MODE_DEBUG 2

/* arg len boundary */
#define MAX_ARG_LEN 1024

#define MAX_IP_ADDR_LEN 46

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

#endif /* FLOWCACHE_DOT_H */