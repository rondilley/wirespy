/****
 *
 * Headers for system dependencies
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

#ifndef SYSDEP_DOT_H
#define SYSDEP_DOT_H

#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <stdarg.h>
#include <errno.h>
#include <pwd.h>
#include <grp.h>
#include <getopt.h>
#include <time.h>

#ifdef HAVE_ARPA_INET_H
# include <arpa/inet.h>
#endif

#ifdef HAVE_DIRENT_H
# include <dirent.h>
#endif

#ifdef HAVE_FCNTL_H
# include <fcntl.h>
#endif

#ifdef HAVE_INTTYPES_H
# include <inttypes.h>
#endif

#if !defined(HAVE_NETINET_IF_ETHER_H) && defined(HAVE_LINUX_IF_ETHER_H)
# include <linux/if_ether.h>
# define ether_header ethhdr
# define ether_type h_proto
# define ETHERTYPE_IP ETH_P_IP
#endif

#ifdef HAVE_MEMORY_H
# include <memory.h>
#endif

#ifdef HAVE_NDIR_H
# include <ndir.h>
#endif

#ifdef HAVE_NETDB_H
# include <netdb.h>
#endif

#ifdef HAVE_NETINET_IN_H
# include <netinet/in.h>
#endif

#ifdef HAVE_SYS_SOCKET_H
# include <sys/socket.h>
#endif

#ifdef HAVE_NET_IF_ARP_H
# include <net/if_arp.h>
#endif

#ifdef HAVE_NETINET_IF_ETHER_H
# include <netinet/if_ether.h>
#endif

#ifdef HAVE_NETINET_IN_SYSTM_H
# include <netinet/in_systm.h>
#endif

#ifdef HAVE_NETINET_IP_H
# include <netinet/ip.h>
#endif

#ifdef HAVE_NETINET_TCP_H
# include <netinet/tcp.h>
#endif

#ifdef HAVE_NET_IF_H
# include <net/if.h>
#endif

#ifdef HAVE_NETINET_UDP_H
# include <netinet/udp.h>
#endif

#ifdef HAVE_NETINET_IP_ICMP_H
# include <netinet/ip_icmp.h>
#endif

#ifdef HAVE_NETINET_ETHER_H
# include <netinet/ether.h>
#endif

#ifdef HAVE_PATHS_H
# include <paths.h>
#endif

#ifdef HAVE_SIGNAL_H
# include <signal.h>
#endif

#ifdef HAVE_STANDARDS_H
# include <standards.h>
#endif

#ifdef HAVE_STDINT_H
# include <stdint.h>
#endif

#ifdef HAVE_STDLIB_H
# include <stdlib.h>
#endif

#ifdef HAVE_STRING_H
# include <string.h>
#endif

#ifdef HAVE_STRINGS_H
# include <strings.h>
#endif

#ifdef HAVE_SYSLOG_H
# include <syslog.h>
#endif

#ifdef HAVE_SYS_BITYPES_H
# include <sys/bitypes.h>
#endif

#ifdef HAVE_SYS_DIR_H
# include <sys/dir.h>
#endif

#ifdef HAVE_SYS_IOCTL_H
# include <sys/ioctl.h>
#endif

#ifdef HAVE_SYS_NDIR_H
# include <sys/ndir.h>
#endif

#ifdef HAVE_SYS_PARAM_H
# include <sys/param.h>
#endif

#ifdef HAVE_SYS_RESOURCE_H
# include <sys/resource.h>
#endif

#ifdef HAVE_SYS_STAT_H
# include <sys/stat.h>
#endif

#ifdef HAVE_SYS_TIME_H
# include <sys/time.h>
#endif

#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif

#ifdef HAVE_UNISTD_H
# include <unistd.h>
#endif

#ifdef HAVE_VFORK_H
# include <vfork.h>
#endif

#ifdef HAVE_LIBNET_H
# include <libnet.h>
#endif

#ifdef HAVE_PCAP_H
# include <pcap.h>
#endif

#endif /* SYSDEP_H */
