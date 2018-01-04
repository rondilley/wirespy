dnl Process this file with autoconf to produce a configure script
m4_include([version.m4])
AC_PREREQ([2.59])
AC_INIT([wsd], VERSION_NUMBER)
AC_CONFIG_SRCDIR(src/main.c)
AC_CONFIG_AUX_DIR(config)
AM_INIT_AUTOMAKE([1.11])
AC_USE_SYSTEM_EXTENSIONS

dnl Checks for programs
AC_PROG_CC

dnl make /usr/local as the default install dir
AC_PREFIX_DEFAULT(/usr/local)

CFLAGS="${CFLAGS} -I. -I.. -I../include"

DEBUG="no"
AC_ARG_ENABLE(debug,
    [  --enable-debug          Enable debugging],
    [ if test "$GCC" = yes; then
          DEBUG="yes"
          CFLAGS="${CFLAGS} -DDEBUG -ggdb -pg"
      else
          DEBUG="yes"
          CFLAGS="${CFLAGS} -DDEBUG"
      fi
    ],)

MEM_DEBUG="no"
AC_ARG_ENABLE(memdebug,
    [  --enable-memdebug       Enable memory debugging],
      MEM_DEBUG="yes"
      CFLAGS="${CFLAGS} -DMEM_DEBUG"
    ,)

SHOW_MEM_DEBUG="no"
AC_ARG_ENABLE(showmemdebug,
    [  --enable-showmemdebug   Enable verbose memory debugging],
      SHOW_MEM_DEBUG="yes"
      MEM_DEBUG="yes"
      CFLAGS="${CFLAGS} -DMEM_DEBUG -DSHOW_MEM_DEBUG"
    ,)

dnl ############# System Dependencies

AC_MSG_CHECKING([for special system dependencies])

AC_CANONICAL_HOST
AC_C_CONST
AC_PROG_GCC_TRADITIONAL

dnl Checks for OS type.
case "$host" in
    *-freebsd*)
        AC_DEFINE([BSD_DERIVED],1,BSD_DERIVED)
        AC_DEFINE([FREEBSD],1,FREEBSD)
	LDFLAGS="${LDFLAGS}"
        ;;
    *-netbsd*)
        AC_DEFINE([BSD_DERIVED],1,BSD_DERIVED)
        AC_DEFINE([NETBSD],1,NETBSD)
        ;;
    *-openbsd*)
        AC_DEFINE([BSD_DERIVED],1,BSD_DERIVED)
        AC_DEFINE([OPENBSD],1,OPENBSD)
        CFLAGS="${CFLAGS} -Wbounded"
	LDFLAGS="${LDFLAGS}"
        ;;
    *-apple*)
        AC_DEFINE([BSD_DERIVED],1,BSD_DERIVED)
        AC_DEFINE([MACOS],1,MACOS)
        LDFLAGS="${LDFLAGS} -L/sw/lib"
        AC_SUBST(more_incl)
        more_incl=-I/sw/include
        ;;
    *-linux*)
        AC_DEFINE([SYSV_DERIVED],1,SYSV_DERIVED)
        AC_DEFINE([LINUX],1,LINUX)
        AC_SUBST(more_incl)
        more_incl="-I/usr/include/pcap"
        dnl libpcap's DLT_NULL seems to be broken under Linux.
        AC_DEFINE([DLT_NULL_BROKEN],1,DLT_NULL_BROKEN)
	AC_DEFINE([__USE_BSD],1,__USE_BSD)
	AC_DEFINE([__FAVOR_BSD],1,__FAVOR_BSD)
	LDFLAGS="${LDFLAGS}"
        ;;
    *-solaris*)
        AC_DEFINE([SYSV_DERIVED],1,SYSV_DERIVED)
        AC_DEFINE([SOLARIS],1,SOLARIS)
	LDFLAGS="${LDFLAGS}"
        ;;
    *-aix*)
        AC_DEFINE([SYSV_DERIVED],1,SYSV_DERIVED)
        AC_DEFINE([AIX],1,AIX)
        ;;
    *-hpux*)
        AC_DEFINE([SYSV_DERIVED],1,SYSV_DERIVED)
        AC_DEFINE([HPUX],1,HPUX)
        ;;
esac

dnl libpcap

AC_ARG_WITH(libpcap,
[  --with-libpcap=PATH        Specify path to libpcap library.],
    [
        AC_MSG_CHECKING(for --with-libpcap option)
        case "$withval" in
          yes|no)
            AC_MSG_ERROR(PATH required with libpcap option)
            ;;
          *)
            if test '!' -d "$withval"; then
                AC_MSG_ERROR($withval does not exist!)
            else
                AC_MSG_RESULT($withval)
                if test -d "$withval/include"; then
                  CFLAGS="-I$withval/include ${CFLAGS}"
                  CPPFLAGS="-I$withval/include ${CPPFLAGS}"
                else
                  CFLAGS="-I$withval ${CFLAGS}"
                  CPPFLAGS="-I$withval ${CPPFLAGS}"
                fi
                if test -d "$withval/lib"; then
                  LDFLAGS="-L$withval/lib ${LDFLAGS}"
                else
                  LDFLAGS="-L$withval ${LDFLAGS}"
                fi
            fi
            ;;
          esac
    ]
)

dnl Checks for libraries

AC_CHECK_HEADERS(pcap.h,, LIBPCAP="no")
if test "$LIBPCAP" = "no"; then
   echo ""
   echo "Error: Can't find Libpcap. Visit http://www.tcpdump.org for the latest version."
   exit;
fi

AC_CHECK_LIB(pcap, pcap_open_live,LIBPCAP="yes",LIBPCAP="no")
if test "$LIBPCAP" = "no"; then
    echo ""
    echo "Error: Can't find Libpcap. Visit http://www.tcpdump.org for the latest version."
    exit;
else
   AC_CHECK_LIB(pcap, pcap_setnonblock,, SETNONBLOCK="no")
   if test "$SETNONBLOCK" = "no"; then
       echo "compensating for lack of pcap_setnonblock()"
   else
       AC_DEFINE([HAVE_SETNONBLOCK],1,HAVE_SETNONBLOCK)
   fi

   AC_CHECK_LIB(pcap, pcap_freecode,, FREECODE="no")
   if test "$FREECODE" = "no"; then
       echo "compensating for lack of pcap_freecode()"
   else
       AC_DEFINE([HAVE_FREECODE],1,HAVE_FREECODE)
   fi
fi

AC_MSG_CHECKING(for bpf)
if test -r /dev/bpf0 ; then
    AC_DEFINE([HAVE_BPF],1,HAVE_BPF)
    AC_MSG_RESULT(yes)
elif test -c /dev/bpf0 ; then
    AC_DEFINE([HAVE_BPF],1,HAVE_BPF)
    AC_MSG_RESULT(yes)
else
    AC_MSG_RESULT(no)
fi

dnl ############## Header Checks

AC_HEADER_DIRENT
AC_CHECK_HEADERS([sys/types.h])
AC_CHECK_HEADERS([arpa/inet.h])
AC_CHECK_HEADERS([sys/socket.h])
AC_CHECK_HEADERS([net/if_arp.h], [], [],
[#if HAVE_SYS_SOCKET_H
# include <sys/socket.h>
#endif
])
AC_CHECK_HEADERS([fcntl.h])
AC_CHECK_HEADERS([netdb.h])
AC_CHECK_HEADERS([netinet/in.h])
AC_CHECK_HEADERS([netinet/ip.h], [], [],
[#if HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif
#if HAVE_ARPA_INET_H
# include <arpa/inet.h>
#endif
])
AC_CHECK_HEADERS([netinet/udp.h])
AC_CHECK_HEADERS([netinet/tcp.h])
AC_CHECK_HEADERS([netinet/ip.h netinet/ip_icmp.h], [], [],
[#if HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif
#if HAVE_ARPA_INET_H
# include <arpa/inet.h>
#endif
#if HAVE_NETINET_IP_H
# include <netinet/ip.h>
#endif
])
AC_CHECK_HEADERS([netinet/in_systm.h])
AC_CHECK_HEADERS([netinet/if_ether.h], [], [],
[#if HAVE_ARPA_INET_H
# include <arpa/inet.h>
#endif
#if HAVE_SYS_SOCKET_H
# include <sys/socket.h>
#endif
#if HAVE_NET_IF_ARP_H
# include <net/if_arp.h>
#endif
])
AC_CHECK_HEADERS([netinet/ether.h])
AC_CHECK_HEADERS([paths.h])
AC_CHECK_HEADERS([signal.h])
AC_CHECK_HEADERS([standards.h])
AC_CHECK_HEADERS([stdint.h])
AC_CHECK_HEADERS([stdlib.h])
AC_CHECK_HEADERS([string.h])
AC_CHECK_HEADERS([strings.h])
AC_CHECK_HEADERS([sys/ioctl.h])
AC_CHECK_HEADERS([sys/param.h])
AC_CHECK_HEADERS([sys/time.h])
AC_CHECK_HEADERS([sys/resource.h])
AC_CHECK_HEADERS([sys/bitypes.h])
AC_CHECK_HEADERS([sys/dir.h])
AC_CHECK_HEADERS([sys/ndir.h])
AC_CHECK_HEADERS([sys/stat.h])
AC_CHECK_HEADERS([getopt.h])
AC_CHECK_HEADERS([syslog.h])
AC_CHECK_HEADERS([dirent.h])
AC_CHECK_HEADERS([inttypes.h])
AC_CHECK_HEADERS([linux/if_ether.h])
AC_CHECK_HEADERS([memory.h])
AC_CHECK_HEADERS([ndir.h])
AC_CHECK_HEADERS([netdb.h])
AC_CHECK_HEADERS([net/if.h], [], [],
[#if HAVE_ARPA_INET_H
# include <arpa/inet.h>
# endif
#if HAVE_SYS_SOCKET_H
# include <sys/socket.h>
#endif
#if HAVE_NET_IF_ARP_H
# include <net/if_arp.h>
#endif
])
AC_CHECK_HEADERS([unistd.h])
AC_CHECK_HEADERS([vfork.h])

dnl ############## Function checks

AC_CHECK_FUNCS([getopt_long])
AC_CHECK_FUNCS([alarm])
AC_CHECK_FUNCS([bzero])
AC_CHECK_FUNCS([endgrent])
AC_CHECK_FUNCS([endpwent])
AC_CHECK_FUNCS([fchdir])
AC_CHECK_FUNCS([getcwd])
AC_CHECK_FUNCS([gethostname])
AC_CHECK_FUNCS([inet_ntoa])
AC_CHECK_FUNCS([localtime_r])
AC_CHECK_FUNCS([memmove])
AC_CHECK_FUNCS([memset])
AC_CHECK_FUNCS([socket])
AC_CHECK_FUNCS([strchr])
AC_CHECK_FUNCS([strdup])
AC_CHECK_FUNCS([strlcpy])
AC_CHECK_FUNCS([strlcat])
AC_FUNC_CLOSEDIR_VOID
AC_FUNC_FORK
AC_FUNC_LSTAT
AC_FUNC_LSTAT_FOLLOWS_SLASHED_SYMLINK
AC_FUNC_MALLOC
AC_FUNC_REALLOC
AC_FUNC_VPRINTF

dnl ############## Type checks

AC_STRUCT_TM
AC_TYPE_PID_T
AC_TYPE_SIGNAL
AC_TYPE_SIZE_T
AC_TYPE_UID_T
AC_CHECK_SIZEOF([size_t])
AC_CHECK_SIZEOF([time_t])

AM_CONFIG_HEADER(include/config.h)
AC_PROG_INSTALL
AC_OUTPUT(Makefile src/Makefile wsd.1)

BINDIR=`eval echo ${bindir}`; BINDIR=`eval echo ${BINDIR}`;
MANDIR=`eval echo ${mandir}/${mansubdir}`; MANDIR=`eval echo ${MANDIR}`;

echo ""
echo "-----------------------------------------------"
echo "Host type             : ${host}"
echo "Compiler              : ${CC}"
echo "Compiler flags        : ${CFLAGS}"
echo "Linker flags          : ${LDFLAGS}"
echo "Libraries             : ${LIBS}"
echo ""
echo "Binary                : ${BINDIR}"
echo "Manual pages          : ${MANDIR}"
echo ""
echo "Enable debugging      : ${DEBUG}"
echo "Enable mem debugging  : ${MEM_DEBUG}"
echo "Show mem debugging    : ${SHOW_MEM_DEBUG}"
echo "-----------------------------------------------"
echo ""
