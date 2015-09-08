/****
 *
 * Wirespy
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

PUBLIC int quit = FALSE;
PUBLIC int reload = FALSE;
PUBLIC Config_t *config = NULL;

/* md5 stuff */
PUBLIC struct MD5Context md5_ctx;
PUBLIC unsigned char md5_digest[16];
/* sha1 stuff */
PUBLIC struct SHA1Context sha1_ctx;
PUBLIC unsigned char sha1_digest[20];

/****
 *
 * external variables
 *
 ****/

extern int errno;
extern char **environ;

/****
 *
 * main function
 *
 ****/

int main(int argc, char *argv[]) {
  PRIVATE int pid = 0;
  PRIVATE int c = 0, i = 0, fds = 0, status = 0;
  int digit_optind = 0;
  PRIVATE struct passwd *pwd_ent;
  PRIVATE struct group *grp_ent;
  PRIVATE char **ptr;
  char *tmp_ptr = NULL;
  char *pid_file = NULL;
  char *home_dir = NULL;
  char *chroot_dir = NULL;
  char *user = NULL;
  char *group = NULL;

#ifndef DEBUG
  struct rlimit rlim;

  rlim.rlim_cur = rlim.rlim_max = 0;
  setrlimit( RLIMIT_CORE, &rlim );
#endif

  /* setup config */
  config = ( Config_t * )XMALLOC( sizeof( Config_t ) );
  XMEMSET( config, 0, sizeof( Config_t ) );

  /* store current pid */
  config->cur_pid = getpid();

  /* store current user record */
  config->starting_uid = getuid();
  pwd_ent = getpwuid( config->starting_uid );
  if ( pwd_ent EQ NULL ) {
    fprintf( stderr, "Unable to get user's record\n" );
    endpwent();
    exit( EXIT_FAILURE );
  }
  if ( ( tmp_ptr = strdup( pwd_ent->pw_dir ) ) EQ NULL ) {
    fprintf( stderr, "Unable to dup home dir\n" );
    endpwent();
    exit( EXIT_FAILURE );
  }
  /* set home dir */
  home_dir = ( char * )XMALLOC( MAXPATHLEN+1 );
  strncpy( home_dir, ( char * )pwd_ent->pw_dir, MAXPATHLEN );
  endpwent();

  /* get real uid and gid in prep for priv drop */
  config->gid = getgid();
  config->uid = getuid();

  while (1) {
    int this_option_optind = optind ? optind : 1;
    int option_index = 0;
    static struct option long_options[] = {
      {"logdir", required_argument, 0, 'l' },
      {"version", no_argument, 0, 'v' },
      {"debug", required_argument, 0, 'd' },
      {"help", no_argument, 0, 'h' },
      {"iniface", required_argument, 0, 'i' },
      {"chroot", required_argument, 0, 'c' },
      {"pidfile", required_argument, 0, 'p' },
      {"user", required_argument, 0, 'u' },
      {"group", required_argument, 0, 'g' },
      {0, no_argument, 0, 0}
    };

    c = getopt_long(argc, argv, "vd:hi:l:p:u:g:", long_options, &option_index);
    if (c EQ -1)
      break;

    switch (c) {
    case 0:
      printf ("option %s", long_options[option_index].name);
      if (optarg)
        printf (" with arg %s", optarg);

      printf ("\n");
      break;

    case 'v':
      /* show the version */
      print_version();
      return( EXIT_SUCCESS );

    case 'd':
      /* show debig info */
      config->debug = atoi( optarg );
      config->mode = MODE_INTERACTIVE;
      break;

    case 'h':
      /* show help info */
      print_help();
      return( EXIT_SUCCESS );

    case 'p':
      /* define the location of the pid file used for rotating logs, etc */
#ifdef DEBUG
      fprintf( stderr, "MAXPATHLEN: %d\n", MAXPATHLEN );
#endif
      pid_file = ( char * )XMALLOC( MAXPATHLEN+1 );
      XMEMSET( pid_file, 0, MAXPATHLEN+1 );
      strncpy( pid_file, optarg, MAXPATHLEN );

      break;

    case 'l':
      /* define the dir to store logs in */
      config->log_dir = ( char * )XMALLOC( MAXPATHLEN+1 );
      XMEMSET( config->log_dir, 0, MAXPATHLEN+1 );
      strncpy( config->log_dir, optarg, MAXPATHLEN );

      break;

    case 'c':
      /* chroot the process into the specific dir */
      chroot_dir = ( char * )XMALLOC( MAXPATHLEN+1 );
      XMEMSET( chroot_dir, 0, MAXPATHLEN+1 );
      strncpy( chroot_dir, optarg, MAXPATHLEN );

      break;

    case 'i':
      /* set the interface to monitor */
      config->in_iface = ( char * )XMALLOC( (sizeof(char)*MAXPATHLEN)+1 );
      XMEMSET( config->in_iface, 0, (sizeof(char)*MAXPATHLEN)+1 );
      strncpy( config->in_iface, optarg, MAXPATHLEN );

      break;

    case 'u':

      /* set user to run as */
      user = ( char * )XMALLOC( (sizeof(char)*MAX_USER_LEN)+1 );
      XMEMSET( user, 0, (sizeof(char)*MAX_USER_LEN)+1 );
      strncpy( user, optarg, MAX_USER_LEN );
      if ( ( pwd_ent = getpwnam( user ) ) EQ NULL ) {
	fprintf( stderr, "ERR - Unknown user [%s]\n", user );
	endpwent();
	XFREE( user );
	cleanup();
	exit( EXIT_FAILURE );
      }
      config->uid = pwd_ent->pw_uid;
      endpwent();
      XFREE( user );

      break;

    case 'g':

      /* set gid to run as */
      group = ( char * )XMALLOC( (sizeof(char)*MAX_GROUP_LEN)+1 );
      XMEMSET( group, 0, (sizeof(char)*MAX_GROUP_LEN)+1 );
      strncpy( group, optarg, MAX_GROUP_LEN );
      if ( ( grp_ent = getgrnam( group ) ) EQ NULL ) {
	fprintf( stderr, "ERR - Unknown group [%s]\n", group );
	endgrent();
	XFREE( group );
	cleanup();
	exit( EXIT_FAILURE );
      }
      config->gid = grp_ent->gr_gid;
      endgrent();
      XFREE( group );
    
      break;

    default:
      fprintf( stderr, "Unknown option code [0%o]\n", c);
    }
  }

  if (optind < argc) {
    fprintf( stderr, "non-option ARGV-elements: ");
    while (optind < argc)
      fprintf( stderr, "%s ", argv[optind++]);
    fprintf( stderr, "\n");
  }

  /* set default options */
  if ( config->log_dir EQ NULL ) {
    config->log_dir = ( char * )XMALLOC( MAXPATHLEN+1 );
    XMEMSET( config->log_dir, 0, MAXPATHLEN+1 );
    XSTRNCPY( config->log_dir, LOGDIR, MAXPATHLEN );   
  }

  if ( pid_file EQ NULL ) {
    pid_file = ( char * )XMALLOC( MAXPATHLEN+1 );
    XMEMSET( pid_file, 0, MAXPATHLEN+1 );
    XSTRNCPY( pid_file, PID_FILE, MAXPATHLEN );
  }

  /* if not interactive, then become a daemon */
  if ( config->mode != MODE_INTERACTIVE ) {
    /* let everyone know we are running */
    fprintf( stderr, "%s v%s [%s - %s] starting in daemon mode\n", PROGNAME, VERSION, __DATE__, __TIME__ );

    /* check if we are already in the background */
    if ( getppid() EQ 1 ) {
      /* already owned by init */
    } else {
      /* ignore terminal signals */
      signal( SIGTTOU, SIG_IGN );
      signal( SIGTTIN, SIG_IGN );
      signal( SIGTSTP, SIG_IGN );

      /* first fork */
      if ( ( pid = fork() ) < 0 ) {
        /* that didn't work, bail */
        fprintf( stderr, "Unable to fork, forker must be broken\n" );
        exit( EXIT_FAILURE );
      } else if ( pid > 0 ) {
        /* this is the parent, quit */
        exit( EXIT_SUCCESS );
      }

      /* this is the first child, confused? */

      /* set process group leader AKA: I AM THE LEADER */
      if ( setpgid( 0, 0 ) != 0 ) {
        fprintf( stderr, "Unable to become the process group leader\n" );
        exit( EXIT_FAILURE );
      }

      /* ignore hup */
      signal( SIGHUP, SIG_IGN );

      /* second fork */
      if ( ( pid = fork() ) < 0 ) {
        /* that didn't work, bail */
        fprintf( stderr, "Unable to fork, forker must be broken\n" );
        exit( EXIT_FAILURE );
      } else if ( pid > 0 ) {
        /* this is the first child, quit */
        exit( EXIT_SUCCESS );
      }

      /* this is the second child, really confused? */

      /* move to '/' */
      chdir( "/" );

      /* close all open files */
      if ( ( fds = getdtablesize() ) EQ FAILED ) fds = MAX_FILE_DESC;
      for ( i = 0; i < fds; i++ ) close( i );

      /* reopen stdin, stdout and stderr to the null device */

      /* reset umask */
      umask( 0027 );

      /* stir randoms if used */

      /* done forking off */

      /* enable syslog */
      openlog( PROGNAME, LOG_CONS & LOG_PID, LOG_LOCAL0 );
    }
  } else {
    show_info();
    display( LOG_INFO, "Running in interactive mode" );
  }

  /* write pid to file */
#ifdef DEBUG
  display( LOG_DEBUG, "PID: %s", pid_file );
#endif
  if ( create_pid_file( pid_file ) EQ FAILED ) {
    display( LOG_ERR, "Creation of pid file failed" );
    cleanup();
    exit( EXIT_FAILURE );
  }

  /* check dirs and files for danger */

  /* figure our where our default dir will be */
  if ( chroot_dir EQ NULL ) {
    /* if chroot not defined, use user's home dir */
#ifdef DEBUG
    display( LOG_DEBUG, "CWD: %s", home_dir );
#endif
    /* move into home dir */
    chdir( home_dir );
    config->display_to_pipe = FALSE;
  } else {
    /* chroot this puppy */
#ifdef DEBUG
    if ( config->debug >= 3 ) {
      display( LOG_DEBUG, "chroot to [%s]", chroot_dir );
    }
#endif
    if ( chroot( chroot_dir ) != 0 ) {
      display( LOG_ERR, "Can't chroot to [%s]", chroot_dir );
      cleanup();
      exit( EXIT_FAILURE );
    }
    chdir( "/" );
  }

  /* setup gracefull shutdown */
  signal( SIGINT, sigint_handler );
  signal( SIGTERM, sigterm_handler );
  signal( SIGFPE, sigfpe_handler );
  signal( SIGBUS, sigbus_handler );
  signal( SIGILL, sigill_handler );
  signal( SIGHUP, sighup_handler );
  signal( SIGSEGV, sigsegv_handler );

  /* setup current time updater */
  signal( SIGALRM, ctime_prog );
  alarm( 5 );

  if ( time( &config->current_time ) EQ -1 ) {
    display( LOG_ERR, "Unable to get current time" );
    /* cleanup syslog */
    if ( config->mode != MODE_INTERACTIVE ) {
      closelog();
    }
    /* cleanup buffers */
    cleanup();
    return EXIT_FAILURE;
  }

  /* initialize program wide config options */
  config->hostname = (char *)XMALLOC( MAXHOSTNAMELEN+1 );

  /* get processor hostname */
  if ( gethostname( config->hostname, MAXHOSTNAMELEN ) != 0 ) {
    display( LOG_ERR, "Unable to get hostname" );
    strcpy( config->hostname, "unknown" );
  }

  config->cur_pid = getpid();
  /* start collecting */
  display( LOG_INFO, "Listening" );
  
  /* lets get this show on the road */
  start_collecting();

  /* cleanup syslog */
  if ( config->mode != MODE_INTERACTIVE ) {
    closelog();
  }

  /* shut everything down */
  if ( config->pcap_handle > 0 ) {
    pcap_close( config->pcap_handle );
  }

  cleanup();

  return( EXIT_SUCCESS );
}

/****
 *
 * display prog info
 *
 ****/

void show_info( void ) {
  printf( "%s v%s [%s - %s]\n", PROGNAME, VERSION, __DATE__, __TIME__ );
  printf( "By: Ron Dilley\n" );
  printf( "\n" );
  printf( "%s comes with ABSOLUTELY NO WARRANTY.\n", PROGNAME );
  printf( "This is free software, and you are welcome\n" );
  printf( "to redistribute it under certain conditions;\n" );
  printf( "See the GNU General Public License for details.\n" );
  printf( "\n" );
}

/****
 *
 * SIGINT handler
 *
 ****/
 
void sigint_handler( int signo ) {
  signal( signo, SIG_IGN );

  /* do a calm shutdown as time and pcap_loop permit */
  quit = TRUE;
  signal( signo, sigint_handler );
}

/****
 *
 * SIGTERM handler
 *
 ****/
 
void sigterm_handler( int signo ) {
  signal( signo, SIG_IGN );

  /* do a calm shutdown as time and pcap_loop permit */
  quit = TRUE;
  signal( signo, sigterm_handler );
}

/****
 *
 * SIGHUP handler
 *
 ****/
 
void sighup_handler( int signo ) {
  signal( signo, SIG_IGN );

  /* time to rotate logs and check the config */
  reload = TRUE;
  signal( SIGHUP, sighup_handler );
}

/****
 *
 * SIGSEGV handler
 *
 ****/
 
void sigsegv_handler( int signo ) {
  signal( signo, SIG_IGN );

  fprintf( stderr, "Caught a sig%d, shutting down fast\n", signo );
  /* pcmcia nics seem to do strange things sometimes if pcap does not close clean */
  pcap_close( config->pcap_handle );
#ifdef MEM_DEBUG
  XFREE_ALL();
#endif
  /* core out */
  abort();
}

/****
 *
 * SIGBUS handler
 *
 ****/
 
void sigbus_handler( int signo ) {
  signal( signo, SIG_IGN );
  
  fprintf( stderr, "Caught a sig%d, shutting down fast\n", signo );
  /* pcmcia nics seem to do strange things sometimes if pcap does not close clean */
  pcap_close( config->pcap_handle );
#ifdef MEM_DEBUG
  XFREE_ALL();
#endif
  /* core out */
  abort();
}

/****
 *
 * SIGILL handler
 *
 ****/
 
void sigill_handler ( int signo ) {
  signal( signo, SIG_IGN );

  fprintf( stderr, "Caught a sig%d, shutting down fast\n", signo );
  /* pcmcia nics seem to do strange things sometimes if pcap does not close clean */
  pcap_close( config->pcap_handle );
#ifdef MEM_DEBUG
  XFREE_ALL();
#endif
  /* core out */
  abort();
}

/****
 *
 * SIGFPE handler
 *
 ****/
 
void sigfpe_handler( int signo ) {
  signal( signo, SIG_IGN );

  fprintf( stderr, "Caught a sig%d, shutting down fast\n", signo );
  /* pcmcia nics seem to do strange things sometimes if pcap does not close clean */
  pcap_close( config->pcap_handle );
#ifdef MEM_DEBUG
  XFREE_ALL();
#endif
  /* core out */
  abort();
}

/*****
 *
 * interrupt handler (current time)
 *
 *****/

void ctime_prog( int signo ) {
  time_t ret;

  /* disable SIGALRM */
  signal( SIGALRM, SIG_IGN );
  /* update current time */
  if ( ( ret = time( &config->current_time ) ) EQ FAILED ) {
    display( LOG_ERR, "Unable to update time [%d]", errno );
  } else if ( ret != config->current_time ) {
    display( LOG_WARNING, "Time update inconsistent [%d] [%d]", ret, config->current_time );
  }

  /* reset SIGALRM */
  signal( SIGALRM, ctime_prog );
  /* reset alarm */
  alarm( 5 );
}

/*****
 *
 * display version info
 *
 *****/

PRIVATE void print_version( void ) {
  printf( "%s v%s [%s - %s]\n", PROGNAME, VERSION, __DATE__, __TIME__ );
}

/*****
 *
 * print help info
 *
 *****/

PRIVATE void print_help( void ) {
  print_version();

  printf( "\n" );
  printf( "syntax: %s [options]\n", PACKAGE );
  printf( " -c|--chroot {dir}    chroot into directory\n" );
  printf( " -d|--debug (0-9)     enable debugging info\n" );
  printf( " -g|--group {group}   run as an alternate group\n" );
  printf( " -h|--help            this info\n" );
  printf( " -i|--iniface {int}   specify interface to listen on\n" );
  printf( " -l|--logdir {dir}    directory to create logs in (default: %s)\n", LOGDIR );
  printf( " -p|--pidfile {fname} specify pid file (default: %s)\n", PID_FILE );
  printf( " -u|--user {user}     run as an alernate user\n" );
  printf( " -v|--version         display version information\n" );
  printf( "\n" );
}

/****
 *
 * drop privs
 *
 ****/

void drop_privileges( void ) {
  gid_t oldgid = getegid();
  uid_t olduid = geteuid();

#ifdef DEBUG
  if ( config->debug >= 5 ) {
    display( LOG_DEBUG, "dropping privs - uid: %i gid: %i euid: %i egid: %i", config->uid, config->gid, olduid, oldgid );
  }
#endif

  if ( !olduid ) setgroups( 1, &config->gid );

  if ( config->gid != oldgid ) {
    if ( setgid( config->gid ) EQ FAILED ) abort();
  }

  if ( config->uid != olduid ) {
    if ( setuid( config->uid ) EQ FAILED ) abort();
  }

#ifdef DEBUG
  if ( config->debug >= 4 ) {
    display( LOG_DEBUG, "dropped privs - uid: %i gid: %i euid: %i egid: %i", config->uid, config->gid, geteuid(), getegid() );
  }
#endif

  /* verify things are good */
  if ( config->gid != oldgid && ( setegid( oldgid ) != FAILED || getegid() != config->gid ) ) abort();
  if ( config->uid != olduid && ( seteuid( olduid ) != FAILED || geteuid() != config->uid ) ) abort();
}

/****
 *
 * start collecting traffic
 *
 ****/

PRIVATE int start_collecting( void ) {
  PRIVATE int ret;
  PRIVATE bpf_u_int32 netp;
  PRIVATE bpf_u_int32 maskp;
  PRIVATE struct in_addr addr;
  PRIVATE int i;
  /* libpcap stuff */
  PRIVATE char errbuf[PCAP_ERRBUF_SIZE];
  XMEMSET( errbuf, 0, PCAP_ERRBUF_SIZE );
  PRIVATE char pcap_filter_buf[1024];
  XMEMSET( pcap_filter_buf, 0, 1024 );
  PRIVATE pcap_t *handle;
  pcap_handler handler;
  struct pcap_stat packet_stats;
  struct bpf_program fp;
  int dlt;
  const char *dlt_name;
  char *tmp_dev;
  /**/
  int dynamic_loop_count = LOOP_PACKET_COUNT;
  int prs, pds;
  time_t start_time;
  /* log stuff */
  char log_buf[MAX_LOG_LINE];
  XMEMSET( log_buf, 0, MAX_LOG_LINE );
  char log_name[MAXPATHLEN];
  XMEMSET( log_name, 0, MAXPATHLEN );
  char log_digest_name[MAXPATHLEN];
  XMEMSET( log_digest_name, 0, MAXPATHLEN );
  size_t log_buf_len;
  size_t write_count;
  struct tm current_time;

  /* did someone select an interface to watch? */
  if ( config->in_iface EQ NULL ) {
    /* no device specified, pick the first one */
    config->in_iface = ( char * )XMALLOC( (sizeof(char)*MAXPATHLEN)+1 );
    XMEMSET( config->in_iface, 0, (sizeof(char)*MAXPATHLEN)+1 );
    if ( ( tmp_dev = pcap_lookupdev( errbuf ) ) EQ NULL ) {
      display( LOG_ERR, "unable to find device to monitor" );
      return FAILED;
    }
    strncpy( config->in_iface, tmp_dev, MAXPATHLEN );
  }

  /* get ip addr and mtu */
  if ( ( addr.s_addr = get_iface_info( config->in_iface ) ) EQ FAILED ) {
    config->in_dev_ip_addr_str = NULL;
  } else {
    config->in_dev_ip_addr_str = (char *)XMALLOC( ( sizeof(char) * MAX_IP_ADDR_LEN ) + 1 );
    strcpy( config->in_dev_ip_addr_str, inet_ntoa( addr ) );
  }

  /* ask pcap for the network address and mask of the device */
  if ( ( ret = pcap_lookupnet( config->in_iface, &netp, &maskp, errbuf ) ) EQ FAILED ) {
    display( LOG_ERR, "pcap_lookupnet failed [%s]", errbuf );
    errbuf[0] = 0;
    config->in_dev_net_addr_str = NULL;
    XMEMSET( &config->in_dev_net_addr, 0, sizeof( struct in_addr ) );
    config->in_dev_net_mask_str = NULL;
    XMEMSET( &config->in_dev_net_mask, 0, sizeof( struct in_addr ) );
  } else {
    /* get net addr */
    addr.s_addr = netp;
    XMEMCPY( &config->in_dev_net_addr, &addr, sizeof( struct in_addr ) );
    config->in_dev_net_addr_str = (char *)XMALLOC( ( sizeof(char) * MAX_IP_ADDR_LEN ) + 1 );
    strcpy( config->in_dev_net_addr_str, inet_ntoa( addr ) );
    /* get netnmask */
    addr.s_addr = maskp;
    XMEMCPY( &config->in_dev_net_mask, &addr, sizeof( struct in_addr ) );
    config->in_dev_net_mask_str = (char *)XMALLOC( ( sizeof(char) * MAX_IP_ADDR_LEN ) + 1 );
    strcpy( config->in_dev_net_mask_str, inet_ntoa( addr ) );
  }

  /* start collecting */
#ifdef DEBUG
  if ( config->debug >= 1 ) {
    display( LOG_DEBUG, "Openning pcap session" );
   }
#endif

  /* open pcap session */
  if ( ( handle = pcap_open_live( config->in_iface, BUFSIZ, 1, 0, errbuf ) ) == NULL ) {
    display( LOG_ERR, "Unable to open pcap session on [%s]", config->in_iface );
    return;
  } else {
    display( LOG_INFO, "libpcap initialized on: %s", config->in_iface );
  }

  /* stuff it in a list for emergency cleanups, unclean shutdowns seem to freak pcmcia nics out */
  config->pcap_handle = handle;

  /****
   *
   * drop root privs
   *
   ****/
  drop_privileges();

  /* display dev info */
  display( LOG_INFO, "Device: %s", config->in_iface );
  dlt = pcap_datalink(handle);
  display( LOG_INFO, "Link Type: %d", dlt );
  if ( config->in_dev_ip_addr_str EQ NULL ) {
    display( LOG_INFO, "IP Addr: none" );
  } else {
    display( LOG_INFO, "IP Addr: %s", config->in_dev_ip_addr_str );
  }
  if ( config->in_dev_net_addr_str EQ NULL ) {
    display( LOG_INFO, "Net Addr: none" );
  } else {
    display( LOG_INFO, "Net Addr: %s", config->in_dev_net_addr_str );
  }
  if ( config->in_dev_net_mask_str EQ NULL ) {
    display( LOG_INFO, "Net Mask: none" );
  } else {
    display( LOG_INFO, "Net Mask: %s", config->in_dev_net_mask_str );
  }

  /* get the handler for this kind of packets */
  if ( ( handler = get_handler( dlt, config->in_iface ) ) EQ 0 ) {
    display( LOG_ERR, "Unable to determin proper data-link handler" );
    return FAILED;
  }

  /* initialize current time struct */
  localtime_r(&config->current_time, &current_time);
  
  /* create log file name */
  sprintf( log_name, "%s/%s_%04d%02d%02d_%02d%02d%02d.log",
	   config->log_dir,
	   config->hostname,
	   current_time.tm_year+1900,
	   current_time.tm_mon+1,
	   current_time.tm_mday,
	   current_time.tm_hour,
	   current_time.tm_min,
	   current_time.tm_sec );
               
  /* create log digest name */
  sprintf( log_digest_name, "%s.sig", log_name );

#ifdef DEBUG
  if ( config->debug >= 4 ) {
    display( LOG_DEBUG, "Creating log file [%s]", log_name );
  }
#endif

  /* open new packet log file */
  if ( ( config->log_st = fopen( log_name, "w" ) ) EQ NULL ) {
    display( LOG_ERR, "Unable to open log file [%s]", log_name );
    quit = TRUE;
    return FAILED;
  }

  /* initialize md5 context */
  MD5Init( &md5_ctx );

  /* initialize the sha1 context */
  SHA1Init( &sha1_ctx );

  /* loop through pcap loops */
  for( ;; ) {
    /* save start time */
    start_time = config->current_time;

#ifdef DEBUG
    if ( config->debug >= 8 ) {
      display( LOG_DEBUG, "Dropping into pcap loop for [%d] packets", dynamic_loop_count );
    }
#endif

    /* drop into pcap loop */
    if ( pcap_loop( handle, dynamic_loop_count, handler, NULL ) EQ FAILED ) {
      display( LOG_ERR, "pcap_loop returned (-1) [%s]", errbuf );
      quit = TRUE;
    } else {
      if ( errbuf[0] != 0 ) {
        display( LOG_ERR, "errbuf is not empty [%s]", errbuf );
	errbuf[0] = 0;
      }
      if ( pcap_stats( handle, &packet_stats ) EQ FAILED ) {
        display( LOG_ERR, "unable to get pcap statistics" );
      } else {
        /* show pcap stats */
        if ( packet_stats.ps_drop > 0 ) {
          display( LOG_WARNING, "pcap dropped %d packets", packet_stats.ps_drop );
        }
        /* save stats */
        config->pcap_rec += packet_stats.ps_recv;
        config->pcap_drop += packet_stats.ps_drop;
        /* test time */
        if ( ( config->current_time - start_time ) != LOOP_PACKET_TIME ) {
          /* adjust packet count */
          if ( ( config->current_time - start_time ) > 0 ) {
            dynamic_loop_count = avg_loop_count( ( dynamic_loop_count / ( config->current_time - start_time ) ) * LOOP_PACKET_TIME );
            prs = packet_stats.ps_recv / ( config->current_time - start_time );
            pds = packet_stats.ps_drop / ( config->current_time - start_time );
          } else {
            dynamic_loop_count = avg_loop_count( dynamic_loop_count * LOOP_PACKET_TIME );
            prs = packet_stats.ps_recv;
            pds = packet_stats.ps_drop;
          }
        }

#ifdef DEBUG
        if ( config->debug >= 1 ) {
          display( LOG_DEBUG, "rec: %d drop: %d", packet_stats.ps_recv, packet_stats.ps_drop );
        }

        if ( config->debug >= 2 ) {
          display( LOG_DEBUG, "dyn_loop: %d", dynamic_loop_count );
        }
#endif
      }
    }

    if ( quit EQ TRUE ) {
#ifdef DEBUG
      if ( config->debug >= 5 ) {
        display( LOG_DEBUG, "Time to quit" );
      }
#endif

      /* close the log file */
      fclose( config->log_st );

      /* finalize md5 hash */
      MD5Final( md5_digest, &md5_ctx );

      /* finalize sha1 hash */
      SHA1Final( sha1_digest, &sha1_ctx );

      /* open packet log digest */
      if ( ( config->log_st = fopen( log_digest_name, "w" ) ) EQ NULL ) {
	display( LOG_ERR, "Unable to open plog digest file [%s]", log_digest_name );
	quit = TRUE;
	return FAILED;
      }

      /* convert the md5 digest to hex */
      sprintf( log_buf, "%s %02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x md5\n",
	       log_name,
	       md5_digest[0],
	       md5_digest[1],
	       md5_digest[2],
	       md5_digest[3],
	       md5_digest[4],
	       md5_digest[5],
	       md5_digest[6],
	       md5_digest[7],
	       md5_digest[8],
	       md5_digest[9],
	       md5_digest[10],
	       md5_digest[11],
	       md5_digest[12],
	       md5_digest[13],
	       md5_digest[14],
	       md5_digest[15] );
	       
      /* display md5 digest */
      display( LOG_INFO, "%s", log_buf );

      /* write the md5 digest */
      if ( fputs( log_buf, config->log_st ) EQ EOF ) {
	display( LOG_WARNING, "Unable to write to [%s]", log_digest_name );
      }

      /* convert the sha1 digest to hex */
      sprintf( log_buf, "%s %02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x sha1\n",
	       log_name,
	       sha1_digest[0],
	       sha1_digest[1],
	       sha1_digest[2],
	       sha1_digest[3],
	       sha1_digest[4],
	       sha1_digest[5],
	       sha1_digest[6],
	       sha1_digest[7],
	       sha1_digest[8],
	       sha1_digest[9],
	       sha1_digest[10],
	       sha1_digest[11],
	       sha1_digest[12],
	       sha1_digest[13],
	       sha1_digest[14],
	       sha1_digest[15],
	       sha1_digest[16],
	       sha1_digest[17],
	       sha1_digest[18],
	       sha1_digest[19] );

      /* display sha1 digest */
      display( LOG_INFO, "%s", log_buf );

      /* write the sha1 digest */
      if ( fputs( log_buf, config->log_st ) EQ EOF ) {
	display( LOG_WARNING, "Unable to write to [%s]", log_digest_name );
      }

      /* close the digest */
      fclose( config->log_st );

      return;
    } else if ( reload EQ TRUE ) {
      /* time to rotate the logs */
      
      fclose( config->log_st );

      /* finalize md5 hash */
      MD5Final( md5_digest, &md5_ctx );

      /* finalize sha1 hash */
      SHA1Final( sha1_digest, &sha1_ctx );

      /* open packet log digest */
      if ( ( config->log_st = fopen( log_digest_name, "w" ) ) EQ NULL ) {
	display( LOG_ERR, "Unable to open plog digest file [%s]", log_digest_name );
	quit = TRUE;
	return;
      }

      /* convert the md5 digest to hex */
      sprintf( log_buf, "%s %02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x md5\n",
	       log_name,
	       md5_digest[0],
	       md5_digest[1],
	       md5_digest[2],
	       md5_digest[3],
	       md5_digest[4],
	       md5_digest[5],
	       md5_digest[6],
	       md5_digest[7],
	       md5_digest[8],
	       md5_digest[9],
	       md5_digest[10],
	       md5_digest[11],
	       md5_digest[12],
	       md5_digest[13],
	       md5_digest[14],
	       md5_digest[15] );
	       
      /* display md5 digest */
      display( LOG_INFO, "%s", log_buf );

      /* write the md5 digest */
      if ( fputs( log_buf, config->log_st ) EQ EOF ) {
	display( LOG_WARNING, "Unable to write to [%s]", log_digest_name );
      }

      /* convert the sha1 digest to hex */
      sprintf( log_buf, "%s %02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x sha1\n",
	       log_name,
	       sha1_digest[0],
	       sha1_digest[1],
	       sha1_digest[2],
	       sha1_digest[3],
	       sha1_digest[4],
	       sha1_digest[5],
	       sha1_digest[6],
	       sha1_digest[7],
	       sha1_digest[8],
	       sha1_digest[9],
	       sha1_digest[10],
	       sha1_digest[11],
	       sha1_digest[12],
	       sha1_digest[13],
	       sha1_digest[14],
	       sha1_digest[15],
	       sha1_digest[16],
	       sha1_digest[17],
	       sha1_digest[18],
	       sha1_digest[19] );

      /* display sha1 digest */
      display( LOG_INFO, "%s", log_buf );

      /* write the sha1 digest */
      if ( fputs( log_buf, config->log_st ) EQ EOF ) {
	display( LOG_WARNING, "Unable to write to [%s]", log_digest_name );
      }

      /* close the digest */
      fclose( config->log_st );

      /* empty out the traffic report linked lists */
      cleanupTrafficReports();

      /* empty out the tcp flow linked lists */
      cleanupTcpFlows();

      /* initialize current time struct */
      localtime_r(&config->current_time, &current_time);
       
      /* initialize md5 context */
      MD5Init( &md5_ctx );

      /* initialize sha1 context */
      SHA1Init( &sha1_ctx );

      /* create log file name */
      sprintf( log_name, "%s/%s_%04d%02d%02d_%02d%02d%02d.log",
	       config->log_dir,
	       config->hostname,
	       current_time.tm_year+1900,
	       current_time.tm_mon+1,
	       current_time.tm_mday,
	       current_time.tm_hour,
	       current_time.tm_min,
	       current_time.tm_sec );
               
      /* create log digest name */
      sprintf( log_digest_name, "%s.sig", log_name );

#ifdef DEBUG
      if ( config->debug >= 4 ) {
	display( LOG_DEBUG, "Creating log file [%s]", log_name );
      }
#endif

      /* open new packet log file */
      if ( ( config->log_st = fopen( log_name, "w" ) ) EQ NULL ) {
	display( LOG_ERR, "Unable to open log file [%s]", log_name );
	quit = TRUE;
	return;
      }

      /* reset reload flag */
      reload = FALSE;   
    }
  }

  /* cleanup */
  pcap_freecode( &fp );

  display( LOG_INFO, "Received: %d, Dropped: %d", config->pcap_rec, config->pcap_drop );
  
  return TRUE;
}

/****
 *
 * cleanup
 *
 ****/

PRIVATE void cleanup( void ) {
  int i = 0;

  XFREE( config->hostname );
  XFREE( config->in_dev_net_addr_str );
  XFREE( config->in_dev_net_mask_str );
  XFREE( config->in_dev_ip_addr_str );
  XFREE( config->in_iface );

  cleanupTrafficReports();
  cleanupTcpFlows();

#ifdef MEM_DEBUG
  XFREE_ALL();
#endif
  XFREE( config );
}

/****
 *
 * sort tcp flow
 *
 ****/

int sortTcpFlow( struct tcpFlow *tfPtr ) {
  struct trafficRecord *trPtr = tfPtr->head;
  struct trafficRecord *tmpTrPtr;
  int found;
  u_int tmpSeq;

  display( LOG_DEBUG, "TCPFLOW: Sorting TCP Flow" );

  while ( trPtr != NULL ) {
    tmpSeq = trPtr->seq;

    display( LOG_DEBUG, "TCPFLOW: Seq [%08x]", tmpSeq );

    /* find ack */
    tmpTrPtr = tfPtr->head;
    found = FALSE;
    while( tmpTrPtr != NULL ) {
      if ( tmpTrPtr->seq == ( tmpSeq + 1 ) ) {
	/* found the ack */
	found = TRUE;
      }
    }
    if ( ! found ) {
      display( LOG_INFO, "TCPFLOW: No ack for [%08x]", tmpSeq );
    }
    trPtr = trPtr->next;
  }

  return TRUE;
}

/****
 *
 * cleanup traffic report linked lists
 *
 ****/

void cleanupTrafficReports( void ) {
  int i = 0;

  while( config->trHead != NULL ) {
#ifdef DEBUG
    i++;
#endif
    if ( config->trHead EQ config->trTail ) {
      XFREE( config->trHead );
      config->trHead = NULL;
    } else {
      config->trTail = config->trTail->prev;
      XFREE( config->trTail->next );
    }
  }
  config->trHead = config->trTail = NULL;

#ifdef DEBUG
  if ( config->debug >= 1 ) {
    display( LOG_DEBUG, "[%d] traffic records deleted", i );
  }
#endif
}

/****
 *
 * cleanup tcp flow linked lists
 *
 ****/

void cleanupTcpFlows( void ) {
  int i = 0;

  while( config->tfHead != NULL ) {
#ifdef DEBUG
    i++;
#endif
    if ( config->tfHead EQ config->tfTail ) {
      XFREE( config->tfHead );
      config->tfHead = NULL;
    } else {
      config->tfTail = config->tfTail->prev;
      XFREE( config->tfTail->next );
    }
  }
  config->tfHead = config->tfTail = NULL;

#ifdef DEBUG
  if ( config->debug >= 1 ) {
    display( LOG_DEBUG, "[%d] tcp flow records deleted", i );
  }
#endif
}

/****
 *
 * more portable way to get info about monitored interface
 *
 ****/

bpf_u_int32 get_iface_info( char *device ) {
   struct ifreq ifr;
   int sock_fd;
   bpf_u_int32 iface_ip_addr;

   if ( ( sock_fd = socket(AF_INET, SOCK_DGRAM, 0 ) ) < 0 ) {
     if ( errno EQ EPROTONOSUPPORT ) {
       display( LOG_ERR, "Protocol not supported on socket open" );
       return FAILED;
     }
     display( LOG_ERR, "Unable to open socket" );
     return FAILED;
   }
   XMEMSET(&ifr, 0, sizeof(ifr));
   strncpy(ifr.ifr_name, device, sizeof(ifr.ifr_name));
   ifr.ifr_addr.sa_family = AF_INET;
   if ( ( ioctl( sock_fd, SIOCGIFADDR, &ifr ) ) < 0 ) {
     display( LOG_ERR, "Unable to get ip address via ioctl" );
     close( sock_fd );
     return FAILED;
   }	
   XMEMCPY( &iface_ip_addr, ifr.ifr_addr.sa_data+2, sizeof( bpf_u_int32 ) );
   close( sock_fd );
	
   return iface_ip_addr;
}

/****
 *
 * average loop packet count
 *
 ****/

#define SAMPLECOUNT 10

PRIVATE int avg_loop_count( int cur_loop_count ) {
  int i, count = 0, total = 0;
  static int samples[SAMPLECOUNT];

  if ( cur_loop_count <= 0 ) {
    cur_loop_count = 1;
  }

  for ( i = 1; i < SAMPLECOUNT; i++ ) {
    samples[i-1] = samples[i];
  }
  samples[9] = cur_loop_count;

  for ( i = 0; i < SAMPLECOUNT; i++ ) {
    if ( samples[i] > 0 ) {
      count++;
      total += samples[i];
    }
  }

  return ( total / count );
}
