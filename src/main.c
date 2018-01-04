/****
 *
 * Wirespy
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

/****
 *
 * external variables
 *
 ****/

extern int errno;
extern char **environ;

/****
 * 
 * external functions
 * 
 ****/

extern int writeFlowState( char *out_fName );
extern int readFlowState( char *in_fName );
extern void cleanupTcpFlows( void );

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
  XFREE( tmp_ptr );
  
  /* get real uid and gid in prep for priv drop */
  config->gid = getgid();
  config->uid = getuid();

  while (1) {
    int this_option_optind = optind ? optind : 1;
    int option_index = 0;
    static struct option long_options[] = {
      {"logdir", required_argument, 0, 'l' },
      {"logfile", required_argument, 0, 'L' },
      {"version", no_argument, 0, 'v' },
      {"verbose", no_argument, 0, 'V' },
      {"debug", required_argument, 0, 'd' },
      {"help", no_argument, 0, 'h' },
      {"iniface", required_argument, 0, 'i' },
      {"chroot", required_argument, 0, 'c' },
      {"read", required_argument, 0, 'r' },
      {"pidfile", required_argument, 0, 'p' },
      {"user", required_argument, 0, 'u' },
      {"group", required_argument, 0, 'g' },
      {"wflow", required_argument, 0, 'W' },
      {"rflow", required_argument, 0, 'R' },
      {0, no_argument, 0, 0}
    };

    c = getopt_long(argc, argv, "vVd:hi:l:L:p:u:g:r:R:W:", long_options, &option_index);
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

    case 'V':
      /* print more detailed traffic logs */
      config->verbose = TRUE;
      break;
      
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
      
    case 'L':
      /* define the file, overrides -l */
      config->log_fName = ( char * )XMALLOC( MAXPATHLEN+1 );
      XMEMSET( config->log_fName, 0, MAXPATHLEN+1 );
      strncpy( config->log_fName, optarg, MAXPATHLEN );

      break;
      
    case 'r':
      /* define pcap file to read from */
      config->pcap_fName = ( char * )XMALLOC( MAXPATHLEN+1 );
      XMEMSET( config->pcap_fName, 0, MAXPATHLEN+1 );
      strncpy( config->pcap_fName, optarg, MAXPATHLEN );
      config->mode = MODE_INTERACTIVE;
      
      break;

    case 'W':
      /* define flow cache file to write to */
      config->wFlow_fName = ( char * )XMALLOC( MAXPATHLEN+1 );
      XMEMSET( config->wFlow_fName, 0, MAXPATHLEN+1 );
      strncpy( config->wFlow_fName, optarg, MAXPATHLEN );
      
      break;
      
    case 'R':
      /* define flow cache file to read from */
      config->rFlow_fName = ( char * )XMALLOC( MAXPATHLEN+1 );
      XMEMSET( config->rFlow_fName, 0, MAXPATHLEN+1 );
      strncpy( config->rFlow_fName, optarg, MAXPATHLEN );
      
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
      if ( chdir( "/" ) EQ FAILED ) {
        display( LOG_ERR, "Can't chdir to [/]" );
        cleanup();
        exit( EXIT_FAILURE );
      }

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

      /* write pid to file */
#ifdef DEBUG
      display( LOG_DEBUG, "PID: %s", pid_file );
#endif
      if ( create_pid_file( pid_file ) EQ FAILED ) {
        display( LOG_ERR, "Creation of pid file failed" );
        cleanup();
        exit( EXIT_FAILURE );
      }
    }
  } else {
    show_info();
    display( LOG_INFO, "Running in interactive mode" );
  }

  /* check dirs and files for danger */

  /* figure our where our default dir will be */
  if ( chroot_dir EQ NULL ) {
    /* if chroot not defined, use user's home dir */
#ifdef DEBUG
    display( LOG_DEBUG, "CWD: %s", home_dir );
#endif
    /* move into home dir */
    if ( chdir( home_dir ) EQ FAILED ) {
      display( LOG_ERR, "Can't chdir to [%s]", home_dir );
      cleanup();
      exit( EXIT_FAILURE );
    }
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
    
    if ( chdir( "/" ) EQ FAILED ) {
      display( LOG_ERR, "Can't chdir to [/]" );
      cleanup();
      exit( EXIT_FAILURE );
    }
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
#ifdef HAVE_STRLCPY
    strlcpy( config->hostname, "unknown", 8 );
#else
    strncpy( config->hostname, "unknown", 8 );
#endif
}

  config->cur_pid = getpid();
  /* start collecting */
  display( LOG_INFO, "Listening" );
  
  /****
   ****
   * GOGOGO
   ****
   ****/
  
  /* init hashes */
  config->tcpFlowHash = initHash( 52 );
  
  if ( config->rFlow_fName != NULL )
    readFlowState( config->rFlow_fName );
  
#ifdef DEBUG
  if ( config->debug >= 1 )
      display( LOG_DEBUG, "Starting the packet processing" );
#endif
  
  /* lets get this show on the road */
  if ( config->pcap_fName != NULL )
    process_pcap( config->pcap_fName );
  else
    start_collecting();

  /****
   ****
   * STOPSTOPSTOP
   ****
   ****/
  
  /* cleanup syslog */
  if ( config->mode != MODE_INTERACTIVE ) {
    closelog();
  }

  /* shut everything down */
  if ( config->pcap_handle > 0 ) {
    pcap_close( config->pcap_handle );
  }

  if ( home_dir != NULL )
    XFREE( home_dir );
  if ( pid_file != NULL )
    XFREE( pid_file );

  if ( config->wFlow_fName != NULL ) {
    writeFlowState( config->wFlow_fName );
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

  config->pruneCounter++;
  
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
  printf( " -L|--logfile {fname} specify log file instead of dynamic generated filenames\n" );
  printf( " -p|--pidfile {fname} specify pid file (default: %s)\n", PID_FILE );
  printf( " -r|--read {fname}    specify pcap file to read\n" );
  printf( " -R|--rflow {fname}   specify flow cache file to read\n" );
  printf( " -u|--user {user}     run as an alernate user\n" );
  printf( " -v|--version         display version information\n" );
  printf( " -V|--verbose         log additional details about traffic\n" );
  printf( " -W|--wflow {fname}   specify flow cache file to write\n" );
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
 * start processing pcap file
 * 
 ****/

PRIVATE int process_pcap( char *fName ) {
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
  char log_name[MAXPATHLEN+1];
  XMEMSET( log_name, 0, MAXPATHLEN+1 );
  size_t log_buf_len;
  size_t write_count;
  struct tm current_time;  

#ifdef DEBUG
  if ( config->debug > 5 )
      display( LOG_DEBUG, "Opening pcap file for read [%s]", fName );
#endif
  
  /* open pcap file */
  if ( ( handle = pcap_open_offline( fName, errbuf ) ) EQ NULL ) {
    display( LOG_ERR, "Unable to open pcap file [%s] -- %s", fName, errbuf );
    return FAILED;
  } else {
    display( LOG_INFO, "Opened pcap file: %s", fName );
  }

  /* stuff it in a list for emergency cleanups, unclean shutdowns seem to freak pcmcia nics out */
  config->pcap_handle = handle;
  
  /****
   *
   * drop root privs
   *
   ****/
  if ( ! config->debug ) // don't drop privs in debug mode so that core files are written
    drop_privileges();

  /* display dev info */
  dlt = pcap_datalink(handle);
  display( LOG_INFO, "Link Type: %d", dlt );

  /* get the handler for this kind of packets */
  if ( ( handler = get_handler( dlt, config->in_iface ) ) EQ 0 ) {
    display( LOG_ERR, "Unable to determin proper data-link handler" );
    return FAILED;
  }

  /* initialize current time struct */
  localtime_r(&config->current_time, &current_time);
  
  /* create log file name */
  if ( config->log_fName != NULL )
    strncpy( log_name, config->log_fName, MAXPATHLEN );
  else
    snprintf( log_name, MAXPATHLEN, "%s.log", config->pcap_fName );

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

  /* drop into pcap loop */
  if ( pcap_loop( handle, 0, handler, NULL ) EQ FAILED ) {
    display( LOG_ERR, "pcap_loop error [%s]", errbuf );
  } else {
    if ( errbuf[0] != 0 ) {
      display( LOG_ERR, "errbuf is not empty [%s]", errbuf );
      errbuf[0] = 0;
    }

    fclose( config->log_st );
  }
  
  /* cleanup */
  //pcap_freecode( &fp );

  return TRUE;  
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
  char log_name[MAXPATHLEN+1];
  XMEMSET( log_name, 0, MAXPATHLEN+1 );
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
#ifdef HAVE_STRLCPY
    strlcpy( config->in_dev_ip_addr_str, inet_ntoa( addr ), MAX_IP_ADDR_LEN );    
#else
    strncpy( config->in_dev_ip_addr_str, inet_ntoa( addr ), MAX_IP_ADDR_LEN );
#endif
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
#ifdef HAVE_STRLCPY
    strlcpy( config->in_dev_net_addr_str, inet_ntoa( addr ), MAX_IP_ADDR_LEN );    
#else
    strncpy( config->in_dev_net_addr_str, inet_ntoa( addr ), MAX_IP_ADDR_LEN );
#endif
    /* get netnmask */
    addr.s_addr = maskp;
    XMEMCPY( &config->in_dev_net_mask, &addr, sizeof( struct in_addr ) );
    config->in_dev_net_mask_str = (char *)XMALLOC( ( sizeof(char) * MAX_IP_ADDR_LEN ) + 1 );
#ifdef HAVE_STRLCPY
    strlcpy( config->in_dev_net_mask_str, inet_ntoa( addr ), MAX_IP_ADDR_LEN );    
#else
    strncpy( config->in_dev_net_mask_str, inet_ntoa( addr ), MAX_IP_ADDR_LEN );
#endif
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
    return FAILED;
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
  if ( ! config->debug ) // don't drop privs in debug mode so that core files are written
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
  snprintf( log_name, MAXPATHLEN, "%s/%s_%04d%02d%02d_%02d%02d%02d.log",
	   config->log_dir,
	   config->hostname,
	   current_time.tm_year+1900,
	   current_time.tm_mon+1,
	   current_time.tm_mday,
	   current_time.tm_hour,
	   current_time.tm_min,
	   current_time.tm_sec );

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

      return TRUE;
    } else if ( reload EQ TRUE ) {
      /* time to rotate the logs */
      
      fclose( config->log_st );

      /* initialize current time struct */
      localtime_r(&config->current_time, &current_time);
       
      /* create log file name */
      snprintf( log_name, MAXPATHLEN, "%s/%s_%04d%02d%02d_%02d%02d%02d.log",
	       config->log_dir,
	       config->hostname,
	       current_time.tm_year+1900,
	       current_time.tm_mon+1,
	       current_time.tm_mday,
	       current_time.tm_hour,
	       current_time.tm_min,
	       current_time.tm_sec );

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

      /* reset reload flag */
      reload = FALSE;   
    }
  }

  /* cleanup */
  //pcap_freecode( &fp );

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

  if ( config->hostname != NULL )
    XFREE( config->hostname );
  if ( config->in_dev_net_addr_str != NULL )
    XFREE( config->in_dev_net_addr_str );
  if ( config->in_dev_net_mask_str != NULL )
    XFREE( config->in_dev_net_mask_str );
  if ( config->in_dev_ip_addr_str != NULL )
    XFREE( config->in_dev_ip_addr_str );
  if ( config->in_iface != NULL )
    XFREE( config->in_iface );
  if ( config->pcap_fName != NULL )
    XFREE( config->pcap_fName );
  if ( config->log_dir != NULL )
    XFREE( config->log_dir );
  if ( config->log_fName != NULL )
    XFREE( config->log_fName );
  if ( config->wFlow_fName != NULL )
    XFREE( config->wFlow_fName );
  if ( config->rFlow_fName != NULL )
    XFREE( config->rFlow_fName );
  
  cleanupTcpFlows();

  if ( config->tcpFlowHash != NULL )
    freeHash( config->tcpFlowHash );

  #ifdef MEM_DEBUG
  XFREE_ALL();
#endif
  XFREE( config );
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
   XMEMSET(&ifr, 0, sizeof(struct ifreq));
#ifdef HAVE_STRLCPY
   strlcpy(ifr.ifr_name, device, sizeof(IFNAMSIZ));   
#else
   strncpy(ifr.ifr_name, device, sizeof(IFNAMSIZ));
#endif
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