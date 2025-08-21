/****
 *
 * Interact with flow cache files
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

#include "flowcache.h"

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
  PRIVATE int c = 0;
  PRIVATE char **ptr;


#ifndef DEBUG
  struct rlimit rlim;

  rlim.rlim_cur = rlim.rlim_max = 0;
  setrlimit( RLIMIT_CORE, &rlim );
#endif

  /* setup config */
  config = ( Config_t * )XMALLOC( sizeof( Config_t ) );
  XMEMSET( config, 0, sizeof( Config_t ) );

  while (1) {
    int option_index = 0;
    static struct option long_options[] = {
      {"version", no_argument, 0, 'v' },
      {"verbose", no_argument, 0, 'V' },
      {"debug", required_argument, 0, 'd' },
      {"help", no_argument, 0, 'h' },
      {0, no_argument, 0, 0}
    };

    c = getopt_long(argc, argv, "vd:h", long_options, &option_index);
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

    default:
      fprintf( stderr, "Unknown option code [0%o]\n", c);
    }
  }

  show_info();

  /****
   ****
   * GOGOGO
   ****
   ****/
  
  /* init hashes */
  config->tcpFlowHash = initHash( 52 );
  
  while( optind < argc ) {
      readFlowState( argv[optind++] );
  }
  
  /****
   ****
   * STOPSTOPSTOP
   ****
   ****/
  
  if ( config->wFlow_fName != NULL )
    writeFlowState( config->wFlow_fName );
  else
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
  printf( " -d|--debug (0-9)     enable debugging info\n" );
  printf( " -h|--help            this info\n" );
  printf( " -v|--version         display version information\n" );
  printf( "\n" );
}


/****
 *
 * cleanup
 *
 ****/

PRIVATE void cleanup( void ) {
  int i = 0;

  cleanupTcpFlows();

  if ( config->tcpFlowHash != NULL )
      freeHash( config->tcpFlowHash );

#ifdef MEM_DEBUG
  XFREE_ALL();
#endif
  XFREE( config );
  config = NULL;
}
