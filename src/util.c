/****
 *
 * Utility Functions
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

/****
 *
 * defines
 *
 ****/

/* turn on priority names */
#define SYSLOG_NAMES

/****
 *
 * includes
 *
 ****/

#include "wsd.h"
#include <libgen.h>  /* for dirname() */

/****
 *
 * local variables
 *
 ****/

PRIVATE char *restricted_environ[] = {
  "IFS= \t\n",
  "PATH= /bin:/usr/bin",
  0
};
PRIVATE char *preserve_environ[] = {
  "TZ",
  0
};

/****
 *
 * external global variables
 *
 ****/

extern Config_t *config;
extern CODE prioritynames[];
extern char **environ;

/****
 *
 * functions
 *
 ****/

/****
 *
 * display output
 *
 ****/

int display( int level, char *format, ... ) {
  PRIVATE va_list args;
  PRIVATE char tmp_buf[SYSLOG_MAX+1];
  PRIVATE int i;

  va_start( args, format );
  vsnprintf( tmp_buf, SYSLOG_MAX, format, args );
  if ( tmp_buf[strlen(tmp_buf)-1] == '\n' ) {
    tmp_buf[strlen(tmp_buf)-1] = 0;
  }
  va_end( args );

  if ( config->mode != MODE_INTERACTIVE ) {
    /* display info via syslog */
    syslog( level, "%s", tmp_buf );
  } else {
    if ( level <= LOG_ERR ) {
      /* display info via stderr */
      for ( i = 0; prioritynames[i].c_name != NULL; i++ ) {
	if ( prioritynames[i].c_val == level ) {
	  fprintf( stderr, "%s[%u] - %s\n", prioritynames[i].c_name, config->cur_pid, tmp_buf );
	  return TRUE;
	}
      }
    } else {
      /* display info via stdout */
      for ( i = 0; prioritynames[i].c_name != NULL; i++ ) {
	if ( prioritynames[i].c_val == level ) {
	  printf( "%s[%u] - %s\n", prioritynames[i].c_name, config->cur_pid, tmp_buf );
	  return TRUE;
	}
      }
    }
  }

  return FAILED;
}

/****
 *
 * open file descriptor for the null device
 *
 ****/

PUBLIC int open_devnull( int fd ) {
  FILE *f_st = 0;

  if ( fd EQ 0 ) f_st = freopen( DEV_NULL, "rb", stdin );
  else if ( fd EQ 1 ) f_st = freopen( DEV_NULL, "wb", stdout );
  else if ( fd EQ 2 ) f_st = freopen( DEV_NULL, "wb", stderr );
  return ( f_st && fileno( f_st ) EQ fd );
}

/****
 *
 * check to see if dir is safe
 *
 ****/

int is_dir_safe( const char *dir ) {
  DIR *fd, *start;
  int rc = FAILED;
  char new_dir[PATH_MAX+1];
  uid_t uid;
  struct stat f, l;

  if ( !( start = opendir( "." ) ) ) return FAILED;
  if ( lstat( dir, &l ) == FAILED ) {
    closedir( start );
    return FAILED;
  }
  uid = geteuid();

  do {
    if ( chdir( dir ) EQ FAILED ) break;
    if ( !( fd = opendir( "." ) ) ) break;
    if ( fstat( dirfd( fd ), &f ) EQ FAILED ) {
      closedir( fd );
      break;
    }
    closedir( fd );

    if ( l.st_mode != f.st_mode || l.st_ino != f.st_ino || l.st_dev != f.st_dev )
      break;
    if ( ( f.st_mode & ( S_IWOTH | S_IWGRP ) ) || ( f.st_uid && f.st_uid != uid ) ) {
      rc = 0;
      break;
    }
    dir = "..";
    if ( lstat( dir, &l ) EQ FAILED ) break;
    if ( !getcwd( new_dir, PATH_MAX + 1 ) ) break;
  } while ( new_dir[1] ); /* new_dir[0] will always be a slash */
  if ( !new_dir[1] ) rc = 1;

  if ( fchdir( dirfd( start ) ) EQ FAILED ) {
    fprintf( stderr, "ERR - Unable to fchdir\n" );
    return FAILED;
  }
  
  closedir( start );
  return rc;
}

/****
 *
 * validate that a path is safe and doesn't contain directory traversal
 *
 ****/

int is_path_safe( const char *path ) {
  char *resolved_path;
  char *ptr;
  int safe = TRUE;
  
  if ( path == NULL || strlen(path) == 0 ) {
    return FAILED;
  }
  
  /* Check for obvious directory traversal patterns */
  if ( strstr(path, "../") != NULL || strstr(path, "..\\") != NULL ) {
    display( LOG_ERR, "Path contains directory traversal: %s", path );
    return FAILED;
  }
  
  /* Check for absolute paths when not expected */
  if ( path[0] == '/' && strlen(path) > 1 ) {
    /* Allow absolute paths but validate they resolve properly */
    resolved_path = realpath(path, NULL);
    if ( resolved_path == NULL ) {
      /* Path doesn't exist yet, check parent directory */
      char *path_copy = strdup(path);
      char *dir_name = dirname(path_copy);
      resolved_path = realpath(dir_name, NULL);
      free(path_copy);
      if ( resolved_path == NULL ) {
        display( LOG_ERR, "Invalid path or parent directory: %s", path );
        return FAILED;
      }
    }
    
    /* Check if resolved path stays within expected boundaries */
    if ( strncmp(resolved_path, "/tmp", 4) == 0 || 
         strncmp(resolved_path, "/var", 4) == 0 ||
         strncmp(resolved_path, "/usr/local", 10) == 0 ||
         strncmp(resolved_path, "/home", 5) == 0 ) {
      safe = TRUE;
    } else {
      display( LOG_ERR, "Path outside allowed directories: %s -> %s", path, resolved_path );
      safe = FAILED;
    }
    
    free(resolved_path);
    return safe;
  }
  
  /* For relative paths, ensure they don't contain null bytes or other dangerous chars */
  for ( ptr = (char *)path; *ptr != '\0'; ptr++ ) {
    if ( *ptr == '\0' || *ptr < 32 || *ptr > 126 ) {
      display( LOG_ERR, "Path contains invalid characters: %s", path );
      return FAILED;
    }
  }
  
  return TRUE;
}

/****
 *
 * create pid file
 *
 ****/

int create_pid_file( const char *filename ) {
  int fd;
  FILE *lockfile;
  size_t len;
  pid_t pid;

  /* remove old pid file if it exists */
  cleanup_pid_file( filename );
  if ( ( fd = safe_open( filename ) ) < 0 ) {
    display( LOG_ERR, "Unable to open pid file [%s]", filename );
    return FAILED;
  }
  if ( ( lockfile = fdopen(fd, "w") ) EQ NULL ) {
    display( LOG_ERR, "Unable to fdopen() pid file [%d]", fd );
    return FAILED;
  }
  pid = getpid();
  if (fprintf( lockfile, "%ld\n", (long)pid) < 0) {
    display( LOG_ERR, "Unable to write pid to file [%s]", filename );
    fclose( lockfile );
    return FAILED;
  }
  if ( fflush( lockfile ) EQ EOF ) {
    display( LOG_ERR, "fflush() failed [%s]", filename );
    fclose( lockfile );
    return FAILED;
  }

  fclose( lockfile );
  return TRUE;
}

/****
 *
 * safely open a file for writing
 *
 ****/

static int safe_open( const char *filename ) {
  int fd;
  struct stat sb;
  XMEMSET( &sb, 0, sizeof( struct stat ) );
                                                                 
  /* First try to create the file atomically */
  fd = open( filename, O_WRONLY|O_CREAT|O_EXCL, S_IRUSR|S_IWUSR|S_IRGRP|S_IROTH );
  if ( fd >= 0 ) {
    return fd;  /* Successfully created new file */
  }
  
  if ( errno != EEXIST ) {
    return FAILED;  /* Some other error occurred */
  }
  
  /* File exists, check if it's safe to replace */
  if ( lstat(filename, &sb) EQ FAILED ) {
    return FAILED;
  }
  
  /* Ensure it's a regular file and not a symlink or special file */
  if ( ( sb.st_mode & S_IFREG) EQ 0 ) {
    errno = EOPNOTSUPP;
    return FAILED;
  }
  
  /* Remove existing file and try again atomically */
  if ( unlink( filename ) EQ FAILED ) {
    return FAILED;
  }
  
  fd = open( filename, O_WRONLY|O_CREAT|O_EXCL, S_IRUSR|S_IWUSR|S_IRGRP|S_IROTH );

  return (fd);
}

/****
 *
 * cleaup pid file
 *
 ****/

static void cleanup_pid_file( const char *filename ) {
  if ( strlen( filename ) > 0 ) {
    unlink( filename );
  }
}

/****
 *
 * sanitize environment
 *
 ****/

void sanitize_environment( void ) {
  int i;
  char **new_environ;
  char *ptr, *value, *var;
  size_t arr_size = 1;
  size_t arr_ptr = 0;
  size_t len;
  size_t new_size = 0;

  for( i = 0; (var = restricted_environ[i]) != 0; i++ ) {
    new_size += strlen( var ) + 1;
    arr_size++;
  }

  for ( i = 0; (var = preserve_environ[i]) != 0; i++ ) {
    if ( !(value = getenv(var))) continue;
    new_size += strlen( var ) + strlen( value ) + 2;
    arr_size++;
  }

  new_size += ( arr_size * sizeof( char * ) );
  new_environ = (char **)XMALLOC( new_size );
  new_environ[arr_size - 1] = 0;
  ptr = ( char * )new_environ + (arr_size * sizeof(char *));
  for ( i = 0; ( var = restricted_environ[i] ) != 0; i++ ) {
    new_environ[arr_ptr++] = ptr;
    len = strlen( var );
    XMEMCPY( ptr, var, len + 1 );
    ptr += len + 1;
  }

  for ( i = 0; ( var = preserve_environ[i] ) != 0; i++ ) {
    if ( !( value = getenv( var ) ) ) continue;
    new_environ[arr_ptr++] = ptr;
    len = strlen( var );
    XMEMCPY( ptr, var, len );
    *(ptr + len) = '=';
    XMEMCPY( ptr + len + 1, value, strlen( value ) + 1 );
    ptr += len + strlen( value ) + 2;
  }

  environ = new_environ;
}
