/*****
 * $Id: common.h,v 1.2 2005/08/07 22:33:43 rdilley Exp $
 *
 *           common.h  -  description
 *           -------------------
 * begin     : Tue Aug  1 15:35:14 PDT 2005
 * copyright : (C) 2005 by Ron Dilley
 * email     : ron.dilley@uberadmin.com
 *****/

/*****
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 *****/

#ifndef COMMON_H
#define COMMON_H 1

/****
 *
 * defines
 *
 ****/

#define FAILED -1
#define FALSE 0
#define TRUE 1

#ifndef EXIT_SUCCESS
# define EXIT_SUCCESS 0
# define EXIT_FAILURE 1
#endif

#define MODE_DAEMON 0
#define MODE_INTERACTIVE 1
#define MODE_DEBUG 2

#define PRIVATE static
#define PUBLIC
#define EQ ==
#define NE !=

#ifdef __cplusplus
# define BEGIN_C_DECLS extern "C" {
# define END_C_DECLS }
#else /* !__cplusplus */
# define BEGIN_C_DECLS
# define END_C_DECLS
#endif

/****
 *
 * enums & typedefs
 *
 ****/

typedef unsigned char byte;
typedef unsigned int word;
typedef unsigned long dword;

#endif	/* end of COMMON_H */

