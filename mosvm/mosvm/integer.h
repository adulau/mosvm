/* Copyright (C) 2006, Ephemeral Security, LLC 
* 
* This library is free software; you can redistribute it and/or modify it  
* under the terms of the GNU Lesser General Public License, version 2.1
* as published by the Free Software Foundation.
* 
* This library is distributed in the hope that it will be useful, but WITHOUT 
* ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or 
* FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License 
* for more details. 
* 
* You should have received a copy of the GNU Lesser General Public License 
* along with this library; if not, write to the Free Software Foundation, 
* Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA 
*/ 

#ifndef MQO_INTEGER_H
#define MQO_INTEGER_H 1

#if defined( __OpenBSD__ )

typedef unsigned char mqo_byte;
typedef unsigned short mqo_word;
typedef unsigned long mqo_long;
typedef signed long mqo_integer;
typedef int mqo_boolean;

#else

#include <stdint.h>

typedef uint8_t mqo_byte;
typedef uint16_t mqo_word;
typedef uint32_t mqo_long;
typedef int32_t mqo_integer;
typedef int mqo_boolean;

#endif

#if defined( _WIN32  )||defined( __CYGWIN__ )
#undef ntohs
#undef htons
#undef ntohl
#undef htonl

#define htons ntohs
#define ntohs __ntohs
#define htonl ntohl
#define ntohl __ntohl

static inline unsigned long __ntohl (unsigned long x){
    __asm__ ("xchgb %b0, %h0\n\t"   /* swap lower bytes  */
	     "rorl  $16, %0\n\t"    /* swap words        */
	     "xchgb %b0, %h0"       /* swap higher bytes */
	    : "=q" (x) : "0" (x));
    return (x);
}

static inline unsigned short __ntohs (unsigned short x){
	__asm__ ("xchgb %b0, %h0"       /* swap bytes */
		: "=q" (x) : "0" (x));
	return (x);
}

#endif

#endif
