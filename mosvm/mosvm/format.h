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

#ifndef MQO_FORMAT_H
#define MQO_FORMAT_H

#include "memory.h"
#include <stdarg.h>

void mqo_format_begin( mqo_string buf, void* o );
void mqo_format_end( mqo_string buf );
int mqo_format_item( mqo_string s, mqo_value v );
void mqo_format_value( 
    mqo_string s, mqo_value v, mqo_quad breadth, mqo_quad depth 
);
mqo_string mqo_formatf( char* fmt, ... );

#define mqo_printf( fmt, ... ) mqo_printstr( mqo_formatf( fmt, __VA_ARGS__ ) );

#endif

