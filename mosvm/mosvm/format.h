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

void mqo_format_char( mqo_string buf, char ch );
void mqo_format_nl( mqo_string buf );
void mqo_format_hexnibble( mqo_string buf, mqo_quad digit );
void mqo_format_hexbyte( mqo_string buf, mqo_quad byte );
void mqo_format_hexword( mqo_string buf, mqo_quad word );
void mqo_format_hexquad( mqo_string buf, mqo_quad word );
void mqo_format_indent( mqo_string buf, mqo_integer depth );
void mqo_format_dec( mqo_string str, mqo_quad number );
void mqo_format_int( mqo_string str, mqo_integer number );
void mqo_format_hex( mqo_string str, mqo_quad number );
void mqo_format_str( mqo_string buf, mqo_string s );
void mqo_format_sym( mqo_string buf, mqo_symbol s );
void mqo_format_addr( mqo_string buf, mqo_integer i );
void mqo_format_cs( mqo_string buf, const char* c );
void mqo_format_begin( mqo_string buf, void* o );
void mqo_format_end( mqo_string buf );
void mqo_format( mqo_string s, mqo_value v );
mqo_string mqo_formatf( char* fmt, ... );

#endif

