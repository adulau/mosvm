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

#ifndef MQO_PRINT_H
#define MQO_PRINT_H 1

#include "memory.h"

void mqo_format_hexnibble( char* dst, mqo_quad digit );
void mqo_format_hexbyte( char* dst, mqo_quad byte );
void mqo_format_hexword( char* dst, mqo_quad word );
void mqo_format_hexquad( char* dst, mqo_quad word );

void mqo_printmem( const void* mem, mqo_integer len );
void mqo_print( const char* st );
void mqo_printch( mqo_byte ch );
void mqo_printint( mqo_integer number );
void mqo_printhex( mqo_quad number );
void mqo_printstr( mqo_string s );
void mqo_printsym( mqo_symbol s );
void mqo_printaddr( mqo_integer i );
void mqo_newline( );
void mqo_space( );

mqo_quad mqo_parse_hexnibble( const char* src );
mqo_quad mqo_parse_hexbyte( const char* src );
mqo_quad mqo_parse_hexword( const char* src );
mqo_quad mqo_parse_hexlong( const char* src );

void mqo_show( mqo_value v, mqo_word* ct );
void mqo_begin_showtag( mqo_value v );
void mqo_end_showtag( );
void mqo_indent( mqo_integer depth );
void mqo_init_print_subsystem( );
#endif
