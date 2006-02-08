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

#ifndef MQO_SHOW_H
#define MQO_SHOW_H 1

#include "memory.h"

void mqo_write( const char* st );
void mqo_writemem( const void* mem, mqo_integer len );
void mqo_writestr( mqo_string st );
void mqo_writech( mqo_byte ch );
void mqo_writeint( mqo_integer i );
void mqo_writehex( mqo_long number );
void mqo_writesym( mqo_symbol sy );
void mqo_space( );
void mqo_newline( );

void mqo_show( mqo_value v, mqo_word* ct );
// Displays the supplied value.  If ct is nonnull, it is employed to prevent
// excessive display by refusing to display contained values beyond the 
// specified value.
//
// Note that self-referential values with a nonnull ct can result in an
// infinite loop, or stack overflow.  High counts may also result in 
// overflows.

void mqo_write_address( mqo_integer c );
void mqo_show_unknown( mqo_type t, mqo_integer d );
#define mqo_show_atom NULL
#define mqo_show_void NULL

#endif

