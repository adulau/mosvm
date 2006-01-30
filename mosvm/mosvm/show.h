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

void mqo_show_cstring( const char* st );
void mqo_show( mqo_value v, mqo_word ct );
// Displays the supplied value.  If ct is nonzero, it is employed to prevent excessive display by refusing to display
// contained values beyond the specified value.
//
// Note that self-referential values with a nonzero ct can result in an infinite loop, or stack overflow.  High counts may
// also result in overflows.

void mqo_show_pair( mqo_pair p, mqo_word ct );
// As above.

void mqo_show_error( mqo_error, mqo_word ct  );
// As above

void mqo_show_vector( mqo_vector, mqo_word ct  );
// As above

void mqo_show_instruction( mqo_instruction i, mqo_word ct );
void mqo_show_program( mqo_program s, mqo_word ct );
void mqo_show_closure( mqo_closure s );

void mqo_show_symbol( mqo_symbol s );
void mqo_show_integer( mqo_integer i );
void mqo_show_string( mqo_string a );
void mqo_show_descr( mqo_descr a );
void mqo_show_tree( mqo_tree a, mqo_word ct );
void mqo_space( );
void mqo_newline( );

#endif

