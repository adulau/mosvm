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

#ifndef MQO_STRING_H
#define MQO_STRING_H 1

#include "memory.h"

void mqo_show_string( mqo_string a, mqo_word* ct );
void mqo_show_symbol( mqo_symbol s, mqo_word* ct );
mqo_string mqo_string_fm( const void* s, mqo_integer sl );
mqo_string mqo_string_fs( const char* s );
mqo_value mqo_symbol_key( mqo_value item );
mqo_symbol mqo_symbol_fm( const void* s, mqo_integer sl );
mqo_symbol mqo_symbol_fs( const char* s );
mqo_string mqo_make_string( mqo_integer length );
mqo_integer mqo_string_compare( mqo_string a, mqo_string b );
mqo_boolean mqo_eqvs( mqo_string a, mqo_string b );

#endif
