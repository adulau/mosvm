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

// The string Type provides a expansible memory object that works well 
// for I/O buffers, and strings. 
MQO_BEGIN_TYPE( string ) 
    mqo_integer origin, length, capacity; 
    char* pool; 
MQO_END_TYPE( string ) 

#define REQ_STRING_ARG( vn ) REQ_TYPED_ARG( vn, string )
#define STRING_RESULT( vn ) TYPED_RESULT( string, vn )
#define OPT_STRING_ARG( vn ) OPT_TYPED_ARG( vn, string )

MQO_BEGIN_TYPE( symbol )
    mqo_string  string;
    mqo_value   value;
    mqo_boolean global;
MQO_END_TYPE( symbol )
#define REQ_SYMBOL_ARG( vn ) REQ_TYPED_ARG( vn, symbol )
#define SYMBOL_RESULT( vn ) TYPED_RESULT( vn, symbol )
#define OPT_SYMBOL_ARG( vn ) OPT_TYPED_ARG( vn, symbol )

static inline mqo_quad mqo_string_length( mqo_string string ){ 
    return string->length; 
}

mqo_value mqo_lexicon_key( mqo_value item );
mqo_symbol mqo_symbol_fm( const void* s, mqo_integer sl );
mqo_symbol mqo_symbol_fs( const char* s );
mqo_string mqo_make_string( mqo_integer capacity );
mqo_integer mqo_string_compare( mqo_string a, mqo_string b );
mqo_boolean mqo_eqvs( mqo_string a, mqo_string b );
mqo_boolean mqo_has_global( mqo_symbol name );
void mqo_set_global( mqo_symbol name, mqo_value value );
mqo_value mqo_get_global( mqo_symbol name );
void mqo_format_string( mqo_string buf, mqo_string str );

mqo_list mqo_get_globals( );
void mqo_init_string_subsystem( );
void mqo_compact_string( mqo_string string );
void mqo_string_expand( mqo_string string, mqo_integer count );
void mqo_string_flush( mqo_string string );
void mqo_string_append( mqo_string string, const void* src, mqo_integer srclen );
void mqo_string_alter( 
    mqo_string string, mqo_integer dstofs, mqo_integer dstlen, 
    const void* src, mqo_integer srclen
);
char* mqo_sf_string( mqo_string string );
void mqo_string_skip( mqo_string string, mqo_integer offset );
void* mqo_string_read( mqo_string string, mqo_integer* r_count );
void* mqo_string_read_line( mqo_string string, mqo_integer* r_count );
mqo_string mqo_string_fm( const void* s, mqo_integer sl );
mqo_string mqo_string_fs( const char* s );
void mqo_string_append( mqo_string string, const void* src, mqo_integer srclen );
void mqo_string_prepend( mqo_string string, const void* src, mqo_integer srclen );
void mqo_string_append_byte( mqo_string string, mqo_byte x );
void mqo_string_append_byte( mqo_string string, mqo_byte x );
void mqo_string_append_word( mqo_string string, mqo_word x );
void mqo_string_append_quad( mqo_string string, mqo_quad x );
void* mqo_string_head( mqo_string head );
void* mqo_string_tail( mqo_string head );
void mqo_string_wrote( mqo_string string, mqo_integer len );
void mqo_string_skip( mqo_string string, mqo_integer offset );
mqo_boolean mqo_string_empty( mqo_string str );

#endif
