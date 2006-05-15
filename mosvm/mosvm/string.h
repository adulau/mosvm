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
char* mqo_sf_string( mqo_string a );
static inline mqo_integer mqo_string_length( mqo_string s ){ return s->length; }

void mqo_expand_string( mqo_string string, mqo_integer data );
// Ensures that the string's capacity is sufficient for data bytes to be
// written to the string.

void mqo_skip_string( mqo_string string, mqo_integer offset );
// Advances the string head offset bytes, removing them from its current
// length.

void* mqo_string_read( mqo_string string, mqo_integer* count );
// Reads data from the string up to *count.  *count is updated with the
// actual number of bytes read, and the pointer returned points to the
// origin.  This pointer will be valid until the next string expansion or
// write operation.

void* mqo_read_line_string( mqo_string string, mqo_integer* count );
// Reads data from the string up to the next '\n' or '\r\n' separator, then
// advances the origin past the line and accompanying separator.  If a
// separator cannot be found, returns NULL.

void mqo_flush_string( mqo_string string );

static inline mqo_boolean mqo_string_empty( mqo_string string ){ 
    return string->length <= 0;
}

void mqo_string_alter( 
    mqo_string string, mqo_integer dstofs, mqo_integer dstlen,
    const void* src, mqo_integer srclen 
);
// Replaces dstlen data at dstofs with srclen data from src; alters the
// string memory pool to compensate if necessary.

void mqo_string_write( mqo_string string, const void* src, mqo_integer srclen );
static inline void mqo_string_insert( 
    mqo_string string, mqo_integer offset, const void* src, mqo_integer srclen 
){
    mqo_string_alter( string, offset, 0, src, srclen );
}
static inline void mqo_string_append( 
    mqo_string string, const void* src, mqo_integer srclen 
){
    mqo_string_insert( string, string->length, src, srclen );
}
static inline void mqo_string_prepend( 
    mqo_string string, const void* src, mqo_integer srclen 
){
    mqo_string_insert( string, 0, src, srclen );
}
#endif
