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

#include "mosvm.h"

mqo_string mqo_make_string( mqo_integer capacity ){
    mqo_string string = MQO_ALLOC( mqo_string, 0 );
    // string->pool = GC_malloc_atomic( capacity + 1 );
    string->pool = GC_malloc( capacity + 1 );
    string->capacity = capacity;
    string->length = string->origin = 0;
    return string;
}

void mqo_compact_string( mqo_string string ){
    if( string->origin ){
        if( string->length ){
            memmove( string->pool, 
                    string->pool + string->origin, 
                    string->length );
        }
        string->pool[string->length + 1] = 0;
        string->origin = 0;
    }
}
void mqo_expand_string( mqo_string string, mqo_integer count ){
    mqo_integer space = (
        string->capacity - string->origin - string->length - count 
    );

    if( space >= 0 ) return;

    if(( string->origin + space )>= 0 ){
        // We can just compress for it.
        mqo_compact_string( string );
    }else{
        // We expand enough to get the new write in, and add the capacity
        // of the old string for good measure.
        mqo_integer new_capacity = string->capacity << 1 - space + 1;
        mqo_compact_string( string );

        string->pool = GC_realloc( string->pool, new_capacity );
        string->capacity = new_capacity;
    }
}
void mqo_flush_string( mqo_string string ){
    string->pool[ string->origin = string->length = 0 ] = 0;
}
void mqo_string_write(
    mqo_string string, const void* src, mqo_integer srclen 
){
    memmove( string->pool + string->origin + string->length, src, srclen );
    string->length += srclen;
    string->pool[ string->origin +  string->length ] = 0;
}
void mqo_string_alter( 
    mqo_string string, mqo_integer dstofs, mqo_integer dstlen, 
    const void* src, mqo_integer srclen
){
    mqo_integer newlen = string->length + srclen - dstlen;

    mqo_expand_string( string, newlen );
    
    void* dst = string->pool + string->origin + dstofs;

    void* tail = dst + dstlen;
    mqo_integer taillen = string->length - dstlen - dstofs;

    void* newtail = dst + srclen;
    
    if( taillen && ( tail != newtail ))memmove( dst + srclen, tail, taillen );
    if( srclen ) memmove( dst, src, srclen );

    string->length = newlen;
    string->pool[ newlen ] = 0;
}
char* mqo_sf_string( mqo_string string ){
    string->pool[ string->origin + string->length ] = 0;
    return string->pool + string->origin;
}

void mqo_skip_string( mqo_string string, mqo_integer offset ){
    assert( string->length >= offset );
    
    string->length -= offset;
    string->origin += offset;
}

void* mqo_string_read( mqo_string string, mqo_integer* r_count ){
    mqo_integer count = *r_count;
    void* pool = mqo_sf_string( string );
    if( count > string->length ) count = string->length;
    string->length -= count;
    string->origin += count;

    *r_count = count;
    return pool;
}
void* mqo_read_line_string( mqo_string string, mqo_integer* r_count ){
    char* line = mqo_sf_string( string );
    mqo_integer linelen = string->length;
    mqo_integer seplen = 0;
    mqo_integer index = 0;

    while( index < linelen ){
        if( line[ index ] == '\n' ){
            linelen = index;
            seplen = 1;
            goto complete;
        }else if( line[ index ] == '\r' ){
            linelen = index;
            seplen = ( line[ index + 1 ] == '\n' ) ? 2 : 1;
            goto complete;
        }else{
            index ++;
        }
    }
incomplete:
    return NULL;
complete:
    //TODO: Adjust string length and origin.
    string->origin += linelen + seplen;
    string->length -= linelen + seplen;
    *r_count = linelen;
    return line;
}

void mqo_show_string( mqo_string a, mqo_word* ct ){
    //TODO: Escape.
    mqo_writech( '"' );
    mqo_integer ln = mqo_string_length( a );
    if( ct ){
        if( *ct <( ln / 8 ) ){
            ln = ( *ct ) * 8;
            *ct = 0;
        }else{
            *ct -= ln / 8;
        }
    }
    mqo_writemem( a->pool, ln );
    mqo_writech( '"' );
}
void mqo_show_symbol( mqo_symbol s, mqo_word* ct ){
    mqo_writesym( s );
}

mqo_tree mqo_lexicon = NULL;
// When new symbols are created from strings, a search is made of the lexicon
// for an equivalent string.

mqo_string mqo_string_fm( const void* s, mqo_integer sl ){
    mqo_string a = mqo_make_string( sl );
    memcpy( a->pool, s, sl );
    a->pool[sl+1] = 0;
    a->length = sl;
    return a;
}
mqo_string mqo_string_fs( const char* s ){
    return mqo_string_fm( (const void*)s, strlen( s ) );
}
mqo_value mqo_symbol_key( mqo_value item ){
    return mqo_vf_string( mqo_symbol_fv( item )->string );
}
mqo_symbol mqo_symbol_fm( const void* s, mqo_integer sl ){
    mqo_pair lx;
    mqo_symbol sym;
    mqo_string str;
    mqo_node node; 

    str = mqo_string_fm( s, sl );
    
    node = mqo_tree_lookup( mqo_lexicon, mqo_vf_string( str ) );
    if( node ){ 
        GC_free( str );
        return mqo_symbol_fv( node->data ); 
    }else{
    
        sym = MQO_ALLOC( mqo_symbol, 0 );
        sym->string = str;
        sym->value = mqo_make_void();
        mqo_tree_insert( mqo_lexicon, mqo_vf_symbol( sym ) );
        return sym;
    }
}
mqo_symbol mqo_symbol_fs( const char* s ){
    return mqo_symbol_fm( s, strlen( s ) );
}
mqo_integer mqo_string_compare( mqo_string a, mqo_string b ){
    //This will result in dictionary-style ordering of strings,
    //with case sensitivity.
    //
    //NOTE: Ideally, we would also use a string hash here to
    //      give us a second form of equality testing prior
    //      to degenerating into memcmp, but there's a point
    //      where performance optimizations must give way.

    mqo_integer al = mqo_string_length( a );
    mqo_integer bl = mqo_string_length( b );
    mqo_integer d = memcmp( mqo_sf_string( a ), 
                            mqo_sf_string( b ),
                            al < bl ? al : bl );

    return d ? d : ( al - bl );
}

mqo_boolean mqo_eqvs( mqo_string a, mqo_string b ){
    return ! mqo_string_compare( a, b );
}
