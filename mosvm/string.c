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
#include <string.h>

#ifdef AUDIT_STRINGS
#define AUDIT_STRING( x ) mqo_audit_string( x );
void mqo_audit_string( mqo_string string ){
    assert( string );
    assert( string->pool );
    assert( string->length <= string->capacity );
    assert( string->origin <= string->capacity );
    assert(( string->origin + string->length ) <= string->capacity );
    assert( string->origin < 32767 );
    assert( string->length < 32767 );
    assert( string->capacity < 32767 );
    assert( string->origin < 32767 );
    assert( string->length < 32767 );
    assert( string->capacity < 32767 );
}
#else
#define AUDIT_STRING( x ) ;
#endif

mqo_value mqo_lexicon_key( mqo_value item ){
    return mqo_vf_string( mqo_symbol_fv( item )->string );
}

extern struct mqo_type_data mqo_tree_type_data;

struct mqo_tree_data mqo_lexicon_data = { 
    { &mqo_tree_type_data },
    (mqo_node)NULL, 
    mqo_lexicon_key 
};

mqo_tree mqo_lexicon = &mqo_lexicon_data;

mqo_symbol mqo_symbol_fm( const void* s, mqo_integer sl ){
    mqo_symbol sym;
    mqo_string str;
    mqo_node node; 

    str = mqo_string_fm( s, sl );
    AUDIT_STRING( str );
    node = mqo_tree_lookup( mqo_lexicon, mqo_vf_string( str ) );

    if( node ){ 
        mqo_objfree( str );
        return mqo_symbol_fv( node->data ); 
    }else{
        sym = MQO_OBJALLOC( symbol );
        sym->string = str;
        sym->global = 0;
        sym->value = mqo_vf_null();
        //TODO: ldg and stg must respect global.
        mqo_tree_insert( mqo_lexicon, mqo_vf_symbol( sym ) );
        return sym;
    }
}
mqo_symbol mqo_symbol_fs( const char* s ){
    return mqo_symbol_fm( s, strlen( s ) );
}

mqo_string mqo_make_string( mqo_integer capacity ){
    mqo_string string = MQO_OBJALLOC( string );
    string->origin = 0;
    string->length = 0;
    string->pool = malloc( capacity + 1 );
    string->capacity = capacity;
    AUDIT_STRING( string );
    return string;
}

mqo_integer mqo_string_compare( mqo_string a, mqo_string b ){
    //This will result in dictionary-style ordering of strings,
    //with case sensitivity.
    //
    //NOTE: Ideally, we would also use a string hash here to
    //      give us a second form of equality testing prior
    //      to degenerating into memcmp, but there's a point
    //      where performance optimizations must give way to
    //      code complexity.

    mqo_quad al = mqo_string_length( a );
    mqo_quad bl = mqo_string_length( b );
    mqo_integer d = memcmp( mqo_sf_string( a ), 
                            mqo_sf_string( b ),
                            al < bl ? al : bl );

    return d ? d : ( al - bl );
}

mqo_boolean mqo_has_global( mqo_symbol name ){
    return name->global;    
}

void mqo_set_global( mqo_symbol name, mqo_value value ){
    name->value = value;
    name->global = 1;
}

mqo_value mqo_get_global( mqo_symbol name ){
    return mqo_has_global( name ) ? name->value : mqo_vf_null();
}

void mqo_show_string( mqo_string str, mqo_word* ct ){
    //TODO: Improve with ellision, scored length, escaping unprintables.
    AUDIT_STRING( str );
    mqo_printch( '"' );
    mqo_printstr( str );
    mqo_printch( '"' );
    (*ct) --;
}

MQO_GENERIC_TRACE( string );
void mqo_free_string( mqo_string str ){
    AUDIT_STRING( str );
    free( str->pool );
    mqo_objfree( (mqo_object) str );
}
MQO_C_TYPE( string );

void mqo_trace_symbol( mqo_symbol symbol ){
    AUDIT_STRING( symbol->string );
    mqo_grey_obj( (mqo_object) symbol->string );
    if( symbol->global )mqo_grey_val( symbol->value );    
}
void mqo_show_symbol( mqo_symbol sym, mqo_word* ct ){
    mqo_printsym( sym );
    (*ct) --;
}
void mqo_free_symbol( mqo_symbol sym ){
    assert( 0 );
    mqo_objfree( (mqo_object) sym );
}
// MQO_GENERIC_FREE( symbol);
MQO_GENERIC_COMPARE( symbol);
MQO_C_TYPE( symbol );

void mqo_globals_iter( mqo_value data, mqo_pair tc ){
    mqo_symbol sym = mqo_symbol_fv( data );
    if( mqo_has_global( sym ) ){ 
        mqo_tc_append( tc, mqo_vf_pair( mqo_cons( mqo_vf_symbol( sym ),
                                                  mqo_get_global( sym ) ) ) );
    }
}
mqo_list mqo_get_globals( ){
    mqo_pair tc = mqo_make_tc( );
    mqo_iter_tree( mqo_lexicon, (mqo_iter_mt)mqo_globals_iter, tc );
    return mqo_list_fv( mqo_car( tc ) );
}
void mqo_init_string_subsystem( ){
    mqo_root_obj( (mqo_object)mqo_lexicon );
    MQO_I_TYPE( string );
    MQO_I_TYPE( symbol );
}
void mqo_compact_string( mqo_string str ){
    AUDIT_STRING( str );
    if( str->origin ){
        if( str->length ){
            memmove( str->pool, 
                    str->pool + str->origin, 
                    str->length );
        };
        str->pool[str->length + 1] = 0;
        str->origin = 0;
    };
    AUDIT_STRING( str );
}
void mqo_string_expand( mqo_string string, mqo_integer incr ){
    AUDIT_STRING( string );
    mqo_integer head = string->origin;
    mqo_integer tail = string->capacity - head - string->length;

    if( tail > incr )return;

    mqo_compact_string( string );

    if(( tail + head )> incr )return;
    
    mqo_integer req_cap = string->length + incr;
    mqo_integer new_cap = string->capacity; 

    while( new_cap < req_cap ) new_cap <<= 1;

    string->pool = realloc( string->pool, new_cap + 1 );
    string->capacity = new_cap;
    
    AUDIT_STRING( string );
}
void mqo_string_flush( mqo_string string ){
    AUDIT_STRING( string );
    string->pool[ string->origin = string->length = 0 ] = 0;
    AUDIT_STRING( string );
}
void mqo_string_append(
    mqo_string string, const void* src, mqo_integer srclen 
){
    AUDIT_STRING( string );
    mqo_string_expand( string, srclen );
    memmove( string->pool + string->origin + string->length, src, srclen );
    string->length += srclen;
    string->pool[ string->origin +  string->length ] = 0;
    AUDIT_STRING( string );
}
void mqo_string_alter( 
    mqo_string string, mqo_integer dstofs, mqo_integer dstlen, 
    const void* src, mqo_integer srclen
){
    AUDIT_STRING( string );
    mqo_integer newlen = string->length + srclen - dstlen;

    mqo_string_expand( string, newlen );
    
    void* dst = string->pool + string->origin + dstofs;

    void* tail = dst + dstlen;
    mqo_integer taillen = string->length - dstlen - dstofs;

    void* newtail = dst + srclen;
    
    if( taillen && ( tail != newtail ))memmove( dst + srclen, tail, taillen );
    if( srclen ) memmove( dst, src, srclen );

    string->length = newlen;
    string->pool[ newlen ] = 0;
    AUDIT_STRING( string );
}
void mqo_string_prepend( 
    mqo_string string, const void* src, mqo_integer srclen
){
    mqo_string_alter( string, 0, 0, src, srclen );
}
char* mqo_sf_string( mqo_string string ){
    string->pool[ string->origin + string->length ] = 0;
    return string->pool + string->origin;
}
void mqo_string_skip( mqo_string string, mqo_integer offset ){
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
void* mqo_string_read_line( mqo_string string, mqo_integer* r_count ){
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
    string->origin += linelen + seplen;
    string->length -= linelen + seplen;
    *r_count = linelen;
    return line;
}
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
void mqo_string_append_byte( mqo_string string, mqo_byte x ){
    mqo_string_append( string, &x, 1 );
    AUDIT_STRING( string );
}
void mqo_string_append_word( mqo_string string, mqo_word x ){
    x = htons( x );
    mqo_string_append( string, &x, 2 );
    AUDIT_STRING( string );
}
void mqo_string_append_quad( mqo_string string, mqo_quad x ){
    x = htonl( x );
    mqo_string_append( string, &x, 4 );
    AUDIT_STRING( string );
}
void* mqo_string_head( mqo_string head ){
    AUDIT_STRING( head );
    return head->pool + head->origin;
}
void* mqo_string_tail( mqo_string string ){
    AUDIT_STRING( string );
    return string->pool + string->origin + string->length;
}
void mqo_string_wrote( mqo_string string, mqo_integer len ){
    AUDIT_STRING( string );
    string->length += len;
}
mqo_boolean mqo_string_empty( mqo_string str ){
    AUDIT_STRING( str );
    return ! str->length;
}

