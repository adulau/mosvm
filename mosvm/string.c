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
#include <ctype.h>

#ifdef _WIN32
// We need hton and ntoh
#include <winsock2.h>
#endif

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

void mqo_format_string( mqo_string buf, mqo_string str ){
    //TODO: Improve with ellision, scored length.
    AUDIT_STRING( str );
    mqo_string_append_byte( buf, '"' );
    const char* ptr = mqo_string_head( str );
    mqo_integer i, len = mqo_string_length( str );
    for( i =0; i < len; i ++ ){
        unsigned char ch = *(ptr + i );
        switch( ch ){
        case '\r':
            mqo_string_append_cs( buf, "\\r" );
            break;
        case '\n':
            mqo_string_append_cs( buf, "\\n" );
            break;
        case '\t':
            mqo_string_append_cs( buf, "\\t" );
            break;
        case '"':
            mqo_string_append_cs( buf, "\\\"" );
            break;
        default:
            if( isprint( ch ) ){
                mqo_string_append_byte( buf, ch );
            }else{
                mqo_string_append_byte( buf, '\\' );
                mqo_string_append_unsigned( buf, ch );
            }
        }
    };
    mqo_string_append_byte( buf, '"' );
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
void mqo_format_symbol( mqo_string buf, mqo_symbol sym ){
    mqo_string_append_sym( buf, sym ); 
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
            str->pool[str->length + 1] = 0;
        };
        str->origin = 0;
    };
    AUDIT_STRING( str );
}
void mqo_string_expand( mqo_string string, mqo_integer newlen ){
    AUDIT_STRING( string );
    mqo_integer incr = newlen - string->length;
    if( incr < 0 )return;

    mqo_integer head = string->origin;

    mqo_integer tail = string->capacity - head - string->length;
    if( tail > incr )return;

    mqo_compact_string( string );

    if(( tail + head )> incr )return;
    
    mqo_integer newcap = string->capacity + 1; 

    while( newcap < newlen ) newcap <<= 1;

    string->pool = realloc( string->pool, newcap + 1 );
    string->capacity = newcap;
    
    AUDIT_STRING( string );
}
void mqo_string_flush( mqo_string string ){
    AUDIT_STRING( string );
    string->pool[ string->origin = string->length = 0 ] = 0;
    AUDIT_STRING( string );
}
void mqo_string_alter( 
    mqo_string string, mqo_integer dstofs, mqo_integer dstlen, 
    const void* src, mqo_integer srclen
){
    //TODO: This is still naive -- there are situations where the head could
    //      be moved upwards, and the tail moved downwards, without needing
    //      to totally alter the string.
    
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
    string->pool[ string->origin + newlen ] = 0;
    AUDIT_STRING( string );
}
void mqo_string_prepend( 
    mqo_string string, const void* src, mqo_integer srclen
){
    if( srclen < string->origin ){
        string->origin -= srclen;
        string->length += srclen;
        memmove( string->pool + string->origin, src, srclen );
    }else{
        mqo_string_alter( string, 0, 0, src, srclen );
    }
}
void mqo_string_append(
    mqo_string string, const void* src, mqo_integer srclen 
){
    mqo_integer endpos = string->length + string->origin;

    if( srclen < ( string->capacity - endpos ) ){
        string->length += srclen;
        memmove( string->pool + endpos, src, srclen );
    }else{
        mqo_string_alter( string, string->length, 0, src, srclen );
    }
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
    a->pool[sl] = 0;
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
void mqo_string_append_newline( mqo_string buf ){
#if defined(_WIN32)||defined(__CYGWIN__)
    mqo_string_append_cs( buf, "\r\n" );
#else
    mqo_string_append_byte( buf, '\n' );
#endif
}

void mqo_string_append_hexnibble( mqo_string buf, mqo_quad digit ){
    if( digit > 9 ){
        mqo_string_append_byte( buf, 'A' + digit - 10 );
    }else{
        mqo_string_append_byte( buf, '0' + digit );
    }
}

void mqo_string_append_hexbyte( mqo_string buf, mqo_quad byte ){
    mqo_string_append_hexnibble( buf, byte / 16 );
    mqo_string_append_hexnibble( buf, byte % 16 );
}
void mqo_string_append_hexword( mqo_string buf, mqo_quad word ){
    mqo_string_append_hexbyte( buf, word / 256 );
    mqo_string_append_hexbyte( buf + 2, word % 256 );
}
void mqo_string_append_hexquad( mqo_string buf, mqo_quad word ){
    mqo_string_append_hexword( buf, word / 65536 );
    mqo_string_append_hexword( buf + 4, word % 65536 );
}
void mqo_string_append_indent( mqo_string buf, mqo_integer depth ){
    while( ( depth-- ) > 0 ) mqo_string_append_byte( buf, ' ' );
}
void mqo_string_append_unsigned( mqo_string str, mqo_quad number ){
    static char buf[256];
    buf[255] = 0;
    int i = 255;

    do{
        buf[ --i ] = '0' + number % 10;
    }while( number /= 10 );
   
    mqo_string_append( str, buf + i, 255 - i );
};
void mqo_string_append_signed( mqo_string str, mqo_integer number ){
    if( number < 0 ){
        mqo_string_append_byte( str, '-' );
        number = -number;
    }
    mqo_string_append_unsigned( str, number );
}
void mqo_string_append_hex( mqo_string str, mqo_quad number ){
    static char buf[256];
    buf[255] = 0;
    int i = 255;
    
    do{
        int digit = number % 16;
        if( digit > 9 ){
            buf[ -- i ] = 'A' + digit - 10;
        }else{
            buf[ --i ] = '0' + digit;
        }
    }while( number /= 16 );
   
    mqo_string_append( str, buf + i, 255 - i ); 
}
void mqo_string_append_str( mqo_string buf, mqo_string s ){
    mqo_string_append( buf, mqo_sf_string( s ), mqo_string_length( s ) );
}
void mqo_string_append_sym( mqo_string buf, mqo_symbol s ){
    mqo_string_append_str( buf, s->string );
}
void mqo_string_append_addr( mqo_string buf, mqo_integer i ){
    //TODO: Replace.
    if( i ){
        mqo_string_append_hex( buf, (mqo_quad)i );
    }else{
        mqo_string_append_cs( buf, "null" );
    }
}
void mqo_string_append_cs( mqo_string buf, const char* c ){
    mqo_string_append( buf, c, strlen( c ) );
}


