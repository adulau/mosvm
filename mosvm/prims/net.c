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

#include "../mosvm.h"
#include "../mosvm/prim.h"
#include <ctype.h>

MQO_BEGIN_PRIM( "xml-escape", xml_escape )
    REQ_STRING_ARG( data );
    NO_MORE_ARGS( );
    
    const char* src = mqo_sf_string( data );
    int srclen = mqo_string_length( data );

    int dstlen = 0;
    int ix;

    for( ix = 0; ix < srclen; ix ++ ){
        char ch = src[ix];
        switch( src[ix] ){
        case '\'':
        case '"':
            dstlen += 6;
            break;
        case '&':
            dstlen += 5;
            break;
        case '<':
        case '>':
            dstlen += 4;
            break;
        default:
            dstlen ++;
        }
    }
    
    mqo_string result = mqo_make_string( dstlen );
    char* dst = result->data;
    
    for( ix = 0; ix < srclen; ix ++ ){
        char ch = src[ix];
        switch( ch ){
        case '\'':
            strcpy( dst, "&apos;" );
            dst += 6;
            break;
        case '"':
            strcpy( dst, "&quot;" );
            dst += 6;
            break;
        case '&':
            strcpy( dst, "&amp;" );
            dst += 5;
            break;
        case '<':
            strcpy( dst, "&lt;" );
            dst += 4;
            break;
        case '>':
            strcpy( dst, "&gt;" );
            dst += 4;
            break;
        default:
            *( dst++ ) = ch;
        };
    }
    
    MQO_RESULT( mqo_vf_string( result ) );
MQO_END_PRIM( xml_escape )

MQO_BEGIN_PRIM( "percent-encode", percent_encode )
    REQ_STRING_ARG( data );
    REQ_STRING_ARG( mask );
    NO_MORE_ARGS( );
    
    const char* src = mqo_sf_string( data );
    int srclen = mqo_string_length( data );

    const char* maskstr = mqo_sf_string( mask );

    int dstlen = 0;
    int ix;

    for( ix = 0; ix < srclen; ix ++ ){
        char ch = src[ix];
        if( ch == '%' || strchr( maskstr, ch ) ){
            dstlen += 3;
        }else{
            dstlen ++;
        }
    }
    
    mqo_string result = mqo_make_string( dstlen );
    char* dst = result->data;

    for( ix = 0; ix < srclen; ix ++ ){
        char ch = src[ix];
        if( ch == '%' || strchr( maskstr, ch ) ){
            *( dst++ ) = '%';
            mqo_hexbyte( dst, ch );
            dst += 2;
        }else{
            *( dst++ ) = ch;
        }
    }
    
    MQO_RESULT( mqo_vf_string( result ) );
MQO_END_PRIM( percent_encode )

MQO_BEGIN_PRIM( "percent-decode", percent_decode )
    REQ_STRING_ARG( data );
    NO_MORE_ARGS( );

    const char* src = mqo_sf_string( data );
    int srclen = mqo_string_length( data );
    int dstlen = 0;
    int ix;

    for( ix = 0; ix < srclen; ix ++ ){
        char ch = src[ix];
        if( ch != '%' ){
            dstlen ++;
        }else if( isxdigit( src[ ix + 1 ] ) && isxdigit( src[ ix + 2 ] ) ){
            dstlen ++; ix += 2;
        }else{
            mqo_errf( mqo_es_vm, "s", "decode failed, bogus code");
        }
    }
    
    mqo_string result = mqo_make_string( dstlen );
    char* dst = result->data;

    for( ix = 0; ix < srclen; ix ++ ){
        char ch = src[ix];
        if( ch == '%' ){
            ch = mqo_parse_hexbyte( src + ix + 1 );
            ix += 2;
        }
        *( dst ++ ) = ch;
    }
    
    MQO_RESULT( mqo_vf_string( result ) );
MQO_END_PRIM( percent_decode )

MQO_BEGIN_PRIM( "resolve", resolve )
    REQ_STRING_ARG( name );
    NO_MORE_ARGS( );
    
    MQO_RESULT( mqo_vf_integer( mqo_resolve( name ) ) );
MQO_END_PRIM( resolve )

MQO_BEGIN_PRIM( "connect-tcp", connect_tcp )
    REQ_VALUE_ARG( address );
    REQ_INTEGER_ARG( port );
    NO_MORE_ARGS( );
    
    mqo_integer addr;

    if( mqo_is_integer( address ) ){
        addr = mqo_integer_fv( address );
    }else if( mqo_is_string( address ) ){
        addr = mqo_resolve( mqo_string_fv( address ) );
    }else{
        mqo_errf( mqo_es_args, "sx", 
                  "expected a string or integer for addr", addr );
    }
    
    MQO_RESULT( mqo_vf_socket( mqo_connect_tcp( addr, port ) ) );
MQO_END_PRIM( connect_tcp )

MQO_BEGIN_PRIM( "serve-tcp", serve_tcp )
    REQ_INTEGER_ARG( port );
    NO_MORE_ARGS( );
    
    MQO_RESULT( mqo_vf_listener( mqo_serve_tcp( port ) ) );
MQO_END_PRIM( serve_tcp )

void mqo_bind_net_prims( ){
    MQO_BEGIN_PRIM_BINDS( );

    MQO_BIND_PRIM( serve_tcp );
    MQO_BIND_PRIM( connect_tcp );
    MQO_BIND_PRIM( resolve );

    MQO_BIND_PRIM( percent_decode )
    MQO_BIND_PRIM( percent_encode )
    MQO_BIND_PRIM( xml_escape )
}
