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
#include <stdio.h>
#include <string.h>
#include <unistd.h>

void mqo_printmem( const void* mem, mqo_integer len ){
    while( len ){
       int rs = write( STDOUT_FILENO, mem, len );
       if( rs > 0 ){
          len -= rs;
       }else if( rs ){ break; }
    }
}
void mqo_print( const char* st ){
    mqo_printmem( st, strlen( st ) );
}
void mqo_printch( mqo_byte ch ){
    mqo_printmem( &ch, 1 );
}
void mqo_printstr( mqo_string s ){
    if( s )mqo_print( mqo_sf_string( s ) );
}
void mqo_newline( ){
    mqo_printch( '\n' );
}
void mqo_space( ){
    mqo_printch( ' ' );
}
void mqo_show( mqo_value v, mqo_word* ct ){
    mqo_string s = mqo_make_string( 64 );
    mqo_format( s, v );
    mqo_printstr( s );
    mqo_objfree( s );
}

MQO_BEGIN_PRIM( "print", print )
    REQ_STRING_ARG( value );
    NO_REST_ARGS( );
    
    mqo_printstr( value );

    NO_RESULT( );
MQO_END_PRIM( print )

MQO_BEGIN_PRIM( "format", format )
    REQ_ANY_ARG( value );
    OPT_STRING_ARG( buffer );
    NO_REST_ARGS( );
    
    if( ! has_buffer ) buffer = mqo_make_string( 64 );
    mqo_format( buffer, v );

    STRING_RESULT( buffer );
MQO_END_PRIM( format )

void mqo_init_print_subsystem( ){
    MQO_BIND_PRIM( print );
    MQO_BIND_PRIM( format );
}
