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
    MQO_BIND_PRIM( serve_tcp );
    MQO_BIND_PRIM( connect_tcp );
    MQO_BIND_PRIM( resolve );
}
