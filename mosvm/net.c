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

#if defined(_WIN32)||defined(__CYGWIN__)
#include <sys/time.h>
#include <winsock2.h>
#else
#include <netinet/in.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>
#include <string.h>
#endif

mqo_integer mqo_resolve( mqo_string name ){
    struct hostent *entry = gethostbyname( mqo_sf_string( name ) );
    if( !entry ){ 
        mqo_report_os_error( );
    //TODO }else if( entry->h_addrtype != ... ){
        //TODO: Signal an error.
    }else if( entry->h_length != 4 ){
        //TODO: Signal an error.
    }else{
        //TODO: A better version of resolve would return a list of
        //      addresses..
        return ntohl( *(mqo_integer*)(entry->h_addr) );
    }
}
mqo_descr mqo_connect_tcp( mqo_integer address, mqo_integer port ){
    static struct sockaddr_in addr;

    memset( &addr, 0, sizeof( addr ) );
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl( address );
    addr.sin_port = htons( port );

    int client_fd = socket( AF_INET, SOCK_STREAM, IPPROTO_TCP );

    connect( client_fd, (struct sockaddr*)&addr, sizeof( addr ) );

    mqo_string client_name = mqo_string_fs( "tcp-client-conn" );
    return mqo_make_descr( client_name, client_fd );
}
mqo_descr mqo_serve_tcp( mqo_integer port ){
    static struct sockaddr_in addr;

    memset( &addr, 0, sizeof( addr ) );
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl( INADDR_ANY );
    addr.sin_port = htons( port );

    int server_fd = mqo_os_error( socket( AF_INET, SOCK_STREAM, IPPROTO_TCP ) );
    mqo_os_error( bind( server_fd, (struct sockaddr*)&addr, sizeof( addr ) ) );
    mqo_os_error( listen( server_fd, 5 ) ); 
    
    //TODO: Create a server name.
    mqo_string server_name = mqo_string_fs( "tcp-server" );
    return mqo_make_descr( server_name, server_fd );
}
mqo_descr mqo_accept( mqo_descr server ){
    static struct sockaddr_in addr;
    int addr_sz = sizeof( addr );

    int server_fd = server->fd;
    
    int conn_fd = mqo_os_error( accept( server->fd, (struct sockaddr*)&addr, &addr_sz ) );
    
    mqo_string client_name = mqo_string_fs( "tcp-server-conn" );
    return mqo_make_descr( client_name, conn_fd );
}
