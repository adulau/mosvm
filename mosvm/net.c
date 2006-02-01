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

#if defined(_WIN32)||defined(__CYGWIN__)
#include <sys/time.h>
#include <winsock2.h>
#define MQO_EWOULDBLOCK WSAEWOULDBLOCK
#else
#include <netinet/in.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#define MQO_EWOULDBLOCK EWOULDBLOCK
#endif


void mqo_unblock_socket( mqo_integer s ){
#if defined( _WIN32 )||defined( __CYGWIN__ )
    unsigned long unblocking = 1;
    mqo_os_error( ioctlsocket( s, FIONBIO, &unblocking ) );
#else
    mqo_os_error( fcntl( s, F_SETFL, O_NONBLOCK ) );
#endif
}
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
mqo_socket mqo_connect_tcp( mqo_integer address, mqo_integer port ){
    static struct sockaddr_in addr;

    memset( &addr, 0, sizeof( addr ) );
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl( address );
    addr.sin_port = htons( port );

    int client_fd = socket( AF_INET, SOCK_STREAM, IPPROTO_TCP );

    connect( client_fd, (struct sockaddr*)&addr, sizeof( addr ) );
    mqo_unblock_socket( client_fd );
    mqo_string client_name = mqo_string_fs( "tcp-client-conn" );
    return mqo_make_socket( client_name, client_fd );
}
mqo_listener mqo_serve_tcp( mqo_integer port ){
    static struct sockaddr_in addr;

    memset( &addr, 0, sizeof( addr ) );
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl( INADDR_ANY );
    addr.sin_port = htons( port );

    int server_fd = mqo_os_error( socket( AF_INET, SOCK_STREAM, IPPROTO_TCP ) );
    mqo_os_error( bind( server_fd, (struct sockaddr*)&addr, sizeof( addr ) ) );
    mqo_os_error( listen( server_fd, 5 ) ); 
    mqo_unblock_socket( server_fd );    

    //TODO: Create a server name.

    mqo_string server_name = mqo_string_fs( "tcp-server" );
    return mqo_make_listener( server_name, server_fd );
}

mqo_tree mqo_monitors;

void mqo_monitor( mqo_value target, mqo_process process ){
    assert( mqo_direct_type( target ) == mqo_descr_type );
    mqo_descr descr = (mqo_descr)target.data;

    if( descr->monitor &&( process != descr->monitor )){
        mqo_errf( mqo_es_vm, "sx", "object already has a monitor", target );
    }

    descr->monitor = process; 
    mqo_tree_insert( mqo_monitors, target);
}
void mqo_unmonitor( mqo_value target, mqo_process process ){
    assert( mqo_direct_type( target ) == mqo_descr_type );
    mqo_descr descr = (mqo_descr)target.data;

    if( descr->monitor != process ){
        mqo_errf( mqo_es_vm, "sx", "process is not monitoring object", target );
    }
    descr->monitor = NULL; 
    mqo_tree_remove( mqo_monitors, target );
}
void mqo_attempt_read( mqo_descr descr ){
    static char buffer[ BUFSIZ ];
    
    mqo_value result;
    mqo_integer rs;
    mqo_type type;
    
    if( descr->type == MQO_LISTENER ){
        struct sockaddr_storage addr;
        mqo_integer len = sizeof( addr );
        rs = accept( descr->fd, (struct sockaddr*)&addr, &len);
        type = mqo_listener_type;
        if( rs == -1 && errno == MQO_EWOULDBLOCK )return;
        mqo_unblock_socket( rs );
        mqo_string name = mqo_string_fs( "tcp-incoming" );
        result = mqo_vf_socket( mqo_make_socket( name, rs ) );
    }else{
        if( descr->type == MQO_SOCKET ){
            rs = recv( descr->fd, buffer, BUFSIZ, 0 );
            type = mqo_socket_type;
        }else{
            rs = read( descr->fd, buffer, BUFSIZ );
            type = mqo_console_type;
        };
        if( rs == -1 ){
            if( errno == MQO_EWOULDBLOCK ){
                return;
            }else{
                mqo_report_os_error( );
            }
        }
        result = mqo_vf_string( mqo_string_fm( buffer, rs ) );
    }

    descr->result = result;
    result = mqo_make_value( type, (mqo_integer)descr );
    if( descr->monitor ){
        mqo_resume( descr->monitor, result );
#if defined( _WIN32)||defined(__CYGWIN__)
        if( descr->type != MQO_CONSOLE )
#endif
            mqo_tree_remove( mqo_monitors, result );
    };
}

int mqo_dispatch_monitors_once( ){
    // Returns nonzero if there are no monitors.

    //TODO: Currently, we rely on a blocking connect to guard against
    //      premature writing.  Ideally, we would actually monitor sockets
    //      that have not completed connection for WRITE.

    struct timeval *timeout;
    struct fd_set reads, errors;
    mqo_descr descr;
    mqo_node node;
    int fd, maxfd;

    FD_ZERO( &reads );
    FD_ZERO( &errors );
    maxfd = -1;

    if( mqo_first_process ){
        struct timeval timeout_data = { 0, 0 };
        timeout = &timeout_data;
    }else{
        //TODO: This should be modified by the window of the next timed
        //      alarm.
        timeout = NULL;
    }
    
    node = mqo_first_node( mqo_monitors );
    while( node = mqo_next_node( node ) ){
        descr = (mqo_descr)(node->data.data);
#if defined( _WIN32)||defined(__CYGWIN__)
        if( descr->type == MQO_CONSOLE )continue;
#endif
        if( descr->monitor->status != mqo_ps_suspended )continue;
        if( descr->closed )continue;

        fd = descr->fd;
        if( fd > maxfd ) maxfd = fd;
        FD_SET( fd, &reads );
        FD_SET( fd, &errors );
    }

#if defined( _WIN32)||defined(__CYGWIN__)
    if( mqo_the_console->monitor && mqo_is_void( mqo_the_console->result ) ){
        mqo_attempt_read( (mqo_descr)mqo_the_console );
    }else if( maxfd == -1 ){ return 1; };
#else
    if( maxfd == -1 ){ return 1; }
#endif

    maxfd = mqo_os_error(select( maxfd + 1, &reads, NULL, &errors, timeout )); 
    if( ! maxfd )return 0;

    node = mqo_first_node( mqo_monitors );

    while( node = mqo_next_node( node ) ){
        descr = (mqo_descr)(node->data.data);
#if defined( _WIN32)||defined(__CYGWIN__)
        if( descr->type == MQO_CONSOLE )continue;
#endif
        if( descr->monitor->status != mqo_ps_suspended )continue;
        if( descr->closed )continue;

        fd = descr->fd;
        if( FD_ISSET( fd, &reads ) || FD_ISSET( fd, &errors ) ){ 
            mqo_attempt_read( descr );
        }
    }

    return 0;
}
int mqo_dispatch_monitors( ){
    for(;;){
        int all_quiet = mqo_dispatch_monitors_once( );
        if( mqo_first_process ){
            return 1;
        }else if( all_quiet ){
            return 0;
        }
    }
}

mqo_console mqo_the_console;

void mqo_init_net_subsystem( ){
#ifdef _WIN32
    WSADATA wsa;
    WSAStartup( 2, &wsa );
    // mqo_unblock_socket( STDIN_FILENO );
#endif
    mqo_monitors = mqo_make_tree( mqo_set_key );
    mqo_the_console = mqo_make_console( mqo_string_fs( "console" ) );
}

