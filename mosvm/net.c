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


void mqo_start_listening( mqo_descr descr ){
    if( mqo_first_listening )mqo_first_listening->prev = descr;
    descr->prev = NULL;
    descr->next = mqo_first_listening;
    mqo_first_listening = descr;
}
void mqo_stop_listening( mqo_descr descr ){
    if( descr->prev ){
        descr->prev->next = descr->next;
    }else{
        mqo_first_listening = descr->next;
    }

    if( descr->next )descr->next->prev = descr->prev;
    descr->next = descr->prev = NULL;
    descr->monitor = NULL;
}

void mqo_report_net_error( ){
#if defined(_WIN32)||defined(__CYGWIN__)
    mqo_errf( mqo_es_os, "s", strerror( WSAGetLastError() ) );
#else
    mqo_errf( mqo_es_os, "s", strerror( errno ) );
#endif
}
mqo_integer mqo_net_error( mqo_integer k ){
    if( k == -1 )mqo_report_net_error( );
    return k;
}
void mqo_unblock_socket( mqo_integer s ){
#if defined( _WIN32 )||defined( __CYGWIN__ )
    unsigned long unblocking = 1;
    mqo_net_error( ioctlsocket( s, FIONBIO, &unblocking ) );
#else
    mqo_os_error( fcntl( s, F_SETFL, O_NONBLOCK ) );
#endif
}
mqo_integer mqo_resolve( mqo_string name ){
    struct hostent *entry = gethostbyname( mqo_sf_string( name ) );
    if( !entry ){ 
        mqo_report_net_error( );
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

    int server_fd = mqo_net_error( socket( AF_INET, SOCK_STREAM, IPPROTO_TCP ) );
    mqo_net_error( bind( server_fd, (struct sockaddr*)&addr, sizeof( addr ) ) );
    mqo_net_error( listen( server_fd, 5 ) ); 
    mqo_unblock_socket( server_fd );    

    //TODO: Create a server name.

    mqo_string server_name = mqo_string_fs( "tcp-server" );
    return mqo_make_listener( server_name, server_fd );
}

mqo_descr mqo_first_listening = NULL;

void mqo_poll_descr( mqo_descr descr ){
    static char buffer[ BUFSIZ ];
    
    mqo_value result;
    mqo_integer rs;
    mqo_type type;
    
    if( descr->type == MQO_LISTENER ){
        struct sockaddr_storage addr;
        unsigned long len = sizeof( addr );
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
                mqo_report_net_error( );
            }
        }else if( rs == 0 ){
            // POSIX specifies that a terminal read or recv has size 0.
            mqo_close( descr );
            return;
        }else{
            result = mqo_vf_string( mqo_string_fm( buffer, rs ) );
        }
    }
 
    mqo_resume( descr->monitor, result );
    mqo_stop_listening( descr );
}

int mqo_dispatch_monitors_once( ){
    //TODO: Currently, we rely on a blocking connect to guard against
    //      premature writing.  Ideally, we would actually monitor sockets
    //      that have not completed connection for WRITE.

    struct timeval *timeout;
    struct fd_set reads, errors;
    mqo_descr descr, next;
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
   
    descr = mqo_first_listening;
    while( descr ){
        next = descr->next;
#ifdef _WIN32
        if( descr->type == MQO_CONSOLE ){
            mqo_poll_descr( descr );   
        }else{
#endif
            fd = descr->fd;
            if( fd > maxfd ) maxfd = fd;
            FD_SET( fd, &reads );
            FD_SET( fd, &errors );
#ifdef _WIN32
        }
#endif
        descr = next;
    }
    
    if( maxfd >= 0 ){
        maxfd = select( maxfd + 1, &reads, NULL, &errors, timeout ); 

        descr = mqo_first_listening;
        while( descr ){
            next = descr->next;
#ifdef _WIN32
            if( descr->type != MQO_CONSOLE ){
#endif
                fd = descr->fd;
                if( FD_ISSET( fd, &reads ) || FD_ISSET( fd, &errors ) ){ 
                    mqo_poll_descr( descr );
                }
#ifdef _WIN32
            }
#endif
            descr = next;
        }
    }
}
int mqo_dispatch_monitors( ){
    while( mqo_first_listening ){
        mqo_dispatch_monitors_once( );
        if( mqo_first_process )return 1;
    }
    return 0;
}

void mqo_close( mqo_descr descr ){
    if( descr->closed )return;

    if( descr->monitor )mqo_resume( descr->monitor, mqo_vf_false() );
    mqo_stop_listening( descr );
    
    if( descr->type == MQO_CONSOLE )return;
    descr->closed = 1;
    mqo_os_error( close( descr->fd ) );
}

mqo_console mqo_the_console;

void mqo_init_net_subsystem( ){
#ifdef _WIN32
    WSADATA wsa;
    WSAStartup( 2, &wsa );
#else
    mqo_unblock_socket( STDIN_FILENO );
#endif
    mqo_the_console = mqo_make_console( mqo_string_fs( "console" ) );
}

