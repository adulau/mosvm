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
#include <stdlib.h>

#if defined(_WIN32)||defined(__CYGWIN__)
#include <sys/time.h>
#include <winsock2.h>
#define MQO_EWOULDBLOCK WSAEWOULDBLOCK
#else
#ifdef LINUX
// Linux sometimes conforms to POSIX, but only when
// it conflicts with BSD.
#include <sys/select.h>
#endif
#include <arpa/inet.h>
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

void mqo_report_net_error( ){
#if defined(_WIN32)||defined(__CYGWIN__)
    mqo_errf( mqo_es_os, "s", strerror( WSAGetLastError() ) );
#else
    mqo_errf( mqo_es_os, "s", strerror( errno ) );
#endif
}

void mqo_report_host_error( ){
#if defined(_WIN32)||defined(__CYGWIN__)
    mqo_errf( mqo_es_os, "s", strerror( WSAGetLastError() ) );
#else
    mqo_errf( mqo_es_os, "s", hstrerror( h_errno ) );
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

void mqo_start_dispatching( mqo_descr descr ){
    if( mqo_first_dispatching )mqo_first_dispatching->prev = descr;
    descr->prev = NULL;
    descr->next = mqo_first_dispatching;
    descr->dispatch = 1;
    mqo_first_dispatching = descr;
}

void mqo_stop_dispatching( mqo_descr descr ){
    if( descr->dispatch ){
        if( descr->prev ){
            descr->prev->next = descr->next;
        }else{
            mqo_first_dispatching = descr->next;
        }

        if( descr->next )descr->next->prev = descr->prev;
        descr->next = descr->prev = NULL;
        descr->dispatch = 0;
    };
}

//TODO: Test - write continuously to a port -- close the port remotely.

int mqo_in_dispatch( mqo_descr descr ){ return descr->dispatch; };
int mqo_is_reading( mqo_descr descr ){ 
    return mqo_in_dispatch( descr )&& descr->read_mt;
}
int mqo_is_writing( mqo_descr descr ){
    return ( mqo_in_dispatch( descr )
             &&( descr->write_data )
             &&( ! mqo_buffer_empty( descr->write_data ) ) );
}
int mqo_is_listening( mqo_descr descr ){
    return ( mqo_in_dispatch( descr )
             &&( descr->type == MQO_LISTENER ) );
}

void mqo_write_descr( mqo_descr descr, const void* data, mqo_integer datalen ){
    mqo_integer written = 0;

    if( descr->type == MQO_CONSOLE ){
        while( written < datalen ){
            written += mqo_os_error( write( STDOUT_FILENO, data, 
                                            datalen ) );     
        }
    }else if( descr->type == MQO_SOCKET ){
        mqo_start_writing( descr, data, datalen );
    }else if( descr->type == MQO_LISTENER ){
        mqo_errf( mqo_es_vm, "s", "cannot write to listener descriptors" );
    }else{
        while( written < datalen ){
            written += mqo_os_error( write( descr->fd, data, datalen ) );     
        }        
    }
}

mqo_value mqo_start_reading( mqo_descr descr, mqo_process monitor, 
                             mqo_read_mt read_mt 
){
    mqo_value r = mqo_make_void( );

    if( ( descr->type == MQO_LISTENER ) ){
    }else if( descr->read_data == NULL ){
        descr->read_data = mqo_make_buffer( BUFSIZ );
    }else if( ! mqo_buffer_empty( descr->read_data ) ){
        r = read_mt( descr );
    }

    if( mqo_is_void( r ) && monitor ){
        assert( monitor->reading == NULL );

        descr->read_mt = read_mt;
        descr->monitor = monitor;
        monitor->reading = descr;

        if( ! mqo_in_dispatch( descr ) )mqo_start_dispatching( descr );
    };

    return r;
}

void mqo_start_writing( mqo_descr descr, const char* data, 
                        mqo_integer datalen 
){
    assert( descr->type != MQO_LISTENER );
    
    if( descr->write_data == NULL ){
        descr->write_data = mqo_make_buffer( BUFSIZ );
    }

    mqo_expand_buffer( descr->write_data, datalen );
    mqo_write_buffer( descr->write_data, data, datalen );

    if( ! mqo_in_dispatch( descr ) )mqo_start_dispatching( descr );
}

void mqo_stop_reading( mqo_descr descr ){
    // Should only be called via mqo_resume, and the halt prim.
    descr->read_mt = NULL;
    if( descr->monitor ){
        descr->monitor->reading = NULL;
        descr->monitor = NULL;
    }
    if( ! mqo_is_writing( descr ) )mqo_stop_dispatching( descr );
}
void mqo_stop_writing( mqo_descr descr ){
    // Should only be called via write_event
    if( ! mqo_is_reading( descr ) )mqo_stop_dispatching( descr );
}

int mqo_parse_dotted_quad( mqo_string quad, mqo_integer* addr ){
    mqo_byte* bytes = (mqo_byte*)addr;

    int ct = 0;
    const char* ptr = mqo_sf_string( quad );
    const char* tail = ptr + mqo_string_length( quad );
    char* next; 

    while(( ct < 4 )&&( ptr != tail )){
        mqo_long x = strtoul( ptr, &next, 10 );  
        if( ptr == next ) break; // *ptr wasn't a digit
        if(( x > 255 )||( x < 0 )) return 0; // Not a byte.
        bytes[ ct ++ ] = (mqo_byte)x; // Otherwise, we've got one more byte.
        ptr = next;              // Advance our base-pointer.
        if( *ptr != '.' ) break; // A dot indicates we've got another quad
        ptr ++;
    }
    
    if( ct != 4 ) return 0;        // Not enough bytes were found.
    if( ptr != tail ) return 0; // Not all of the string was parsed.

    *addr = ntohl( *addr );
    return 1;
}

mqo_integer mqo_resolve( mqo_string name ){
    mqo_integer addr;

    if( ! mqo_parse_dotted_quad( name, &addr ) ){
        struct hostent *entry = gethostbyname( mqo_sf_string( name ) );
        if( !entry ){ 
            mqo_report_host_error( );
            //TODO }else if( entry->h_addrtype != ... ){
            //TODO: Signal an error.
        }else if( entry->h_length != 4 ){
            //TODO: Signal an error.
        }else{
            //TODO: A better version of resolve would return a list of
            //      addresses..
            addr = ntohl( *(mqo_integer*)(entry->h_addr) );
        }
    }

    return addr;
}

mqo_socket mqo_connect_tcp( mqo_integer address, mqo_integer port ){
    static struct sockaddr_in addr;

    memset( &addr, 0, sizeof( addr ) );
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl( address );
    addr.sin_port = htons( port );

    int client_fd = mqo_net_error( socket( AF_INET, SOCK_STREAM, 
                                           IPPROTO_TCP ) );

    mqo_net_error( connect( client_fd, (struct sockaddr*)&addr, 
                            sizeof( addr ) ) );

    //TODO: Create a client name.

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

    int server_fd = mqo_net_error( socket( AF_INET, SOCK_STREAM, 
                                           IPPROTO_TCP ) );
    mqo_net_error( bind( server_fd, (struct sockaddr*)&addr, sizeof( addr ) ) );
    mqo_net_error( listen( server_fd, 5 ) ); 
    mqo_unblock_socket( server_fd );    

    //TODO: Create a server name.

    mqo_string server_name = mqo_string_fs( "tcp-server" );
    return mqo_make_listener( server_name, server_fd );
}

mqo_descr mqo_first_dispatching = NULL;

void mqo_write_event( mqo_descr descr ){
    mqo_buffer buffer = descr->write_data;
    const char* data = mqo_buffer_head( buffer );
    mqo_word datalen = mqo_buffer_length( buffer );

    if( descr->type == MQO_SOCKET ){
        datalen = mqo_net_error( send( descr->fd, data, datalen, 0 ) );
    }else{
        datalen = mqo_net_error( write( descr->fd, data, datalen ) );
    }

    mqo_skip_buffer( buffer, datalen );

    /* Death is slow, but death is sure.. */
    if( mqo_buffer_empty( buffer ) )mqo_stop_writing( descr );
}
void mqo_read_descr_event( mqo_descr descr ){
    static char data[ BUFSIZ ];
    mqo_integer datalen;

    if( descr->type == MQO_SOCKET ){
        datalen = recv( descr->fd, data, BUFSIZ, 0 );
    }else{
        datalen = read( descr->fd, data, BUFSIZ );
    }

    if( datalen >= 0 ){
        if( datalen == 0 ){
            descr->closed = 1;
        }else{
            mqo_expand_buffer( descr->read_data, datalen );
            mqo_write_buffer( descr->read_data, data, datalen );
        };

        if( descr->monitor ){ 
            mqo_value r = descr->read_mt( descr ); 

            if( ! mqo_is_void( r ) ){
                mqo_resume( descr->monitor, r );
            }
        }else{ 
            mqo_stop_dispatching( descr );
        };
    }else if( errno == MQO_EWOULDBLOCK ){
        // WIN32 and other OS's do not guarantee that a read event means that
        // the socket can actually be read -- EAGAIN / EWOULDBLOCK in this
        // context means "Gee, our select implementation sucks."
        return;
    }else if( descr->type == MQO_SOCKET ){
        mqo_report_net_error( );
    }else{
        mqo_report_os_error( );
    }
}
void mqo_read_listener_event( mqo_descr descr ){
    struct sockaddr_storage addr;
#ifdef _WIN32
    unsigned long len = sizeof( addr );
#else
    socklen_t len = sizeof( addr );
#endif
    int fd = accept( descr->fd, (struct sockaddr*)&addr, &len );

    if( fd == -1 ){
        if( errno == MQO_EWOULDBLOCK )return;
        // As in mqo_read_descr_event, select sometimes liiiiiies.
    }else{
        mqo_unblock_socket( fd );
        mqo_string name = mqo_string_fs( "tcp-incoming" );
        mqo_resume( descr->monitor, 
                    mqo_vf_socket( mqo_make_socket( name, fd ) ) );
    }
}
void mqo_read_event( mqo_descr descr ){
    if( descr->type == MQO_LISTENER ){
        mqo_read_listener_event( descr );
    }else{
        mqo_read_descr_event( descr );
    }
}

int mqo_dispatch_monitors_once( ){
    //TODO: Currently, we rely on a blocking connect to guard against
    //      premature writing.  Ideally, we would actually monitor sockets
    //      that have not completed connection for WRITE.

    struct timeval *timeout;
#ifdef LINUX
    //Because, hey, why should we use the same typedef as every other
    //OS..
    fd_set reads, writes, errors;
#else
    struct fd_set reads, writes, errors;
#endif
    mqo_descr descr, next;
    int fd, maxfd;

    FD_ZERO( &reads );
    FD_ZERO( &writes );
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
    
    descr = mqo_first_dispatching;
    while( descr ){
        next = descr->next;
#ifdef _WIN32
        if( descr->type == MQO_CONSOLE ){
            mqo_read_event( descr );
        }else{
#endif
            fd = descr->fd;
            if( fd > maxfd ) maxfd = fd;

            if( mqo_is_reading( descr ) || mqo_is_listening( descr ) ){
                FD_SET( fd, &reads );
                FD_SET( fd, &errors );
            };

            if( mqo_is_writing( descr ) ){
                FD_SET( fd, &writes );
            };
#ifdef _WIN32
        }
#endif
        descr = next;
    }
    
    if( maxfd >= 0 ){
        maxfd = select( maxfd + 1, &reads, &writes, &errors, timeout ); 

        descr = mqo_first_dispatching;
        while( descr ){
            next = descr->next;
#ifdef _WIN32
            if( descr->type != MQO_CONSOLE ){
#endif
                fd = descr->fd;

                if( FD_ISSET( fd, &reads ) || FD_ISSET( fd, &errors ) ){ 
                    mqo_read_event( descr );
                };

                if( FD_ISSET( fd, &writes ) ){
                    mqo_write_event( descr );
                };
#ifdef _WIN32
            }
#endif
            descr = next;
        }
    }
}

int mqo_dispatch_monitors( ){
    while( mqo_first_dispatching ){
        mqo_dispatch_monitors_once( );
        if( mqo_first_process )return 1;
    }
    return 0;
}

void mqo_close( mqo_descr descr ){
    if( descr->closed )return;
    if( descr->type == MQO_CONSOLE )return;

    descr->closed = 1;

    if( descr->dispatch ){
        mqo_stop_dispatching( descr );
        
        if( descr->monitor ){
            mqo_value r = descr->read_mt( descr );
            if( ! mqo_is_void( r ) ){ mqo_resume( descr->monitor, r ); }
        }
    }

    descr->dispatch = 0;
    descr->monitor = NULL;

#ifdef _WIN32
    if(( descr->type == MQO_SOCKET )||( descr->type == MQO_LISTENER )){
        mqo_net_error( closesocket( descr->fd ) );
        return;
    }
#endif    
    mqo_os_error( close( descr->fd ) );
}

mqo_console mqo_the_console;

void mqo_show_descr( mqo_descr f, mqo_word* ct ){
    mqo_write( f->closed ? "[closed " : "[" );
    switch( f->type ){
    case MQO_CONSOLE:
        mqo_write( "console" );
        break;
    case MQO_SOCKET:
        mqo_write( "socket" );
        break;
        //TODO: Add the address information.
    case MQO_LISTENER:
        mqo_write( "listener" );
        break;
        //TODO: Add the listening port.
    case MQO_FILE:
        mqo_write( "file " );
    default:
        if( f->name ){
            mqo_writestr( f->name );
        }else{
            mqo_write( "descr" );
        }
    }
    mqo_write( "]" );
}
void mqo_init_net_subsystem( ){
#ifdef _WIN32
    WSADATA wsa;
    WSAStartup( 2, &wsa );
#else
    // Commented out, because BSDs will make STDOUT nonblocking if you make
    // STDIN nonblocking.  This totally fucks with many I/O operations.
    //
    // If it turns out that this breaks other UNIXen, which is possible since
    // select on a blocking socket is sort of an edge case, we should unblock
    // then reblock during our poll loop.
    //
    // Ain't C fun, kids?
    //
    // mqo_unblock_socket( STDIN_FILENO );
#endif
    mqo_the_console = mqo_make_console( mqo_string_fs( "console" ) );
}

mqo_boolean mqo_is_descr( mqo_value value ){
    mqo_type type = mqo_value_type( value );
    if( type == mqo_file_type )return 1;
    if( type == mqo_socket_type )return 1;
    if( type == mqo_listener_type )return 1;
    if( type == mqo_console_type )return 1;
    return( type == mqo_descr_type );
}
mqo_descr mqo_descr_fv( mqo_value value ){
#ifndef NDEBUG
    mqo_type type = mqo_value_type( value );
    assert( ( type == mqo_file_type )
            || ( type == mqo_socket_type )
            || ( type == mqo_listener_type )
            || ( type == mqo_console_type )
            || ( type == mqo_descr_type ) 
    );
#endif
    return (mqo_descr)(value.data);
}
mqo_value mqo_vf_descr( mqo_descr descr ){
    mqo_type type;
    switch( descr->type ){
    case MQO_CONSOLE: type = mqo_console_type; break;
    case MQO_SOCKET:  type = mqo_socket_type; break;
    case MQO_LISTENER: type = mqo_listener_type; break;
    case MQO_FILE: type = mqo_file_type; break;
    default: type = mqo_descr_type; break;
    }
    return mqo_make_value( type, (mqo_integer)descr );
}
void mqo_descr_finalizer( void* ptr, void* cd ){
    if( ! ((mqo_descr)ptr)->closed )close( ((mqo_descr)ptr)->fd );
}
mqo_descr mqo_make_descr( mqo_string path, int fd, mqo_byte type ){
    mqo_descr f = MQO_ALLOC( mqo_descr, 0 );
    f->name = path;
    f->fd = fd;
    f->type = type;
    f->monitor = NULL;
    GC_register_finalizer( f, mqo_descr_finalizer, NULL, NULL, NULL );
    return f;
}
mqo_file mqo_make_file( mqo_string path, int fd ){
    return mqo_make_descr( path, fd, MQO_FILE );
}
mqo_socket mqo_make_socket( mqo_string path, int fd ){
    return mqo_make_descr( path, fd, MQO_SOCKET );
}
mqo_listener mqo_make_listener( mqo_string path, int fd ){
    return mqo_make_descr( path, fd, MQO_LISTENER );
}
mqo_console mqo_make_console( mqo_string path ){
    return mqo_make_descr( path, 0, MQO_CONSOLE );
}
mqo_value mqo_read_data_mt( mqo_descr descr ){
    mqo_integer datalen;
    char* data;

    if( mqo_buffer_empty( descr->read_data ) ){
        return descr->closed ? mqo_vf_false( )
                             : mqo_make_void( );
    }else if( descr->quantity ){
        if( mqo_buffer_length( descr->read_data ) < descr->quantity ){
            return mqo_make_void( );
        } 
        datalen = descr->quantity;
    }else{
        datalen = BUFSIZ;
    }

    data = mqo_read_buffer( descr->read_data, &datalen );
    return mqo_vf_string( mqo_string_fm( data, datalen ) );
}
mqo_value mqo_read_all_mt( mqo_descr descr ){
    if( ! descr->closed ){
        return mqo_make_void( );
    }else{
        mqo_integer datalen = 1 << 30;
        char *data = mqo_read_buffer( descr->read_data, &datalen );

        return mqo_vf_string( mqo_string_fm( data, datalen ) );
    }
}
mqo_value mqo_read_byte_mt( mqo_descr descr ){
    if( mqo_buffer_length( descr->read_data ) >= 1 ){
        mqo_integer datalen = 1;
        mqo_byte *data = mqo_read_buffer( descr->read_data, &datalen );
        return mqo_vf_integer( *data );
    }
    if( descr->closed )return mqo_vf_false( );
    return mqo_make_void( );
}

mqo_value mqo_read_word_mt( mqo_descr descr ){
    if( mqo_buffer_length( descr->read_data ) >= 2 ){
        mqo_integer datalen = 2;
        mqo_word *data = mqo_read_buffer( descr->read_data, &datalen );
        return mqo_vf_integer( ntohs( *data ) );
    }
    if( descr->closed )return mqo_vf_false( );
    return mqo_make_void( );
}

mqo_value mqo_read_line_mt( mqo_descr descr ){
    mqo_integer linelen;
    const char* line = mqo_read_line_buffer( descr->read_data, &linelen );
    if( line ){
        return mqo_vf_string( mqo_string_fm( line, linelen ) );
    }else if( descr->closed ){ 
        return mqo_read_all_mt( descr );
    }else{
        return mqo_make_void( );
    }
}

mqo_value mqo_read_quad_mt( mqo_descr descr ){
    if( mqo_buffer_length( descr->read_data ) >= 4 ){
        mqo_integer datalen = 4;
        mqo_long *data = mqo_read_buffer( descr->read_data, &datalen );
        return mqo_vf_integer( ntohl( *data ) );
    }
    if( descr->closed )return mqo_vf_false( );
    return mqo_make_void( );
}
