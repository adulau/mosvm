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
#include <setjmp.h>
#include <stdarg.h>

#include <string.h>
#include <stdlib.h>

#if defined(_WIN32)||defined(__CYGWIN__)
#include <sys/time.h>
#include <winsock2.h>
#include <errno.h>
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
#include <sys/ioctl.h>
#define MQO_EWOULDBLOCK EWOULDBLOCK
#endif

mqo_process mqo_stream_monitor = NULL;

mqo_listener mqo_first_listener = NULL;
mqo_listener mqo_last_listener = NULL; 

mqo_stream mqo_first_stream = NULL;
mqo_stream mqo_last_stream = NULL; 

mqo_symbol mqo_ss_fail;
mqo_symbol mqo_ss_close;
mqo_symbol mqo_ss_connect;

void mqo_stream_error( mqo_stream stream, int code ){
    mqo_channel_append( 
        stream->evt, 
        mqo_vf_list( 
            mqo_listf( 4, 
                       mqo_vf_symbol( mqo_ss_fail ),  
                       mqo_vf_string( mqo_string_fs( strerror( code ) ) ),
                       stream, 
                       mqo_vf_integer( code ) ) ) );
}

void mqo_stream_net_error( mqo_stream stream ){
#ifndef _WIN32 
    mqo_stream_error( stream, errno );
#else
    mqo_stream_error( stream, WSAGetLastError() );
#endif
}

void mqo_report_host_error( ){
#if defined(_WIN32)||defined(__CYGWIN__)
    mqo_errf( mqo_es_vm, "s", strerror( WSAGetLastError() ) );
#else
    mqo_errf( mqo_es_vm, "s", hstrerror( h_errno ) );
#endif
}

void mqo_report_net_error( ){
#if defined(_WIN32)||defined(__CYGWIN__)
    mqo_errf( mqo_es_vm, "s", strerror( WSAGetLastError() ) );
#else
    if( errno == EINPROGRESS )return;
    mqo_errf( mqo_es_vm, "s", strerror( errno ) );
#endif
}

void mqo_signal_net_error( ){
}

mqo_integer mqo_net_error( mqo_integer k ){
    if( k == -1 )mqo_report_net_error( );
    return k;
}

mqo_boolean mqo_is_stream_writing( mqo_stream s ){
    return ! mqo_channel_empty( s->cmd );
}

mqo_boolean mqo_is_stream_reading( mqo_stream s ){
    return (mqo_boolean) s->evt->monitor;
}

int mqo_parse_dotted_quad( mqo_string quad, mqo_integer* addr ){
    mqo_byte* bytes = (mqo_byte*)addr;

    int ct = 0;
    const char* ptr = mqo_sf_string( quad );
    const char* tail = ptr + mqo_string_length( quad );
    char* next; 

    while(( ct < 4 )&&( ptr != tail )){
        mqo_quad x = strtoul( ptr, &next, 10 );  
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

mqo_stream mqo_make_stream( mqo_integer fd ){
    mqo_stream s = MQO_OBJALLOC( stream );
    s->fd = fd;
    s->cmd = mqo_make_channel( );
    s->cmd->source = mqo_vf_stream( s );
    s->evt = mqo_make_channel( );
    s->evt->source = mqo_vf_stream( s );
    s->prev = mqo_last_stream;
    s->state = MQO_READY;
#if defined( _WIN32 )||defined( __CYGWIN__ )
    unsigned long unblocking = 1;
    mqo_net_error( ioctlsocket( s->fd, FIONBIO, &unblocking ) );
#else
    // mqo_net_error( fcntl( fd, F_SETFL, O_NONBLOCK ) );
    unsigned long unblocking = 1;
    if( fd )mqo_net_error( ioctl( fd, FIONBIO, &unblocking ) );
#endif

    return s;
}

mqo_listener mqo_make_listener( mqo_integer fd ){
    mqo_listener l = MQO_OBJALLOC( listener );
    l->fd = fd;
    l->conns = mqo_make_channel( );
    l->prev = mqo_last_listener;
    
    if( mqo_last_listener ){
        mqo_last_listener->next = l;
    }else{
        mqo_first_listener = l;    
        mqo_enable_process( mqo_stream_monitor );
    };
    
    l->prev = mqo_last_listener;
    mqo_last_listener = l;
    
    return l;
}

void mqo_enable_stream( mqo_stream stream ){
    if( stream->enabled ) return;
    stream->enabled = 1;

    mqo_stream prev = mqo_last_stream;

    if( prev ){
        stream->prev = prev;
        prev->next = stream;
    }else{
        mqo_first_stream = stream;
        mqo_enable_process( mqo_stream_monitor );
    }

    mqo_last_stream = stream;
}

void mqo_disable_stream( mqo_stream stream ){
    if( ! stream->enabled ) return;
    stream->enabled = 0;

    mqo_stream prev = stream->prev;
    mqo_stream next = stream->next;
    
    if( prev ){
        prev->next = next;
        stream->prev = NULL;
    }else if( mqo_first_stream == stream ){
        mqo_first_stream = next;
    }

    if( next ){
        next->prev = prev;
        stream->next = NULL;
    }else if( mqo_last_stream == stream ){
        mqo_last_stream = prev;
    }
}

void mqo_close_stream( mqo_stream stream ){
    mqo_disable_stream( stream );
    mqo_channel_append( stream->evt, mqo_vf_symbol( mqo_ss_close ) );
    stream->state = MQO_CLOSED;
#ifdef _WIN32
    // No non-socket streams on win32..
    closesocket( stream->fd );
#else
    close( stream->fd );
#endif
}

void mqo_stream_read_evt( mqo_stream stream ){
    mqo_string buf;
    mqo_boolean put;

    if( mqo_channel_empty( stream->evt ) ){
        put = 1;
        buf = mqo_make_string( 1024 );
    }else{
        put = 0;
        buf = mqo_string_fv( mqo_channel_tail( stream->evt ) );
    }

#ifdef _WIN32
    // No non-socket streams on win32..
    int rs = recv( stream->fd, mqo_string_tail( buf ), 1024, 0 );
#else
    int rs = stream->fd ? recv( stream->fd, mqo_string_tail( buf ), 1024, 0 )
                        : read( stream->fd, mqo_string_tail( buf ), 1024 );
#endif    

    if( rs > 0 ){
        mqo_string_wrote( buf, rs );
        if( put ){ mqo_channel_append( stream->evt, mqo_vf_string( buf ) ); }
    }else if( rs == -1 ){
#if defined(_WIN32)||defined(__CYGWIN__)
        // Lies.. Why does select lie to us so?
        if( WSAGetLastError() == EAGAIN )return;
#else
        // Lies.. Why does select lie to us so?
        if( errno == EAGAIN )return;
#endif
        
        mqo_stream_net_error( stream );
        
        // TODO: Assumption: all errors are fatal..
        mqo_close_stream( stream );
    }else if( rs == 0 ){
        mqo_close_stream( stream );
    }
}

void mqo_listener_read_evt( mqo_listener listener ){
    struct sockaddr_storage sa;
    int sl = sizeof( sa );

    int conn = accept( listener->fd, (struct sockaddr*)&sa, &sl );
    if( conn == -1 ){
        //TODO: We blissfully ignore errors during accept..
        //TODO: We do need to report the catastrophic event of EMFILE or ENFILE
    }else{
        mqo_channel_append( 
            listener->conns, mqo_vf_stream( mqo_make_stream( conn ) ) );
    }
}

int mqo_stream_send( mqo_stream stream, void* data, mqo_quad datalen ){
    int result;

#ifdef _WIN32
    //There are no non-socket streams on win32..
    result = send( stream->fd, data, datalen, 0 );
    if( result == -1 ) mqo_stream_net_error( stream );
#else
    if( stream->fd ){
        result = send( stream->fd, data, datalen, 0 );
        if( result == -1 ) mqo_stream_net_error( stream );
    }else{
        result = write( STDOUT_FILENO, data, datalen );
        if( result == -1 ) mqo_stream_error( stream, errno );
    };
#endif

    return result; 
}

void mqo_stream_write_evt( mqo_stream stream ){
    mqo_string buf;
    mqo_boolean put;

    if( stream->state == MQO_CONNECTING ){
        if( mqo_stream_send( stream, NULL, 0 ) == -1 ){
            mqo_close_stream( stream );
        }else{
            mqo_channel_append( stream->evt, mqo_vf_symbol( mqo_ss_connect ) );
            stream->state = MQO_READY;
        }
    };

    if( mqo_channel_empty( stream->cmd ) )return;

    mqo_value  cmd = mqo_read_channel( stream->cmd );
    
    if( cmd == (mqo_value)mqo_ss_close ){
        mqo_close_stream( stream );
    }else if( mqo_is_string( cmd ) ){
        mqo_string buf = mqo_string_fv( cmd );
        mqo_integer len = mqo_string_length( buf );
        if( len == 0 ){ return; };

        char* str = mqo_sf_string( buf );

        mqo_integer fd = stream->fd;
        
        int rs = mqo_stream_send( stream, str, len );

        if( rs > 0 ){
            if( len -= rs ){
                mqo_channel_prepend( 
                    stream->cmd, 
                    mqo_vf_string( mqo_string_fm( str + rs, len ) )
                );
            };
        }
    }else{
        mqo_channel_append( 
            stream->evt, 
            mqo_vf_list( 
                mqo_listf( 
                    4, 
                    mqo_vf_symbol( mqo_ss_fail ),  
                    mqo_string_fs( "streams only accept strings and 'close" ),
                    stream,
                    cmd 
                )
            )
        );
    }
}

void mqo_activate_netmon( mqo_process monitor, mqo_object context ){
    mqo_stream next, stream;
    mqo_listener listener;
#if defined( LINUX )
    fd_set reads, errors, writes;
#else
    struct fd_set reads, errors, writes;
#endif
    int fd, maxfd = 0;
    
    FD_ZERO( &reads );
    FD_ZERO( &writes );
    FD_ZERO( &errors );

    for( stream = mqo_first_stream; stream; stream = next ){
        // Okay.. Here we go:
        //     If a stream is in the active set, we know it's got to be
        //     open, and something recently tried to check its command or
        //     event channels.
        //
        //     That's worth a read -- just in case something looks again; but
        //     if nothing is actively watching this stream, it's not worth
        //     checking twice.
        //
        //     If the event channel is being actively monitored, or if there
        //     are commands, we will keep it in the active list.
        int use = 0;
        next = stream->next; fd = stream->fd;
       
        if( stream->state == MQO_CLOSED ){
            mqo_disable_stream( stream );
            continue;
        }else if( stream->state == MQO_CONNECTING ){
            FD_SET( fd, &errors );
            FD_SET( fd, &writes );
            use = 1;
        }else{
            if( mqo_is_stream_reading( stream ) ){
                FD_SET( fd, &reads );
                FD_SET( fd, &errors );
                use = 1;
            };
            if( mqo_is_stream_writing( stream ) ){
#ifndef _WIN32
                if( fd == STDIN_FILENO ) fd = STDOUT_FILENO;
#endif
                FD_SET( fd, &writes );
                use = 1;
            };
        }

        if( ! use ){
            mqo_disable_stream( stream );
        }else if( (++fd) > maxfd ) maxfd = fd;
    }
    
    for( listener = mqo_first_listener; listener; listener = listener->next ){
        fd = listener->fd;
        FD_SET( fd, &reads );
        FD_SET( fd, &errors );
        if( (++fd) > maxfd ) maxfd = fd;
    }
    
    if(!( mqo_first_stream || mqo_first_listener )){
        mqo_disable_process( mqo_stream_monitor );
        return;
    }
   
    struct timeval* timeout;

    if( mqo_can_be_only_one( ) ){
        timeout = NULL;
    }else if( mqo_vm_count ){
        struct timeval time = { 0, 0 };
        timeout = &time;
        //TODO: If timemon and netmon are alone, they will spin hot.
    }else{  
        //TODO: Must only be other monitors.. We'll throttle back to 1ms / tick
        struct timeval time = { 0, 1000 };
        timeout = &time;
    }
    
    select( maxfd,
            &reads, &writes, &errors,
            timeout );
   
    for( stream = mqo_first_stream; stream; stream = next ){
        next = stream->next;
        fd = stream->fd;
        if( FD_ISSET( fd, &reads ) || FD_ISSET( fd, &errors ) ){
            mqo_stream_read_evt( stream );
        };
#ifndef _WIN32
        fd = fd ? fd : STDOUT_FILENO;
#endif
        if( FD_ISSET( fd, &writes ) ){
            mqo_stream_write_evt( stream );
        };
    }
    
    for( listener = mqo_first_listener; listener; listener = listener->next ){
        fd = listener->fd;
        if( FD_ISSET( listener->fd, &reads ) 
         || FD_ISSET( listener->fd, &errors ) ){
            mqo_listener_read_evt( listener );
        };
    }
}

void mqo_deactivate_netmon( mqo_process monitor, mqo_object context ){}

void mqo_trace_stream( mqo_stream stream ){
    mqo_grey_obj( (mqo_object) stream->cmd );
    mqo_grey_obj( (mqo_object) stream->evt );

    //TODO: This means that any open stream persists until it
    //      crashes.  Ideally, we should be killing them when there
    //      are no more references to the stream object..

    mqo_grey_obj( (mqo_object) stream->prev );
    mqo_grey_obj( (mqo_object) stream->next );
}
void mqo_free_stream( mqo_stream stream ){
    mqo_objfree( stream );
}
MQO_GENERIC_FORMAT( stream );
MQO_GENERIC_COMPARE( stream );
MQO_C_TYPE( stream );

void mqo_trace_listener( mqo_listener listener ){
    mqo_grey_obj( (mqo_object) listener->conns );
    
    mqo_grey_obj( (mqo_object) listener->prev );
    mqo_grey_obj( (mqo_object) listener->next );
}
MQO_GENERIC_FORMAT( listener );
MQO_GENERIC_COMPARE( listener );
MQO_GENERIC_FREE( listener );
//TODO: This should never be used -- but we should be killing, here.
MQO_C_TYPE( listener );

void mqo_trace_network( ){
    mqo_stream stream;

    for( stream = mqo_first_stream; stream; stream = stream->next ){
        mqo_grey_obj( (mqo_object) stream );
    }
   
    mqo_listener listener;

    for( listener = mqo_first_listener; listener; listener = listener->next ){
        mqo_grey_obj( (mqo_object) listener );
    }
}

MQO_BEGIN_PRIM( "tcp-listen", tcp_listen )
    REQ_INTEGER_ARG( portno );
    NO_REST_ARGS( );

    static struct sockaddr_in addr;

    memset( &addr, 0, sizeof( addr ) );
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl( INADDR_ANY );
    addr.sin_port = htons( portno );

    int server_fd = mqo_net_error( socket( AF_INET, SOCK_STREAM,
                                           IPPROTO_TCP ) );
    mqo_net_error( bind( server_fd, (struct sockaddr*)&addr, sizeof( addr ) ) );
    mqo_net_error( listen( server_fd, 5 ) );

#if defined( _WIN32 )||defined( __CYGWIN__ )
    unsigned long unblocking = 1;
    mqo_net_error( ioctlsocket( server_fd, FIONBIO, &unblocking ) );
#else
    // mqo_net_error( fcntl( server_fd, F_SETFL, O_NONBLOCK ) );
    unsigned long unblocking = 1;
    mqo_net_error( ioctl( server_fd, FIONBIO, &unblocking ) );
#endif

    //TODO: Create a server name.

    LISTENER_RESULT( mqo_make_listener( server_fd ) );
MQO_END_PRIM( tcp_listen )

MQO_BEGIN_PRIM( "tcp-connect", tcp_connect )
    REQ_ANY_ARG( address );
    REQ_INTEGER_ARG( portno );
    NO_REST_ARGS( );
    
    mqo_integer addint;

    if( mqo_is_integer( address ) ){
        addint = mqo_integer_fv( address );
    }else if( mqo_is_string( address ) ){
        addint = mqo_resolve( mqo_string_fv( address ) );
    }else{  
        mqo_errf( mqo_es_vm, "sx",
                  "expected a string or integer for address", address );
    }   
    
    static struct sockaddr_in addr; 
 
    memset( &addr, 0, sizeof( addr ) );
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl( addint );
    addr.sin_port = htons( portno );

    int fd = mqo_net_error( socket( AF_INET, SOCK_STREAM, IPPROTO_TCP ) );

#if defined( _WIN32 )||defined( __CYGWIN__ )
    unsigned long unblocking = 1;
    mqo_net_error( ioctlsocket( fd, FIONBIO, &unblocking ) );
#else
    // mqo_net_error( fcntl( fd, F_SETFL, O_NONBLOCK ) );
    unsigned long unblocking = 1;
    mqo_net_error( ioctl( fd, FIONBIO, &unblocking ) );
#endif

    mqo_net_error( connect( fd, (struct sockaddr*)&addr, sizeof( addr ) ) );
    
    mqo_stream s = mqo_make_stream( fd );
    s->state = MQO_CONNECTING;
    STREAM_RESULT( s );
MQO_END_PRIM( tcp_connect )

MQO_BEGIN_PRIM( "stream-closed?", stream_closedq )
    REST_ARGS( s );
    while ( s ){
        if( mqo_req_stream( mqo_car( s ) )->state == MQO_CLOSED )TRUE_RESULT( );
        s = mqo_req_list( mqo_cdr( s ) );
    }
    FALSE_RESULT( );
MQO_END_PRIM( stream_closedq );

MQO_BEGIN_PRIM( "resolve-addr", resolve_addr )
    REQ_STRING_ARG( addr )
    NO_REST_ARGS( )

    RESULT( mqo_vf_integer( mqo_resolve( addr ) ) );
MQO_END_PRIM( resolve_addr )

void mqo_init_stream_subsystem( ){
    MQO_I_TYPE( stream );
    MQO_I_TYPE( listener );
   
    mqo_ss_close = mqo_symbol_fs( "close" );
    mqo_ss_connect = mqo_symbol_fs( "connect" );
    mqo_ss_fail = mqo_symbol_fs( "fail" );

    MQO_BIND_PRIM( tcp_listen );
    MQO_BIND_PRIM( tcp_connect );
    MQO_BIND_PRIM( resolve_addr );
    MQO_BIND_PRIM( stream_closedq );

    mqo_stream_monitor = mqo_make_process( 
        (mqo_proc_fn) mqo_activate_netmon, 
        (mqo_proc_fn) mqo_deactivate_netmon, 
        mqo_vf_null( ) 
    );
    
    mqo_root_obj( (mqo_object) mqo_stream_monitor );

#ifdef _WIN32
    WSADATA wsa;
    WSAStartup( 2, &wsa );
    //TODO: fork a pipe.
#else
    // On Unix, *stdin* is a stream. On WIN32, *stdio* is a filthy word..
    mqo_stdio = mqo_make_stream( 0 );
    mqo_root_obj( (mqo_object) mqo_stdio );
    mqo_set_global( mqo_symbol_fs( "*stdio*"), mqo_vf_stream( mqo_stdio ) );
#endif
}

void mqo_set_stream_input( mqo_stream s, mqo_channel input ){
    mqo_enable_stream( s );
    s->cmd = input;
}
mqo_channel mqo_stream_input( mqo_stream s ){ mqo_enable_stream( s );
                                              return s->cmd; }
void mqo_set_stream_output( mqo_stream s, mqo_channel output ){
    mqo_enable_stream( s );
    s->evt = output;
}
mqo_channel mqo_stream_output( mqo_stream s ){ mqo_enable_stream( s );
                                               assert( s->evt );
                                              return s->evt; }

mqo_stream mqo_stdio;
