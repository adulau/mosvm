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

mqo_process mqo_stream_monitor;

mqo_listener mqo_first_listener = NULL;
mqo_listener mqo_last_listener = NULL; 

mqo_stream mqo_first_stream = NULL;
mqo_stream mqo_last_stream = NULL; 

mqo_symbol mqo_eof = NULL;

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
    mqo_errf( mqo_es_vm, "s", strerror( errno ) );
#endif
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
    s->evt = mqo_make_channel( );
    s->next = NULL;
    s->prev = mqo_last_stream;
    s->error = 0;
    s->closed = 0;
    s->enabled = 0;
#if defined( _WIN32 )||defined( __CYGWIN__ )
    unsigned long unblocking = 1;
    mqo_net_error( ioctlsocket( s->fd, FIONBIO, &unblocking ) );
#else
    if( fd ) mqo_net_error( fcntl( s->fd, F_SETFL, O_NONBLOCK ) );
#endif

    return s;
}

mqo_listener mqo_make_listener( mqo_integer fd ){
    mqo_listener l = MQO_OBJALLOC( listener );
    l->fd = fd;
    l->conns = mqo_make_channel( );
    l->next = NULL;
    l->prev = mqo_last_listener;
    l->error = 0;

    if( mqo_last_listener ){
        mqo_last_listener->next = l;
    }else{
        mqo_first_listener = l;    
        mqo_enable_process( mqo_stream_monitor );
        mqo_print( "Enabling stream monitor for listener.\n" );
    };
    
    l->prev = mqo_last_listener;
    mqo_last_listener = l;
    
    return l;
}

void mqo_enable_stream( mqo_stream stream ){
    if( stream->enabled ) return;
    if( stream->closed ) return;
    stream->enabled = 1;

    mqo_stream prev = mqo_last_stream;

    if( prev ){
        stream->prev = prev;
        prev->next = stream;
    }else{
        mqo_first_stream = stream;
        mqo_enable_process( mqo_stream_monitor );
        mqo_print( "Enabling stream monitor for stream.\n" );
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

    if( ( mqo_first_stream == NULL )&&( NULL  == mqo_first_listener ) ){
        mqo_disable_process( mqo_stream_monitor );
    }
}

void mqo_close_stream( mqo_stream stream ){
    mqo_disable_stream( stream );
    if( stream->closed )return;
    mqo_close_channel( stream->evt );
    mqo_close_channel( stream->cmd );
    stream->closed = 1;
    close( stream->fd );
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
        mqo_string_expand( buf, 1024 );
    }
    
    int rs = stream->fd ? recv( stream->fd, mqo_string_tail( buf ), 1024, 0 )
                        : read( stream->fd, mqo_string_tail( buf ), 1024 );
    

    if( rs > 0 ){
        mqo_string_wrote( buf, rs );
        if( put ){ mqo_channel_append( stream->evt, mqo_vf_string( buf ) ); }
    }else if( rs == -1 ){
#if defined(_WIN32)||defined(__CYGWIN__)
        int errno = WSAGetLastError();
#endif
        // Lies.. Why does select lie to us so?
        if( errno == EAGAIN )return;

        stream->error = errno;
        
        // No patience for badly behaved connections..
        mqo_close_stream( stream );
    }else if( rs == 0 ){
        mqo_close_stream( stream );
    }
}

void mqo_listener_read_evt( mqo_listener listener ){
    struct sockaddr_storage sa;
    socklen_t sl = sizeof( sa );

    int conn = accept( listener->fd, (struct sockaddr*)&sa, &sl );
    if( conn == -1 ){
        //TODO: We blissfully ignore errors during accept..
        //TODO: We do need to report the catastrophic event of EMFILE or ENFILE
    }else{
        mqo_channel_append( 
            listener->conns, mqo_vf_stream( mqo_make_stream( conn ) ) );
    }
}

void mqo_stream_write_evt( mqo_stream stream ){
    mqo_string buf;
    mqo_boolean put;

    mqo_value  cmd = mqo_channel_head( stream->cmd );

    if( mqo_is_symbol( cmd ) && ( mqo_symbol_fv( cmd ) == mqo_eof ) ){
        mqo_read_channel( stream->cmd );
        mqo_close_stream( stream );
    }else if( mqo_is_string( cmd ) ){
        mqo_string buf = mqo_string_fv( cmd );
        int rs = stream->fd ? send( stream->fd, mqo_string_head( buf ), 
                                    mqo_string_length( buf ), 0 )
                            : write( stream->fd, mqo_string_head( buf ), 
                                     mqo_string_length( buf ) );
        if( rs > 0 ){
            mqo_string_skip( buf, rs );
            if( mqo_string_empty( buf ) ){
                mqo_read_channel( stream->cmd );
            }
        }else{
#if defined(_WIN32)||defined(__CYGWIN__)
        int errno = WSAGetLastError();
#endif
            stream->error = errno;
        }
    }else{
        mqo_errf( mqo_es_vm, "sx", "bad write command", cmd );
    }
}

void mqo_activate_netmon( mqo_process monitor, mqo_object context ){
    mqo_stream next, stream;
    mqo_listener listener;
    struct fd_set reads, errors, writes;
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

        next = stream->next; fd = stream->fd;
        
        int use = 0;
        
        if( mqo_is_stream_reading( stream ) ){
            mqo_print( "Stream is reading.\n" );
            use = 1;
        };

        FD_SET( fd, &reads );
        FD_SET( fd, &errors );

        if( mqo_is_stream_writing( stream ) ){
            mqo_print( "Stream is writing.\n" );
            fd = fd ? fd : STDOUT_FILENO;
            FD_SET( fd, &writes );
            use = 1;
        };

        if( fd > maxfd ) maxfd = fd;

        if( ! use ){
            mqo_print( "Stream is not in use.\n" );
            mqo_disable_stream( stream );
        }
    }
    
    for( listener = mqo_first_listener; listener; listener = listener->next ){
        fd = listener->fd;
        if( fd > maxfd ) maxfd = fd;
        FD_SET( fd, &reads );
        FD_SET( fd, &errors );
    }
   
    if(!( mqo_first_stream || mqo_first_listener )){
        mqo_print( "Disabling stream monitor for disuse.\n" );
        mqo_disable_process( mqo_stream_monitor );
        return;
    };

    struct timeval timeout = { 0, 0 };
    select( maxfd + 1,
            &reads, &writes, &errors,
            //&timeout );
            mqo_can_be_only_one( ) ? (struct timeval*) NULL 
                                   : &timeout  );
   
    for( stream = mqo_first_stream; stream; stream = next ){
        next = stream->next;
        fd = stream->fd;
        if( fd > maxfd ) maxfd = fd;
        if( FD_ISSET( stream->fd, &reads ) || FD_ISSET( stream->fd, &errors ) ){
            mqo_stream_read_evt( stream );
        };
        if( FD_ISSET( stream->fd, &writes ) ){
            mqo_stream_write_evt( stream );
        };
    }
    for( listener = mqo_first_listener; listener; listener = listener->next ){
        fd = listener->fd;
        if( fd > maxfd ) maxfd = fd;
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
    mqo_net_error( fcntl( server_fd, F_SETFL, O_NONBLOCK ) );
#endif

    //TODO: Create a server name.

    LISTENER_RESULT( mqo_make_listener( server_fd ) );
MQO_END_PRIM( tcp_listen )

MQO_BEGIN_PRIM( "tcp-connect", tcp_connect )
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
    mqo_net_error( fcntl( server_fd, F_SETFL, O_NONBLOCK ) );
#endif

    //TODO: Create a server name.

    LISTENER_RESULT( mqo_make_listener( server_fd ) );
MQO_END_PRIM( tcp_connect )

MQO_BEGIN_PRIM( "stream-closed?", stream_closedq )
    REST_ARGS( s );
    while ( s ){
        if( mqo_req_stream( mqo_car( s ) )->closed ) TRUE_RESULT( );
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
    
    MQO_BIND_PRIM( tcp_listen );
    MQO_BIND_PRIM( tcp_connect );
    MQO_BIND_PRIM( resolve_addr );
    MQO_BIND_PRIM( stream_closedq );

    mqo_stream_monitor = mqo_make_process( 
        (mqo_proc_fn) mqo_activate_netmon, 
        (mqo_proc_fn) mqo_deactivate_netmon, 
        mqo_vf_null( ) 
    );
    
    mqo_eof = mqo_symbol_fs( "eof" );
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
    s->evt = input;
}
mqo_channel mqo_stream_input( mqo_stream s ){ mqo_enable_stream( s );
                                              return s->evt; }
void mqo_set_stream_output( mqo_stream s, mqo_channel output ){
    mqo_enable_stream( s );
    s->cmd = output;
}
mqo_channel mqo_stream_output( mqo_stream s ){ mqo_enable_stream( s );
                                              return s->cmd; }
//TODO: Spam eof to the evt monitor every time someone tries to read a closed
//      channel.

mqo_stream mqo_stdio;

