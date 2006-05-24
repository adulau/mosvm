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

mqo_symbol mqo_cmd_close = NULL;


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

#if defined( _WIN32 )||defined( __CYGWIN__ )
    unsigned long unblocking = 1;
    mqo_net_error( ioctlsocket( s->fd, FIONBIO, &unblocking ) );
#else
    mqo_net_error( fcntl( s->fd, F_SETFL, O_NONBLOCK ) );
#endif

    if( mqo_last_stream ){
        mqo_last_stream->next = s;
    }else{
        mqo_first_stream = s;    
        mqo_enable_process( mqo_stream_monitor );
    };
    
    s->prev = mqo_last_stream;
    mqo_last_stream = s;
    
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
    };
    
    l->prev = mqo_last_listener;
    mqo_last_listener = l;
    
    return l;
}

void mqo_kill_stream( mqo_stream stream ){
    mqo_stream prev = stream->prev;
    mqo_stream next = stream->next;

    if( prev ){
        prev->next = next;
    }else if( mqo_first_stream == stream ){
        mqo_first_stream = next;
    }

    if( next ){
        next->prev = prev;
    }else if( mqo_last_stream == stream ){
        mqo_last_stream = prev;
    }

    if( ( mqo_first_stream == NULL )&&( NULL  == mqo_first_listener ) ){
        mqo_disable_process( mqo_stream_monitor );
    }
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
   
    int rs = recv( stream->fd, mqo_string_tail( buf ), 1024, 0 );

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
        close( stream->fd );
        mqo_channel_append( stream->evt, mqo_vf_symbol( mqo_cmd_close ) );
        mqo_kill_stream( stream );
    }else if( rs == 0 ){
        mqo_channel_append( stream->evt, mqo_vf_symbol( mqo_cmd_close ) );
        mqo_kill_stream( stream );
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

    if( mqo_is_symbol( cmd ) && ( mqo_symbol_fv( cmd ) == mqo_cmd_close ) ){
        mqo_read_channel( stream->cmd );
        close( stream->fd );
        mqo_kill_stream( stream );
    }else if( mqo_is_string( cmd ) ){
        mqo_string buf = mqo_string_fv( cmd );
        int rs = send( stream->fd, mqo_string_head( buf ), 
                        mqo_string_length( buf ), 0 );
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
    mqo_stream stream;
    mqo_listener listener;
    struct fd_set reads, errors, writes;
    int fd, maxfd = 0;
    
    FD_ZERO( &reads );
    FD_ZERO( &writes );
    FD_ZERO( &errors );

    for( stream = mqo_first_stream; stream; stream = stream->next ){
        fd = stream->fd;
        if( fd > maxfd ) maxfd = fd;
        FD_SET( stream->fd, &reads );
        if( ! mqo_channel_empty( stream->cmd ) ){
            FD_SET( stream->fd, &writes );
        }
        FD_SET( stream->fd, &errors );
    }
    
    for( listener = mqo_first_listener; listener; listener = listener->next ){
        fd = listener->fd;
        if( fd > maxfd ) maxfd = fd;
        FD_SET( listener->fd, &reads );
        FD_SET( listener->fd, &errors );
    }
    
    if( ! maxfd ){
        mqo_disable_process( mqo_stream_monitor );
        return;
    }

    struct timeval timeout = { 0, 0 };
    select( maxfd + 1,
            &reads, &writes, &errors,
            //&timeout );
            mqo_can_be_only_one( ) ? (struct timeval*) NULL 
                                   : &timeout  );
    
    for( stream = mqo_first_stream; stream; stream = stream->next ){
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
    mqo_kill_stream( stream );
    mqo_objfree( stream );
}
MQO_GENERIC_SHOW( stream );
MQO_GENERIC_COMPARE( stream );
MQO_C_TYPE( stream );

void mqo_trace_listener( mqo_listener listener ){
    mqo_grey_obj( (mqo_object) listener->conns );
    
    //TODO: This means that any open stream persists until it
    //      crashes.  Ideally, we should be killing them when there
    //      are no more references to the stream object..

    mqo_grey_obj( (mqo_object) listener->prev );
    mqo_grey_obj( (mqo_object) listener->next );
}
MQO_GENERIC_SHOW( listener );
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

MQO_BEGIN_PRIM( "resolve-addr", resolve_addr )
    REQ_STRING_ARG( addr )
    NO_REST_ARGS( )

    RESULT( mqo_vf_integer( mqo_resolve( addr ) ) );
MQO_END_PRIM( resolve_addr )


void mqo_init_stream_subsystem( ){
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

    MQO_I_TYPE( stream );
    MQO_I_TYPE( listener );
    
    MQO_BIND_PRIM( tcp_listen );
    MQO_BIND_PRIM( tcp_connect );
    MQO_BIND_PRIM( resolve_addr );

    mqo_stream_monitor = mqo_make_process( 
        (mqo_proc_fn) mqo_activate_netmon, 
        (mqo_proc_fn) mqo_deactivate_netmon, 
        mqo_vf_null( ) 
    );
    
    mqo_cmd_close = mqo_symbol_fs( "close" );
    mqo_root_obj( (mqo_object) mqo_stream_monitor );
}
