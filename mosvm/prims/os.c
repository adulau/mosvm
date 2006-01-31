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
#include <string.h>
#include <unistd.h>
#include <sys/param.h>
#include <errno.h>
#include <fcntl.h>

#if defined(_WIN32)||defined(__CYGWIN__)
    // Win32 doesn't supply this header -- we get our htonl and htons
    // from some nasty inline assembler elsewhere.
#else
#include <arpa/inet.h>
#endif

mqo_symbol mqo_es_fs;

MQO_BEGIN_PRIM( "file-open", file_open )
    REQ_STRING_ARG( path );
    REQ_STRING_ARG( flags );
    OPT_INTEGER_ARG( mode );
    NO_MORE_ARGS( )
    const char* fp = mqo_sf_string( flags );
    int flag = 0;
#if defined(_WIN32)||defined(__CYGWIN__)
    flag |= O_BINARY;
    // Let's not have any magic line ending conversions screwing up seek, 
    // tyvm.
#endif

    if( ! has_mode ){ mode = 0666; };

    while( *fp ){
        switch( *(fp++) ){
        case 'r':
            flag |= O_RDONLY;
            break;
        case 'w':
            flag |= O_WRONLY;
            break;
        case 'c':
            flag |= O_CREAT;
        case 'a':
            flag |= O_APPEND;
            break;
#ifdef _WIN32
    //The core WIN32 headers don't provide NONBLOCK or SYNC.
        case 'n':
        case 's':
            break;
#else
        case 'n':
            flag |= O_NONBLOCK;
            break;
        case 's':
            flag |= O_SYNC;
            break;
#if defined( __CYGWIN__ )||defined( linux )||defined( _WIN32 )
        //Neither Linux or Cygwin support implied locking.
        case 'l':
        case 'L':
            break;
#else
        case 'l':
            flag |= O_SHLOCK;
            break;
        case 'L':
            flag |= O_EXLOCK;
            break;
#endif
#endif
#if defined( __CYGWIN__ )||defined( _WIN32 )||defined(linux)
        //Additionally, Cygwin doesn't do NOFOLLOW since windows lacks
        //symlinks.
        case 'f': 
            break;
#else
        case 'f':
            flag |= O_NOFOLLOW;
            break;
#endif
        case 'e':
            flag |= O_EXCL;
            break;
        default:
            mqo_errf( 
                mqo_es_vm, "sx", "Unrecognized flag encountered in flags.", 
                v_flags
            );    
        }
    }
    int fd = open( mqo_sf_string( path ), flag, mode );
    if( fd == -1 ){
        mqo_errf( mqo_es_fs, "sxx", strerror( errno ), v_path, v_flags );
    }else{
        MQO_RESULT( mqo_vf_descr( mqo_make_descr( path, fd ) ) );
    }
    MQO_RESULT( mqo_vf_true( ) );
MQO_END_PRIM( file_open )

MQO_BEGIN_PRIM( "descr-path", descr_path )
    REQ_DESCR_ARG( descr );
    NO_MORE_ARGS( )

    MQO_RESULT( mqo_vf_string( descr->path ) );
MQO_END_PRIM( descr_path )

MQO_BEGIN_PRIM( "descr-fd", descr_fd )
    REQ_DESCR_ARG( descr );
    NO_MORE_ARGS( )

    MQO_RESULT( mqo_vf_integer( descr->fd ) );
MQO_END_PRIM( descr_fd )

MQO_BEGIN_PRIM( "descr?", descrq )
    REQ_VALUE_ARG( value );
    NO_MORE_ARGS( )

    MQO_RESULT( mqo_vf_boolean( mqo_is_descr( value ) ) );
MQO_END_PRIM( descrq )

MQO_BEGIN_PRIM( "read-descr", read_descr )
    static char buffer[ BUFSIZ ];
    REQ_DESCR_ARG( descr );
    NO_MORE_ARGS( )

    mqo_integer count = read( descr->fd, buffer, BUFSIZ );
    
    if( count == -1 ){
        mqo_errf( mqo_es_fs, "sx", strerror( errno ), v_descr );
        MQO_NO_RESULT( );
    }else{
        MQO_RESULT( mqo_vf_string( mqo_string_fm( buffer, count ) ) );
    }
MQO_END_PRIM( read_descr )

MQO_BEGIN_PRIM( "read-descr-all", read_descr_all )
    REQ_DESCR_ARG( descr );
    NO_MORE_ARGS( )
    
    mqo_integer ofs = lseek( descr->fd, 0, SEEK_CUR );
    mqo_integer len = lseek( descr->fd, 0, SEEK_END ) - ofs;
    lseek( descr->fd, ofs, SEEK_SET );
    
    mqo_string data = mqo_make_string( len );
    len = read( descr->fd, data->data, len );
    
    if( len == -1 ){
        mqo_errf( mqo_es_fs, "sx", strerror( errno ), v_descr );
        GC_free( data );
        MQO_NO_RESULT( );
    }else{
        data->data[len] = 0;
        data->length = len;
        MQO_RESULT( mqo_vf_string( data ) );
    }
MQO_END_PRIM( read_descr_all )

MQO_BEGIN_PRIM( "close-descr", close_descr )
    REQ_DESCR_ARG( descr );
    NO_MORE_ARGS( );
    
    if( close( descr->fd ) == -1 );
    descr->closed = 1;

    MQO_NO_RESULT( );
MQO_END_PRIM( close_descr )

MQO_BEGIN_PRIM( "descr-closed?", descr_closedq )
    REQ_DESCR_ARG( descr );
    NO_MORE_ARGS( );
    MQO_RESULT( mqo_vf_boolean( descr->closed ) ); 
MQO_END_PRIM( descr_closedq )

MQO_BEGIN_PRIM( "write-descr", write_descr )
    REQ_DESCR_ARG( descr );
    REQ_STRING_ARG( data );
    NO_MORE_ARGS( )
    
    ssize_t result = write( 
        descr->fd, mqo_sf_string( data ), mqo_string_length( data )
    );

    if( result == -1 ){
        mqo_errf( mqo_es_fs, "sxi", strerror( errno ), v_descr, descr->fd );
    };

    MQO_NO_RESULT( )
MQO_END_PRIM( write_descr )

MQO_BEGIN_PRIM( "write-descr-byte", write_descr_byte )
    REQ_DESCR_ARG( descr );
    REQ_INTEGER_ARG( byte );
    NO_MORE_ARGS( )
    
    mqo_byte data = byte;
    ssize_t result = write( descr->fd, &data, 1 ); 

    if( result == -1 ){
        mqo_errf( mqo_es_fs, "sx", strerror( errno ), v_descr );
    };

    MQO_NO_RESULT( )
MQO_END_PRIM( write_descr_byte )

MQO_BEGIN_PRIM( "write-descr-word", write_descr_word )
    REQ_DESCR_ARG( descr );
    REQ_INTEGER_ARG( word );
    NO_MORE_ARGS( )
    
    mqo_word data = htons( word );
    ssize_t result = write( descr->fd, &data, 2 ); 

    if( result == -1 ){
        mqo_errf( mqo_es_fs, "sx", strerror( errno ), v_descr );
    };

    MQO_NO_RESULT( )
MQO_END_PRIM( write_descr_word )

MQO_BEGIN_PRIM( "write-descr-quad", write_descr_quad )
    REQ_DESCR_ARG( descr );
    REQ_INTEGER_ARG( quad );
    NO_MORE_ARGS( )
    
    mqo_long data = htonl( quad );
    ssize_t result = write( descr->fd, &data, 4 ); 

    if( result == -1 ){
        mqo_errf( mqo_es_fs, "sx", strerror( errno ), v_descr );
    };

    MQO_NO_RESULT( )
MQO_END_PRIM( write_descr_quad )

MQO_BEGIN_PRIM( "skip-file", skip_file )
    REQ_DESCR_ARG( descr );
    REQ_INTEGER_ARG( offset );
    NO_MORE_ARGS( );

    offset = lseek( descr->fd, offset, SEEK_CUR );

    if( offset == -1 ){
        mqo_errf( mqo_es_fs, "sx", strerror( errno ), v_descr );
    }

    MQO_RESULT( mqo_vf_integer( offset ) );
MQO_END_PRIM( skip_file )

MQO_BEGIN_PRIM( "pos-file", pos_file )
    REQ_DESCR_ARG( descr );
    NO_MORE_ARGS( );

    mqo_integer offset = lseek( descr->fd, 0, SEEK_CUR );

    if( offset == -1 ){
        mqo_errf( mqo_es_fs, "sx", strerror( errno ), v_descr );
    }

    MQO_RESULT( mqo_vf_integer( offset ) );
MQO_END_PRIM( pos_file )

MQO_BEGIN_PRIM( "seek-file", seek_file )
    REQ_DESCR_ARG( descr );
    REQ_INTEGER_ARG( offset );
    NO_MORE_ARGS( );
    
    if( offset < 0 ){
        offset = lseek( descr->fd, offset + 1, SEEK_END );
    }else{
        offset = lseek( descr->fd, offset, SEEK_SET );
    };

    if( offset == -1 ){
        mqo_errf( mqo_es_fs, "sx", strerror( errno ), v_descr );
    };

    MQO_RESULT( mqo_vf_integer( offset ) );
MQO_END_PRIM( seek_file )

void mqo_bind_os_prims( ){
    mqo_es_fs = mqo_symbol_fs( "fs" );

#if defined(_WIN32)||defined(__CYGWIN__)
    mqo_symbol_fs( "*path-sep*" )->value = 
        mqo_vf_string( mqo_string_fs( "\\" ) );
    mqo_symbol_fs( "*line-sep*" )->value = 
        mqo_vf_string( mqo_string_fs( "\r\n" ) );
#else
    mqo_symbol_fs( "*path-sep*" )->value = 
        mqo_vf_string( mqo_string_fs( "/" ) );
    mqo_symbol_fs( "*line-sep*" )->value = 
        mqo_vf_string( mqo_string_fs( "\n" ) );
#endif
    mqo_symbol_fs( "*stdin*" )->value =
        mqo_vf_descr( 
          mqo_make_descr( mqo_string_fs( "<stdin>" ), STDIN_FILENO ) );
    mqo_symbol_fs( "*stdout*" )->value =
        mqo_vf_descr( 
            mqo_make_descr( mqo_string_fs( "<stdout>" ), STDOUT_FILENO ) );
    mqo_symbol_fs( "*stderr*" )->value =
        mqo_vf_descr( 
            mqo_make_descr( mqo_string_fs( "<stderr>" ), STDERR_FILENO ) );

    MQO_BIND_PRIM( file_open );
    MQO_BIND_PRIM( close_descr );
    MQO_BIND_PRIM( descr_closedq );
    MQO_BIND_PRIM( descrq );
    MQO_BIND_PRIM( descr_path );
    MQO_BIND_PRIM( descr_fd );
    MQO_BIND_PRIM( read_descr );
    MQO_BIND_PRIM( read_descr_all );
    MQO_BIND_PRIM( write_descr );
    MQO_BIND_PRIM( write_descr_byte );
    MQO_BIND_PRIM( write_descr_word );
    MQO_BIND_PRIM( write_descr_quad );
    MQO_BIND_PRIM( skip_file );
    MQO_BIND_PRIM( seek_file );
    MQO_BIND_PRIM( pos_file );
    //TODO: Add is-file-descr?, is-input-descr?, is-output-descr? and 
    //      is-tcp-descr? prims.
}

