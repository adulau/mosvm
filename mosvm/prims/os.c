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
        MQO_RESULT( mqo_vf_file( mqo_make_file( path, fd ) ) );
    }
    MQO_RESULT( mqo_vf_true( ) );
MQO_END_PRIM( file_open )

MQO_BEGIN_PRIM( "open-stdin", open_stdin )
    NO_MORE_ARGS( );
    MQO_RESULT( mqo_vf_file( mqo_make_file( mqo_string_fs( "<stdin>" ), STDIN_FILENO ) ) );
MQO_END_PRIM( open_stdin )

MQO_BEGIN_PRIM( "open-stdout", open_stdout )
    NO_MORE_ARGS( );
    MQO_RESULT( mqo_vf_file( mqo_make_file( mqo_string_fs( "<stdout>" ), STDOUT_FILENO ) ) );
MQO_END_PRIM( open_stdout )

MQO_BEGIN_PRIM( "open-stderr", open_stderr )
    NO_MORE_ARGS( );
    MQO_RESULT( mqo_vf_file( mqo_make_file( mqo_string_fs( "<stderr>" ), STDERR_FILENO ) ) );
MQO_END_PRIM( open_stderr )

MQO_BEGIN_PRIM( "file-path", file_path )
    REQ_FILE_ARG( file );
    NO_MORE_ARGS( )

    MQO_RESULT( mqo_vf_string( file->path ) );
MQO_END_PRIM( file_path )

MQO_BEGIN_PRIM( "file-fd", file_fd )
    REQ_FILE_ARG( file );
    NO_MORE_ARGS( )

    MQO_RESULT( mqo_vf_integer( file->fd ) );
MQO_END_PRIM( file_fd )

MQO_BEGIN_PRIM( "file?", fileq )
    REQ_VALUE_ARG( value );
    NO_MORE_ARGS( )

    MQO_RESULT( mqo_vf_boolean( mqo_is_file( value ) ) );
MQO_END_PRIM( fileq )

MQO_BEGIN_PRIM( "file-read", file_read )
    REQ_FILE_ARG( file );
    REQ_INTEGER_ARG( count );
    NO_MORE_ARGS( )

    mqo_string data = mqo_make_string( count );
    count = read( file->fd, data->data, count );
    
    if( count == -1 ){
        mqo_errf( mqo_es_fs, "sx", strerror( errno ), v_file );
        GC_free( data );
        MQO_NO_RESULT( );
    }else{
        data = GC_realloc( data, sizeof( struct mqo_string_data ) + count + 1 );
        data->data[count] = 0;
        data->length = count;
        MQO_RESULT( mqo_vf_string( data ) );
    }
MQO_END_PRIM( file_read )

MQO_BEGIN_PRIM( "file-read-all", file_read_all )
    REQ_FILE_ARG( file );
    NO_MORE_ARGS( )
    
    mqo_integer ofs = lseek( file->fd, 0, SEEK_CUR );
    mqo_integer len = lseek( file->fd, 0, SEEK_END ) - ofs;
    lseek( file->fd, ofs, SEEK_SET );
    
    mqo_string data = mqo_make_string( len );
    len = read( file->fd, data->data, len );
    
    if( len == -1 ){
        mqo_errf( mqo_es_fs, "sx", strerror( errno ), v_file );
        GC_free( data );
        MQO_NO_RESULT( );
    }else{
        data->data[len] = 0;
        data->length = len;
        MQO_RESULT( mqo_vf_string( data ) );
    }
MQO_END_PRIM( file_read_all )

MQO_BEGIN_PRIM( "file-close", file_close )
    REQ_FILE_ARG( file );
    NO_MORE_ARGS( );
    
    if( close( file->fd ) == -1 );
    file->closed = 1;

    MQO_NO_RESULT( );
MQO_END_PRIM( file_close )

MQO_BEGIN_PRIM( "file-write", file_write )
    REQ_FILE_ARG( file );
    REQ_STRING_ARG( data );
    NO_MORE_ARGS( )
    
    ssize_t result = write( 
        file->fd, mqo_sf_string( data ), mqo_string_length( data )
    );

    if( result == -1 ){
        mqo_errf( mqo_es_fs, "sx", strerror( errno ), v_file );
    };
    
    //TODO: Process failed writes.

    MQO_NO_RESULT( )
MQO_END_PRIM( file_write )

MQO_BEGIN_PRIM( "file-write-byte", file_write_byte )
    REQ_FILE_ARG( file );
    REQ_INTEGER_ARG( byte );
    NO_MORE_ARGS( )
    
    mqo_byte data = byte;
    ssize_t result = write( file->fd, &data, 1 ); 

    if( result == -1 ){
        mqo_errf( mqo_es_fs, "sx", strerror( errno ), v_file );
    };
    
    //TODO: Process failed writes.

    MQO_NO_RESULT( )
MQO_END_PRIM( file_write_byte )

MQO_BEGIN_PRIM( "file-write-word", file_write_word )
    REQ_FILE_ARG( file );
    REQ_INTEGER_ARG( word );
    NO_MORE_ARGS( )
    
    mqo_word data = htons( word );
    ssize_t result = write( file->fd, &data, 2 ); 

    if( result == -1 ){
        mqo_errf( mqo_es_fs, "sx", strerror( errno ), v_file );
    };
    
    //TODO: Process failed writes.

    MQO_NO_RESULT( )
MQO_END_PRIM( file_write_word )

MQO_BEGIN_PRIM( "file-write-quad", file_write_quad )
    REQ_FILE_ARG( file );
    REQ_INTEGER_ARG( quad );
    NO_MORE_ARGS( )
    
    mqo_long data = htonl( quad );
    ssize_t result = write( file->fd, &data, 4 ); 

    if( result == -1 ){
        mqo_errf( mqo_es_fs, "sx", strerror( errno ), v_file );
    };
    
    //TODO: Process failed writes.

    MQO_NO_RESULT( )
MQO_END_PRIM( file_write_quad )

MQO_BEGIN_PRIM( "file-skip", file_skip )
    REQ_FILE_ARG( file );
    REQ_INTEGER_ARG( offset );
    NO_MORE_ARGS( );

    offset = lseek( file->fd, offset, SEEK_CUR );

    if( offset == -1 ){
        mqo_errf( mqo_es_fs, "sx", strerror( errno ), v_file );
    }

    MQO_RESULT( mqo_vf_integer( offset ) );
MQO_END_PRIM( file_skip )

MQO_BEGIN_PRIM( "file-pos", file_pos )
    REQ_FILE_ARG( file );
    NO_MORE_ARGS( );

    mqo_integer offset = lseek( file->fd, 0, SEEK_CUR );

    if( offset == -1 ){
        mqo_errf( mqo_es_fs, "sx", strerror( errno ), v_file );
    }

    MQO_RESULT( mqo_vf_integer( offset ) );
MQO_END_PRIM( file_pos )

MQO_BEGIN_PRIM( "file-seek", file_seek )
    REQ_FILE_ARG( file );
    REQ_INTEGER_ARG( offset );
    NO_MORE_ARGS( );
    
    if( offset < 0 ){
        offset = lseek( file->fd, offset + 1, SEEK_END );
    }else{
        offset = lseek( file->fd, offset, SEEK_SET );
    };

    if( offset == -1 ){
        mqo_errf( mqo_es_fs, "sx", strerror( errno ), v_file );
    };

    MQO_RESULT( mqo_vf_integer( offset ) );
MQO_END_PRIM( file_seek )

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
    MQO_BIND_PRIM( file_open );
    MQO_BIND_PRIM( file_close );
    MQO_BIND_PRIM( fileq );
    MQO_BIND_PRIM( file_path );
    MQO_BIND_PRIM( file_fd );
    MQO_BIND_PRIM( file_read );
    MQO_BIND_PRIM( file_read_all );
    MQO_BIND_PRIM( file_write );
    MQO_BIND_PRIM( file_write_byte );
    MQO_BIND_PRIM( file_write_word );
    MQO_BIND_PRIM( file_write_quad );
    MQO_BIND_PRIM( file_skip );
    MQO_BIND_PRIM( file_seek );
    MQO_BIND_PRIM( file_pos );
    MQO_BIND_PRIM( open_stdin );
    MQO_BIND_PRIM( open_stdout );
    MQO_BIND_PRIM( open_stderr );
}

