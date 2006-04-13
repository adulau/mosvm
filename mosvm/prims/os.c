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
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>

#if defined(_WIN32)||defined(__CYGWIN__)
    // Win32 doesn't supply this header -- we get our htonl and htons
    // from some nasty inline assembler elsewhere.
#else
#include <arpa/inet.h>
#include <sys/socket.h>
#endif

mqo_symbol mqo_es_fs;

MQO_BEGIN_PRIM( "resolve-addr", resolve_addr )
    REQ_STRING_ARG( addr )
    NO_MORE_ARGS( )
    
    MQO_RESULT( mqo_vf_integer( mqo_resolve( addr ) ) );
MQO_END_PRIM( resolve_addr )

MQO_BEGIN_PRIM( "open-file-descr", open_file_descr )
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
    
    int i, fl = mqo_string_length( flags );

    for( i = 0; i < fl; i++ ){
        switch( fp[i] ){
        case 'r':
            flag |= O_RDONLY;
            break;
        case 'w':
            flag |= O_WRONLY;
            break;
        case 'c':
            flag |= O_CREAT;
            break;
        case 'a':
            flag |= O_APPEND;
            break;
        case 't':
            flag |= O_TRUNC;
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
        case 0:
            break;
        default:
            mqo_errf( 
                mqo_es_vm, "sx", "unrecognized flag encountered in flags", 
                v_flags
            );    
        }
    }
    MQO_RESULT( mqo_vf_file( mqo_make_file( path, mqo_os_error( open( mqo_sf_string( path ), flag, mode ) ) ) ) );
MQO_END_PRIM( open_file_descr )

MQO_BEGIN_PRIM( "descr?", descrq )
    REQ_VALUE_ARG( value );
    NO_MORE_ARGS( )

    MQO_RESULT( mqo_vf_boolean( mqo_is_descr( value ) ) );
MQO_END_PRIM( descrq )

MQO_BEGIN_PRIM( "file-len", file_len )
    REQ_FILE_ARG( file );
    NO_MORE_ARGS( );
    
    mqo_integer pos = mqo_os_error( lseek( file->fd, 0, SEEK_CUR ) );
    mqo_integer len = mqo_os_error( lseek( file->fd, 0, SEEK_END ) );
    mqo_os_error( lseek( file->fd, pos, SEEK_SET ) );   

    MQO_RESULT( mqo_vf_integer( len ) );
MQO_END_PRIM( file_len )

//TODO: read-descr-byte
//TODO: read-descr-word
//TODO: read-descr-quad

void mqo_async_read( mqo_descr descr, mqo_read_mt read_mt ){
    mqo_value r = mqo_start_reading( descr, MQO_PP, read_mt );
    mqo_drop_ds( mqo_pop_int_ds() );

    mqo_return( );

    if( mqo_is_void( r ) ){
        MQO_SUSPEND( );
    }else{
        mqo_push_ds( r );
    };
}

MQO_BEGIN_PRIM( "read-descr", read_descr )
    REQ_DESCR_ARG( descr );
    OPT_VALUE_ARG( quantity );
    NO_MORE_ARGS( );

    int quantint;

    if( has_quantity && mqo_is_integer( quantity ) ){
        quantint = mqo_integer_fv( quantity );
        if(( 0 > quantint )||( quantint > BUFSIZ )){
            quantint = BUFSIZ;
        }
    }else{
        quantint = 0;
    }

    if( descr->closed ){
        MQO_RESULT( mqo_vf_false() );
    }else if( descr->type == MQO_FILE ){
        static char buffer[ BUFSIZ ];
        mqo_integer count = mqo_os_error( read( descr->fd, 
                                                buffer, 
                                                quantint ? quantint 
                                                         : BUFSIZ ) );
        if( count == 0 ){
            MQO_RESULT( mqo_vf_false( ) );
        }else{
            MQO_RESULT( mqo_vf_string( mqo_string_fm( buffer, count ) ) );
        }
    }else if( mqo_is_reading( descr ) ){
        mqo_errf( mqo_es_vm, "s", 
                  "another object is waiting on descriptor" );
    }else{
        descr->quantity = quantint;
        mqo_async_read( descr, mqo_read_data_mt );
        return;
    }
MQO_END_PRIM( read_descr )

MQO_BEGIN_PRIM( "read-descr-line", read_descr_line )
    REQ_DESCR_ARG( descr );
    NO_MORE_ARGS( );
    
    if( descr->type != MQO_SOCKET){
        //TODO: Implement for files.
        mqo_errf( mqo_es_args, "s", "read-descr-line only accepts sockets" );
    }else if( mqo_is_reading( descr ) ){
        mqo_errf( mqo_es_vm, "s", 
                  "another object is waiting on descriptor" );
    }else{
        mqo_async_read( descr, mqo_read_line_mt );
        return;
    }
MQO_END_PRIM( read_descr_line )

MQO_BEGIN_PRIM( "read-descr-all", read_descr_all )
    REQ_ANY_DESCR_ARG( descr );
    NO_MORE_ARGS( )
   
    if( descr->type == MQO_FILE ){
        mqo_integer ofs = mqo_os_error( lseek( descr->fd, 0, SEEK_CUR ) );
        mqo_integer len = mqo_os_error( lseek( descr->fd, 0, SEEK_END ) - ofs );
        mqo_os_error( lseek( descr->fd, ofs, SEEK_SET ) );
    
        if( len == 0 ){
            MQO_RESULT( mqo_vf_false( ) );
        };
        mqo_string data = mqo_make_string( len );
        len = mqo_os_error( read( descr->fd, data->data, len ) );
    
        data->data[len] = 0;
        data->length = len;
        MQO_RESULT( mqo_vf_string( data ) );
    }else if( descr->type == MQO_SOCKET ){
        mqo_async_read( descr, mqo_read_all_mt );
        return;
    }else{
        mqo_errf( mqo_es_os, "s", 
                  "only sockets and files permit read-descr-all" );

        //TODO: We should support MQO_CONSOLE for this.
    };
MQO_END_PRIM( read_descr_all )

MQO_BEGIN_PRIM( "close-descr", close_descr )
    REQ_ANY_DESCR_ARG( descr );
    NO_MORE_ARGS( );
    
    mqo_close( descr );
    MQO_NO_RESULT( );
MQO_END_PRIM( close_descr )

MQO_BEGIN_PRIM( "descr-closed?", descr_closedq )
    REQ_ANY_DESCR_ARG( descr );
    NO_MORE_ARGS( );
    MQO_RESULT( mqo_vf_boolean( descr->closed ) ); 
MQO_END_PRIM( descr_closedq )

//TODO Fix for new buffered writes.

MQO_BEGIN_PRIM( "write-descr", write_descr )
    REQ_ANY_DESCR_ARG( descr );
    REQ_STRING_ARG( data );
    NO_MORE_ARGS( )
   
    mqo_write_descr( descr, mqo_sf_string( data ), mqo_string_length( data ) );
    
    MQO_NO_RESULT( )
MQO_END_PRIM( write_descr )

MQO_BEGIN_PRIM( "write-descr-byte", write_descr_byte )
    REQ_ANY_DESCR_ARG( descr );
    REQ_BYTE_ARG( byte );
    NO_MORE_ARGS( )
    
    mqo_byte data = byte;
    mqo_write_descr( descr, &data, 1 );

    MQO_NO_RESULT( )
MQO_END_PRIM( write_descr_byte )

MQO_BEGIN_PRIM( "write-descr-word", write_descr_word )
    REQ_ANY_DESCR_ARG( descr );
    REQ_WORD_ARG( word );
    NO_MORE_ARGS( )
    
    mqo_word data = htons( word );
    mqo_write_descr( descr, &data, 2 );

    MQO_NO_RESULT( )
MQO_END_PRIM( write_descr_word )

MQO_BEGIN_PRIM( "write-descr-quad", write_descr_quad )
    REQ_ANY_DESCR_ARG( descr );
    REQ_QUAD_ARG( quad );
    NO_MORE_ARGS( )
    
    mqo_long data = htonl( quad );
    mqo_write_descr( descr, &data, 4 );  

    MQO_NO_RESULT( )
MQO_END_PRIM( write_descr_quad )

MQO_BEGIN_PRIM( "file-skip", file_skip )
    REQ_FILE_ARG( descr );
    REQ_INTEGER_ARG( offset );
    NO_MORE_ARGS( );

    offset = mqo_os_error( lseek( descr->fd, offset, SEEK_CUR ) );

    MQO_RESULT( mqo_vf_integer( offset ) );
MQO_END_PRIM( file_skip )

MQO_BEGIN_PRIM( "file-pos", file_pos )
    REQ_FILE_ARG( descr );
    NO_MORE_ARGS( );

    mqo_integer offset = mqo_os_error( lseek( descr->fd, 0, SEEK_CUR ) );

    MQO_RESULT( mqo_vf_integer( offset ) );
MQO_END_PRIM( file_pos )

MQO_BEGIN_PRIM( "file-seek", file_seek )
    REQ_FILE_ARG( descr );
    REQ_INTEGER_ARG( offset );
    NO_MORE_ARGS( );
    
    if( offset < 0 ){
        offset = lseek( descr->fd, offset + 1, SEEK_END );
    }else{
        offset = lseek( descr->fd, offset, SEEK_SET );
    };

    mqo_os_error( offset );

    MQO_RESULT( mqo_vf_integer( offset ) );
MQO_END_PRIM( file_seek )

//TODO: We really need a time type.
MQO_BEGIN_PRIM( "path-mtime", path_mtime )
    REQ_STRING_ARG( path )
    NO_MORE_ARGS( );

    struct stat s;

    mqo_os_error( stat( mqo_sf_string( path ), &s ) );

#if defined( LINUX )||defined( _WIN32 )
    time_t mtime = s.st_mtime;
#else
    time_t mtime = s.st_mtimespec.tv_sec;
#endif

    MQO_RESULT( mqo_vf_integer( mtime ) );
MQO_END_PRIM( path_mtime )

MQO_BEGIN_PRIM( "path-exists?", path_existsq )
    REQ_STRING_ARG( path )
    NO_MORE_ARGS( );

    struct stat s;
    
    MQO_RESULT( mqo_vf_boolean( stat( mqo_sf_string( path ), &s ) == 0 ) );
MQO_END_PRIM( path_existsq )

MQO_BEGIN_PRIM( "file-path?", file_pathq )
    REQ_STRING_ARG( path )
    NO_MORE_ARGS( );

    struct stat s;

    int r = stat( mqo_sf_string( path ), &s );

    if( r == 0 ){
        MQO_RESULT( mqo_vf_boolean( S_ISREG( s.st_mode ) ) );
    }else{
        MQO_RESULT( mqo_vf_false( ) );
    }
MQO_END_PRIM( file_pathq )

void mqo_bind_os_prims( ){
    MQO_BEGIN_PRIM_BINDS( );

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
    mqo_symbol_fs( "*console*" )->value = mqo_vf_console( mqo_the_console );

    MQO_BIND_PRIM( open_file_descr );
    MQO_BIND_PRIM( close_descr );
    MQO_BIND_PRIM( descr_closedq );
    MQO_BIND_PRIM( descrq );
    MQO_BIND_PRIM( read_descr );
    MQO_BIND_PRIM( read_descr_all );
    MQO_BIND_PRIM( read_descr_line );
    MQO_BIND_PRIM( write_descr );
    MQO_BIND_PRIM( write_descr_byte );
    MQO_BIND_PRIM( write_descr_word );
    MQO_BIND_PRIM( write_descr_quad );
    MQO_BIND_PRIM( file_skip );
    MQO_BIND_PRIM( file_seek );
    MQO_BIND_PRIM( file_pos );
    MQO_BIND_PRIM( file_len );

    MQO_BIND_PRIM( path_mtime );
    MQO_BIND_PRIM( path_existsq );
    MQO_BIND_PRIM( file_pathq );

    MQO_BIND_PRIM( resolve_addr );

    //TODO: Halt needs to know if a process is monitoring a port, so it can
    //      clear that.
}

