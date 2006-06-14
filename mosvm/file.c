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
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <ctype.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>

mqo_file mqo_make_file( mqo_string path, int fd ){
    mqo_file file = MQO_OBJALLOC( file );
    file->path = path;
    file->fd = fd;
    return file;
}
void mqo_trace_file( mqo_file file ){
    mqo_grey_obj( (mqo_object) file->path );
}
void mqo_free_file( mqo_file file ){
    if( ! file->closed )close( file->fd );
    mqo_objfree( file );
}
void mqo_format_file( mqo_string buf, mqo_file file ){
    mqo_format_begin( buf, file );
    mqo_string_append_cs( buf, file->closed ? " closed" : " open" );
    if( file->path ){
        mqo_string_append_byte( buf, ' ' );
        mqo_string_append_str( buf, file->path );
    };
    mqo_format_end( buf );
}
MQO_GENERIC_COMPARE( file );
int mqo_os_error( int code ){
    if( code == -1 ){
        mqo_errf( mqo_es_vm, "si", strerror( errno ), errno );
    };
    return code;
}
mqo_string mqo_read_file( mqo_file file, mqo_quad max ){
    char buf[1024];
    mqo_string data = mqo_make_string( 1024 );
    mqo_quad total = 0;

    while( total < max ){
        mqo_quad amt = max - total;
        if( amt > 1024 ) amt = 1024;
       
        // mqo_printf( "sin", "MQO_READ_FILE: amt: ", amt );
        mqo_integer r = mqo_os_error( read( file->fd, buf, amt ) );
        if( ! r )break; // End of file..
        total += r;
        mqo_string_append( data, buf, r );
    }
    
    return data;
}
void mqo_write_file( mqo_file file, const void* data, mqo_integer datalen ){
    mqo_integer written = 0;
    while( written < datalen ){
        written += mqo_os_error( write( file->fd, data, datalen ) );     
    }        
}
void mqo_close_file( mqo_file file ){
    mqo_os_error( close( file->fd ) ); 
    file->closed = 1;
}
mqo_file mqo_open_file( const char* path, const char* flags, mqo_integer mode ){
    int flag = 0;
#if defined(_WIN32)||defined(__CYGWIN__)
    flag |= O_BINARY;
    // Let's not have any magic line ending conversions screwing up seek, 
    // tyvm.
#endif
    while( *flags ){
        switch( *(flags++) ){
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
                mqo_es_vm, "ss", "unrecognized flag encountered in flags", 
                flags
            );    
        };
    };

    return mqo_make_file( 
        mqo_string_fs( path ), 
        mqo_os_error( open( path, flag, mode ) ) 
    );
}
MQO_BEGIN_PRIM( "open-file", open_file )
    REQ_STRING_ARG( path );
    REQ_STRING_ARG( flags );
    OPT_INTEGER_ARG( mode );
    NO_REST_ARGS( )
    const char* fp = mqo_sf_string( flags );

    int i, fl = mqo_string_length( flags );
    
    FILE_RESULT( mqo_open_file( mqo_sf_string( path ), mqo_sf_string( flags ), 
                                has_mode ? mode : 0600 ) );
MQO_END_PRIM( open_file )

MQO_BEGIN_PRIM( "file-len", file_len )
    REQ_FILE_ARG( file );
    NO_REST_ARGS( );
    
    mqo_integer pos = mqo_os_error( lseek( file->fd, 0, SEEK_CUR ) );
    mqo_integer len = mqo_os_error( lseek( file->fd, 0, SEEK_END ) );
    mqo_os_error( lseek( file->fd, pos, SEEK_SET ) );   

    RESULT( mqo_vf_integer( len ) );
MQO_END_PRIM( file_len )

MQO_BEGIN_PRIM( "read-file", read_file )
    REQ_FILE_ARG( file );
    OPT_INTEGER_ARG( quantity );
    NO_REST_ARGS( );

    if( ! has_quantity )quantity = MQO_MAX_IMM; 
    // mqo_printf( "sisxn", "READ-FILE, quantity: ", quantity, " file: ", file );
    mqo_string data = mqo_read_file( file, quantity );
    mqo_value result;

    if( quantity && (! mqo_string_length( data ) ) ){
        result = mqo_vf_false( );
    }else{
        result = mqo_vf_string( data );
    }
    
    RESULT( result );
MQO_END_PRIM( read_file )

MQO_BEGIN_PRIM( "close-file", close_file )
    REQ_FILE_ARG( file );
    NO_REST_ARGS( );
    
    mqo_close_file( file );

    NO_RESULT( );
MQO_END_PRIM( close_file )

MQO_BEGIN_PRIM( "closed-file?", closed_fileq )
    REQ_FILE_ARG( file );
    NO_REST_ARGS( );
    RESULT( mqo_vf_boolean( file->closed ) ); 
MQO_END_PRIM( closed_fileq )

MQO_BEGIN_PRIM( "write-file", write_file )
    REQ_FILE_ARG( file );
    REQ_STRING_ARG( data );
    NO_REST_ARGS( )
   
    mqo_write_file( file, mqo_sf_string( data ), mqo_string_length( data ) );
    
    NO_RESULT( )
MQO_END_PRIM( write_file )

MQO_BEGIN_PRIM( "file-skip", file_skip )
    REQ_FILE_ARG( file );
    REQ_INTEGER_ARG( offset );
    NO_REST_ARGS( );

    offset = mqo_os_error( lseek( file->fd, offset, SEEK_CUR ) );

    RESULT( mqo_vf_integer( offset ) );
MQO_END_PRIM( file_skip )

MQO_BEGIN_PRIM( "file-pos", file_pos )
    REQ_FILE_ARG( file );
    NO_REST_ARGS( );

    mqo_integer offset = mqo_os_error( lseek( file->fd, 0, SEEK_CUR ) );

    RESULT( mqo_vf_integer( offset ) );
MQO_END_PRIM( file_pos )

MQO_BEGIN_PRIM( "file-seek", file_seek )
    REQ_FILE_ARG( file );
    REQ_INTEGER_ARG( offset );
    NO_REST_ARGS( );
    
    if( offset < 0 ){
        offset = lseek( file->fd, offset + 1, SEEK_END );
    }else{
        offset = lseek( file->fd, offset, SEEK_SET );
    };

    mqo_os_error( offset );

    RESULT( mqo_vf_integer( offset ) );
MQO_END_PRIM( file_seek )

//TODO: We really need a time type.
MQO_BEGIN_PRIM( "path-mtime", path_mtime )
    REQ_STRING_ARG( path )
    NO_REST_ARGS( );

    struct stat s;

    mqo_os_error( stat( mqo_sf_string( path ), &s ) );

#if defined( LINUX )||defined( _WIN32 )
    time_t mtime = s.st_mtime;
#else
    time_t mtime = s.st_mtimespec.tv_sec;
#endif

    RESULT( mqo_vf_integer( mtime ) );
MQO_END_PRIM( path_mtime )

MQO_BEGIN_PRIM( "path-exists?", path_existsq )
    REQ_STRING_ARG( path )
    NO_REST_ARGS( );

    struct stat s;
    
    RESULT( mqo_vf_boolean( stat( mqo_sf_string( path ), &s ) == 0 ) );
MQO_END_PRIM( path_existsq )

MQO_BEGIN_PRIM( "file-path?", file_pathq )
    REQ_STRING_ARG( path )
    NO_REST_ARGS( );

    struct stat s;

    int r = stat( mqo_sf_string( path ), &s );

    if( r == 0 ){
        RESULT( mqo_vf_boolean( S_ISREG( s.st_mode ) ) );
    }else{
        RESULT( mqo_vf_false( ) );
    }
MQO_END_PRIM( file_pathq )

MQO_C_TYPE( file );

void mqo_init_file_subsystem( ){
    MQO_I_TYPE( file );

#if defined(_WIN32)||defined(__CYGWIN__)
    mqo_set_global( mqo_symbol_fs( "*path-sep*" ), 
                    mqo_vf_string( mqo_string_fs( "\\" ) ) );
    mqo_set_global( mqo_symbol_fs( "*line-sep*" ),
                    mqo_vf_string( mqo_string_fs( "\r\n" ) ) );
#else
    mqo_set_global( mqo_symbol_fs( "*path-sep*" ),
                    mqo_vf_string( mqo_string_fs( "/" ) ) );
    mqo_set_global( mqo_symbol_fs( "*line-sep*" ),
                    mqo_vf_string( mqo_string_fs( "\n" ) ) );
#endif

    MQO_BIND_PRIM( open_file );
    MQO_BIND_PRIM( close_file );
    MQO_BIND_PRIM( closed_fileq );
    MQO_BIND_PRIM( fileq );
    MQO_BIND_PRIM( read_file );
    MQO_BIND_PRIM( write_file );
    MQO_BIND_PRIM( file_skip );
    MQO_BIND_PRIM( file_seek );
    MQO_BIND_PRIM( file_pos );
    MQO_BIND_PRIM( file_len );

    MQO_BIND_PRIM( path_mtime );
    MQO_BIND_PRIM( path_existsq );
    MQO_BIND_PRIM( file_pathq );
}


