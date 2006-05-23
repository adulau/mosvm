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
#include <unistd.h>
#include <fcntl.h>
#include <ctype.h>
#include <stdio.h>

int mqo_os_error( const char* what, int code ){
    if( code == -1 ){
        perror( what );
        exit( 2 );
    };
    return code;
}
mqo_string mqo_read_file( const char* path ){
    int fd = mqo_os_error( "opening input file", open( path, O_RDONLY, 0 ) );

    int fs = mqo_os_error( "checking input file size", lseek( fd, 0, SEEK_END ) );
    mqo_os_error( "restoring input offset", lseek( fd, 0, SEEK_SET ) );

    mqo_string data = mqo_make_string( fs );
    char* ptr = mqo_string_head( data );
	mqo_string_wrote( data, fs  );

    while( fs > 0 ){
        int amt = mqo_os_error( "reading from input file", read( fd, ptr, fs ) );
        fs -= amt;
        ptr += amt;
    }
	
    mqo_os_error( "closing input file", close( fd ) );
    return data;
}
void mqo_write_file( const char* path, mqo_string data ){
    int fd = mqo_os_error( "opening output file", 
                        open( path, O_CREAT | O_TRUNC | O_WRONLY, 0700 ) );
    
    const char* str = mqo_sf_string( data );
    mqo_integer len = mqo_string_length( data );

    while( len > 0 ){
        int amt = mqo_os_error( "writing to output file",
                            write( fd, str, len ) );
        len -= amt;
        str += amt;
    }
}
