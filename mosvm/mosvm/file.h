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

#include "memory.h"
#ifndef MQO_FILE_H
#define MQO_FILE_H 1

MQO_BEGIN_TYPE( file );
    mqo_string path;
    mqo_integer fd;
    mqo_boolean closed;
MQO_END_TYPE( file );

mqo_file mqo_make_file( mqo_string path, int fd );

void mqo_init_file_subsystem( );

int mqo_os_error( int code );
mqo_string mqo_read_file( mqo_file file, mqo_quad max );
void mqo_write_file( mqo_file file, const void* data, mqo_integer datalen );
void mqo_close_file( mqo_file file );
mqo_file mqo_open_file( const char* path, const char* flags, mqo_integer mode );

mqo_boolean mqo_file_exists( mqo_string filename );
mqo_string mqo_locate_file( mqo_string filename, mqo_list paths );
mqo_string mqo_locate_util( mqo_string utilname );

#define REQ_FILE_ARG( vn  ) REQ_TYPED_ARG( vn, file );
#define OPT_FILE_ARG( vn  ) OPT_TYPED_ARG( vn, file );
#define FILE_RESULT( x  ) TYPED_RESULT( file, x );

#endif
