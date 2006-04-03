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

#ifndef MQO_OS_H
#define MQO_OS_H 1

#include "memory.h"

#define MQO_CONSOLE 0
#define MQO_LISTENER 1
#define MQO_SOCKET 2
#define MQO_FILE 3

extern mqo_type mqo_descr_type;
struct mqo_descr_data;
typedef struct mqo_descr_data* mqo_descr;
typedef mqo_value (*mqo_read_mt) (mqo_descr);
struct mqo_descr_data {
    unsigned int type:2;
    unsigned int closing:1;
    unsigned int closed:1;
    unsigned int dispatch:1;

    mqo_descr next, prev;
    mqo_string name;
    mqo_integer fd, quantity;
    mqo_process monitor;
    mqo_buffer  write_data, read_data;
    mqo_read_mt read_mt;
};

mqo_descr mqo_req_descr( mqo_value v, const char* f );
mqo_descr mqo_req_sub_descr( mqo_value v, const char* f );
mqo_descr mqo_descr_fv( mqo_value v );
mqo_value mqo_vf_descr( mqo_descr d );
mqo_boolean mqo_is_descr( mqo_value v );
mqo_boolean mqo_isa_descr( mqo_value v );


typedef mqo_descr mqo_socket;
MQO_DECL_TYPE( socket );
MQO_TYPE_INLINES( socket );

typedef mqo_descr mqo_listener;
MQO_DECL_TYPE( listener );
MQO_TYPE_INLINES( listener );

typedef mqo_descr mqo_console;
MQO_DECL_TYPE( console );
MQO_TYPE_INLINES( console );

typedef mqo_descr mqo_file;
MQO_DECL_TYPE( file );
MQO_TYPE_INLINES( file );

mqo_integer mqo_resolve( mqo_string name );

void mqo_start_dispatching( mqo_descr descr );
void mqo_stop_dispatching( mqo_descr descr );

mqo_value mqo_start_reading( mqo_descr descr, mqo_process monitor, 
                             mqo_read_mt read_mt );
void mqo_stop_reading( mqo_descr descr );

void mqo_start_writing( mqo_descr descr, const char* data, 
                        mqo_integer datalen );
void mqo_stop_writing( mqo_descr descr );

int mqo_in_dispatch( mqo_socket socket );
int mqo_is_reading( mqo_socket socket );
int mqo_is_writing( mqo_socket socket );

void mqo_write_descr( mqo_descr descr, const void* data, mqo_integer datalen );
void mqo_read_descr( mqo_descr descr, mqo_process monitor, 
                     mqo_read_mt read_mt );

mqo_value mqo_read_all_mt( mqo_descr descr );
mqo_value mqo_read_line_mt( mqo_descr descr );
mqo_value mqo_read_data_mt( mqo_descr descr );
mqo_value mqo_read_byte_mt( mqo_descr descr );
mqo_value mqo_read_word_mt( mqo_descr descr );
mqo_value mqo_read_quad_mt( mqo_descr descr );

mqo_descr mqo_connect_tcp( mqo_integer addr, mqo_integer port );
mqo_descr mqo_serve_tcp( mqo_integer port );
mqo_descr mqo_accept( mqo_descr server );

void mqo_close( mqo_descr descr );
void mqo_complete_close( mqo_descr descr );

extern mqo_console mqo_the_console;
extern mqo_descr mqo_first_dispatching;

int mqo_dispatch_monitors( );
void mqo_init_net_subsystem( );

mqo_descr mqo_make_descr( mqo_string path, int fd, mqo_byte type );
mqo_file mqo_make_file( mqo_string path, int fd );
mqo_socket mqo_make_socket( mqo_string path, int fd );
mqo_listener mqo_make_listener( mqo_string path, int fd );
mqo_console mqo_make_console( mqo_string path );

void mqo_show_descr( mqo_descr d, mqo_word *ct );
#define mqo_show_listener mqo_show_descr
#define mqo_show_console mqo_show_descr
#define mqo_show_file mqo_show_descr
#define mqo_show_socket mqo_show_descr

#endif
