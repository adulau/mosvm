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

#ifndef MQO_NET_H
#define MQO_NET_H 1

#include "memory.h"

void mqo_start_listening( mqo_descr descr );
void mqo_stop_listening( mqo_descr descr );
mqo_integer mqo_resolve( mqo_string name );
mqo_descr mqo_connect_tcp( mqo_integer addr, mqo_integer port );
mqo_descr mqo_serve_tcp( mqo_integer port );
mqo_descr mqo_accept( mqo_descr server );
void mqo_close( mqo_descr descr );

extern mqo_console mqo_the_console;
extern mqo_descr mqo_first_listening;

int mqo_dispatch_monitors( );
void mqo_init_net_subsystem( );

#endif
