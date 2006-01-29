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

#ifndef MQO_PARSE_H
#define MQO_PARSE_H 1

#include "memory.h"

extern mqo_symbol mqo_sym_quote;
extern mqo_symbol mqo_sym_quasiquote;
extern mqo_symbol mqo_sym_unquote;
extern mqo_symbol mqo_sym_unquote_splicing;

mqo_integer mqo_read_integer( const char** pt );
mqo_string mqo_read_string( const char** pt );
mqo_symbol mqo_read_symbol( const char** pt );
mqo_pair mqo_read_list( const char** pt );
mqo_value mqo_read_value( const char** pt );
mqo_pair mqo_read_exprs( const char* og );

void mqo_init_parse_subsystem();

#endif

