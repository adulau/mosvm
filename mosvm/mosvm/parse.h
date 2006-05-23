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

// These expressions can parse a S-Expression, as defined by Mosquito Lisp;
// they do not do any pre-pass alteration of the contents, such as altering
// '(...) to (quote ...) or `(...) to (quasiquote ...).  

#ifndef MQO_PARSE_H
#define MQO_PARSE_H 1

#include "memory.h"

mqo_quad mqo_parse_dec( char** r_str, mqo_boolean* r_succ );
mqo_quad mqo_parse_hex( char** r_str, mqo_boolean* r_succ );
mqo_integer mqo_parse_int( char** r_str, mqo_boolean* r_succ );

mqo_symbol mqo_parse_sym( char** r_str, mqo_boolean* r_succ );

mqo_string mqo_parse_str( char** r_str, mqo_boolean* r_succ );
mqo_list   mqo_parse_list( char** r_str, mqo_boolean* r_succ );
mqo_value  mqo_parse_value( char** r_str, mqo_boolean* r_succ );
mqo_list mqo_parse_document( char* doc, mqo_boolean* r_succ );

extern const char* mqo_parse_errmsg;
extern mqo_integer mqo_parse_incomplete;

void mqo_init_parse_subsystem( );

#endif
