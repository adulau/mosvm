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

#ifndef MQO_REGEX_H
#define MQO_REGEX_H 1

// Some old BSD regexes require that sys/types.h be included first.
#include <sys/types.h>
#include <regex.h>

MQO_BEGIN_TYPE( regex )
    regex_t rx;
MQO_END_TYPE( regex )
#define REQ_REGEX_ARG( vn ) REQ_TYPED_ARG( vn, regex )
#define REGEX_RESULT( vn ) TYPED_RESULT( vn, regex )
#define OPT_REGEX_ARG( vn ) OPT_TYPED_ARG( vn, regex )

extern mqo_symbol mqo_es_rx;

mqo_regex mqo_make_regex( mqo_string pattern, const char* flagstr );
mqo_value  mqo_match_regex( mqo_regex regex, 
                            const char* str, const char* flagstr,
                            const char** head, const char** tail );

void mqo_init_regex_subsystem( );
#endif
