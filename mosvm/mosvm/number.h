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

#ifndef MQO_INTEGER_H
#define MQO_INTEGER_H 1

#include "memory.h"

struct mqo_number_data {
    struct mqo_object_data header;

    mqo_integer intval;
};
typedef struct mqo_number_data* mqo_number;

MQO_H_TP( number );
MQO_H_VF( number );

mqo_number mqo_nf_integer( mqo_integer x );
mqo_integer mqo_integer_fn( mqo_number x );

MQO_H_RQ( integer );
MQO_H_RQ( number );

#define REQ_INTEGER_ARG( vn ) mqo_integer vn = mqo_req_intarg( );
#define INTEGER_RESULT( vn )  RESULT( mqo_vf_integer( vn ) );
#define OPT_INTEGER_ARG( vn ) \
    mqo_boolean has_##vn; \
    mqo_integer vn = mqo_opt_intarg( &has_##vn );

mqo_boolean mqo_is_integer( mqo_value val );
mqo_boolean mqo_is_number( mqo_value val );
mqo_value mqo_vf_integer( mqo_integer ix );
mqo_integer mqo_integer_fv( mqo_value val );

mqo_integer mqo_number_compare( mqo_value a, mqo_value b );
mqo_integer mqo_req_intarg( );
mqo_integer mqo_opt_intarg( );

void mqo_init_number_subsystem( );

#endif
