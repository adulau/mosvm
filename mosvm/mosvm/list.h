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

#ifndef MQO_LIST_H
#define MQO_LIST_H 1

#include "memory.h"

MQO_BEGIN_TYPE( pair )
    mqo_value car, cdr;
MQO_END_TYPE( pair )

#define REQ_PAIR_ARG( vn ) REQ_TYPED_ARG( vn, pair )
#define PAIR_RESULT( vn ) TYPED_RESULT( vn, pair )
#define OPT_PAIR_ARG( vn ) OPT_TYPED_ARG( vn, pair )

MQO_H_SUBTYPE( tc, pair );

#define REQ_TC_ARG( vn ) REQ_TYPED_ARG( vn, tc )
#define TC_RESULT( vn ) TYPED_RESULT( vn, tc )
#define OPT_TC_ARG( vn ) OPT_TYPED_ARG( vn, tc )

#define mqo_list mqo_pair
#define mqo_list_type mqo_pair_type

static inline mqo_boolean mqo_is_list( mqo_value v ){
    return mqo_is_pair( v ) || mqo_is_null( v );
}

static inline mqo_list mqo_list_fv( mqo_value v ){
    assert( mqo_is_list( v ) );
    return (mqo_list)v;
}

static inline mqo_list mqo_req_list( mqo_value v ){
    return( mqo_is_null( v ) ) ? NULL : mqo_req_pair( v );
}

#define mqo_vf_list mqo_vf_pair
#define REQ_LIST_ARG( vn ) mqo_list vn = mqo_req_list( mqo_req_any( ) );
#define LIST_RESULT( vn ) TYPED_RESULT( list, vn )
#define OPT_LIST_ARG( vn ) mqo_boolean has_##vn = 1; mqo_list vn = mqo_opt_list( &has_##vn );

static inline mqo_value mqo_car( mqo_pair pair ){ 
    assert( pair );
    return pair->car; 
}
static inline mqo_value mqo_cdr( mqo_pair pair ){ 
    assert( pair );
    return pair->cdr;
}
static inline mqo_value mqo_set_car( mqo_pair pair, mqo_value x ){ 
    assert( pair );
    pair->car = x; 
}
static inline mqo_value mqo_set_cdr( mqo_pair pair, mqo_value x ){ 
    assert( pair );
    pair->cdr = x; 
}
void mqo_format_list_items( void* b, mqo_pair p, mqo_boolean sp );
static inline mqo_list mqo_opt_list( mqo_boolean* has ){
    mqo_value v = mqo_opt_any( has );
    return ( *has ) ? mqo_req_list( v ) : NULL;
}
mqo_pair mqo_cons( mqo_value car, mqo_value cdr );
mqo_list mqo_list_ref( mqo_list p, mqo_integer ofs );

mqo_tc mqo_make_tc( );
void mqo_tc_append( mqo_tc tc, mqo_value v );

mqo_boolean mqo_eqvp( mqo_pair a, mqo_pair b );
mqo_boolean mqo_equalp( mqo_pair a, mqo_pair b );
mqo_pair mqo_last_pair( mqo_list p );

void mqo_format_pair( void * b, mqo_pair p );
void mqo_init_list_subsystem( );
mqo_integer mqo_list_length( mqo_list p );

mqo_pair mqo_listf( mqo_integer ct, ... );
#endif
