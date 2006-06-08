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

mqo_value mqo_the_true;
mqo_value mqo_the_false;

void mqo_format_boolean( mqo_string buf, mqo_value v ){
    mqo_string_append_cs( buf, v == mqo_the_false ? "#f" : "#t" );
}
mqo_integer mqo_boolean_compare( mqo_value a, mqo_value b ){
    if( a == b )return 0;
    return ( a == mqo_the_false ) ? -1 : +1;
}
MQO_GENERIC_GC( boolean );
MQO_C_TYPE( boolean );

mqo_value mqo_make_mote( mqo_type type ){
    mqo_object mote = mqo_objalloc( type, sizeof( struct mqo_object_data ) );
    mqo_root_obj( mote );
    return mqo_vf_obj( mote );
}

void mqo_init_boolean_subsystem( ){
    MQO_I_TYPE( boolean );
    mqo_the_true = mqo_make_mote( mqo_boolean_type );
    mqo_the_false = mqo_make_mote( mqo_boolean_type );
}
