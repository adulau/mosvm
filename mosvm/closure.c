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
 * along with this library; if not, print to the Free Software Foundation, 
 * Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA 
 */

#include "mosvm.h"

mqo_closure mqo_make_closure( mqo_instruction inst, mqo_pair env ){
    mqo_closure clos = MQO_OBJALLOC( closure );
    clos->inst = inst;
    clos->env = env;
    clos->name = mqo_vf_null();
    return clos;
}

void mqo_trace_closure( mqo_closure clos ){
    mqo_grey_val( mqo_clos_name( clos ) );
    mqo_grey_obj( (mqo_object) mqo_clos_inst( clos )->proc );
    mqo_grey_obj( (mqo_object) mqo_clos_env( clos ) );
}

void mqo_show_closure( mqo_closure clos, mqo_word* ct ){
    mqo_print( "[closure" );
    mqo_value name = mqo_clos_name( clos );
    if( mqo_is_symbol( name ) ){
        mqo_space( );
        mqo_printsym( mqo_symbol_fv( name ) );
    };
    mqo_print( "]" );
}

MQO_GENERIC_COMPARE( closure );
MQO_GENERIC_FREE( closure );
MQO_C_TYPE( closure );

void mqo_init_closure_subsystem( ){
    MQO_I_TYPE( closure );
}

