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

void mqo_init_mosvm( ){
    mqo_init_memory_subsystem( );
    mqo_init_boolean_subsystem( );
    mqo_init_number_subsystem( );
    mqo_init_list_subsystem( );
    mqo_init_tree_subsystem( );
    mqo_init_string_subsystem( );
    mqo_init_vector_subsystem( );
    mqo_init_procedure_subsystem( );
    mqo_init_primitive_subsystem( );
    mqo_init_closure_subsystem( );
    mqo_init_regex_subsystem( );
    mqo_init_vm_subsystem( );
    mqo_init_error_subsystem( );
    mqo_init_package_subsystem( );
    mqo_init_print_subsystem( );
    mqo_init_process_subsystem( );
    mqo_init_channel_subsystem( );
    mqo_init_net_subsystem( );
    mqo_init_crypto_subsystem( );
    mqo_init_parse_subsystem( );
    mqo_init_tag_subsystem( );
    mqo_init_multimethod_subsystem( );

    mqo_bind_core_prims( );
}

