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

#ifndef MQO_PACKAGE_H
#define MQO_PACKAGE_H

#include "memory.h"
#include "string.h"

mqo_value mqo_thaw_mem( const void* mem, mqo_quad len );
mqo_string mqo_freeze( mqo_value value );

static inline mqo_value mqo_thaw_str( mqo_string str ){
    return mqo_thaw_mem( mqo_sf_string( str ), mqo_string_length( str ) );
}
void mqo_init_package_subsystem();

#endif
