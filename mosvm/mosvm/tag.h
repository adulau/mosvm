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

#ifndef MQO_TAG_H
#define MQO_TAG_H

#include "memory.h"

MQO_BEGIN_TYPE( tag )
    mqo_symbol name;
    mqo_value info;
MQO_END_TYPE( tag )

MQO_BEGIN_TYPE( cell )
    mqo_tag tag;
    mqo_value repr;
MQO_END_TYPE( cell )

#define REQ_TAG_ARG( vn ) REQ_TYPED_ARG( vn, tag )
#define TAG_RESULT( vn ) TYPED_RESULT( tag, vn )
#define OPT_TAG_ARG( vn ) OPT_TYPED_ARG( vn, tag )

#define REQ_CELL_ARG( vn ) REQ_TYPED_ARG( vn, cell )
#define CELL_RESULT( vn ) TYPED_RESULT( cell, vn )
#define OPT_CELL_ARG( vn ) OPT_TYPED_ARG( vn, cell )

void mqo_init_tag_subsystem( );
mqo_boolean mqo_isaq( mqo_value x, mqo_value t );
#endif
