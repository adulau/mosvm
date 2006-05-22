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

#ifndef MQO_ERROR_H
#define MQO_ERROR_H 1

#include "memory.h"

MQO_BEGIN_TYPE( error )
    mqo_symbol key;
    mqo_pair   info, context;
MQO_END_TYPE( error )

MQO_BEGIN_TYPE( guard )
    mqo_value fn;
    mqo_callframe ap, cp;
    mqo_instruction ip;
    mqo_pair ep;
MQO_END_TYPE( guard )

#define REQ_ERROR_ARG( vn ) REQ_TYPED_ARG( vn, error )
#define ERROR_RESULT( vn ) TYPED_RESULT( vn, error )
#define OPT_ERROR_ARG( vn ) OPT_TYPED_ARG( vn, error )

#define REQ_GUARD_ARG( vn ) REQ_TYPED_ARG( vn, guard )
#define GUARD_RESULT( vn ) TYPED_RESULT( vn, guard )
#define OPT_GUARD_ARG( vn ) OPT_TYPED_ARG( vn, guard )

void mqo_errf( mqo_symbol key, const char* fmt, ... );
void mqo_show_error( mqo_error e, mqo_word* ct );
void mqo_traceback( mqo_error e );
mqo_error mqo_make_error( mqo_symbol key, mqo_list info, mqo_list context );
mqo_pair mqo_frame_context( mqo_callframe callframe );
void mqo_throw_error( mqo_error e );

mqo_guard mqo_make_guard( 
    mqo_value fn, mqo_callframe cp, mqo_callframe ap, mqo_pair ep, 
    mqo_instruction ip
);

void mqo_init_error_subsystem( );

#endif
