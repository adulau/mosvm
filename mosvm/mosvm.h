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

#ifndef MQO_MOSVM_H
#define MQO_MOSVM_H 1

#include "mosvm/memory.h"
#include "mosvm/number.h"
#include "mosvm/boolean.h"
#include "mosvm/list.h"
#include "mosvm/tree.h"
#include "mosvm/string.h"
#include "mosvm/vector.h"
#include "mosvm/primitive.h"
#include "mosvm/procedure.h"
#include "mosvm/closure.h"
#include "mosvm/parse.h"
#include "mosvm/print.h"
#include "mosvm/format.h"
#include "mosvm/regex.h"
#include "mosvm/file.h"
#include "mosvm/package.h"
#include "mosvm/vm.h"
#include "mosvm/process.h"
#include "mosvm/channel.h"
#include "mosvm/stream.h"
#include "mosvm/error.h"
#include "mosvm/tag.h"
#include "mosvm/multimethod.h"
#include "mosvm/file.h"
#include "mosvm/time.h"

void mqo_init_mosvm( );
void mqo_init_crypto_subsystem( );
void mqo_init_crc32_subsystem( );
void mqo_bind_core_prims( );
mqo_value mqo_make_mote( mqo_type type );
int mqo_argc;
mqo_list mqo_argv;
extern int mqo_abort_on_error;

#endif
