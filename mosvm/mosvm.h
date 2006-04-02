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
#include "mosvm/buffer.h"
#include "mosvm/exec.h"
#include "mosvm/parse.h"
#include "mosvm/show.h"
#include "mosvm/thaw.h"
#include "mosvm/tree.h"
#include "mosvm/os.h"
#include "mosvm/string.h"
#include "mosvm/list.h"
#include "mosvm/error.h"
#include "mosvm/vector.h"
#include "mosvm/program.h"
#include "mosvm/regex.h"

extern mqo_integer mqo_argc;
extern mqo_pair mqo_argv;

void mqo_bind_core_prims( );
void mqo_bind_os_prims( );
void mqo_bind_progn_prims( );
void mqo_bind_net_prims( );
void mqo_bind_regex_prims( );

#endif
