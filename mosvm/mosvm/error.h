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

void mqo_raise( mqo_symbol key, mqo_pair info );
void mqo_errf( mqo_symbol key, const char* fmt, ... );

void mqo_report_os_error( );
int mqo_os_error( int code );
void mqo_dump_error( mqo_error e );

void mqo_show_error( mqo_error e, mqo_word* ct );
#define mqo_show_guard NULL;

#endif
