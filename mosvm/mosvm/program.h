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

#ifndef MQO_PROGRAM_H
#define MQO_PROGRAM_H 1

#include <string.h>

void mqo_show_instruction( mqo_instruction i, mqo_word* ct );
#define mqo_show_program NULL
mqo_program mqo_make_program( mqo_integer length );
mqo_instruction mqo_program_ref( mqo_program program, mqo_integer index );
void mqo_dump_program( mqo_program program );

#endif
