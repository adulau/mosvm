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

#ifndef MQO_ALARM_H
#define MQO_ALARM_H 1

#include "memory.h"

MQO_BEGIN_TYPE( alarm )
    mqo_symbol type;
    mqo_process process;
    mqo_descr   descr;
MQO_END_TYPE( alarm )

extern mqo_symbol mqo_as_read;
extern mqo_symbol mqo_as_write;

extern mqo_tree mqo_read_alarms;
extern mqo_tree mqo_write_alarms;

mqo_alarm mqo_make_alarm( mqo_symbol type, mqo_process process, 
                          mqo_descr descr );

static inline mqo_alarm mqo_make_read_alarm( mqo_process process, mqo_descr descr ){
    return mqo_make_alarm( mqo_as_read, process, descr );
}
static inline mqo_alarm mqo_make_write_alarm( mqo_process process, mqo_descr descr ){
    return mqo_make_alarm( mqo_as_write, process, descr );
}
static inline mqo_boolean mqo_is_read_alarm( mqo_alarm alarm ){
    return alarm->type == mqo_as_read;
}
static inline mqo_boolean mqo_is_write_alarm( mqo_alarm alarm ){
    return alarm->type == mqo_as_write;
}
void mqo_enable_alarm( mqo_alarm alarm );
void mqo_disable_alarm( mqo_alarm alarm );
int mqo_process_alarms( );

void mqo_init_alarm_subsystem( );
#endif

