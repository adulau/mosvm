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

#include "../mosvm.h"
#include "../mosvm/prim.h"

MQO_BEGIN_PRIM( read_alarm, "read-alarm" )
    REQ_DESCR_ARG( descr );
    OPT_PROCESS_ARG( process );
    NO_MORE_ARGS( );
    if( ! has_process )process = MQO_PP;
    MQO_RESULT( mqo_vf_alarm( mqo_read_alarm( process, descr ) ) );
MQO_END_PRIM( read_alarm )

MQO_BEGIN_PRIM( write_alarm, "write-alarm" )
    REQ_DESCR_ARG( descr );
    OPT_PROCESS_ARG( process );
    NO_MORE_ARGS( );
    if( ! has_process )process = MQO_PP;
    MQO_RESULT( mqo_vf_alarm( mqo_write_alarm( process, descr ) ) );
MQO_END_PRIM( write_alarm )

MQO_BEGIN_PRIM( alarmq, "alarm?" )
    REQ_VALUE_ARG( value );
    NO_MORE_ARGS( );
    MQO_RESULT( mqo_vf_boolean( mqo_is_alarm( value ) ) );
MQO_END_PRIM( alarmq )

MQO_BEGIN_PRIM( read_alarmq, "read-alarm?" )
    REQ_VALUE_ARG( value );
    NO_MORE_ARGS( );
    MQO_RESULT( mqo_vf_boolean( mqo_is_alarm( value ) && 
                                mqo_alarm_fv( value )->type == mqo_as_read ) );
MQO_END_PRIM( read_alarmq )

MQO_BEGIN_PRIM( write_alarmq, "write-alarm?" )
    REQ_VALUE_ARG( value );
    NO_MORE_ARGS( );
    MQO_RESULT( mqo_vf_boolean( mqo_is_alarm( value ) && 
                                mqo_alarm_fv( value )->type == 
                                    mqo_as_write ) );
MQO_END_PRIM( write_alarmq )

MQO_BEGIN_PRIM( alarm_descr, "alarm-descr" )
    REQ_ALARM_ARG( alarm );
    NO_MORE_ARGS( );
    MQO_RESULT( mqo_vf_descr( alarm->descr ) );
MQO_END_PRIM( alarm_descr )

MQO_BEGIN_PRIM( enable_alarm, "enable-alarm" )
    REQ_ALARM_ARG( alarm );
    NO_MORE_ARGS( );
    mqo_enable_alarm( alarm );
    MQO_NO_RESULT( );
MQO_END_PRIM( enable_alarm )

MQO_BEGIN_PRIM( disable_alarm, "disable-alarm" )
    REQ_ALARM_ARG( alarm );
    NO_MORE_ARGS( );
    mqo_disable_alarm( alarm );
    MQO_NO_RESULT( );
MQO_END_PRIM( disable_alarm )

void mqo_bind_alarm_prims( ){
    MQO_BIND_PRIM( read_alarm );
    MQO_BIND_PRIM( write_alarm );
    MQO_BIND_PRIM( alarmq );
    MQO_BIND_PRIM( read_alarmq );
    MQO_BIND_PRIM( write_alarmq );
    MQO_BIND_PRIM( alarm_descr );
    MQO_BIND_PRIM( enable_alarm );
    MQO_BIND_PRIM( disable_alarm );
}
