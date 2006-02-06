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

mqo_error mqo_make_error( mqo_symbol key, mqo_pair info ){
    mqo_error e = MQO_ALLOC( mqo_error, 0 );
    mqo_vmstate s = mqo_make_vmstate( );

    e->key = key;
    e->info = info;
    e->state = s;

    s->cp = MQO_CP;
    s->ip = MQO_IP;
    s->rv = mqo_copy_vector( MQO_RV, MQO_RI );
    s->sv = mqo_copy_vector( MQO_SV, MQO_SI );
    s->ri = MQO_RI;
    s->si = MQO_SI;
    s->ep = MQO_EP;
    s->gp = MQO_GP;

    return e;
}
mqo_guard mqo_make_guard( 
    mqo_value fn, mqo_integer ri, mqo_integer si, 
    mqo_program cp,  mqo_instruction ip, mqo_pair ep
){
    mqo_guard e = MQO_ALLOC( mqo_guard, 0 );

    e->fn = fn;
    e->ri = ri;
    e->si = si;
    e->cp = cp;
    e->ip = ip;
    e->ep = ep;

    return e;
}
void mqo_show_error( mqo_error e, mqo_word* ct ){
    if( ! e )mqo_show_unknown( mqo_error_type, 0 );
    mqo_write( "[error " );
    mqo_writesym( e->key );
    mqo_show_pair_contents( e->info, ct );
    mqo_write( "]" );
}
