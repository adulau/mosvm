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

MQO_BEGIN_PRIM( "match-regex", match_regex )
    REQ_REGEX_ARG( regex );
    REQ_STRING_ARG( text );
    OPT_STRING_ARG( flags );
    NO_MORE_ARGS( );
   
    MQO_RESULT( mqo_match_regex( regex, mqo_sf_string( text ), 
                                        has_flags ? mqo_sf_string( flags )
                                                  : NULL,
                                        NULL, NULL ) );
MQO_END_PRIM( match_regex )

MQO_BEGIN_PRIM( "match-regex*", match_regexm )
    REQ_REGEX_ARG( regex );
    REQ_STRING_ARG( text );
    OPT_STRING_ARG( flags );
    NO_MORE_ARGS( );

    mqo_tc tc = mqo_make_tc( );
    const char* str = mqo_sf_string( text );
    const char* flagstr = has_flags ? mqo_sf_string( flags ) : NULL;
    mqo_boolean has_matched = 0;

    for(;;){
        const char* nxt;
        mqo_value m = mqo_match_regex( regex, str, flagstr, NULL, &nxt );
        if( mqo_is_false( m ) ) break;
        has_matched = 1;
        mqo_tc_append( tc, m );
        str = nxt;
    }
    
    MQO_RESULT( has_matched ? mqo_car( tc ) : mqo_vf_false( ) );
MQO_END_PRIM( match_regexm )

MQO_BEGIN_PRIM( "make-regex", make_regex )
    REQ_STRING_ARG( pattern );
    OPT_STRING_ARG( flags );
    NO_MORE_ARGS( );

    MQO_RESULT( 
        mqo_vf_regex( mqo_make_regex( pattern, 
                                      has_flags ? mqo_sf_string( flags ) 
                                                : NULL ) ) 
    );
MQO_END_PRIM( make_regex )

MQO_BEGIN_PRIM( "regex?", regexq )
    REQ_VALUE_ARG( value );
    NO_MORE_ARGS( );

    MQO_RESULT( mqo_vf_boolean( mqo_is_regex( value ) ) );
MQO_END_PRIM( regexq )

void mqo_bind_regex_prims( ){
    MQO_BEGIN_PRIM_BINDS( );

    MQO_BIND_PRIM( make_regex );
    MQO_BIND_PRIM( match_regexm );
    MQO_BIND_PRIM( match_regex );
    MQO_BIND_PRIM( regexq );
}

