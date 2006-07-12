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

#include <sys/types.h>
#include <regex.h>
#include "mosvm.h"
#ifdef _WIN32
#include <malloc.h>
#endif

mqo_symbol mqo_es_rx;

int mqo_regex_error( mqo_regex regex, int code ){
    if( ! code )return 0;

    char errbuf[256];
    regerror( code, &( regex->rx ), errbuf, sizeof( errbuf ) );
    mqo_errf( mqo_es_rx, "s", errbuf );

    return code;
}

mqo_regex mqo_make_regex( mqo_string pattern, const char* flagstr ){
    int flags = REG_EXTENDED;
    if( flagstr ){
        for( ; *flagstr; flagstr++ )switch( *flagstr ){
        case 'b':
            if( flags & REG_EXTENDED ) flags ^= REG_EXTENDED;
            break;
        case 'i':
            flags |= REG_ICASE;
            break;
        case 'n':
            flags |= REG_NEWLINE;
            break;
        case 'm':
            flags |= REG_NOSUB;
            break;
        default:
            mqo_errf( mqo_es_rx, "s", "regex flag not recognized" );
        }
    }

    mqo_regex regex = MQO_OBJALLOC( regex );
    mqo_regex_error( regex, regcomp( &( regex->rx ), 
                     mqo_sf_string( pattern ), flags ) );
    return regex;
}

mqo_value  mqo_match_regex( mqo_regex regex, 
                           const char* str, const char* flagstr,
                           const char** head, const char** tail 
){
    int flags = 0;
    if( flagstr ){
        for( ; *flagstr; flagstr++ )switch( *flagstr ){
        case 'b':
            flags |= REG_NOTBOL;
            break;
        case 'e':
            flags |= REG_NOTEOL;
            break;
        default:
            mqo_errf( mqo_es_rx, "s", "regex flag not recognized" );
        }
    };

    int ct = regex->rx.re_nsub + 1;
    regmatch_t* mx = alloca( sizeof( regmatch_t ) * ct );
    int rs = regexec( &( regex->rx ), str, ct, mx, flags );
    if( rs == 0 ){
        const char* b = str + mx[0].rm_so;
        const char* e = str + mx[0].rm_eo;
        if( head ) (*head) = b;
        if( tail ) (*tail) = e;
        if( ct == 1 ){
            return mqo_vf_string( mqo_string_fm( b, e - b ) );
        }
        mqo_pair tc = mqo_make_tc( );
        int ix;
        for( ix = 1; ix < ct; ix ++ ){
            if( mx[ix].rm_so == -1 ){
                mqo_tc_append( tc, mqo_vf_false( ) );
            }else{
                b = str + mx[ix].rm_so;
                e = str + mx[ix].rm_eo;
                mqo_tc_append( 
                    tc, mqo_vf_string( mqo_string_fm( b, e - b ) ) 
                );
            }
        }
        return mqo_car( tc );
    }else if( rs == REG_NOMATCH ){
        return mqo_vf_false( );
    }else{
        mqo_regex_error( regex, rs );
    }
}


void mqo_free_regex( mqo_regex regex ){
    regfree( &( regex->rx ) );
    mqo_objfree( regex );
}

MQO_GENERIC_TRACE( regex );
MQO_GENERIC_COMPARE( regex );
MQO_GENERIC_FORMAT( regex );
MQO_C_TYPE( regex );

MQO_BEGIN_PRIM( "match-regex", match_regex )
    REQ_REGEX_ARG( regex );
    REQ_STRING_ARG( text );
    OPT_STRING_ARG( flags );
    NO_REST_ARGS( );
   
    RESULT( mqo_match_regex( regex, mqo_sf_string( text ), 
                                        has_flags ? mqo_sf_string( flags )
                                                  : NULL,
                                        NULL, NULL ) );
MQO_END_PRIM( match_regex )

MQO_BEGIN_PRIM( "match-regex*", match_regexm )
    REQ_REGEX_ARG( regex );
    REQ_STRING_ARG( text );
    OPT_STRING_ARG( flags );
    NO_REST_ARGS( );

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
    
    RESULT( has_matched ? mqo_car( tc ) : mqo_vf_false( ) );
MQO_END_PRIM( match_regexm )

MQO_BEGIN_PRIM( "make-regex", make_regex )
    REQ_STRING_ARG( pattern );
    OPT_STRING_ARG( flags );
    NO_REST_ARGS( );

    RESULT( 
        mqo_vf_regex( mqo_make_regex( pattern, 
                                      has_flags ? mqo_sf_string( flags ) 
                                                : NULL ) ) 
    );
MQO_END_PRIM( make_regex )

MQO_BEGIN_PRIM( "string-read-regex!", string_read_regex )
    REQ_STRING_ARG( text );
    REQ_REGEX_ARG( regex );
    OPT_STRING_ARG( flags );

    NO_REST_ARGS( );
   
    const char* endp = NULL;
    const char* str = mqo_sf_string( text );
    const char* flagstr = has_flags ? mqo_sf_string( flags ) : NULL;
        
    mqo_value m = mqo_match_regex( regex, str, flagstr, NULL, &endp );

    if( ! mqo_is_false( m ) ){
        mqo_string_skip( text, endp - str );
    }

    RESULT( m );
MQO_END_PRIM( string_read_regex )

void mqo_init_regex_subsystem( ){
    MQO_I_TYPE( regex );
    mqo_es_rx = mqo_symbol_fs( mqo_regex_name );
    
    MQO_BIND_PRIM( make_regex );
    MQO_BIND_PRIM( match_regexm );
    MQO_BIND_PRIM( match_regex );
    MQO_BIND_PRIM( regexq );
    MQO_BIND_PRIM( string_read_regex );
}
