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

#include <regex.h>
#include "mosvm.h"

mqo_symbol mqo_es_rx;

MQO_DEFN_TYPE( regex );

void mqo_init_regex_subsystem( ){
    MQO_BIND_TYPE( regex, nil );
    mqo_es_rx = mqo_symbol_fs( "regex" );
}

int mqo_regex_error( mqo_regex regex, int code ){
    if( ! code )return 0;

    char errbuf[256];
    regerror( code, &( regex->rx ), errbuf, sizeof( errbuf ) );
    mqo_errf( mqo_es_rx, "s", errbuf );

    return code;
}

void mqo_regex_finalizer( void* regex, void* huh ){
    regfree( & ((mqo_regex)regex)->rx );
}

mqo_regex mqo_make_regex( mqo_string pattern, const char* flagstr ){
    int flags = REG_EXTENDED;
    if( flagstr ){
        for( ; *flagstr; flagstr++ )switch( *flagstr ){
        case 'b':
            if( flags & REG_EXTENDED ) flags ^= REG_EXTENDED;
            break;
        case 's':
            if( flags & REG_EXTENDED ) flags ^= REG_EXTENDED;
            flags |= REG_NOSPEC;
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

    mqo_regex regex = MQO_ALLOC( mqo_regex, 0 );
    GC_register_finalizer( regex, mqo_regex_finalizer, NULL, NULL, NULL );
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

void mqo_show_regex( mqo_regex regex, mqo_word* ct ){
    mqo_write( "[regex]" );
}

