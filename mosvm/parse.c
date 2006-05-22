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

// These expressions can parse a S-Expression, as defined by Mosquito Lisp;
// they do not do any pre-pass alteration of the contents, such as altering
// '(...) to (quote ...) or `(...) to (quasiquote ...).  

#include <string.h>
#include <ctype.h>
#include "mosvm.h"

const char* mqo_parse_errmsg = NULL;
const char* mqo_em_nodigits = "expected digits";
const char* mqo_em_noprint = "illegal character";
const char* mqo_em_endq = "closing \" missing";
const char* mqo_em_endp = "closing ) missing";
const char* mqo_em_more = "expected more";

mqo_quad mqo_parse_dec( char** r_str, mqo_boolean* r_succ ){
    char* str = *r_str;
    mqo_quad result = 0;
    mqo_boolean any = 0;

    for(;;){
        char ch = *str;

        if(( ch >= '0' )&&( ch <= '9' )){
            result = result * 10 + ( ch - '0' );
        }else{
            break;
        }

        str++;
        any = 1;
    };

    if( any ){
        *r_succ = 1; 
        *r_str = str; 
    }else{
        mqo_parse_errmsg = mqo_em_nodigits;
        *r_succ = 0; 
    }
    
    return result;
}

mqo_quad mqo_parse_hex( char** r_str, mqo_boolean* r_succ ){
    char* str = *r_str;
    mqo_quad result = 0;
    mqo_boolean any = 0;

    for(;;){
        char ch = *str;

        if(( ch >= '0' )&&( ch <= '9' )){
            result = ( result << 4 ) | ( ch - '0' );
        }else if(( ch >= 'A' )&&( ch <= 'F' )){
            result = ( result << 4 ) | ( 10 + ch - 'A' );
        }else if(( ch >= 'a' )&&( ch <= 'f' )){
            result = ( result << 4 ) | ( 10 + ch - 'a' );
        }else{
            break;
        }
        
        str++;
        any = 1;
    };

    if( any ){
        *r_succ = 1; 
        *r_str = str; 
    }else{
        mqo_parse_errmsg = mqo_em_nodigits;
        *r_succ = 0; 
    }
    
    return result;
}

mqo_integer mqo_parse_int( char** r_str, mqo_boolean* r_succ ){
    //TODO: Check for integer overflows.
    switch( **r_str ){
    case '$':
        (*r_str) ++; return mqo_parse_hex( r_str, r_succ );
    case '-':
        (*r_str) ++; return -1 * mqo_parse_dec( r_str, r_succ );
    case '+':
        (*r_str) ++;
    default:
        return mqo_parse_dec( r_str, r_succ );
    }
}

const char* sym_lead_chars = "*<>=!";

mqo_symbol mqo_parse_sym( char** r_str, mqo_boolean* r_succ ){
    char* str = *r_str;
    char* sym = str;
    
    char ch = *str;

    // Only alphabetics and *<>=! lead multi-character symbols.  Everything
    // else is treated like a special operator, like "'", "`", ",", "#", 
    // or "@" 

    if(!( isalpha( ch ) || strchr( sym_lead_chars, ch ) )){
        if( isprint( ch ) ){
            (*r_str)++;
            *r_succ = 1;
            return mqo_symbol_fm( sym, 1 );
        }else{
            mqo_parse_errmsg = mqo_em_noprint;
            *r_succ = 0; 
            return NULL;
        }
    }

    for(;;){
        ch = *str;
        if( isspace( ch ) || (ch == '.') || (ch == ')') || 
            ( ! isprint( ch ) ) ) break;
        str ++;
    }
    *r_succ = 1;
    *r_str = str;
    return mqo_symbol_fm( sym, str - sym );
}

mqo_string mqo_parse_str( char** r_str, mqo_boolean* r_succ ){
    char ch;
    char* str = *r_str;
    mqo_string buf = mqo_make_string( 64 );
    
    if( *str != '"' )goto fail;

    str++;

    for(;;){
        switch( ch = *str ){ 
        case 0: 
            mqo_parse_errmsg = mqo_em_endq;
            goto fail;
        case '"': goto succ;
        case '\\':
            ch = *(++str);
            if( isdigit( ch ) ){
                mqo_boolean ok = 0;
                ch = mqo_parse_int( &str, &ok );
                // This should never fail.
                if( ! ok ) goto fail;
            }else{
                switch( ch ){
                case 0:
                    goto fail;
                case 'n':
                    ch = '\n';
                    break;
                case 'r':
                    ch = '\r';
                    break;
                case 't':
                    ch = '\t';
                    break;
                };
                str ++;
            };
            mqo_string_write( buf, &ch, 1 );
            break;
        default:
            mqo_string_write( buf, &ch, 1 );
            str ++;
        }
    }
succ:
    *r_succ = 1;
    *r_str = str + 1;

    return mqo_string_fm( mqo_string_head( buf ),
                          mqo_string_length( buf ) );
fail:
    *r_succ = 0;
    return NULL;
}

char* mqo_skip_space( char* str ){
    //TODO: Add skip comments code.
    for(;;){
        char ch = *str;
        if( isspace( ch ) ){
            str ++;
        }else if( ch == ';' ){
            // Sigh.. Comments.. Who comments, anymore?
            str ++;
            while( ! strchr( "\r\n", *str ) ) str ++;
        }else{
            break;
        }
    }
    return str;
}

mqo_list mqo_parse_list( char** r_str, mqo_boolean* r_succ ){
    char* str = *r_str;

    if( *str != '(' )goto fail;

    char ch;
    mqo_pair tc = mqo_make_tc( );
    mqo_string buf = mqo_make_string( 64 );
    mqo_value x;
    str++;

    for(;;){
        str = mqo_skip_space( str );
        switch( *str ){
        case '.':
            if( mqo_list_fv( mqo_car( tc ) ) ){
                str = mqo_skip_space( str + 1 );
                x = mqo_parse_value( &str, r_succ );

                if( *r_succ ){
                    mqo_set_cdr( mqo_pair_fv( mqo_cdr( tc ) ), x );
                    str = mqo_skip_space( str );
                    if( *str == ')' ){
                        str ++;
                        goto succ;
                    }else{
                        // More than one term follows '.' in a pair.
                        goto fail;
                    }
                }else{
                    // No term follows '.' in the pair.
                    goto fail;
                };
            }else{
                // No term precedes '.' in the pair.
                goto fail;
            }
        case ')':
            str ++;
            goto succ;
        case 0:
            mqo_parse_errmsg = mqo_em_endp;
            goto fail;
        default:
            x = mqo_parse_value( &str, r_succ );
            if( *r_succ ){
                mqo_tc_append( tc, x );
            }else{
                goto fail;
            }
        }
    }    
succ:
    *r_succ = 1;
    *r_str = str;

    return mqo_list_fv( mqo_car( tc ) );
fail:
    *r_succ = 0;
    return NULL;
}

mqo_value mqo_parse_value( char** r_str, mqo_boolean* r_succ ){
    char* str = mqo_skip_space( *r_str );
    char ch = *str;
    mqo_value x;
    
    if( ch == 0 ){
        *r_succ = 0;
        mqo_parse_errmsg = mqo_em_more;
    }else if( isdigit( ch )  || ch == '$' ){
        x = mqo_vf_integer( mqo_parse_int( &str, r_succ ) );
    }else if( ch == '-'|| ch == '+' ){
        if( isdigit( *( str + 1 ) ) ){
            x = mqo_vf_integer( mqo_parse_int( &str, r_succ ) );
        }else{
            mqo_symbol s = mqo_parse_sym( &str, r_succ );
            if( *r_succ ) x = mqo_vf_symbol( s );
        }
    }else if( ch == '(' ){
        x = mqo_vf_list( mqo_parse_list( &str, r_succ ) );
    }else if( ch == '"' ){
        mqo_string s = mqo_parse_str( &str, r_succ );
        if( *r_succ ) x = mqo_vf_string( s );
    }else{
        mqo_symbol s = mqo_parse_sym( &str, r_succ );
        if( *r_succ ) x = mqo_vf_symbol( s );
    }

    if( *r_succ ){
        *r_str = str;
        return x;
    }else{
        return mqo_vf_null();
    }
}

mqo_list mqo_parse_document( char* doc, mqo_boolean* r_succ ){
    mqo_pair tc = mqo_make_tc( );
    
    for(;;){
        doc = mqo_skip_space( doc );
        if( *doc ){
            mqo_value x = mqo_parse_value( &doc, r_succ );
            if( *r_succ ){
                mqo_tc_append( tc, x );
            }else{
                goto fail;
            }
        }else break;
    }
succ:
    *r_succ = 1;
    return mqo_list_fv( mqo_car( tc ) );
fail:
    *r_succ = 0;
    return NULL;
}
