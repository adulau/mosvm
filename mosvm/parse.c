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
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <ctype.h>

mqo_value mqo_make_2list( mqo_symbol tag, mqo_value rest ){
    return mqo_vf_pair( mqo_cons( mqo_vf_symbol( tag ), 
                                  mqo_vf_pair( mqo_cons( rest, 
                                                         mqo_vf_empty()))));
}

void mqo_skip_junk( const char** pt ){
    char ch;
    
    for(;;){
        switch( ch = **pt ){
        case ' ':
        case '\r':
        case '\n':
        case '\t':
            (*pt) += strspn( *pt, " \n\r\t" );
            break;
        case ';':
            (*pt) += strcspn( *pt, "\n\r" );
            break;
        default:
            return;
        }
    }
}

mqo_integer mqo_parse_integer( const char** pt ){
    const char* og = *pt;
    mqo_integer r = strtol( og, (char**)pt, 10 );
    if( og == *pt ){
        mqo_errf( mqo_es_vm, "ss", "could not parse integer", og );
    }else{
        return r;
    }
}

mqo_string mqo_parse_string( const char** pt ){
    //PT should point to the leading '"'.

    (*pt)++;
    const char* og = *pt;
    char ch;
    mqo_integer ct = 0;

    for(;;){
        ch = *((*pt)++);
        if( ch == '\0' ){
            mqo_errf( mqo_es_vm, "ss", "unterminated string", og - 1 );
        }else if( ch == '\"' ){
            break;
        }else if( ch == '\\' ){
            if( *((*pt)++) == 0 ){
                mqo_errf( mqo_es_vm, "ss", "unterminated string", og - 1 );
            }
        }
        ct += 1;
    }
   
    mqo_integer ln = ct;
    mqo_string str = mqo_make_string( ct );

    char* ptr = mqo_sf_string( str ); ct = 0;
    for(;;){
        ch = og[ct++];
        if( ch == '\\' ){
            switch( ch = og[ct++] ){
            case 'r': ch = '\r'; break;
            case 'n': ch = '\n'; break;
            case 't': ch = '\t'; break;
            }
        }else if( ch == '\"' ){
            break;
        }
        *(ptr++) = ch;
    }
    *ptr = 0;
    str->length = ln;
    return str;
}
mqo_symbol mqo_parse_symbol( const char** pt ){
    const char* og = *pt;
    char ch;
    mqo_integer ix, len = 0;
    
    len = strcspn( *pt, " \r\n\t();" );
    *pt = (*pt) + len;
   
    return mqo_symbol_fm( og, len );
}
mqo_pair mqo_parse_list( const char** pt ){
    //PT should point to the leading '('.
    const char* og = *pt;
    char ch;
    (*pt)++;
    mqo_tc tc = mqo_make_tc();
    for(;;){
        mqo_skip_junk( pt );
        ch = **pt;
        if( ch == '\0' ){
            mqo_errf( mqo_es_vm, "ss", "unterminated list", og );
        }else if( ch == '.' ){
            if( mqo_is_empty( mqo_car( tc ) ) ){
                mqo_errf( mqo_es_vm, "ss", 
                          "dot encountered without car", og );
            }else{
                (*pt)++;
                mqo_skip_junk( pt );
                mqo_set_cdr( mqo_pair_fv( mqo_cdr( tc ) ), 
                             mqo_parse_value( pt ) );
                for(;;){
                    mqo_skip_junk( pt );
                    ch = **pt;
                    if( ch == ')' ){
                        (*pt)++;
                        return mqo_pair_fv( mqo_car( tc ) );
                    }else if( ch == '\0' ){
                        mqo_errf( mqo_es_vm, "ss", 
                                  "unterminated list", og - 1 );
                    }else{
                        mqo_errf( mqo_es_vm, "ss",
                                  "expected close paren after dotted value",
                                  og );
                    }
                }
            }
        }else if( ch == ')' ){
            (*pt)++;
            break;
        }else{
            mqo_tc_append( tc, mqo_parse_value( pt ) );
        }    
    }
    return mqo_pair_fv( mqo_car( tc ) );
}

mqo_value mqo_parse_value( const char** pt ){
    const char* og = *pt;
    char ch;
    
    mqo_skip_junk( pt );
    ch = **pt;

    switch( ch ){
    case '"':
        return mqo_vf_string( mqo_parse_string( pt ) );
    case '\'':
        (*pt)++;
        return mqo_make_2list( mqo_sym_quote, mqo_parse_value( pt ) );
    case '`':
        (*pt)++;
        return mqo_make_2list( mqo_sym_quasiquote, mqo_parse_value( pt ) ) ;
    case ',':
        (*pt)++;
        ch = **pt;
        if( ch == '@' ){
            (*pt)++;
            return mqo_make_2list( mqo_sym_unquote_splicing, 
                                   mqo_parse_value( pt ) );
        }else{
            return mqo_make_2list( mqo_sym_unquote, mqo_parse_value( pt ) );
        }
    case '#':
        (*pt)++;
        ch = **pt;
        switch( ch ){
        case 't':
            (*pt)++;
            return mqo_vf_true( );
        case 'f':
            (*pt)++;
            return mqo_vf_false();
        default:
            mqo_errf( mqo_es_vm, 
                    "ss", 
                    "the only #notations mosvm understands"
                    " are #t and #f", og );
        }
    case '(':
        return mqo_vf_pair( mqo_parse_list( pt ) );
    case '+':
    case '-':
        if( isdigit( *((*pt)+1) ) ){
            return mqo_vf_integer( mqo_parse_integer( pt ) );
        }else{
            return mqo_vf_symbol( mqo_parse_symbol( pt ) );
        }
    case '\0':
        mqo_errf( mqo_es_vm, "ss", "no value found in", og );
    case ')':
        mqo_errf( mqo_es_vm, "ss", "unmatched ) found in", og );
    default:
        if( isdigit( *((*pt)) ) ){
            return mqo_vf_integer( mqo_parse_integer( pt ) );
        }else{
            return mqo_vf_symbol( mqo_parse_symbol( pt ) );
        }
    }
}

mqo_pair mqo_parse_exprs( const char* og ){
    const char** pt = &og;
    mqo_tc tc = mqo_make_tc( );

    for(;;){
        mqo_skip_junk( pt );
    
        if( (**pt) == '\0' ){
            return mqo_pair_fv( mqo_car( tc ) );
        }else{
            mqo_tc_append( tc, mqo_parse_value( pt ) );
        };
    }
}

mqo_symbol mqo_sym_quote;
mqo_symbol mqo_sym_quasiquote;
mqo_symbol mqo_sym_unquote;
mqo_symbol mqo_sym_unquote_splicing;

void mqo_init_parse_subsystem( ){
    mqo_sym_quote = mqo_symbol_fs( "quote" );
    mqo_sym_quasiquote = mqo_symbol_fs( "quasiquote" );
    mqo_sym_unquote = mqo_symbol_fs( "unquote" );
    mqo_sym_unquote_splicing = mqo_symbol_fs( "unquote-splicing" );
}

