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
#include <stdio.h>
#include <string.h>
#include <unistd.h>

// FORMAT.H -------------------------------------------------------------------
int mqo_format_item( mqo_string s, mqo_value v );
void mqo_format_value( 
    mqo_string s, mqo_value v, mqo_quad breadth, mqo_quad depth 
);

// FORMAT.C -------------------------------------------------------------------

void mqo_format_begin( mqo_string buf, void* oo ){
    mqo_object o = (mqo_object)oo; 
    mqo_string_append_byte( buf, '[' );
    //TODO: Gross assumption -- need to correct type->name type to symbol only
    mqo_string_append_sym( buf, mqo_symbol_fv( o->type->name ) );
}
void mqo_format_end( mqo_string buf ){
    mqo_string_append_byte( buf, ']' );
}

mqo_quad mqo_format_depth;
mqo_quad mqo_format_breadth;
mqo_quad mqo_format_re_breadth;

int mqo_format_item( mqo_string s, mqo_value v ){
    switch( mqo_format_breadth ){
    case 1:
        mqo_format_breadth --;
        mqo_string_append_cs( s, "..." );
    case 0:
        return 0;
    default:
        mqo_format_breadth --;
    }
    
    if( ! mqo_format_depth ){
        mqo_string_append_cs( s, "..." );
        return 0;
    }

    mqo_format_depth --;

    mqo_type t = mqo_value_type( v );
    mqo_quad end_breadth = mqo_format_breadth;
    mqo_format_breadth = mqo_format_re_breadth;
    
    if( t && t->format ){
        t->format( s, v );
    }else{
        mqo_generic_format( s, v );
    }
    
    mqo_format_breadth = end_breadth;
    mqo_format_depth ++;
}

void mqo_format_value( 
    mqo_string s, mqo_value v, mqo_quad breadth, mqo_quad depth 
){
    //printf( "BREADTH: %i, DEPTH: %i\n", breadth, depth );
    mqo_format_depth = depth;
    mqo_format_breadth = breadth;
    mqo_format_re_breadth = breadth;
    mqo_format_item( s, v );
}

mqo_string mqo_formatf( char* fmt, ... ){
    va_list ap;
    mqo_string buf = mqo_make_string( 64 );
    va_start( ap, fmt );
    char* ptr = fmt;
    for(;;){
        switch( *(ptr++) ){
        case 's':
            mqo_string_append_cs( buf, va_arg( ap, const char* ) );
            break;
        case 'x':
            mqo_format_value( buf, va_arg( ap, mqo_value ), 32, 3 );
            break;
        case 'i':
            mqo_string_append_signed( buf, va_arg( ap, mqo_integer ) );
            break;
        case 'a':
            mqo_string_append_addr( buf, va_arg( ap, mqo_quad ) );
            break;
        case 'n':
            mqo_string_append_newline( buf );
        case 0:
            goto done;
        default:
            va_end( ap );
            mqo_errf( mqo_es_vm, "ss", 
                      "mqo_formatf cannot process format string", fmt );
        }
    }
done:
    va_end( ap );
    return buf;
}
