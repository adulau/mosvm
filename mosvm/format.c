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

// FORMAT.C -------------------------------------------------------------------
void mqo_format_char( mqo_string buf, char ch ){
    mqo_string_append_byte( buf, ch );
}
void mqo_format_nl( mqo_string buf ){
#if defined(_WIN32)||defined(__CYGWIN__)
    mqo_format_char( buf, '\r' );
#endif
    mqo_format_char( buf, '\n' );
}
void mqo_format_hexnibble( mqo_string buf, mqo_quad digit ){
    if( digit > 9 ){
        mqo_format_char( buf, 'A' + digit - 10 );
    }else{
        mqo_format_char( buf, '0' + digit );
    }
}
void mqo_format_hexbyte( mqo_string buf, mqo_quad byte ){
    mqo_format_hexnibble( buf, byte / 16 );
    mqo_format_hexnibble( buf, byte % 16 );
}
void mqo_format_hexword( mqo_string buf, mqo_quad word ){
    mqo_format_hexbyte( buf, word / 256 );
    mqo_format_hexbyte( buf + 2, word % 256 );
}
void mqo_format_hexquad( mqo_string buf, mqo_quad word ){
    mqo_format_hexword( buf, word / 65536 );
    mqo_format_hexword( buf + 4, word % 65536 );
}
void mqo_format_indent( mqo_string buf, mqo_integer depth ){
    while( ( depth-- ) > 0 ) mqo_format_char( buf, ' ' );
}
void mqo_format_dec( mqo_string str, mqo_quad number ){
    static char buf[256];
    buf[255] = 0;
    int i = 255;

    do{
        buf[ --i ] = '0' + number % 10;
    }while( number /= 10 );
   
    mqo_string_append( str, buf + i, 255 - i );
};
void mqo_format_int( mqo_string str, mqo_integer number ){
    if( number < 0 ){
        mqo_format_char( str, '-' );
        number = -number;
    }
    mqo_format_dec( str, number );
}
void mqo_format_hex( mqo_string str, mqo_quad number ){
    static char buf[256];
    buf[255] = 0;
    int i = 255;
    
    do{
        int digit = number % 16;
        if( digit > 9 ){
            buf[ -- i ] = 'A' + digit - 10;
        }else{
            buf[ --i ] = '0' + digit;
        }
    }while( number /= 16 );
   
    mqo_string_append( str, buf + i, 255 - i ); 
}
void mqo_format_str( mqo_string buf, mqo_string s ){
    mqo_string_append( buf, mqo_sf_string( s ), mqo_string_length( s ) );
}
void mqo_format_sym( mqo_string buf, mqo_symbol s ){
    mqo_format_str( buf, s->string );
}
void mqo_format_addr( mqo_string buf, mqo_integer i ){
    //TODO: Replace.
    if( i ){
        mqo_format_hex( buf, (mqo_quad)i );
    }else{
        mqo_format_cs( buf, "null" );
    }
}
void mqo_format_cs( mqo_string buf, const char* c ){
    mqo_string_append( buf, c, strlen( c ) );
}
void mqo_format_begin( mqo_string buf, void* oo ){
    mqo_object o = (mqo_object)oo; 
    mqo_format_char( buf, '[' );
    mqo_format( buf, o->type->name );
}
void mqo_format_end( mqo_string buf ){
    mqo_format_char( buf, ']' );
}
void mqo_format( mqo_string s, mqo_value v ){
    mqo_type t = mqo_value_type( v );

    if( t && t->format ){
        t->format( s, v );
    }else{
        mqo_generic_format( s, v );
    }
}
mqo_string mqo_formatf( char* fmt, ... ){
    va_list ap;
    mqo_string buf = mqo_make_string( 64 );
    va_start( ap, fmt );
    char* ptr = fmt;
    for(;;){
        switch( *(ptr++) ){
        case 's':
            mqo_format_cs( buf, va_arg( ap, const char* ) );
            break;
        case 'x':
            mqo_format( buf, va_arg( ap, mqo_value ) );
            break;
        case 'i':
            mqo_format_int( buf, va_arg( ap, mqo_integer ) );
            break;
        case 'a':
            mqo_format_addr( buf, va_arg( ap, mqo_quad ) );
            break;
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
