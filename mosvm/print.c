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

void mqo_format_hexnibble( char* dst, mqo_quad digit ){
    if( digit > 9 ){
        *dst = 'A' + digit - 10;
    }else{
        *dst = '0' + digit;
    }
}

void mqo_format_hexbyte( char* dst, mqo_quad byte ){
    mqo_format_hexnibble( dst, byte / 16 );
    mqo_format_hexnibble( dst + 1, byte % 16 );
}
void mqo_format_hexword( char* dst, mqo_quad word ){
    mqo_format_hexbyte( dst, word / 256 );
    mqo_format_hexbyte( dst + 2, word % 256 );
}
void mqo_format_hexquad( char* dst, mqo_quad word ){
    mqo_format_hexword( dst, word / 65536 );
    mqo_format_hexword( dst + 4, word % 65536 );
}
void mqo_printmem( const void* mem, mqo_integer len ){
    while( len ){
       int rs = write( STDOUT_FILENO, mem, len );
       if( rs > 0 ){
          len -= rs;
       }else if( rs ){ break; }
    }
}
void mqo_print( const char* st ){
    mqo_printmem( st, strlen( st ) );
}
void mqo_printch( mqo_byte ch ){
    mqo_printmem( &ch, 1 );
    // mqo_os_error( fputc( ch, stdout ) );
    // mqo_os_error( fflush( stdout ) ); 
}
void mqo_indent( mqo_integer depth ){
    while( ( depth-- ) > 0 ) mqo_printch( ' ' );
    // mqo_os_error( fputc( ch, stdout ) );
    // mqo_os_error( fflush( stdout ) ); 
}
void mqo_printint( mqo_integer number ){
    static char buf[256];
    buf[255] = 0;
    int neg, i = 255;

    if( number < 0 ){
        neg = 1; number = -number;
    }else{
        neg = 0;
    }

    do{
        buf[ --i ] = '0' + number % 10;
    }while( number /= 10 );
   
    if( neg )buf[ -- i ] = '-';

    write( STDOUT_FILENO, buf + i, 255 - i ); 
};
void mqo_printhex( mqo_quad number ){
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
   
    write( STDOUT_FILENO, buf + i, 255 - i ); 
};
void mqo_printstr( mqo_string s ){
    if( s )mqo_print( mqo_sf_string( s ) );
}
void mqo_printsym( mqo_symbol s ){
    if( s )mqo_printstr( s->string );
}
void mqo_printaddr( mqo_integer i ){
    //TODO: Replace.
    if( i ){
        mqo_printhex( (mqo_quad)i );
    }else{
        mqo_print( "null" );
    }
}
void mqo_newline( ){
    mqo_printch( '\n' );
}
void mqo_space( ){
    mqo_printch( ' ' );
}
void mqo_show( mqo_value v, mqo_word* ct ){
    mqo_word x = 128;
    if( ct == NULL ) ct = &x;

    mqo_type t = mqo_value_type( v );

    if( *ct ){ 
        mqo_value_type( v )->show( v, ct );
    }else{ 
        x = 1;
        mqo_generic_show( v, &x ); 
    };
}
void mqo_begin_showtag( mqo_value o ){
    mqo_printch( '[' );
    mqo_word ct = 1; mqo_show( mqo_value_type( o )->name, &ct );
}
void mqo_end_showtag( ){
    mqo_printch( ']' );
}
mqo_quad mqo_parse_hexnibble( const char* src ){
#define between( l, x, h ) (( (l) <= (x) )&&( (h) >= (x) ))
    char ch = *src;
    if( between( 'A', ch, 'F' ) ){
        return ch - 'A' + 10;
    }else if( between( 'a', ch, 'f' ) ){
        return ch - 'a' + 10;
    }else{ //Assuming it's '0' to '9'
        assert( between( '0', ch, 'f' ) );
        return ch - '0';
    }
}
mqo_quad mqo_parse_hexbyte( const char* src ){
    return (( mqo_parse_hexnibble( src ) << 4  )
            + mqo_parse_hexnibble( src + 1 ));
}
mqo_quad mqo_parse_hexword( const char* src ){
    return (( mqo_parse_hexnibble( src ) << 8  )
            + mqo_parse_hexnibble( src + 2 ));
}
mqo_quad mqo_parse_hexlong( const char* src ){
    return (( mqo_parse_hexnibble( src ) << 16  )
            + mqo_parse_hexnibble( src + 4 ));
}

MQO_BEGIN_PRIM( "show", show )
    REQ_ANY_ARG( value );
    OPT_INTEGER_ARG( limit );
    NO_REST_ARGS( );
    
    if(! has_limit )limit = 100;

    mqo_word l = limit; mqo_show( value, &l );

    NO_RESULT( );
MQO_END_PRIM( show )

void mqo_init_print_subsystem( ){
    MQO_BIND_PRIM( show );
}
