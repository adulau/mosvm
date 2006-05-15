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
#include <unistd.h>

void mqo_show( mqo_value v, mqo_word* ct );

void mqo_writemem( const void* mem, mqo_integer len ){
    write( STDOUT_FILENO, mem, len );
}
void mqo_write( const char* st ){
    mqo_writemem( st, strlen( st ) );
}
void mqo_writech( mqo_byte ch ){
    write( STDOUT_FILENO, &ch, 1 );
    // mqo_os_error( fputc( ch, stdout ) );
    // mqo_os_error( fflush( stdout ) ); 
}
void mqo_writeint( mqo_integer number ){
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
void mqo_hexnibble( char* dst, mqo_long digit ){
    if( digit > 9 ){
        *dst = 'A' + digit - 10;
    }else{
        *dst = '0' + digit;
    }
}
#define between( l, x, h ) (( (l) <= (x) )&&( (h) >= (x) ))

mqo_long mqo_parse_hexnibble( const char* src ){
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
mqo_long mqo_parse_hexbyte( const char* src ){
    return (( mqo_parse_hexnibble( src ) << 4  )
            + mqo_parse_hexnibble( src + 1 ));
}
mqo_long mqo_parse_hexword( const char* src ){
    return (( mqo_parse_hexnibble( src ) << 8  )
            + mqo_parse_hexnibble( src + 2 ));
}
mqo_long mqo_parse_hexlong( const char* src ){
    return (( mqo_parse_hexnibble( src ) << 16  )
            + mqo_parse_hexnibble( src + 4 ));
}
void mqo_hexbyte( char* dst, mqo_long byte ){
    mqo_hexnibble( dst, byte / 16 );
    mqo_hexnibble( dst + 1, byte % 16 );
}
void mqo_hexword( char* dst, mqo_long word ){
    mqo_hexbyte( dst, word / 256 );
    mqo_hexbyte( dst + 2, word % 256 );
}
void mqo_hexquad( char* dst, mqo_long word ){
    mqo_hexword( dst, word / 65536 );
    mqo_hexword( dst + 4, word % 65536 );
}
void mqo_writehex( mqo_long number ){
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
void mqo_writestr( mqo_string s ){
    if( s )mqo_write( mqo_sf_string( s ) );
}
void mqo_writesym( mqo_symbol s ){
    if( s )mqo_writestr( s->string );
}
void mqo_write_address( mqo_integer i ){
    //TODO: Replace.
    if( i ){
        mqo_writehex( (mqo_long)i );
    }else{
        mqo_write( "null" );
    }
}
void mqo_newline( ){
    mqo_writech( '\n' );
}
void mqo_space( ){
    mqo_writech( ' ' );
}
void mqo_show_unknown( mqo_type type, mqo_integer data ){
    mqo_writech( '[' );
    mqo_writesym( type->name );
    mqo_space( );
    mqo_write_address( data );
    mqo_writech( ']' );
}
void mqo_show( mqo_value v, mqo_word* ct ){
    mqo_type t = mqo_value_type( v );
    if( t->mt_show ){ 
        t->mt_show( (void*)v.data, ct ); 
    }else if( mqo_isa_quark( v ) ){
        mqo_write( "[" );
        mqo_writesym( mqo_value_type( v )->name );
        mqo_write( "]" );
    }else{ 
        mqo_show_unknown( t, v.data );
    }
}
