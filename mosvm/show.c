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

void mqo_write( const char* st ){
    write( STDOUT_FILENO, st, strlen( st ) );
    //----
    // printf( "%s", st ); 
    //----
    // mqo_os_error( fputs( st, stdout ) );
    // mqo_os_error( fflush( stdout ) ); 
                         //For fuck's sake..  On some platforms putchar( '\n' )
                         //does not flush the buffer, despite ANSI C's
                         //requirement that stdout be line buffered.
                         //
                         //Less crack, people..
}
void mqo_writech( mqo_byte ch ){
    write( STDOUT_FILENO, &ch, 1 );
    // mqo_os_error( fputc( ch, stdout ) );
    // mqo_os_error( fflush( stdout ) ); 
}
void mqo_writeint( mqo_integer number ){
    static char buf[256];
    buf[255] = 0;
    int i = 255;
    
    do{
        buf[ --i ] = '0' + number % 10;
    }while( number /= 10 );
   
    write( STDOUT_FILENO, buf + i, 255 - i ); 
};
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
    if( s )mqo_write( s->data );
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
    }else if( mqo_isa_atom( v ) ){
        mqo_write( "[" );
        mqo_writesym( mqo_value_type( v )->name );
        mqo_write( "]" );
    }else{ 
        mqo_show_unknown( t, v.data );
    }
}
