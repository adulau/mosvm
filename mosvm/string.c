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

void mqo_show_string( mqo_string a, mqo_word* ct ){
    //TODO: Escape.
    mqo_writech( '"' );
    mqo_integer ln = mqo_string_length( a );
    if( ct ){
        if( *ct <( ln / 8 ) ){
            ln = ( *ct ) * 8;
            *ct = 0;
        }else{
            *ct -= ln / 8;
        }
    }
    mqo_writemem( a->data, ln );
    mqo_writech( '"' );
}
void mqo_show_symbol( mqo_symbol s, mqo_word* ct ){
    mqo_writesym( s );
}

mqo_tree mqo_lexicon = NULL;
// When new symbols are created from strings, a search is made of the lexicon
// for an equivalent string.

mqo_string mqo_string_fm( const void* s, mqo_integer sl ){
    mqo_string a = mqo_make_string( sl );
    memcpy( a->data, s, sl );
    a->data[sl+1] = 0;
    return a;
}
mqo_string mqo_string_fs( const char* s ){
    return mqo_string_fm( (const void*)s, strlen( s ) );
}
mqo_value mqo_symbol_key( mqo_value item ){
    return mqo_vf_string( mqo_symbol_fv( item )->string );
}
mqo_symbol mqo_symbol_fm( const void* s, mqo_integer sl ){
    mqo_pair lx;
    mqo_symbol sym;
    mqo_string str;
    mqo_node node; 

    str = mqo_string_fm( s, sl );
    
    node = mqo_tree_lookup( mqo_lexicon, mqo_vf_string( str ) );
    if( node ){ 
        GC_free( str );
        return mqo_symbol_fv( node->data ); 
    }else{
    
        sym = MQO_ALLOC( mqo_symbol, 0 );
        sym->string = str;
        sym->value = mqo_make_void();
        mqo_tree_insert( mqo_lexicon, mqo_vf_symbol( sym ) );
        return sym;
    }
}
mqo_symbol mqo_symbol_fs( const char* s ){
    return mqo_symbol_fm( s, strlen( s ) );
}
mqo_string mqo_make_string( mqo_integer length ){
    mqo_string s = MQO_AALLOC( mqo_string, length + 1 );
    s->length = length;
    return s;
}
mqo_integer mqo_string_compare( mqo_string a, mqo_string b ){
    //This will result in dictionary-style ordering of strings,
    //with case sensitivity.
    //
    //NOTE: Ideally, we would also use a string hash here to
    //      give us a second form of equality testing prior
    //      to degenerating into memcmp, but there's a point
    //      where performance optimizations must give way.

/*     
    mqo_integer al = mqo_string_length( a );
    mqo_integer bl = mqo_string_length( b );
    if( al == bl )return memcmp( mqo_sf_string( a ), 
                                 mqo_sf_string( b ),
                                 al );
    return al - bl;
*/
    
    mqo_integer al = mqo_string_length( a );
    mqo_integer bl = mqo_string_length( b );
    mqo_integer d = memcmp( mqo_sf_string( a ), 
                            mqo_sf_string( b ),
                            al < bl ? al : bl );

    return d ? d : ( al - bl );
}

mqo_boolean mqo_eqvs( mqo_string a, mqo_string b ){
    mqo_integer l = mqo_string_length( a );
    if( l != mqo_string_length( b ) )return 0;
    return ! memcmp( a->data, b->data, l );
}
