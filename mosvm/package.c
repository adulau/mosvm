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

#define PKG_IOBJ    0
#define PKG_PAIR    1
#define PKG_PROC    2
#define PKG_LIST    3
#define PKG_STR     4
#define PKG_SYM     5

mqo_symbol mqo_es_pkg;

const char* mqo_mem_underflow = "memory underflow";

static inline mqo_boolean is_thaw_imm( mqo_word w ){ return w >= 0x8000; }
static inline mqo_word thaw_imm( mqo_word w ){ return w - 0x8000; }
static inline mqo_boolean is_thaw_ref( mqo_word w ){
    if( is_thaw_imm( w ) )return 0;
    return w < 0x7FFC;
}

mqo_value mqo_thaw_mem( const void* mem, mqo_quad memlen ){
    mqo_quad   memix  = 0;
    mqo_vector values = NULL;
    
    void err( const char* m ){ mqo_errf( mqo_es_pkg, "s", m ); };
                               

    const void* next_block( mqo_word len ){
        const char* p = mem + memix;
        memix += len;
        if( memix > memlen )err( mqo_mem_underflow );
        return p;
    }

    mqo_byte next_byte( ){
        return *(mqo_byte*)next_block( 1 );
    }
    mqo_word next_word( ){
        return ntohs( *(mqo_word*)next_block( 2 ) );
    }
    mqo_quad next_quad( ){
        return ntohl( *(mqo_quad*)next_block( 4 ) );
    }
    
    mqo_word   record_ct = next_word( );
    
    mqo_value vf_word( mqo_word w ){
        if( is_thaw_imm( w ) )return mqo_vf_integer( w - 0x8000 );
        if( w == 0x7FFF ) return mqo_vf_null( );
        if( w == 0x7FFD ) return mqo_vf_false( );
        if( w == 0x7FFC ) return mqo_vf_true( );
        return mqo_vector_get( values, w );
    };

    if( ! is_thaw_ref( record_ct ) ) return vf_word( record_ct );

    values = mqo_make_vector( record_ct );
   
    mqo_word record_ix = 0;
    mqo_word ln;

    while( record_ix < record_ct ){
        switch( next_byte() ){
        case PKG_IOBJ:  // Integer
            mqo_vector_put( values, record_ix, mqo_vf_integer( next_quad() ) ); 
            break;
        case PKG_PAIR:  // Pair
            next_word(); 
            next_word();
            mqo_vector_put( 
                values, record_ix, 
                mqo_vf_pair( mqo_cons( mqo_vf_null(), mqo_vf_null() ) ) );
            break;
        case PKG_PROC: // Procedure
            // Vicious, dirty.. We assume the procedure is probably much
            // longer than it is..
            ln = next_word();
            next_block( ln );
            mqo_vector_put( 
                values, record_ix, 
                mqo_vf_procedure( mqo_make_procedure( ln ) ) ); 
            break;
        case PKG_LIST: // List
            ln = next_word();
            next_block( ln * 2 );
            mqo_vector_put( 
                values, record_ix, 
                mqo_vf_pair( mqo_cons( mqo_vf_null(), mqo_vf_null() ) ) );
            break;
        case PKG_STR: // String
            ln = next_word();
            mqo_vector_put(
                values, record_ix,
                mqo_vf_string( mqo_string_fm( next_block(ln), ln ) ) );
            break;
        case PKG_SYM: // Symbol
            ln = next_word();
            mqo_vector_put( 
                values, record_ix, 
                mqo_vf_symbol( mqo_symbol_fm( next_block(ln), ln ) ) );
            break;
        default:
            err( "bad record type" );
        }
        record_ix ++;
    }

    mqo_pair pair, next;
    mqo_word ix;

    memix = 0; record_ix = 0; next_word();
    
    while( record_ix < record_ct ){
        switch( next_byte() ){
        case PKG_IOBJ:  // Integer
            break;
        case PKG_PAIR:  // Pair
            pair = mqo_pair_fv( mqo_vector_get( values, record_ix ) );
            mqo_set_car( pair, vf_word( next_word() ) );
            mqo_set_cdr( pair, vf_word( next_word() ) );
            break;
        case PKG_PROC: // Procedure
            // Vicious, dirty.. We assume the procedure is probably much
            // longer than it is..
            ; // For some reason, GCC bails if this isn't here..
            mqo_procedure proc = mqo_procedure_fv( 
                mqo_vector_get( values, record_ix )
            );
            ix = 0; ln = next_word() + memix;  
            while( memix < ln ){
                mqo_byte op = next_byte();
                if( op > mqo_max_opcode )err( "invalid opcode" );
                mqo_primitive prim = mqo_instr_table[ op ];
                proc->inst[ix].prim = prim; 

                if( prim->a ){
                    proc->inst[ix].a = vf_word( next_word() );
                };
                if( prim->b ){
                    proc->inst[ix].b = vf_word( next_word() );
                };

                ix++;
            };
            proc->length = ix; // Ugly like a stomach pump..
            break;
        case PKG_LIST: // List
            pair = mqo_pair_fv( mqo_vector_get( values, record_ix ) );
            ln = next_word();
            while( ln ){
                ln --;

                if( ln ){ 
                    next = mqo_cons( mqo_vf_null(), mqo_vf_null() );
                }else{ 
                    next = NULL;
                };

                mqo_set_car( pair, vf_word( next_word() ) );
                mqo_set_cdr( pair, mqo_vf_list( next ) );

                pair = next;
            }
            break;
        case PKG_STR: // String
            next_block( next_word( ) );
            break;
        case PKG_SYM: // Symbol
            next_block( next_word( ) );
            break;
        default:
            err( "bad record type" );
        }
        record_ix ++;
    }

    mqo_value result = mqo_vector_get( values, 0 );
    return result;
}

mqo_string mqo_freeze( mqo_value root ){
    mqo_integer item_ct = 0;
    mqo_dict      index = mqo_make_tree( mqo_dict_key );
    mqo_pair      items = mqo_make_tc( );

    mqo_boolean inlineq( mqo_value value ){
        if( mqo_is_integer( value ) ){
            mqo_integer x = mqo_integer_fv( value );
            return ( x >= 0 ) && ( x < 0x8000 );
        }else return mqo_is_boolean( value ) ||
                     mqo_is_null( value );
    }
    
    void dissect( mqo_value value ){
        // We have already found this value.
        if( inlineq( value ) )return;
        if( mqo_tree_lookup( index, value ) )return;
        
        mqo_tree_insert( index, 
                         mqo_vf_pair( 
                            mqo_cons( value, mqo_vf_integer( item_ct ) ) ) );
        mqo_tc_append( items, value );
        item_ct ++;

        if( mqo_is_pair( value ) ){
            // Add the car and cdr as work.
            // NOTE: We should analyze this for list compression..
            mqo_pair pair = mqo_pair_fv( value );
            dissect( mqo_car( pair ) );
            dissect( mqo_cdr( pair ) );
        }else if( mqo_is_string( value ) ){
            // Do nothing -- strings do not contain references.
        }else if( mqo_is_symbol( value ) ){
            // Do nothing -- symbols do not contain references.
        }else if( mqo_is_procedure( value ) ){
            // Hoo boy. Here we go..
            mqo_procedure proc = mqo_procedure_fv( value );
            mqo_integer i, l = proc->length;
            for( i = 0; i < l; i ++ ){
                dissect( proc->inst[i].a );
                dissect( proc->inst[i].b );
            }
        }else{
            mqo_errf( mqo_es_pkg, "sx", "cannot package value", value );
        }
    }

    dissect( root );
    
    mqo_string pkg = mqo_make_string( 1024 );
    int i;
    mqo_value item;

    void write_ii( mqo_string buf, mqo_word x ){
        mqo_string_write_word( buf, x | 0x8000 );
    }
    void write_value( mqo_string buf, mqo_value v ){
        if( mqo_is_null( v ) ){
            return mqo_string_write_word( buf, 0x7FFF );
        }else if( mqo_is_true( v ) ){
            return mqo_string_write_word( buf, 0x7FFC );
        }else if( mqo_is_false( v ) ){
            return mqo_string_write_word( buf, 0x7FFD );
        }else if( mqo_is_integer( v ) ){
            int x = mqo_integer_fv( v );
            if(( x >= 0 ) && ( x < 0x8000 )){
                return write_ii( buf, x );
            }
        };

        mqo_string_write_word( buf, mqo_integer_fv( 
            mqo_cdr( mqo_pair_fv( mqo_tree_lookup( index, v )->data ) )
        ) );
    }

    items = mqo_list_fv( mqo_car( items ) );

    if( inlineq( root ) ){ 
        write_value( pkg, root ); 
    }else{
        mqo_string_write_word( pkg, item_ct );

        for( i = 0; i < item_ct; i ++ ){
            item = mqo_car( items );
            items = mqo_list_fv( mqo_cdr( items ) );
            if( mqo_is_integer( item ) ){
                mqo_string_write_byte( pkg, PKG_IOBJ );
                mqo_string_write_quad( pkg, mqo_integer_fv( item ) );
            }else if( mqo_is_pair( item ) ){
                //TODO: Detect Lists.
                mqo_string_write_byte( pkg, PKG_PAIR );
                write_value( pkg, mqo_car( mqo_pair_fv( item ) ) );
                write_value( pkg, mqo_cdr( mqo_pair_fv( item ) ) );
            }else if( mqo_is_procedure( item ) ){ 
                mqo_procedure proc = mqo_procedure_fv( item );
                mqo_string field = mqo_make_string( 1024 );
                int j, m = proc->length;
                for( j = 0; j < m; j ++ ){
                    mqo_primitive prim = proc->inst[j].prim;
                    mqo_string_write_byte( field, prim->code );
                    if( prim->a ) write_value( field, proc->inst[j].a );
                    if( prim->b ) write_value( field, proc->inst[j].b );
                }
                mqo_string_write_byte( pkg, PKG_PROC );
                mqo_string_write_word( pkg, mqo_string_length( field ) );
                mqo_string_write( pkg, mqo_string_head( field ), 
                                       mqo_string_length( field ) );
            }else if( mqo_is_string( item ) ){
                mqo_string_write_byte( pkg, PKG_STR );
                mqo_string s = mqo_string_fv( item );
                mqo_string_write_word( pkg, mqo_string_length( s ) );
                mqo_string_write( pkg, 
                                  mqo_sf_string( s ), mqo_string_length( s ) );
            }else if( mqo_is_symbol( item ) ){
                mqo_string_write_byte( pkg, PKG_SYM );
                mqo_string s = mqo_symbol_fv( item )->string;
                mqo_string_write_word( pkg, mqo_string_length( s ) );
                mqo_string_write( pkg, 
                                  mqo_sf_string( s ), mqo_string_length( s ) );
            }
        }
    }

    return mqo_string_fm( mqo_string_head( pkg ),
                          mqo_string_length( pkg ) );
}

void mqo_init_package_subsystem(){
    mqo_es_pkg = mqo_symbol_fs( "pkg" );
}