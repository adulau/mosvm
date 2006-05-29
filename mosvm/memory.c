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
#include <string.h>

void mqo_unpool_obj( mqo_object obj ){
    if( obj->pool ){
        if( obj->prev ){
            obj->prev->next = obj->next;
        }else{
            obj->pool->head = obj->next;
        };

        if( obj->next ){
            obj->next->prev = obj->prev;
        };
    }
}

void mqo_pool_obj( mqo_object obj, mqo_pool pool ){
    obj->pool = pool;
    obj->prev = NULL;
    obj->next = pool->head;
    if( obj->next ) obj->next->prev = obj;
    pool->head = obj;
}

#ifdef MQO_COUNT_GC
mqo_quad mqo_object_ct = 0;
#endif

#define MQO_MIN_OLDS 4096

mqo_quad mqo_old_objects = MQO_MIN_OLDS;
mqo_quad mqo_new_objects = 0;

mqo_object mqo_objalloc( mqo_type type, mqo_quad size ){
    #ifdef MQO_COUNT_GC
    mqo_object_ct ++;
    #endif
    
    mqo_new_objects++;

    assert( size >= sizeof( struct mqo_object_data ) );

    mqo_object obj = (mqo_object) malloc( size );
    //TODO: Remove all inits of = NULL;
    bzero( obj, size );

    //TODO: MQO_RESTORE: if(! obj )mqo_errf( mqo_es_mem, "sxi", "out of memory", type, size );
    assert( obj );
    obj->type = type;

    mqo_pool_obj( obj, mqo_blacks );
    // assert( ! ( ((mqo_quad)obj) & 1 ) );
    return obj;
}

void mqo_objfree( void* obj ){
    #ifdef MQO_COUNT_GC
    mqo_object_ct --;
    #endif
    
    mqo_unpool_obj( (mqo_object) obj );
    free( obj );
}

void mqo_root_obj( mqo_object obj ){
    if( obj == NULL )return;
    assert( obj->type );
    //TODO: Assertions against rooting during garbage collection.
    mqo_unpool_obj( obj );
    mqo_pool_obj( obj, mqo_roots );
}

void mqo_grey_obj( mqo_object obj ){
    if( obj == NULL )return;

    mqo_pool pool = obj->pool;
    if( pool == mqo_greys )return;
    if( pool == mqo_whites )return;
    if( pool == mqo_roots )return;
    
    mqo_old_objects ++;

    mqo_unpool_obj( obj );
    mqo_pool_obj( obj, mqo_greys );
}

void mqo_trace_object( mqo_object obj ){
    mqo_grey_obj( (mqo_object)obj->type );
    obj->type->trace( obj );
}

void mqo_collect_window( ){
    if( mqo_new_objects > mqo_old_objects )mqo_collect_garbage( );
}
void mqo_collect_garbage( ){
    mqo_object obj;
    /*
    mqo_print( "Tracing " );
    mqo_printint( mqo_old_objects );
    mqo_print( " v. " );
    mqo_printint( mqo_new_objects );
    mqo_newline( );
    */

    mqo_old_objects = mqo_new_objects = 0;
    // printf( "Before Tracing Roots:\n" );
    // printf( "    ROOTS?: %s\n", mqo_roots->head ? "YES" : "NO" );
    // printf( "    GREYS?: %s\n", mqo_greys->head ? "YES" : "NO" );
    // printf( "    BLACKS?: %s\n", mqo_blacks->head ? "YES" : "NO" );
    // printf( "    WHITES?: %s\n", mqo_whites->head ? "YES" : "NO" );

    // printf( "Tracing roots" );

    for( obj = mqo_roots->head; obj; obj = obj->next ){
        mqo_trace_object( obj );
    }
    
    mqo_trace_registers();
    mqo_trace_actives();
    mqo_trace_network();
    // printf( "\n" );

    // printf( "Before Tracing Greys:\n" );
    // printf( "    ROOTS?: %s\n", mqo_roots->head ? "YES" : "NO" );
    // printf( "    GREYS?: %s\n", mqo_greys->head ? "YES" : "NO" );
    // printf( "    BLACKS?: %s\n", mqo_blacks->head ? "YES" : "NO" );
    // printf( "    WHITES?: %s\n", mqo_whites->head ? "YES" : "NO" );

    // printf( "Tracing greys" );

    while( obj = mqo_greys->head ){
        mqo_unpool_obj( obj );
        mqo_pool_obj( obj, mqo_whites );
        mqo_trace_object( obj );
    }
    
    // printf( "\n" );

    // printf( "Before Freeing Blacks:\n" );
    // printf( "    ROOTS?: %s\n", mqo_roots->head ? "YES" : "NO" );
    // printf( "    GREYS?: %s\n", mqo_greys->head ? "YES" : "NO" );
    // printf( "    BLACKS?: %s\n", mqo_blacks->head ? "YES" : "NO" );
    // printf( "    WHITES?: %s\n", mqo_whites->head ? "YES" : "NO" );
    
    // printf( "Freeing" );
    while( obj = mqo_blacks->head ){
        obj->type->free( obj );    
    }
    // printf( "\n" );
    
    mqo_pool temp = mqo_whites;
    mqo_whites = mqo_blacks;
    mqo_blacks = temp;

    if( mqo_old_objects < MQO_MIN_OLDS ) mqo_old_objects = MQO_MIN_OLDS;
}

void mqo_generic_trace( mqo_object obj ){}
void mqo_generic_free( mqo_object obj ){ mqo_objfree( obj ); }

struct mqo_pool_data mqo_blacks_data = { NULL };
mqo_pool mqo_blacks = &( mqo_blacks_data );

struct mqo_pool_data mqo_greys_data = { NULL };
mqo_pool mqo_greys = &( mqo_greys_data );

struct mqo_pool_data mqo_whites_data = { NULL };
mqo_pool mqo_whites = &( mqo_whites_data );

struct mqo_pool_data mqo_roots_data = { NULL };
mqo_pool mqo_roots = &( mqo_roots_data );

void mqo_root_object( mqo_object obj ){
    mqo_unpool_obj( obj );
}

mqo_type mqo_make_type( mqo_value name, mqo_type parent, mqo_value info ){
    mqo_type direct, type = MQO_OBJALLOC( type );

    if(! parent ){
        direct = NULL;
    }else if(! parent->direct ){
        direct = parent;
    }else{
        direct = parent->direct;
    }

    type->direct = direct;
    type->name = name;
    type->parent = parent;
    type->info = info;

    return type;
}

void mqo_trace_type( mqo_type type ){
    mqo_grey_obj( (mqo_object) type->parent );
    mqo_grey_obj( (mqo_object) type->direct );
    mqo_grey_obj( (mqo_object) type->name );
    mqo_grey_val( type->info );
}

void mqo_show_type( mqo_type type, mqo_word* ct ){
    mqo_printch( '<' );
    mqo_show( type->name, ct );

    if( mqo_is_null( type->info ) ){
    }else if( *ct == 0 ){
        mqo_print( " ...");
    }else if( mqo_is_null( type->info ) ){
        // Do nothing.
    }else if( mqo_is_pair( type->info ) ){
        mqo_show_list_contents( mqo_pair_fv( type->info ), ct );
    }else{
        mqo_print( " . " );
        mqo_show( type->info, ct );
    }

    mqo_printch( '>' );
}

void mqo_generic_show( mqo_value value, mqo_word* ct ){
    mqo_begin_showtag( value );
    mqo_end_showtag( value );
}

MQO_GENERIC_COMPARE( type );
MQO_GENERIC_FREE( type );
MQO_C_TYPE( type );

void mqo_show_null( mqo_value null, mqo_word* ct ){
    mqo_print( "null" );
}

MQO_GENERIC_COMPARE( null );
MQO_GENERIC_GC( null );
MQO_C_TP( null );

MQO_GENERIC_COMPARE( imm );
MQO_GENERIC_GC( imm );
void mqo_show_imm( mqo_integer imm, void* ct ){ mqo_printint( imm >> 1 ); };

struct mqo_type_data mqo_imm_type_data = { 
    {NULL, NULL, NULL, NULL }, NULL, NULL 
};
mqo_type mqo_imm_type = &mqo_imm_type_data;

void mqo_bind_type( const char* name, mqo_type type ){
    int namelen = strlen( name );
    char* buf = alloca( namelen + 2 );
    memcpy( buf + 1, name, namelen );
    buf[0] = '<';
    buf[namelen + 1] = '>';
    mqo_symbol sym = mqo_symbol_fm( buf, namelen + 2 );
    mqo_set_global( sym, mqo_vf_type( type ) );
    type->name = mqo_vf_symbol( mqo_symbol_fs( name ) );
}

mqo_integer mqo_cmp_eqv( mqo_value a, mqo_value b ){
    mqo_type at, bt;

    if( mqo_is_number( a ) ){
        at = mqo_number_type;
    }else{
        at = mqo_value_type( a );
    };

    if( mqo_is_number( b ) ){
        bt = mqo_number_type;
    }else{
        bt = mqo_value_type( b );
    };
   
    if( at == bt )return at->compare( a, b ); 
    if( at < bt )return -1;
    if( at > bt )return +1;
    return 0;
}

mqo_integer mqo_cmp_eq( mqo_value a, mqo_value b ){
    if( a == b ) return 0;

    if( mqo_is_number( a ) && mqo_is_number( b ) ){
        return mqo_number_compare( a, b );
    }else if( mqo_is_string( a ) && mqo_is_string( b ) ){
        return mqo_string_compare( mqo_string_fv( a ), mqo_string_fv( b ) );
    };

    if( a < b )return -1;
    if( a > b )return +1;
}

mqo_integer mqo_compare_generic( mqo_value a, mqo_value b ){
    return a - b;
}

void mqo_init_memory_subsystem( ){
    mqo_imm_type = mqo_number_type;
    mqo_string_type->show = (mqo_show_mt)mqo_show_string;
    mqo_string_type->compare = (mqo_cmp_mt)mqo_string_compare;
    MQO_I_TYPE( type );
    MQO_I_TYPE( null );
    //TODO: bind *null* to mqo_vf_null
}
mqo_value mqo_req_any( ){
    if( mqo_arg_ptr ){
        mqo_value x = mqo_car( mqo_arg_ptr );
        mqo_arg_ptr = mqo_list_fv( mqo_cdr( mqo_arg_ptr ) );
        return x;
    }else{
        mqo_errf( mqo_es_vm, "s", "argument underflow" );
    }
}
mqo_value mqo_req_arg( mqo_type type ){
    mqo_value x = mqo_req_any( );
    if( mqo_value_type( x ) == type ){
        return x;
    }
    mqo_errf( mqo_es_vm, "sxx", "argument type mismatch", type, x );
}
mqo_value mqo_opt_any( mqo_boolean* found ){
    if( mqo_arg_ptr ){
        mqo_value x = mqo_car( mqo_arg_ptr );
        mqo_arg_ptr = mqo_list_fv( mqo_cdr( mqo_arg_ptr ) );
        return x;
    }else{
        *found = 0;
        return 0;
    }
}
mqo_value mqo_opt_arg( mqo_type type, mqo_boolean* found ){
    mqo_value x = mqo_opt_any( found );
    if( *found ){
        if( mqo_value_type( x ) == type ){
            return x;
        }
        mqo_errf( mqo_es_vm, "sxx", "argument type mismatch", type, x );
    }else{ 
        return 0;
    }
}
mqo_type mqo_direct_type( mqo_value value ){
    mqo_type type = mqo_value_type( value );
    return type->direct ? type->direct : type;
}
