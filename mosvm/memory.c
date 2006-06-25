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

#ifdef _WIN32
#include <malloc.h>
#endif

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

#define MQO_MIN_TOLERANCE 1024
#define MQO_MAX_TOLERANCE 16384
#define MQO_MAX_SCRAP     16384

mqo_quad mqo_new_tolerance = MQO_MIN_TOLERANCE;
mqo_quad mqo_new_objects = 0;

void mqo_discard( mqo_object obj, mqo_pool pool ){
    mqo_unpool_obj( obj );

    if( pool->count < MQO_MAX_SCRAP ){
        mqo_pool_obj( obj, pool );
        pool->count ++;
    }else{
        free( obj );
    }
}
mqo_object mqo_scavenge( mqo_type type, mqo_pool pool, mqo_quad size ){
    mqo_object obj;

    if( pool->head ){
        obj = pool->head;
        mqo_unpool_obj( obj );
#ifdef _WIN32
        memset( obj, 0, size );
#else
        bzero( obj, size );
#endif
        obj->type = type;
        mqo_pool_obj( obj, mqo_blacks );
        //mqo_printf( "sxn", "Hit for ", type );
        pool->count --;
        return obj;
    }else{
        //mqo_printf( "sxn", "Miss for ", type );
        return mqo_objalloc( type, size );
    }
}
mqo_object mqo_objalloc( mqo_type type, mqo_quad size ){
    #ifdef MQO_COUNT_GC
    mqo_object_ct ++;
    #endif
    
    mqo_new_objects++;

    assert( size >= sizeof( struct mqo_object_data ) );

    mqo_object obj = (mqo_object) malloc( size );
    //TODO: Remove all inits of = NULL;
#ifdef _WIN32
        memset( obj, 0, size );
#else
        bzero( obj, size );
#endif

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
    
    mqo_new_tolerance++;

    mqo_unpool_obj( obj );
    mqo_pool_obj( obj, mqo_greys );
}

void mqo_trace_object( mqo_object obj ){
    mqo_grey_obj( (mqo_object)obj->type );
    obj->type->trace( obj );
}
//mqo_integer mqo_since = 0;
void mqo_collect_window( ){
    //mqo_since ++;
    if( mqo_new_objects > mqo_new_tolerance )mqo_collect_garbage( );
}
void mqo_collect_garbage( ){
    //printf( "Beginning GC at %i; old %i v. new %i..\n", mqo_since, mqo_old_objects, mqo_new_objects );
    mqo_object obj;

    mqo_new_tolerance = mqo_new_objects = 0;

    for( obj = mqo_roots->head; obj; obj = obj->next ){
        mqo_new_tolerance++;
        mqo_trace_object( obj );
    }
    
    mqo_trace_registers();
    mqo_trace_actives();
    mqo_trace_network();
    mqo_trace_timeouts();

    while( obj = mqo_greys->head ){
        mqo_new_tolerance++;
        mqo_unpool_obj( obj );
        mqo_pool_obj( obj, mqo_whites );
        mqo_trace_object( obj );
    }
    
    while( obj = mqo_blacks->head ){
        obj->type->free( obj );    
    }
    
    mqo_pool temp = mqo_whites;
    mqo_whites = mqo_blacks;
    mqo_blacks = temp;

    //printf( ".. GC Complete, kept %i..\n", mqo_old_objects );

    if( mqo_new_tolerance < MQO_MIN_TOLERANCE ){
        mqo_new_tolerance = MQO_MIN_TOLERANCE;
    }else if( mqo_new_tolerance > MQO_MAX_TOLERANCE ){
        mqo_new_tolerance = MQO_MAX_TOLERANCE;
    }
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

mqo_type mqo_make_type( mqo_value name, mqo_type parent ){
    mqo_type direct, type = MQO_OBJALLOC( type );

    if(! parent ){
    }else if(! parent->direct ){
        type->direct = parent;
        direct = parent;
    }else{
        type->direct = parent->direct;
    }

    type->name = name;
    type->parent = parent;

    return type;
}

void mqo_trace_type( mqo_type type ){
    mqo_grey_obj( (mqo_object) type->parent );
    mqo_grey_obj( (mqo_object) type->direct );
    mqo_grey_obj( (mqo_object) type->name );
}

void mqo_format_type( mqo_string buf, mqo_type type ){
    mqo_string_append_byte( buf, '<' );
    //TODO: Clean up -- type->name type should be symbol..
    mqo_string_append_sym( buf, mqo_symbol_fv( type->name ) );
    mqo_string_append_byte( buf, '>' );
}

void mqo_generic_format( void* bbuf, mqo_value value ){
    mqo_string buf = bbuf; 
    mqo_format_begin( buf, mqo_obj_fv( value ) );
    mqo_string_append_byte( buf, ' ' );
    mqo_string_append_addr( buf, value );
    mqo_format_end( buf );
}

MQO_GENERIC_COMPARE( type );
MQO_GENERIC_FREE( type );
MQO_C_TYPE( type );

void mqo_format_null( mqo_string buf, mqo_value null ){
    mqo_string_append_cs( buf, "null" );
}

MQO_GENERIC_COMPARE( null );
MQO_GENERIC_GC( null );
MQO_C_TP( null );

MQO_GENERIC_COMPARE( imm );
MQO_GENERIC_GC( imm );

void mqo_format_imm( mqo_string s, mqo_quad imm ){ 
    mqo_string_append_unsigned( s, imm >> 1 ); 
};

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

MQO_BEGIN_PRIM( "null?", nullq )
    REQ_ANY_ARG( value );
    NO_REST_ARGS( );
    BOOLEAN_RESULT( mqo_is_null( value ) );
MQO_END_PRIM( nullq )

void mqo_init_memory_subsystem( ){
    mqo_imm_type = mqo_number_type;
    mqo_string_type->format = (mqo_format_mt)mqo_format_string;
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
        *found = 1;
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
