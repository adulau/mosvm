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
 * along with this library; if not, print to the Free Software Foundation, 
 * Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA 
 */

#include "mosvm.h"

mqo_tag mqo_make_tag( mqo_symbol name, mqo_value info ){
    mqo_tag tag = MQO_OBJALLOC( tag );
    tag->name = name;
    tag->info = info;
    return tag;
}
void mqo_trace_tag( mqo_tag t ){
    mqo_grey_obj( (mqo_object)t->name );
    mqo_grey_val( t->info );
}
void mqo_format_tag( mqo_string buf, mqo_tag t ){
    mqo_format_char( buf, '<' );
    mqo_format_sym( buf, t->name );
    if( mqo_is_pair( t->info ) ){
        mqo_format_items( buf, mqo_pair_fv( t->info ), 1 )
    }else if( t->info ){
        mqo_format_cs( buf, " . " );
        mqo_format( buf, ct );
    }
    mqo_format_char( buf, '>' );
}
MQO_GENERIC_COMPARE( tag );
MQO_GENERIC_FREE( tag );
MQO_C_TYPE( tag );

mqo_cell mqo_make_cell( mqo_tag tag, mqo_value repr ){
    mqo_cell cell = MQO_OBJALLOC( cell );
    cell->tag = tag;
    cell->repr = repr;
    return cell;
}
void mqo_format_cell( mqo_string buf, mqo_cell c ){
    mqo_format_char( buf, '[' );
    mqo_format_sym( buf, c->tag->name );
    mqo_format_char( buf, ' ' );
    mqo_format( buf, c->repr );
    mqo_format_char( buf, ']' );
}
void mqo_trace_cell( mqo_cell c ){
    mqo_grey_obj( (mqo_object) c->tag );
    mqo_grey_val( c->repr );
}
mqo_integer mqo_cell_compare( mqo_cell a, mqo_cell b ){
    mqo_integer d = a->tag - b->tag;
    if( d )return d;
    return mqo_cmp_eqv( a->repr, b->repr ); 
}
MQO_GENERIC_FREE( cell );
MQO_C_TYPE( cell );

MQO_BEGIN_PRIM( "type-name", type_name )
    REQ_ANY_ARG( value );
    NO_REST_ARGS( );
    
    RESULT( mqo_is_tag( value ) ? mqo_vf_symbol( mqo_tag_fv( value )->name )
                                : mqo_req_type( value )->name );
MQO_END_PRIM( type_name )

MQO_BEGIN_PRIM( "type", xtype )
    REQ_ANY_ARG( value );
    NO_REST_ARGS( );

    if( mqo_is_cell( value ) ){
        TAG_RESULT( mqo_cell_fv( value )->tag );
    }else{
        TYPE_RESULT( mqo_value_type( value ) );
    }
MQO_END_PRIM( xtype );


MQO_BEGIN_PRIM( "repr", repr )
    REQ_ANY_ARG( value );
    NO_REST_ARGS( );

    if( mqo_is_cell( value ) ){
        RESULT( mqo_cell_fv( value )->repr );
    }else{
        RESULT( value );
    }
MQO_END_PRIM( repr );

MQO_BEGIN_PRIM( "tag", tag )
    REQ_CELL_ARG( cell );
    NO_REST_ARGS( );

    TAG_RESULT( cell->tag );
MQO_END_PRIM( tag );

MQO_BEGIN_PRIM( "type?", typeq )
    REQ_ANY_ARG( value );
    NO_REST_ARGS( );
    
    BOOLEAN_RESULT( mqo_is_tag( value ) || mqo_is_type( value ) );
MQO_END_PRIM( typeq )

MQO_BEGIN_PRIM( "tag?", tagq )
    REQ_ANY_ARG( value );
    NO_REST_ARGS( );
    
    BOOLEAN_RESULT( mqo_is_tag( value ) );
MQO_END_PRIM( tagq )

MQO_BEGIN_PRIM( "cell?", cellq )
    REQ_ANY_ARG( value );
    NO_REST_ARGS( );
    
    BOOLEAN_RESULT( mqo_is_cell( value ) );
MQO_END_PRIM( cellq )

MQO_BEGIN_PRIM( "make-tag", make_tag )
    REQ_SYMBOL_ARG( name );
    REST_ARGS( info );
    TAG_RESULT( mqo_make_tag( name, mqo_vf_pair( info ) ) );
MQO_END_PRIM( make_tag );

MQO_BEGIN_PRIM( "tag-info", tag_info )
    REQ_TAG_ARG( tag );
    NO_REST_ARGS( );
    RESULT( tag->info );
MQO_END_PRIM( tag_info );

MQO_BEGIN_PRIM( "cell", cell )
    REQ_TAG_ARG( tag );
    REQ_ANY_ARG( value );
    NO_REST_ARGS( );
    
    RESULT( mqo_vf_cell( mqo_make_cell( tag, value ) ) );
MQO_END_PRIM( cell );

void mqo_init_tag_subsystem( ){
    MQO_I_TYPE( cell );
    MQO_I_TYPE( tag );
    MQO_BIND_PRIM( type_name );
    MQO_BIND_PRIM( xtype );
    MQO_BIND_PRIM( typeq );
    MQO_BIND_PRIM( tagq );
    MQO_BIND_PRIM( make_tag );
    MQO_BIND_PRIM( tag_info );
    MQO_BIND_PRIM( cellq );
    MQO_BIND_PRIM( cell );
    MQO_BIND_PRIM( tag );
    MQO_BIND_PRIM( repr );
}

