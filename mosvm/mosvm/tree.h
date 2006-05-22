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

#ifndef MQO_TREE_H
#define MQO_TREE_H

#include "memory.h"

struct mqo_node_data;
typedef struct mqo_node_data* mqo_node;
struct mqo_node_data{
    mqo_quad weight;
    mqo_value data;
    mqo_node left, right;
};

typedef mqo_value (*mqo_key_fn) (mqo_value);

MQO_BEGIN_TYPE( tree )
    mqo_node root;
    mqo_key_fn key_fn;
MQO_END_TYPE( tree )
#define REQ_TREE_ARG( vn ) REQ_TYPED_ARG( vn, tree )
#define TREE_RESULT( vn ) TYPED_RESULT( vn, tree )
#define OPT_TREE_ARG( vn ) OPT_TYPED_ARG( vn, tree )

typedef mqo_tree mqo_set;
MQO_H_TYPE( set )
#define REQ_SET_ARG( vn ) REQ_TYPED_ARG( vn, set )
#define SET_RESULT( vn ) TYPED_RESULT( vn, set )
#define OPT_SET_ARG( vn ) OPT_TYPED_ARG( vn, set )

typedef mqo_tree mqo_dict;
MQO_H_TYPE( dict )
#define REQ_DICT_ARG( vn ) REQ_TYPED_ARG( vn, dict )
#define DICT_RESULT( vn ) TYPED_RESULT( vn, dict )
#define OPT_DICT_ARG( vn ) OPT_TYPED_ARG( vn, dict )

mqo_value mqo_set_key( mqo_value item );
mqo_value mqo_dict_key( mqo_value item ); 

/* A Warning about Keys and Items:
   For trees where key_of is not an identity function, any Item key will be
   passed to key_of to identify what key would be associated with the item.

   For example, an associative array derived from mqo_tree would want to ensure
   that invocations of mqo_insert_value uses a pair of index and value, not
   just index or value.
*/

mqo_tree mqo_make_tree( mqo_key_fn key_of );
mqo_node mqo_tree_insert(mqo_tree tree, mqo_value item);
int mqo_tree_remove(mqo_tree tree, mqo_value key);
mqo_node mqo_tree_lookup(mqo_tree tree, mqo_value key);

typedef void (*mqo_iter_mt)( mqo_value, void* );

void mqo_iter_tree(mqo_tree tree, mqo_iter_mt iter, void* ctxt );
void mqo_show_tree( mqo_tree tree, mqo_word* word );

void mqo_init_tree_subsystem( );

#endif
