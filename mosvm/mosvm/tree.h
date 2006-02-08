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

#if !defined MQO_TREE_H
#define MQO_TREE_H

#include "memory.h"

struct mqo_tree_iter_data;
typedef struct mqo_tree_iter_data* mqo_tree_iter;
struct mqo_tree_iter_data {
    mqo_byte phase;
    mqo_node node;
    mqo_tree_iter back;
};

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

mqo_tree_iter mqo_iter_tree(mqo_tree tree);
mqo_node mqo_next_node(mqo_tree_iter *iter);

void mqo_dump_tree( mqo_tree tree );

void mqo_show_tree_contents( mqo_tree tree, mqo_word* ct );
void mqo_show_tree( mqo_tree tree, mqo_word* ct );
void mqo_show_set( mqo_tree tree, mqo_word* ct );
void mqo_show_dict( mqo_tree tree, mqo_word* ct );

#define MQO_ITER_TREE( tree, var )\
    mqo_tree_iter var##_iter = mqo_iter_tree( tree ); \
    mqo_node var; \
    while( var = mqo_next_node( &var##_iter ) )
#endif
