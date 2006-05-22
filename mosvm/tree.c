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

// A re-implementation of the MOSVM Tree API to cross-check the possibly
// malfunctioning TAVL.

// By enabling MQO_AUDIT_TREES you will greatly reduce speed of the tree
// library, but a comprehensive audit of the two treap invariants will be
// performed after each insert and remove.

#ifdef MQO_AUDIT_TREES
#  ifdef NDEBUG
#    error "MQO_AUDIT_TREES requires NDEBUG not be set, since it uses asserts"
#  endif
#define MQO_AUDIT_TREE( tree ) mqo_audit_tree( tree ) 
#else
#define MQO_AUDIT_TREE( tree )
#endif

// Raises the left branch of a node to the position of that node.
mqo_node *mqo_raise_left( mqo_node* root ){
    mqo_node base = *root;
    mqo_node left = base->left;

    assert( left );
    
    base->left = left->right;
    left->right = base;
   
    *root = left;
    
    return &left->right;
}

// Raises the right branch of a node to the position of that node.
mqo_node *mqo_raise_right( mqo_node* root ){
    mqo_node base = *root;
    mqo_node right = base->right;
    
    assert( right );
    
    base->right = right->left;
    right->left = base;

    *root = right;

    return &right->left;
}

#ifdef MQO_AUDIT_TREES
void mqo_audit_node( mqo_node node, mqo_key_fn key_fn, mqo_integer *pct ){
    (*pct)++;

    mqo_value key = key_fn( node->data );
    
    if( node->left ){
        assert( node->left->weight >= node->weight );
        assert( mqo_cmp_eq( key, key_fn( node->left->data ) ) > 0 );
        assert( mqo_cmp_eq( key_fn( node->left->data ), key ) < 0 );
        mqo_audit_node( node->left, key_fn, pct );
    }

    if( node->right ){
        assert( node->right->weight >= node->weight );
        assert( mqo_cmp_eq( key, key_fn( node->right->data ) ) < 0 );
        assert( mqo_cmp_eq( key_fn( node->right->data ), key ) > 0 );
        mqo_audit_node( node->right, key_fn, pct );
    }
}
mqo_integer mqo_audit_tree( mqo_tree tree ){
    mqo_integer ct = 0;
    if( tree->root )mqo_audit_node( tree->root, tree->key_fn, &ct );
    return ct;
}
#endif

mqo_tree mqo_make_tree( mqo_key_fn key_fn ){
    mqo_tree tree = MQO_OBJALLOC( tree );
    tree->key_fn = key_fn;
}

mqo_node mqo_make_node( mqo_value data ){
    //TODO: we need to ensure that our random function was initialized.
    mqo_node node = malloc( sizeof( struct mqo_node_data ) );
    node->weight = rand();
    node->data = data;
    return node;
}

mqo_node mqo_tree_insert( mqo_tree tree, mqo_value item ){
    mqo_key_fn key_fn = tree->key_fn;
    mqo_value key = key_fn( item );
    mqo_node yield = NULL;

#ifdef MQO_AUDIT_TREES
mqo_integer count = mqo_audit_tree( tree );
#endif

    //Internal routine to recurse down the tree, and either discover the
    //leaf closest to a new node, or a matching node.  Returns nonzero if a
    //node was created and rebalancing is required.
    //
    //This routine is recursive, therefore the C stack may overflow if
    //the number of nodes exceeds 100,000.  Effort is made to reduce the
    //amount of overhead per recursion by using GCC's nested functions.
    //
    // Returns 0 if the node was found.
    // Returns 1 if the node was made.

    int insert_at( mqo_node* link ){
        mqo_node node = *link;

        if( ! node ){
            *link = yield = mqo_make_node( item );
#ifdef MQO_AUDIT_TREES
        count += 1;
#endif
            return 1;
        };

        mqo_integer difference = mqo_cmp_eq( key, key_fn( node->data ) );

        if( difference < 0 ){
            if( insert_at( &(node->left) ) ){
                if( node->left->weight < node->weight ){
                    mqo_raise_left( link ); return 1;
                };
            };
        }else if( difference > 0 ){
            if( insert_at( &(node->right) ) ){
                if( node->right->weight < node->weight ){
                    mqo_raise_right( link ); return 1;
                };
            };
        }else{
            yield = node;
            node->data = item;
        };

        return 0;
    }
    
    insert_at( &(tree->root) );

#ifdef MQO_AUDIT_TREES
    mqo_integer new_count = mqo_audit_tree( tree );
    assert( count == new_count );
#endif

    return yield;
}

int mqo_tree_remove( mqo_tree tree, mqo_value key ){
    mqo_key_fn key_fn = tree->key_fn;
    
    mqo_node* root = &(tree->root);
    mqo_node node;
    mqo_integer difference;

#ifdef MQO_AUDIT_TREES
    mqo_integer count = mqo_audit_tree( tree );
#endif

    for(;;){
        node = *root; 

        if( node == NULL ){
#ifdef MQO_AUDIT_TREES
            mqo_integer new_count = mqo_audit_tree( tree );
            assert( count == new_count );
#endif
            
            return 0; // Node not found.
        }

        difference = mqo_cmp_eq( key, key_fn( node->data ) );

        if( difference < 0 ){
            root = &(node->left);
        }else if( difference > 0 ){
            root = &(node->right);
        }else{
            break;
        } 
    }

    for(;;){
        if( node->left && node->right ){
            if( node->left->weight > node->right->weight ){
                mqo_raise_right( root );
                root = &((*root)->left);
            }else{
                mqo_raise_left( root );
                root = &((*root)->right);
            }
        }else if( node->left ){
            mqo_raise_left( root );
            root = &((*root)->right);
        }else if( node->right ){
            mqo_raise_right( root );
            root = &((*root)->left);
        }else{
            *root = NULL; 

#ifdef MQO_AUDIT_TREES
    count -= 1;
    mqo_integer new_count = mqo_audit_tree( tree );
    assert( count == new_count );
#endif
            free( node );
            return 1;            
        }
    }
}

mqo_node mqo_tree_lookup( mqo_tree tree, mqo_value key ){
    mqo_key_fn key_fn = tree->key_fn;
    
    mqo_node node = tree->root;
    
    while( node ){
        if( node == NULL )return NULL; // Node not found.
            
        mqo_integer difference = mqo_cmp_eq( key, key_fn( node->data ) );

        if( difference < 0 ){
            node = node->left;
        }else if( difference > 0 ){
            node = node->right;
        }else{
            break;
        } 
    }

    MQO_AUDIT_TREE( tree );

    return node;
}

void mqo_iter_node( mqo_node node, mqo_iter_mt iter, void* ctxt ){
    if( node == NULL )return;
    mqo_iter_node( node->left, iter, ctxt );
    iter( node->data, ctxt );
    mqo_iter_node( node->right, iter, ctxt );
}

void mqo_iter_tree( mqo_tree tree, mqo_iter_mt iter, void* ctxt ){
    mqo_iter_node( tree->root, iter, ctxt );
}

void mqo_show_tree_cb( mqo_value value, mqo_word* ct ){
    if( ct )switch( *ct ){
    case 0:
        return;
    case 1:
        mqo_print( " ..." );
        return;
    default:
        (*ct) --;
    }

    mqo_space( );
    mqo_show( value, ct );
}

void mqo_show_tree( mqo_tree tree, mqo_word* ct ){
    mqo_begin_showtag( mqo_vf_tree( tree ) );
    mqo_iter_tree( tree, (mqo_iter_mt)mqo_show_tree_cb, ct );
    mqo_end_showtag( );
}

mqo_value mqo_set_key( mqo_value item ){ return item; }
mqo_value mqo_dict_key( mqo_value item ){
    return mqo_car( mqo_pair_fv( item ) );
}

void mqo_trace_node( mqo_node node ){
    if( node == NULL )return;
    mqo_grey_val( node->data );
    mqo_trace_node( node->left );
    mqo_trace_node( node->right );
}
void mqo_trace_tree( mqo_tree tree ){
    mqo_trace_node( tree->root );
}
void mqo_free_node( mqo_node node ){
    if( node == NULL )return;
    mqo_free_node( node->left );
    mqo_free_node( node->right );
    free( node );
}
void mqo_free_tree( mqo_tree tree ){
    mqo_free_node( tree->root );
    mqo_objfree( tree );
}

MQO_GENERIC_COMPARE( tree );
MQO_C_TYPE( tree );

MQO_INHERIT_GC( set, tree );
MQO_INHERIT_SHOW( set, tree );
MQO_GENERIC_COMPARE( set );
MQO_C_TYPE( set );

MQO_INHERIT_GC( dict, tree );
MQO_INHERIT_SHOW( dict, tree );
MQO_GENERIC_COMPARE( dict );
MQO_C_TYPE( dict );

void mqo_init_tree_subsystem( ){
    MQO_I_TYPE( tree );
    MQO_I_SUBTYPE( set, tree );
    MQO_I_SUBTYPE( dict, tree );
}

