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

#if !defined MQO_TAVL_H
#define MQO_TAVL_H

#include "memory.h"

/*  Constants are possible return values of "tavl_setdata" */
#define TAVL_OK          0  /* No error. */
#define TAVL_NOMEM       1  /* Out of memory error */
#define TAVL_ILLEGAL_OP  2  /* Requested operation would disrupt the
                               tavl_tree structure; operation cancelled! */

#include <stddef.h>         /* for definition of "NULL" */

/* prototypes */
/* A Warning about Keys and Items:
   For trees where key_of is not an identity function, any Item key will be
   passed to key_of to identify what key would be associated with the item.

   For example, an associative array derived from mqo_tree would want to ensure
   that invocations of mqo_insert_value uses a pair of index and value, not
   just index or value.
*/

mqo_tree mqo_make_tree( mqo_key_fn key_of );
            /*
            Returns pointer to empty tree on success, NULL if insufficient
            memory.  The function pointer passed to "tavl_init" determine
            how that instance of tavl_tree will identify the key of an item
            value.  For a set, this would be the identity function, for an 
            associative array, this would be mqo_car.

            key_of:       Gets pointer to a data object's identifier.
            */

int mqo_alter_node(mqo_tree tree, mqo_node p, mqo_value item);
            /*
            Replace data contents of *p with item.
            returns:
                0  ................ OK
                TAVL_ILLEGAL_OP ...
                     (*tree->key_of)(p->dataptr) != (*tree->key_of)(item)
            */

mqo_node mqo_tree_insert(mqo_tree tree, mqo_value item);
            /*
            Using the user supplied "key_of" function,
            *tree is searched for a node which matches item. If a
            match is found, the new item replaces the old.
            
            If no match is found the item is inserted into *tree.
            "tavl_insert" returns a pointer to the node inserted or found, 
            or NULL if there is not enough memory to create a new node and 
            copy "item".  Uses functions "key_of" for comparisons and to
            retrieve identifiers from data objects.
            */

int mqo_tree_remove(mqo_tree tree, mqo_value key);
            /*
            Delete node identified by "key" from *tree.
            Returns 1 if found and deleted, 0 if not found.
            Uses "compare", "key_of", "free_item" and "dealloc".
            See function tavl_init.
            */

mqo_node mqo_tree_lookup(mqo_tree tree, mqo_value key);
            /*
            Returns pointer to node which contains data item
            in *tree whose identifier equals "key". Uses "key_of"
            to retrieve identifier of data items in the tree,
            "compare" to compare the identifier retrieved with
            *key.  Returns NULL if *key is not found.
            */

/********************************************************************
    Following three functions allow you to treat mqo_trees as a
    doubly linked sorted list with a head node.  This is the point
    of threaded trees - it is almost as efficient to move from node
    to node or back with a threaded tree as it is with a linked list.
*********************************************************************/

mqo_node mqo_first_node(mqo_tree tree);
            /*
            Returns pointer to begin/end of *tree (the head node).
            A subsequent call to mqo_next_node will return a pointer
            to the node containing first (least) item in the tree;
            just as a call to mqo_prev_node would return the last
            (greatest).  Pointer returned can only be used a parameter
            to "mqo_next_node" or "mqo_prev_node" - the head node contains no
            user data.
            */

mqo_node mqo_next_node(mqo_node p);
            /*
            Returns successor of "p", or NULL if "p" has no successor.
            */

mqo_node mqo_prev_node(mqo_node p);
            /*
            Returns predecessor of "p", or NULL if no predecessor.
            */

#endif

