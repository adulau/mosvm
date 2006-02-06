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

// tavl.c -- A derivative of Bert C. Hughes' TAVL library, released to the
// public domain in 1992.  Functionality stripped down for the needs of MOSVM.
//
// All of the functions in tavl.c were either written by Bert C. Hughes,
// directly derived from other functions written by Bert C. Hughes as a part
// of his TAVL library, or written by Scott W. Dunlop to integrate TAVL with
// MOSVM.
//
// Any faults are mine, any brilliance his; if this library sets your house
// on fire, it's your fault, not ours. -- Scott.
//
// Changes include:
//  * The removal of ALL explicit deallocation code -- MOSVM employs 
//    a garbage collector.
//  * Removed any uses of copy_item -- mqo_values are freely copyable.
//  * Removed any uses of make_item -- mqo_values are freely copyable.
//  * Removed any uses of free_item -- we don't use explicit deallocation.
//  * Replace all uses of tree->cmp with mqo_compare -- mqo_values are always
//    compared using this function.
//  * Removed any uses of alloc -- we use a standardized allocator.
//  * Removed any uses of dealloc -- we don't use explicit deallocation.
//  * Replaced all use of dataptr with mqo_value data.
//  * Removed all uses of getdata, as mqo_values can be passed by access.
//  * Consolidated all .c files into one object file, as compilers are 
//    now generally faster than the effort required by make to kick off
//    each compiler.

#include <stdlib.h>
#include <assert.h>
#include "mosvm/tavl.h"
#include "mosvm/show.h"

#define RIGHT   -1
#define LEFT    +1
#define THREAD  0
#define LINK    1
#define LLINK(x)    ((x)->Lbit)
#define RLINK(x)    ((x)->Rbit)
#define LTHREAD(x)  (!LLINK(x))
#define RTHREAD(x)  (!RLINK(x))
#define Leftchild(x)    (LLINK(x) ? (x)->Lptr : NULL)
#define Rightchild(x)   (RLINK(x) ? (x)->Rptr : NULL)
#define Is_Head(x)      ((x)->Rptr == (x))
                            /* always true for head node of initialized */
                            /* tavl_tree, and false for all other nodes */

#define RECUR_STACK_SIZE 40  /* this is extremely enormous */

mqo_node rebalance_tavl(mqo_node a, char *deltaht);
/*  Returns pointer to root of rebalanced tree "a".  If rebalance reduces
    the height of tree "a", *deltaht = 1, otherwise *deltaht = 0.
    "rebalance_tavl" is called ONLY by "tavl_insert" and "mqo_tree_remove".
    *deltaht is always 1 when "rebalance_tavl" is called by "tavl_insert";
    however, *deltaht may return 1 or 0 when called by "mqo_tree_remove".
*/

mqo_node mqo_tree_lookup(mqo_tree tree, mqo_value key){
    /* Return pointer to tree node containing data-item
       identified by "key"; returns NULL if not found */

    mqo_node p = Leftchild(tree->head);
    int side;
    while (p)
    {
        side = mqo_compare(key,(*tree->key_of)(p->data));
        if (side > 0)
            p = Rightchild(p);
        else if (side < 0)
            p = Leftchild(p);
        else
            return p;
    }
    return NULL;
}

/*  Purpose: Initialize threaded AVL tree. Must be called before tree
 *           can be used.
 */
mqo_node mqo_make_node( ){
    mqo_node node = MQO_ALLOC( mqo_node, 0 );
    node->bf = 0;
    node->Lbit = THREAD;
    node->Rbit = THREAD;
    return node;
}

mqo_tree mqo_make_tree( mqo_key_fn key_of ){
    mqo_tree tree = MQO_ALLOC( mqo_tree, 0 );

    if (tree) {
        if ((tree->head = mqo_make_node( )) != NULL) {
            tree->key_of = key_of;
            tree->head->Rbit = LINK;
            tree->head->Lptr = tree->head;
            tree->head->Rptr = tree->head;
        }else {
            tree = NULL;
        }
    }
    return tree;
}

/*  Purpose: Prepare TAVL tree for sequential processing. A TAVL tree
 *           may be viewed as a circular list with a head node, which
 *           contains no data.  "mqo_first_node()" returns a pointer to the
 *           tree's head node, which can then be passed to the routines
 *           "mqo_next_node" and "mqo_prev_node".
 *
 */
mqo_node mqo_first_node(mqo_tree tree) {
    return tree->head;
}

/*  Purpose: Return a pointer to the in-order predeccessor of
 *           the node "p"
 */
mqo_node mqo_prev_node(mqo_node p) {
    mqo_node q;

    if (!p)
        return NULL;

    q = p->Lptr;

    if (LLINK(p))
        while (RLINK(q))
            q = q->Rptr;

    return (Is_Head(q) ? NULL : q);
}

/* Purpose: Return a pointer to the in-order successor of
 *           the node "p"
 */
mqo_node mqo_next_node(mqo_node p) {
    mqo_node q;

    if (!p)
        return NULL;

    q = p->Rptr;

    if (RLINK(p))
        while (LLINK(q))
            q = q->Lptr;

    return (Is_Head(q) ? NULL : q);
}

/* Purpose: Rebalance the TAVLtree "a", which is unbalanced by at most
 *           one leaf.  This function may be called by either "mqo_tree_insert"
 *           or "mqo_tree_remove"; Rebalance is considered to be private to the
 *           TAVL routines, its prototype is in the header "tavlpriv.h",
 *           whereas user routine prototypes are in "tavltree.h".
 *           Assumes balance factors & threads are correct; Returns pointer
 *           to root of balanced tree; threads & balance factors have been
 *           corrected if necessary.  If the height of the subtree "a"
 *           decreases by one, tavl_rebalance sets *deltaht to 1, otherwise
 *           *deltaht is set to 0.  If "tavl_rebalance" is called by
 *           "mqo_tree_insert", *deltaht will always be set to 1 - just by the
 *           nature of the algorithm.  So the function "mqo_tree_insert" does
 *           not need the information provided by *deltaht;  however,
 *           "mqo_tree_remove" does use this information.
 */
mqo_node rebalance_tavl(mqo_node a, char *deltaht){
    mqo_node b,c,sub_root;   /* sub_root will be the return value, */
                                 /* and the root of the newly rebalanced*/
                                 /* sub-tree */

                    /*  definition(tree-height(X)) : the maximum    */
                    /*      path length from node X to a leaf node. */
    *deltaht = 0;   /*  *deltaht is set to 1 if and only if         */
                    /*      tree-height(rebalance()) < tree-height(a)*/

    if (Is_Head(a)          /* Never rebalance the head node! */
        || abs(a->bf) <= 1) /* tree "a" is balanced - nothing more to do */
        return(a);

    if (a->bf == LEFT+LEFT) {
        b = a->Lptr;
        if (b->bf != RIGHT) {   /* LL rotation */
            if (RTHREAD(b)) {       /* b->Rptr is a thread to "a" */
                assert(b->Rptr == a);
                a->Lbit = THREAD;   /* change from link to thread */
                b->Rbit = LINK;     /* change thread to link */
            }
            else {
                a->Lptr = b->Rptr;
                b->Rptr = a;
            }

            *deltaht = b->bf ? 1 : 0;
            a->bf = - (b->bf += RIGHT);

            sub_root = b;
        }
        else {                  /* LR rotation */
            *deltaht = 1;

            c = b->Rptr;
            if (LTHREAD(c)) {
                assert(c->Lptr == b);
                c->Lbit = LINK;
                b->Rbit = THREAD;
            }
            else {
                b->Rptr = c->Lptr;
                c->Lptr = b;
            }

            if (RTHREAD(c)) {
                assert(c->Rptr == a);
                c->Rbit = LINK;
                a->Lptr = c;
                a->Lbit = THREAD;
            }
            else {
                a->Lptr = c->Rptr;
                c->Rptr = a;
            }

            switch (c->bf) {
                case LEFT:  b->bf = 0;
                            a->bf = RIGHT;
                            break;

                case RIGHT: b->bf = LEFT;
                            a->bf = 0;
                            break;

                case 0:     b->bf = 0;
                            a->bf = 0;
            }

            c->bf = 0;

            sub_root = c;
        }
    }
    else if (a->bf == RIGHT+RIGHT) {
        b = a->Rptr;
        if (b->bf != LEFT) {    /* RR rotation */
            if (LTHREAD(b)) {       /* b->Lptr is a thread to "a" */
                assert(b->Lptr == a);
                a->Rbit = THREAD;   /* change from link to thread */
                b->Lbit = LINK;     /* change thread to link */
            }
            else {
                a->Rptr = b->Lptr;
                b->Lptr = a;
            }
            *deltaht = b->bf ? 1 : 0;
            a->bf = - (b->bf += LEFT);

            sub_root = b;
        }
        else {                  /* RL rotation */
            *deltaht = 1;

            c = b->Lptr;
            if (RTHREAD(c)) {
                assert(c->Rptr == b);
                c->Rbit = LINK;
                b->Lbit = THREAD;
            }
            else {
                b->Lptr = c->Rptr;
                c->Rptr = b;
            }

            if (LTHREAD(c)) {
                assert(c->Lptr == a);
                c->Lbit = LINK;
                a->Rptr = c;
                a->Rbit = THREAD;
            }
            else {
                a->Rptr = c->Lptr;
                c->Lptr = a;
            }

            switch (c->bf) {
                case RIGHT: b->bf = 0;
                            a->bf = LEFT;
                            break;

                case LEFT:  b->bf = RIGHT;
                            a->bf = 0;
                            break;

                case 0:     b->bf = 0;
                            a->bf = 0;
            }

            c->bf = 0;

            sub_root = c;
        }
    }

    return sub_root;

}


/*  Development note:  the routines "remove_min" and "remove_max" are
    true recursive routines; i.e., they make calls to themselves. The
    routine "mqo_tree_remove" simulates recursion using a stack (a very deep
    one that should handle any imaginable tree size - up to approximately
    1 million squared nodes).  I arrived at this particular mix by using
    Borland's Turbo Profiler and a list of 60K words as a test file to
    example1.c, which should be included in the distribution package.
    -BCH
*/
static mqo_node remove_node(mqo_tree tree, mqo_node p, char *deltaht);
static mqo_node remove_max(mqo_node p, mqo_node *maxnode, char *deltaht);
static mqo_node remove_min(mqo_node p, mqo_node *minnode, char *deltaht);


/* Purpose:    Delete from TAVL tree the node whose identifier
 *             equals "*identifier", if such a node exists. Returns
 *             non-zero if & only if a node is deleted.
 */
 
#define PUSH_PATH(x,y)  (next->p = (x),  (next++)->side = (y))
#define POP_PATH(x)     (x = (--next)->side, (next->p))

int mqo_tree_remove (mqo_tree tree, mqo_value key) {
    char rb, deltaht;
    int side;
    int  found = deltaht = 0;
    mqo_node p = Leftchild(tree->head);
    int cmpval = -1;
    mqo_node q;

    struct stk_item {
            int side;
            mqo_node p;
        } block[RECUR_STACK_SIZE];

    struct stk_item *next = block;   /* initialize recursion stack */

    tree->head->bf = 0;      /* prevent tree->head from being rebalanced */

    PUSH_PATH(tree->head,LEFT);

    while (p) {
        cmpval = mqo_compare(key,(*tree->key_of)(p->data));
        if (cmpval > 0) {
            PUSH_PATH(p,RIGHT);
            p = Rightchild(p);
        }
        else if (cmpval < 0) {
            PUSH_PATH(p,LEFT);
            p = Leftchild(p);
        }
        else /* cmpval == 0 */ {
            q = p;
            p = NULL;
            found = 1;
        }
    } /* end while(p) */

    if (!found) return 0;

    q = remove_node(tree,q,&deltaht);

    do {
        p = POP_PATH(side);

        if (side != RIGHT)
            p->Lptr = q;
        else
            p->Rptr = q;

        q = p;  rb = 0;

        if (deltaht) {
            p->bf -= side;
            switch (p->bf) {
                case 0:     break;  /* longest side shrank to equal shortest */
                                    /* therefor deltaht remains true */
                case LEFT:
                case RIGHT: deltaht = 0;/* other side is deeper */
                            break;

                default:    {
                                q = rebalance_tavl(p,&deltaht);
                                rb = 1;
                            }
            }
        }
    } while ((p != tree->head) && (rb || deltaht));

    return 1;

#undef PUSH_PATH
#undef POP_PATH

}

static mqo_node remove_node(mqo_tree tree, mqo_node p, char *deltaht){
    char dh;
    mqo_node q;

    *deltaht = 0;

    if (p->bf != LEFT) {
        if (RLINK(p)) {
            p->Rptr = remove_min(p->Rptr,&q,&dh);
            if (dh) {
                p->bf += LEFT;  /* becomes 0 or LEFT */
                *deltaht = (p->bf) ? 0 : 1;
            }
        }
        else { /* leftchild(p),rightchild(p) == NULL */
            assert(p->bf == 0);
            assert(LTHREAD(p));

            *deltaht = 1;           /* p will be removed, so height changes */
            if (p->Rptr->Lptr == p) { /* p is leftchild of it's parent */
                p->Rptr->Lbit = THREAD;
                q = p->Lptr;
            }
            else {  /* p is rightchild of it's parent */
                assert(p->Lptr->Rptr == p);
                p->Lptr->Rbit = THREAD;
                q = p->Rptr;
            }
            return q;
        }
    }
    else { /* p->bf == LEFT */
        p->Lptr = remove_max((p->Lptr),&q,&dh);
        if (dh) {
            p->bf += RIGHT;      /* becomes 0 or RIGHT */
            *deltaht = (p->bf) ? 0 : 1;
        }
    }

    p->data = q->data;
    return p;
}

static mqo_node remove_min(mqo_node p, mqo_node *minnode, char *deltaht){
    char dh = *deltaht = 0;

    if (LLINK(p)) { /* p is not minimum node */
        p->Lptr = remove_min(p->Lptr,minnode,&dh);
        if (dh) {
            p->bf += RIGHT;
            switch (p->bf) {
                case 0: *deltaht = 1;
                        break;
                case RIGHT+RIGHT:
                        p = rebalance_tavl(p,deltaht);
            }
        }
        return p;
    }
    else { /* p is minimum */
        *minnode = p;
        *deltaht = 1;
        if (RLINK(p)) {
            assert(p->Rptr->Lptr == p);
            assert(LTHREAD(p->Rptr) && RTHREAD(p->Rptr));

            p->Rptr->Lptr = p->Lptr;
            return p->Rptr;
        }
        else
            if (p->Rptr->Lptr != p) {   /* was first call to remove_min, */
                p->Lptr->Rbit = THREAD; /* from "remove", not remove_min */
                return p->Rptr;         /* p is never rightchild of head */
            }
            else {
                p->Rptr->Lbit = THREAD;
                return p->Lptr;
            }
    }
}

static mqo_node remove_max(mqo_node p, mqo_node *maxnode, char *deltaht){
    char dh = *deltaht = 0;

    if (RLINK(p)) { /* p is not maximum node */
        p->Rptr = remove_max(p->Rptr,maxnode,&dh);
        if (dh) {
            p->bf += LEFT;
            switch (p->bf) {
                case 0: *deltaht = 1;
                        break;
                case LEFT+LEFT:
                        p = rebalance_tavl(p,deltaht);
            }
        }
        return p;
    }
    else { /* p is maximum */
        *maxnode = p;
        *deltaht = 1;
        if (LLINK(p)) {
            assert(LTHREAD(p->Lptr) && RTHREAD(p->Lptr));
            assert(p->Lptr->Rptr == p);

            p->Lptr->Rptr = p->Rptr;
            return p->Lptr;
        }
        else
            if (p->Rptr->Lptr == p) {   /* p is leftchild of its parent */
                p->Rptr->Lbit = THREAD; /* test must use p->Rptr->Lptr */
                return p->Lptr;         /* because p may be predecessor */
            }                           /* of head node */
            else {
                p->Lptr->Rbit = THREAD;  /* p is rightchild of its parent */
                return p->Rptr;
            }
    }
}

mqo_node mqo_tree_insert(mqo_tree tree, mqo_value item){
                /*
                Using the user supplied (key_of) function, *tree
                is searched for a node which matches *item. If a match is
                found, the new item replaces the old.  If no match is found 
                the item is inserted into *tree.  "mqo_tree_insert" returns 
                a pointer to the node inserted into or found in *tree. 
                "mqo_tree_insert" returns NULL if & only if it is unable 
                to allocate memory for a new node.
                */

    mqo_node a,y,f;
    mqo_node p,q;
    int cmpval = -1; /* cmpval must be initialized - if tree is */
    int side;        /* empty node inserted as LeftChild of head */
    char junk;
    mqo_value key = (*tree->key_of)(item);

    /*  Locate insertion point for item.  "a" keeps track of most
        recently seen node with (bf != 0) - or it is the top of the
        tree, if no nodes with (p->bf != 0) are encountered.  "f"
        is parent of "a".  "q" follows "p" through tree.
    */

    q = tree->head;   a = q;  f = NULL;  p = Leftchild(q);

    while (p) {
        if (p->bf) { a = p; f = q; }

        q = p;

        cmpval = mqo_compare( key, (*tree->key_of)(p->data) );

        if (cmpval < 0)
            p = Leftchild(p);
        else if (cmpval > 0)
            p = Rightchild(p);
        else {
            p->data = item;
            return p;
        }
    }

    /* wasn't found - create new node as child of q */

    y = mqo_make_node( );

    if (y) {
        y->bf = 0;
        y->Lbit = THREAD;
        y->Rbit = THREAD;
        y->data = item;
    }
    else return NULL;           /* out of memory */

    if (cmpval < 0) {           /* connect to tree and thread it */
        y->Lptr = q->Lptr;
        y->Rptr = q;
        q->Lbit = LINK;
        q->Lptr = y;
    }
    else {
        y->Rptr = q->Rptr;
        y->Lptr = q;
        q->Rbit = LINK;
        q->Rptr = y;
    }

    /*  Adjust balance factors on path from a to q.  By definition of "a",
        all nodes on this path have bf = 0, and so will change to LEFT or
        RIGHT.
    */

    if ((a == tree->head) || (mqo_compare(key, (*tree->key_of)(a->data))< 0)){
        p = a->Lptr; side = LEFT;
    }
    else {
        p = a->Rptr; side = RIGHT;
    }

    /* adjust balance factors */

    while (p != y) {
        if (mqo_compare((*tree->key_of)(p->data),key)> 0) {
            p->bf = LEFT;   p = p->Lptr;
        }
        else {
            p->bf = RIGHT;  p = p->Rptr;
        }
    }

    tree->head->bf = 0;     /* if a==tree->head, tree is already balanced */

    /* Is tree balanced? */

    if (abs(a->bf += side) < 2) return y;

    p = rebalance_tavl(a,&junk);

    assert(junk);   /* rebalance always sets junk to 0 */

    assert(f);      /* f was set non-NULL by the search loop */

    if (f->Rptr != a)
        f->Lptr = p;
    else
        f->Rptr = p;

    return y;
}

/* Purpose: Change data in existing node.
 */
int mqo_alter_node(mqo_tree tree, mqo_node p, mqo_value item){
    if (Is_Head(p)) return(TAVL_ILLEGAL_OP);

    if (mqo_compare((*tree->key_of)(p->data),(*tree->key_of)(item)))
        return(TAVL_ILLEGAL_OP);  /* Don't allow identifier to change! */

    p->data = item;

    return TAVL_OK;
}


void mqo_show_tree_contents( mqo_tree t, mqo_word* ct ){
    mqo_node n = mqo_first_node( t );
    int f = 0;
    
    while( n &&( n = mqo_next_node( n ) ) ){
        mqo_space();

        if( ct ){
            if( ! *ct ){
                mqo_write( "..." );
                return;
            }

            (*ct)--;
        }

        mqo_show( n->data, ct );
    }
}

void mqo_show_dict( mqo_dict t, mqo_word* ct ){
    if( ! t )return mqo_show_unknown( mqo_dict_type, 0 );

    mqo_write( "[dict" );
    mqo_show_tree_contents( t, ct );
    mqo_write( "]" );
}

void mqo_show_set( mqo_set t, mqo_word* ct ){
    if( ! t )mqo_show_unknown( mqo_set_type, 0 );

    mqo_write( "[set" );
    mqo_show_tree_contents( t, ct );
    mqo_write( "]" );
}
void mqo_show_tree( mqo_tree t, mqo_word* ct ){
    if( ! t )mqo_show_unknown( mqo_tree_type, 0 );

    mqo_write( "[tree" );
    mqo_show_tree_contents( t, ct );
    mqo_write( "]" );
}
mqo_value mqo_set_key( mqo_value item ){ return item; }
mqo_value mqo_dict_key( mqo_value item ){ return mqo_car( mqo_pair_fv( item ) ); }

