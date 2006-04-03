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

#include "../mosvm.h"
#include "../mosvm/prim.h"

#define MQO_PRIM_NEXT MQO_IP++; return;

void mqo_prim_call_op( ){
    MQO_IP ++;
    mqo_call( mqo_pop_ds() );
}
void mqo_prim_tail_op( ){
    mqo_tail_call( mqo_pop_ds() );
}
void mqo_prim_retn_op( ){
    mqo_return( );
}
void mqo_prim_stop_op( ){
    MQO_IP = NULL;
}
void mqo_prim_ldc_op( ){
    mqo_push_ds( MQO_IP->va );
    MQO_PRIM_NEXT;
}
void mqo_prim_jf_op( ){
    if( mqo_is_false( mqo_pop_ds() ) ){
        MQO_IP = MQO_CP->inst + MQO_IP->w.a;
    }else{ 
        MQO_PRIM_NEXT;
    };
}
void mqo_prim_jt_op( ){
    if( ! mqo_is_false( mqo_pop_ds() ) ){
        MQO_IP = MQO_CP->inst + MQO_IP->w.a;
    }else{ 
        MQO_PRIM_NEXT;
    }
}
void mqo_prim_jmp_op( ){
    MQO_IP = MQO_CP->inst + MQO_IP->w.a;
}
void mqo_prim_ldb_op( ){
    mqo_push_ds( mqo_vector_get( 
        mqo_vector_fv( mqo_car( mqo_list_ref(  MQO_EP, MQO_IP->w.a ) ) ),
        MQO_IP->w.b
    ) );
    MQO_PRIM_NEXT;
}
void mqo_prim_ldf_op( ){
    mqo_push_ds( 
        mqo_vf_closure(
            mqo_make_closure( MQO_CP, MQO_CP->inst + MQO_IP->w.a, MQO_EP )
        )
    );
    MQO_PRIM_NEXT;
}
void mqo_prim_usea_op( ){
    mqo_integer a = MQO_IP->w.a;
    mqo_integer ct = mqo_pop_int_ds();
    mqo_integer i = ct;

    if( a > ct ){
        mqo_vector e = mqo_make_vector( ct );
        while( i ){
            mqo_vector_put( e, --i, mqo_pop_ds() );
        }

        MQO_EP = mqo_cons( 
            mqo_vf_vector( e ), 
            mqo_vf_pair( MQO_EP ) 
        );
    
        mqo_value i = mqo_pop_rs();
        mqo_pop_rs();
        mqo_push_int_rs( ct );
        mqo_push_rs( i );

        mqo_errf( 
            mqo_es_vm, "si", 
            "insufficient arguments to program or closure", ct
        );
    }

    mqo_vector e = mqo_make_vector( MQO_IP->w.b );
    i = ct - a;
    mqo_vector_put( e, a, mqo_vf_pair( mqo_rest( i, 0 ) ) );
    mqo_drop_ds( i );
    i = a;

    while( i ){
        mqo_vector_put( e, --i, mqo_pop_ds() );
    }

    MQO_EP = mqo_cons( 
        mqo_vf_vector( e ), 
        mqo_vf_pair( MQO_EP ) 
    );

    MQO_PRIM_NEXT;
}
void mqo_prim_usen_op( ){
    mqo_integer a = MQO_IP->w.a;
    mqo_integer ct = mqo_pop_int_ds();
    mqo_integer i = ct;
    mqo_vector e;

    if( a != ct ){
        mqo_vector e = mqo_make_vector( ct );
        while( i ){
            mqo_vector_put( e, --i, mqo_pop_ds() );
        }

        MQO_EP = mqo_cons( 
            mqo_vf_vector( e ), 
            mqo_vf_pair( MQO_EP ) 
        );

        mqo_value i = mqo_pop_rs();
        mqo_pop_rs();
        mqo_push_int_rs( ct );
        mqo_push_rs( i );

        mqo_errf( 
            mqo_es_vm, "si", 
            "insufficient arguments to program or closure", ct 
        );
    }

    e = mqo_make_vector( MQO_IP->w.b );

    while( i ){
        mqo_vector_put( e, --i, mqo_pop_ds() );
    }

    MQO_EP = mqo_cons( 
        mqo_vf_vector( e ), 
        mqo_vf_pair( MQO_EP ) 
    );
    MQO_PRIM_NEXT;
}
void mqo_prim_drop_op( ){
    mqo_pop_ds();
    MQO_PRIM_NEXT;
}
void mqo_prim_copy_op( ){
    mqo_push_ds( mqo_vector_get( MQO_SV, MQO_SI - 1 ) );
    MQO_PRIM_NEXT;
}
void mqo_prim_ldg_op( ){
    mqo_value v = MQO_IP->sy->value;
    if( mqo_is_void( v ) ){
        mqo_errf( mqo_es_vm, "sx", "symbol not bound", mqo_vf_symbol( MQO_IP->sy ) );
    }else{
        mqo_push_ds( v );
    }
    MQO_PRIM_NEXT;
}
void mqo_prim_stg_op( ){
    mqo_value v = mqo_pop_ds();
    mqo_symbol s = MQO_IP->sy;

    void set_func_name( mqo_value v ){
        mqo_closure c;
        if( mqo_is_closure( v ) ){
            c = mqo_closure_fv( v );
        }else if( mqo_is_multimethod( v ) ){
            mqo_multimethod m = mqo_multimethod_fv( v );
            if( mqo_is_closure( m->func ) ){
                c = mqo_closure_fv( m->func );
            }else{
                return;
            }
        }else{
            return;
        }
        if( ! c->name )c->name = s; 
    }

    set_func_name( v );
    s->value = v;
    MQO_PRIM_NEXT;
}
void mqo_prim_stb_op( ){
    mqo_vector_put( 
            mqo_vector_fv( 
                mqo_car( mqo_list_ref( MQO_EP, MQO_IP->w.a ))
            ),
            MQO_IP->w.b,
            mqo_pop_ds()
    );
    MQO_PRIM_NEXT;
}
void mqo_prim_ldu_op( ){
    mqo_push_ds( mqo_vf_false( ) );
    MQO_PRIM_NEXT;
}
void mqo_prim_gar_op( ){
    mqo_instruction addr = MQO_CP->inst + MQO_IP->w.a;
    mqo_value fn = mqo_pop_ds();
    MQO_GP = mqo_cons(
        mqo_vf_guard( 
            mqo_make_guard( 
                fn, 
                MQO_RI,  
                MQO_SI, 
                MQO_CP,
                addr,
                MQO_EP
            )
        ),
        mqo_vf_pair( MQO_GP )
    );
    MQO_PRIM_NEXT;
}
void mqo_prim_rag_op( ){
    MQO_GP = mqo_pair_fv( mqo_cdr( MQO_GP ) );
    MQO_PRIM_NEXT;
}
