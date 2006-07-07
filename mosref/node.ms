; Copyright (C) 2006, Ephemeral Security, LLC
; 
; This library is free software; you can redistribute it and/or modify it 
; under the terms of the GNU Lesser General Public License, version 2.1
; as published by the Free Software Foundation.
; 
; This library is distributed in the hope that it will be useful, but WITHOUT 
; ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or 
; FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License 
; for more details.
; 
; You should have received a copy of the GNU Lesser General Public License 
; along with this library; if not, write to the Free Software Foundation, 
; Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA 

(module "mosref/node")
(import "lib/object")

(define *nodes-by-id* (dict))

(define-class node <object>
              (make-node-record id addr)
              node?
              (id node-id)
              (addr node-addr))

(define-class console-node <node>
              (make-console-node-record id addr)
              console-node?
              (id node-id)
              (addr node-addr))

(define-class drone-node <node>
              (make-drone-node-record id addr xmit recv)
              drone-node?
              (id node-id)
              (addr node-addr)
              (xmit drone-node-xmit)
              (recv drone-node-recv))

(define (list-mosref-nodes)
  (dict-values *nodes-by-id*))

(define (find-mosref-node id)
  (dict-ref *nodes-by-id* id))

(define (make-console-node addr)
  (define node (make-console-node-record "console" addr))
  (dict-set! *nodes-by-id* "console" node)
  node) 

(define (make-drone-node id addr xmit recv)
  (define node (make-drone-node-record id addr xmit recv))
  (dict-set! *nodes-by-id* id node)
  node)

