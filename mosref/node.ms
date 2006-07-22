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
(import "lib/bridge")
(import "lib/filter")
(import "lib/package-filter")
(import "lib/with-io")

(import "mosref/format")

(define *nodes-by-id* (dict))
(define *drones-by-bridge* (dict))

(define-class node <object>
              (make-node-record id props)
              node?
              (id node-id)
              (props node-props))

(define-class console-node <node>
              (make-console-node-record id props)
              console-node?
              (id node-id)
              (props node-props))

(define-class drone-node <node>
              (make-drone-node-record id props bridge)
              drone-node?
              (id node-id)
              (bridge drone-node-bridge)
              (props node-props))

(define (list-mosref-nodes)
  (dict-values *nodes-by-id*))

(define (find-mosref-node id)
  (dict-ref *nodes-by-id* id))

(define (make-console-node addr portno)
  (define node (make-console-node-record "console" (dict)))
  (set-node-prop! node 'platform *platform*)
  (set-node-prop! node 'addr addr)
  (set-node-prop! node 'port portno)
  (set-node-prop! node 'online #t)
  (dict-set! *nodes-by-id* "console" node)
  node) 

(define (make-drone-node id addr portno bridge)
  (define node (make-drone-node-record id (dict) bridge))
  (set-node-prop! node 'addr addr)
  (set-node-prop! node 'port portno)
  (set-node-prop! node 'online #t)
  (dict-set! *nodes-by-id* id node)
  (dict-set! *drones-by-bridge* bridge node)
  node)

(define (spawn-node-program (<console-node> node) program)
  (define xmit (make-channel))
  (define recv (make-channel))
  (with-input xmit (with-output recv (spawn program)))
  (list xmit recv))

(define (spawn-node-program (<drone-node> node) program)
  (unless (node-online node)
    (error 'off (string-append "Drone " (node-id node) " is offline."))) 
  (define lane (make-lane (drone-node-bridge node)))
  (define xmit (output-chain (lane-xmit lane)
                             (freeze-filter)))
  (define recv (input-chain (lane-recv lane)
                            (thaw-filter)))
  (send program xmit)
  (list xmit recv))

(export list-mosref-nodes find-mosref-node
        spawn-node-program make-drone-node make-console-node node-id 
        drone-node-bridge <node> <drone-node> <console-node> 
        node? drone-node? console-node?)

(define (expect-data recv)
  ;TODO: timeout
  (define evt (wait recv))
  (when (eq? evt 'close)
    (error 'expect "channel closed while expecting data"))
  (guard (lambda (e)
           (apply error 'expect (error-info e)))
    evt))

(define (expect-signal recv)
  (define evt (expect-data recv))
  (unless (pair? evt)
    (error 'expect "got invalid data while expecting signal" evt))
  evt)

(define (expect-succ recv)
  (define evt (expect-signal recv))
  (when (eq? (car evt) 'fail)
    (error 'expect (string-append "expected success, got " (cadr evt))))
  (unless (eq? (car evt) 'succ)
    (error 'expect (string-append "expected success, got " (format evt))))
  (if (null? (cdr evt))
    #t 
    (cadr evt)))
    
(define-macro (with-node-program node program . stmts)
  `(begin
     (define conn (spawn-node-program ,node ,program))
     (define xmit (car conn))
     (define recv (cadr conn))
     (define result (guard (lambda (e)
                             (send 'close xmit)
                            (re-error e))
                      ,@stmts))
    (send 'close xmit)
    result))

(define-macro (inline . body)
  (assemble (optimize (compile body))))

(export inline with-node-program expect-data expect-signal expect-succ)

(define (find-node-prop node key) (dict-ref (node-props node) key))
(define (list-node-props node) (dict->list (node-props node)))
(define (set-node-prop! node key val) (dict-set! (node-props node) key val))
(define (clear-node-prop! node key) (dict-remove! (node-props node) key))

(export find-node-prop list-node-props set-node-prop! clear-node-prop!)

(define (node-portno node) 
  (define x (find-node-prop node 'port))
  (if (string? x) (string->integer x) x))
(define (set-node-portno! node portno) (set-node-prop! node 'port portno))

(define (node-addr node) (find-node-prop node 'addr))
(define (node-online node) (find-node-prop node 'online))
(define (set-node-online! node flag) (set-node-prop! node 'online flag))
;TODO: Validators for properties.


(define (find-drone-by-bridge bridge)
  (dict-ref *drones-by-bridge* bridge))

(export node-addr node-portno node-online set-node-online! set-node-portno!
        find-drone-by-bridge)
