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
              (make-drone-node-record id addr bridge)
              drone-node?
              (id node-id)
              (addr node-addr)
              (bridge drone-node-bridge))

(define (list-mosref-nodes)
  (dict-values *nodes-by-id*))

(define (find-mosref-node id)
  (dict-ref *nodes-by-id* id))

(define (make-console-node addr)
  (define node (make-console-node-record "console" addr))
  (dict-set! *nodes-by-id* "console" node)
  node) 

(define (make-drone-node id addr bridge)
  (define node (make-drone-node-record id addr bridge))
  (dict-set! *nodes-by-id* id node)
  node)

(define (spawn-node-program (<console-node> node) program)
  (define xmit (make-channel))
  (define recv (make-channel))
  (with-input xmit (with-output recv (spawn program)))
  (list xmit recv))

(define (spawn-node-program (<drone-node> node) program)
  (define lane (make-lane (drone-node-bridge node)))
  (define xmit (output-chain (lane-xmit lane)
                             (freeze-filter)))
  (define recv (input-chain (lane-recv lane)
                            (thaw-filter)))
  (send program xmit)
  (list xmit recv))

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

(define (get-node-file (<console-node> node) path)
  (read-data-file path))

(define *drone-get-file-prog*
  (assemble
    (optimize
      (compile
        `((let ((path (wait))
                (data #f))
            (guard (lambda (e)
                     (send (list 'fail (car (error-info e)))))
              (set! data (read-data-file path))
              (until (empty-string? data)
                (send (string-read! data 16384)))
              (send 'done)))
          (send 'close))))))

(define (get-node-file (<drone-node> node) path)
  (with-node-program node *drone-get-file-prog*
     (send path xmit)
     (define data (make-string))
     (forever
       (define evt (expect-data recv))
       (cond
         ((eq? evt 'done) (return data))
         ((string? evt) (string-append! data evt))
         (else (error 'expect "expected string or done" evt))))))

(define *drone-put-file-prog*
  (assemble 
    (optimize 
      (compile 
        `((let ((path (wait))
                (data (make-string))
                (done #f))
            (guard (lambda (e)
                     (send (list 'fail (car (error-info e)))))
              (until done
                (define evt (wait))
                (cond ((eq? evt 'done) (set! done #t))
                      ((string? evt) (string-append! data evt))
                      (else (error 'fail "expected string or done" evt))))
              (write-data-file path data))
              (send '(succ)))
          (send 'close))))))

(define (put-node-file (<console-node> node) path data)
  (write-data-file path data))

(define (put-node-file (<drone-node> node) path data)
  (with-node-program node *drone-put-file-prog*
    (send path xmit)
    (until (empty-string? data)
      (send (string-read! data 16384) xmit))
    (send 'done xmit)
    (expect-succ recv)))

