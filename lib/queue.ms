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
;  

(module "lib/queue")
(import "lib/object")

(define-class queue <object>
              (make-queue-state tc ps)
              queue?
              (tc queue-tc)
              (ps queue-ps set-queue-ps!))

(define (make-queue . data)
  (define tc (make-tc))
  (unless (null? data)
    (tc-splice! tc (car data)))
  (make-queue-state tc #f))

(define (read-queue queue)
  (define tc (queue-tc queue))
  (if (tc-empty? tc)
    (begin
      (when (queue-ps queue)
        (error 'queue
               "A process is already waiting on this queue"))
      (set-queue-ps! queue (active-process))
      (suspend))
    (tc-next! tc)))

(define (write-queue queue data)
  (define tc (queue-tc queue))
  (define ps (queue-ps queue))
  (if (and (tc-empty? tc) ps)
    (begin (resume ps data)
           (set-queue-ps! queue #f))
    (tc-append! tc data)))

(define (queue-empty?  queue)
  (tc-empty? (queue-tc queue)))

(define (read-queue-all queue)
  (define tc (queue-tc queue))
  (define data (tc->list tc))
  (tc-clear! tc)
  data)

(define (open-queue-port)
  (define queue (make-queue))
  (make-port (lambda (x y) (read-queue queue))
             (lambda (x i) (write-queue queue i))
             #f
             #f))

(export <queue> make-queue read-queue write-queue read-queue-all make-queue
        open-queue-port queue?)


;;; MOSVM2
