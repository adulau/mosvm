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

(module "lib/iterate")

; Generators, in Mosquito Lisp are functions that, when called, return a
; function that will yield a value each time they are called, or raise an
; error, done, to indicate that they can go no further.

(define (list-iter lst)
  (function (next-list-iter)
    (unless (pair? lst)
      (error 'done "no more items in the list"))
    (define item (car lst))
    (set! lst (cdr lst))
    item))

(define (iter value)
  (cond
    ((function? value) value)
    ((list? value)     (list-iter value))
    ((vector? value)   (list-iter (vector->list value)))
    ((dict? value)     (list-iter (dict->list value)))
    (else (error 'seq "no standard sequence iterator"
                      value))))

(define (iter* values)
  (define tc (make-tc))
  (while (pair? values)
    (tc-append! tc (iter (car values)))
    (set! values (cdr values)))
  (tc->list tc))

(define (next iters)
  (define tc (make-tc))
  (while (pair? iters)
    (tc-append! tc ((car iters)))
    (set! iters (cdr iters)))
  (tc->list tc))

(define-macro (with-iter . body)
  `(begin
     (define args (iter* (cons arg0 argN)))

     (guard (function (catch-done err)
              (if (eq? (error-key err) 'done)
                result
                (re-error err)))
       (forever 
         ,@body))))

(define-macro (with-iter-tc . body)
  `(begin
     (define args (iter* (cons arg0 argN)))

     (guard (function (catch-done err)
              (if (eq? (error-key err) 'done)
                (tc->list result)
                (re-error err)))
       (forever 
         ,@body))))

(define (for-each fn arg0 . argN)
  (define result #f)
  (with-iter 
    (set! result (apply fn (next args)))))

(define (map fn arg0 . argN)
  (define result (make-tc))
  (with-iter-tc 
    (tc-append! result (apply fn (next args)))))

(define (fold-left fn result arg0 . argN)
  (with-iter
    (set! result (apply fn result (next args)))))

(define (fold-right fn result arg0 . argN)
  (with-iter
    (set! result (fn (scatter (next args)) result))))

(define fold fold-right)

(define (index fn arg0 . argN)
  (define result #f)
  (define ix 0)
  (with-iter
    (when (apply fn (next args))
      (return ix))
    (set! ix (+ ix 1))))

(define (list-index fn lst)
  (define ix (index fn lst))
  ix)

(define (all fn arg0 . argN)
  (define result #t)
  (with-iter
    (unless (apply fn (next args)) (return #f))))

(define (any fn arg0 . argN)
  (define result #f)
  (with-iter
    (set! result (apply fn (next args)))
    (when result (return result))))

(define (find-tail fn list)
  (until (null? list)
    (when (fn (car list))
      (return list))
    (set! list (cdr list)))
  #f)

(define (find fn list)
  (set! list (find-tail fn list))
  (if list (car list) #f))

(define (filter fn list)
  (define tc (make-tc))
  (until (null? list)
    (define item (car list))
    (when (fn item)
      (tc-append! tc item))
    (set! list (cdr list)))
  (tc->list tc))

(define filter! filter)

(export iter
        for-each map 
        fold-right fold-left fold 
        list-index 
        all any
        find-tail find
        filter filter!)
