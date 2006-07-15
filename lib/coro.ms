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

(module "lib/coro")
; Definition -- A generator is a function that, when called, creates a new
; function that may be called to generate a single value.  The function yielded
; by a generator may be supplied to the iterators in lib/iterate.
;
; A generator should (error 'done) when the generator can not generate any more
; values.

; Constructs a generator in the style of Actor's coroutines.  Each time the
; generator is advanced, it unblocks the function until it yields a result, 
; then pauses for the next step.

; This is extremely useful for things like permutation generators, which are
; either expensive or complicated when implemented in a procedural fashion.

; It is fairly expensive to generate a coroutine, in terms of CPU time and
; context shifts.

(define-macro (define-coro formals . body)
  (define coro-sym (car formals))
  (define gen-args (cdr formals))
  (define proc-sym (make-symbol 'coro- coro-sym))
  (define next-sym (make-symbol 'next- coro-sym))
  
  `(define ,formals 
     (define %done (list 'done)) ; constructs a unique done flag.
     (define %step (make-channel))
     (define %data (make-channel))

     (define (yield value)
       (wait %step)
       (send value %data))

     (spawn (function (,proc-sym)
              (guard (lambda (err)
                       (if (eq? (error-key err) 'done)
                         (send %done %data)
                         (re-error err)))
                     ,@body)))
    
     (function (,next-sym)
       (send 'next %step)
       (define evt (wait %data))
       (when (eq? evt %done)
         (error 'done))
       evt)))

(export define-coro)
