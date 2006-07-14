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

; Constructs an Actor-style coroutine generator -- calling the resulting 
; generator will spawn a coroutine and return a function that, when called,
; will signal the coroutine to advance one iteration, and produce the result.

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
     (define %step (make-channel))
     (define %data (make-channel))
     (define (yield value)
       (wait %step)
       (send value %data))
     (spawn (function (,proc-sym)
               ,@body))
    
    (function (,next-sym)
      (send 'next %step)
      (wait %data))))

(export define-coro)
