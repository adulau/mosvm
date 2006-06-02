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

(module "lib/with-io")

(define (do-with-io io func)
  (let ((old-input (input))
        (old-output (output)))
    (define (reset)
      (set-input! old-input)
      (set-output! old-output))
    (define result
      (guard (lambda (e)
               (reset)
               (re-error e))
        (set-input!  (output io))
        (set-output! (input io))
        (func)))
    (reset)
    result))

(define (do-with-input io func)
  (let ((old-input (input)))
    (define (reset)
      (set-input! old-input))
    (define result
      (guard (lambda (e)
               (reset)
               (re-error e))
        (set-input!  io)
        (func)))
    (reset)
    result))

(define (do-with-output io func)
  (let ((old-output (output)))
    (define (reset)
      (set-output! old-output))
    (define result
      (guard (lambda (e)
               (reset)
               (re-error e))
        (set-output! io)
        (func)))
    (reset)
    result))

(define-macro (with-io io . body)
    (list 'do-with-io io (apply list 'function '(inner-io-func) body)))

(define-macro (with-input input . body)
    (list 'do-with-input input 
          (apply list 'function '(inner-input-func) body)))

(define-macro (with-output output . body)
    (list 'do-with-output output 
          (apply list 'function '(inner-output-func) body)))

(export do-with-io with-io do-with-input do-with-output
        with-input with-output)

