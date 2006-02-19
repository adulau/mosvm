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

(module "lib/format")

(define (unknown->string unknown)
  (string-append "[" (symbol->string (type-name (type unknown))) "]"))

(define (pair-contents->string pair spq) 
  (define sp (open-output-string))
  (while pair
    (if (null? pair) 
      (set! pair #f); We're done.
      (begin
        (if spq (write " " sp) (set! spq #t))
        (write (value->string (car pair)) sp)
        (if (pair? (cdr pair))
          (set! pair (cdr pair))
          (begin
           (write " . " sp)
           (write (value->string (cdr pair)) sp)
           (set! pair #f))))))
  (get-output-string sp))

(define (pair->string pair) 
  (string-append "(" (pair-contents->string pair #f) ")"))

(define (vector-contents->string vector spq)
  (define ln (vector-length vector))
  (define ix 0)
  (define sp (open-output-string))
  (while (< ix ln)
    (if spq (write " " sp) (set! spq #t))
    (write (value->string (vector-ref vector ix)) sp)
    (set! ix (+ ix 1)))
  (get-output-string sp))

(define (vector->string vector) 
  (string-append "#(" (vector-contents->string vector #f) ")"))

(define (object->string object) 
  (string-append "[" 
                 (symbol->string (type-name (type object)))
                 (vector-contents->string (repr object) #t) 
                 "]"))

(define (set->string set)
  (string-append "[set" (pair-contents->string (set->list set) #t) "]" ))

(define (dict->string dict)
  (string-append "[dict" (pair-contents->string (dict->list dict) #t) "]" ))

(define (type->string type) 
  (string-append "<" 
                 (symbol->string (type-name type))
                 (pair-contents->string (type-info type) #t)
                 ">"))

(define (value->string unknown) (unknown->string unknown))
(define (value->string (<set> set)) (set->string (repr set)))
(define (value->string (<dict> dict)) (dict->string (repr dict)))
(define (value->string (<type> type)) (type->string (repr type)))
(define (value->string (<vector> vector)) (vector->string (repr vector)))
(define (value->string (<object> object)) (object->string object))
(define (value->string (<pair> pair)) (pair->string (repr pair)))
(define (value->string (<string> string)) (string-append "\"" (repr string) "\""))
(define (value->string (<symbol> symbol)) (symbol->string (repr symbol)))
(define (value->string (<integer> integer)) (number->string (repr integer)))
(define (value->string (<boolean> value)) (if (repr value) "#t" "#f"))

(define (show value) (show value (current-output-port)))
(define (show value (<port> port)) (write (value->string value) port))

(export unknown->string pair-contents->string pair->string 
        vector-contents->string vector->string object->string
        set->string dict->string type->string value->string 
        show)

