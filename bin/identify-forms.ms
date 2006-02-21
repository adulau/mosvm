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

(import "lib/lib")

(define (identify-forms program)
  (identify-subforms program '()))

(define (identify-expr-forms expr forms)
  (if (pair? expr)
    (let ((a (car expr)))
      (identify-subforms (cdr expr) 
                         (if (pair? a) (identify-expr-forms a forms)
                                       (set-insert a forms))))
    forms))

(define (identify-subforms itm forms)
  (if (pair? itm)
    (fold identify-expr-forms forms (unkink itm))
    forms))

(define (set-insert item set)
  (if (memq item set) set (cons item set)))

(define (main args)
  (display "Identifying forms in ")
  (display (cadr args))
  (display " to ")
  (display (caddr args))
  (display ".")
  (newline)
  (write (identify-forms (read-all (open-input-file (cadr args))))
         (open-output-file (caddr args))))

