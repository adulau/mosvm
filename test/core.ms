; Copyright (C) 2006, Ephemeral Security, LLC 
;  
; This library is free software; you can redistribute it and/or modify it  
; under the terms of the GNU Lesser General Public License as published by  
; the Free Software Foundation; either version 2.1 of the License, or (at  
; your option) any later version. 
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

(import "lib/test")

(enable-spot-tests)

(s: (not #f))
(r: #t)

(s: (not #t))
(r: #f)

(s: (not 1))
(r: #f)

(s: (symbol? 1))
(r: #f)

(s: (symbol? 'f))
(r: #t)

(s: (string? 1))
(r: #f)

(s: (string? "t"))
(r: #t)

(s: (last-pair '(a)))
(r: '(a))

(s: (last-pair '(a b)))
(r: '(b))

(s: (last-pair '(a . b)))
(r: '(a . b))

(s: (last-pair '(a b . c)))
(r: '(b . c))

(s: (last-pair '(a b c)))
(r: '(c))

(s: (last-item '(a)))
(r: 'a)

(s: (last-item '(a b)))
(r: 'b)

(s: (last-item '(a . b)))
(r: 'a)

(s: (last-item '(a b . c)))
(r: 'b)

(s: (last-item '(a b c)))
(r: 'c)

(define tc (make-tc))
(t: (tc? tc))

(s: (tc->list tc))
(r: '())

(s: (tc-append! tc 'a))
(r: tc)

(s: (tc->list tc))
(r: '(a))

(s: (tc-prepend! tc 'x))
(r: tc)

(s: (tc->list tc))
(r: '(x a))

(s: (tc-splice! tc '(1 2 3)))
(r: tc)

(s: (tc->list tc))
(r: '(x a 1 2 3))

(s: (cadr '(1 2)))
(r: 2)

(s: (cadr '(1 2 3)))
(r: 2)

(s: (caddr '(1 2 3)))
(r: 3)

(s: (caddr '(1 2 3 4)))
(r: 3)

(s: (reverse '()))
(r: '())

(s: (reverse '(1)))
(r: '(1))

(s: (reverse '(1 2)))
(r: '(2 1))

(s: (reverse '(1 2 3)))
(r: '(3 2 1))

(s: (reverse! '()))
(r: '())

(s: (reverse! '(1)))
(r: '(1))

(s: (reverse! '(1 2)))
(r: '(2 1))

(s: (reverse! '(1 2 3)))
(r: '(3 2 1))

(s: (fold cons '() '(1 2 3)))
(r: '(3 2 1))

(s: (filter! (lambda (k) (> k 3)) '(1 2 3 4 5 6)))
(r: '(4 5 6))

(s: (symbol->string 'abcdef))
(r: "abcdef")

(s: (abs -1))
(r: +1)

(s: (abs 2))
(r: +2)

(s: (abs 0))
(r: 0)

(define abc "abc")
(s: (string-append abc))
(t: (eq? abc _))

(s: (string-append "a" 32 "cat"))
(r: "a cat")

(s: (quotient 3 2))
(r: 1)

(s: (quotient -3 2))
(r: -1)

(s: (remainder 5 3))
(r: 2)

(s: (remainder -5 3))
(r: -2)

