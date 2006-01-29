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

(s: (string->exprs ""))
(r: '())

(s: (string->exprs "1"))
(r: '(1))

(s: (string->exprs "190"))
(r: '(190))

(s: (string->exprs "+1"))
(r: '(1))

(s: (string->exprs "+190"))
(r: '(190))

(s: (string->exprs "-190"))
(r: '(-190))

(s: (string->exprs "a"))
(r: '(a))

(s: (string->exprs "alpha"))
(r: '(alpha))

(s: (string->exprs "a b"))
(r: '(a b))

(s: (string->exprs "alpha b"))
(r: '(alpha b))

(s: (string->exprs "a beta"))
(r: '(a beta))

(s: (string->exprs "()"))
(r: '(()))

(s: (string->exprs "(a)"))
(r: '((a)))

(s: (string->exprs "(alpha)"))
(r: '((alpha)))

(s: (string->exprs "(a b)"))
(r: '((a b)))

(s: (string->exprs "(alpha b)"))
(r: '((alpha b)))

(s: (string->exprs "(alpha ())"))
(r: '((alpha ())))

(s: (string->exprs "(() ())"))
(r: '((() ())))

(s: (string->exprs "'a"))
(r: '((quote a)))

(s: (string->exprs "'alpha"))
(r: '((quote alpha)))

(s: (string->exprs "'()"))
(r: '((quote ())))

(s: (string->exprs "'(a b c)"))
(r: '((quote (a b c))))

(s: (string->exprs "`a"))
(r: '((quasiquote a)))

(s: (string->exprs "`alpha"))
(r: '((quasiquote alpha)))

(s: (string->exprs "`()"))
(r: '((quasiquote ())))

(s: (string->exprs "`(a b c)"))
(r: '((quasiquote (a b c))))

(s: (string->exprs ",a"))
(r: '((unquote a)))

(s: (string->exprs ",alpha"))
(r: '((unquote alpha)))

(s: (string->exprs ",()"))
(r: '((unquote ())))

(s: (string->exprs ",(a b c)"))
(r: '((unquote (a b c))))

(s: (string->exprs ",@a"))
(r: '((unquote-splicing a)))

(s: (string->exprs ",@alpha"))
(r: '((unquote-splicing alpha)))

(s: (string->exprs ",@()"))
(r: '((unquote-splicing ())))

(s: (string->exprs ",@(a b c)"))
(r: '((unquote-splicing (a b c))))

(s: (string->exprs ";\n"))
(r: '())

(s: (string->exprs ";abc\n"))
(r: '())

(s: (string->exprs " ;abc\n"))
(r: '())

(s: (string->exprs "a;\n"))
(r: '(a))

(s: (string->exprs "a;abc\n"))
(r: '(a))

(s: (string->exprs "a ;abc\n"))
(r: '(a))

(s: (string->exprs ";\na"))
(r: '(a))

(s: (string->exprs ";abc\na"))
(r: '(a))

(s: (string->exprs ";abc\n a"))
(r: '(a))

(s: (string->exprs "();\n"))
(r: '(()))

(s: (string->exprs "();abc\n"))
(r: '(()))

(s: (string->exprs "() ;abc\n"))
(r: '(()))

(s: (string->exprs ";\n()"))
(r: '(()))

(s: (string->exprs ";abc\n()"))
(r: '(()))

(s: (string->exprs ";abc\n ()"))
(r: '(()))

(s: (string->exprs ";\r"))
(r: '())

(s: (string->exprs ";abc\r"))
(r: '())

(s: (string->exprs " ;abc\r"))
(r: '())

(s: (string->exprs "a;\r"))
(r: '(a))

(s: (string->exprs "a;abc\r"))
(r: '(a))

(s: (string->exprs "a ;abc\r"))
(r: '(a))

(s: (string->exprs ";\ra"))
(r: '(a))

(s: (string->exprs ";abc\ra"))
(r: '(a))

(s: (string->exprs ";abc\r a"))
(r: '(a))

(s: (string->exprs "();\r"))
(r: '(()))

(s: (string->exprs "();abc\r"))
(r: '(()))

(s: (string->exprs "() ;abc\r"))
(r: '(()))

(s: (string->exprs ";\r()"))
(r: '(()))

(s: (string->exprs ";abc\r()"))
(r: '(()))

(s: (string->exprs ";abc\r ()"))
(r: '(()))

(s: (string->exprs "(a;\n)"))
(r: '((a)))

(s: (string->exprs "(a;abc\n)"))
(r: '((a)))

(s: (string->exprs "(a ;abc\n)"))
(r: '((a)))

(s: (string->exprs "(;abc\n a)"))
(r: '((a)))

(s: (string->exprs "(a . b)"))
(r: '((a . b)))

(s: (string->exprs "(a b . c)"))
(r: '((a b . c)))

(s: (string->exprs "#t"))
(r: '(#t))

(s: (string->exprs "#f"))
(r: '(#f))

(s: (string->exprs "#t #f"))
(r: '(#t #f))

