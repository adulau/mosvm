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

(s: `())
(r: '())

(s: `(a))
(r: '(a))

(s: `(a b))
(r: '(a b))

(s: `(a ()))
(r: '(a ()))

(s: `(a (b)))
(r: '(a (b)))

(define a 'alpha)

(s: `(,a))
(r: '(alpha))

(s: `(,a b))
(r: '(alpha b))

(s: `(,a ()))
(r: '(alpha ()))

(s: `(,(list 11 22 33)))
(r: '((11 22 33)))

(s: `(,@(list 11 22 33)))
(r: '(11 22 33))

