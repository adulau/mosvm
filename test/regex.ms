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

(define wr (make-regex "[a-z]+"))
(define ar (make-regex "([a-z]+)([0-9]+)"))

(s: (regex? wr))
(r: #t)

(s: (regex? 1))
(r: #f)

(s: (match-regex wr "123 alpha 456"))
(r: "alpha")

(s: (match-regex wr "123456 789"))
(r: #f)

(s: (match-regex ar "alpha123"))
(r: '("alpha" "123"))

(s: (match-regex ar "alpha beta"))
(r: #f)

(s: (match-regex* wr "the quick brown fox"))
(r: '("the" "quick" "brown" "fox"))

(s: (match-regex* wr "1234 56789"))
(r: #f)

(s: (match-regex* ar "alpha123 beta4 c5"))
(r: '(("alpha" "123") ("beta" "4") ("c" "5")))

(s: (match-regex* ar "1234 alpha 5678"))
(r: #f)

