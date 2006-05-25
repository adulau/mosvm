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
(s: (assemble '()))
(t: (program? _))
(t: (= (program-length _) 0))

(s: (assemble '((retn))))
(t: (program? _))
(t: (= (program-length _)    1))
(t: (= (program-code-at _ 0) 11))

(s: (assemble '((ldb 0 1)
                (ldg foo)
                (ldc "xyzzy"))))
(t: (program? _))
(t: (= (program-length _) 3))
(t: (= (program-code-at _ 0) 3))
(t: (= (program-word1-at _ 0) 0))
(t: (= (program-word2-at _ 0) 1))
(t: (= (program-code-at _ 1) 2))
(t: (eq? (program-symbol-at _ 1) 'foo))
(t: (= (program-code-at _ 2) 1))
(t: (equal? (program-value-at _ 2) "xyzzy"))

(s: ((assemble '((usea 0 1)
                 (ldb 0 0)
                 (retn))) 
     'aaa))
(r: '(aaa))

(s: ((assemble '((usen 1 101)
                 (ldb 0 0)
                 (jt t-b)
                 f-b
                 (ldc "false")
                 (jmp d-b)
                 t-b
                 (ldc "true")
                 d-b
                 (retn)))
     #t))
(r: "true")
                 
