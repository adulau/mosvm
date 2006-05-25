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
(import "lib/compile")

(enable-spot-tests)

(s: (compile '()))
(r: '((usea 0 0) 
      (ldu)
      (retn)))

(s: (compile '(1)))
(r: '((usea 0 0) 
      (ldu)
      (drop)
      (ldc 1)
      (retn)))

(s: (compile '(1 2)))
(r: '((usea 0 0) 
      (ldu)
      (drop)
      (ldc 1)
      (drop)
      (ldc 2)
      (retn)))

(s: (compile '((fn))))
(r: '((usea 0 0)
      (ldu)
      (drop)
      (ldc 0)
      (ldg fn)
      (call)
      (retn)))

(s: (compile '((define x 1))))
(r: '((usea 0 1)
      (ldu)
      (drop)
      (ldc 1)
      (stb 0 1)
      (ldu)
      (retn)))

(s: (compile '((let ((x 1)) x))))
(r: '((usea 0 1)
      (ldu)
      (drop)
      (ldc 1)
      (stb 0 1)
      (ldu)
      (drop)
      (ldb 0 1)
      (retn)))

(s: (compile '((quote x))))
(r: '((usea 0 0)
      (ldu)
      (drop)
      (ldc x)
      (retn)))

(s: (compile '((asm x))))
(r: '((usea 0 0)
      (ldu)
      (drop)
      x
      (retn)))

(s: (compile '((begin))))
(r: '((usea 0 0)
      (ldu)
      (drop)
      (ldu)
      (retn)))

(s: (compile '((begin 1 2 3))))
(r: '((usea 0 0)
      (ldu)
      (drop)
      (ldu)
      (drop)
      (ldc 1)
      (drop)
      (ldc 2)
      (drop)
      (ldc 3)
      (retn)))

(s: (compile '(1 2 3)))
(r: '((usea 0 0)
      (ldu)
      (drop)
      (ldc 1)
      (drop)
      (ldc 2)
      (drop)
      (ldc 3)
      (retn)))

(reset-branch-index)
(s: (compile '((if x y))))
(r: '((usea 0 0)
      (ldu)
      (drop)
      (ldg x)
      (jf false-2)
      (ldg y)
      (jmp done-1)
      false-2
      (ldu)
      done-1
      (retn)))

(reset-branch-index)
(s: (compile '((if x y z))))
(r: '((usea 0 0)
      (ldu)
      (drop)
      (ldg x)
      (jf false-2)
      (ldg y)
      (jmp done-1)
      false-2
      (ldg z)
      done-1
      (retn)))

(reset-branch-index)
(s: (compile '((when x y z))))
(r: '((usea 0 0)
      (ldu)
      (drop)
      (ldg x)
      (jf false-2)
      (ldu)
      (drop)
      (ldg y)
      (drop)
      (ldg z)
      (jmp done-1)
      false-2
      (ldu)
      done-1
      (retn)))

(reset-branch-index)
(s: (compile '((unless x y z))))
(r: '((usea 0 0)
      (ldu)
      (drop)
      (ldg x)
      (jf false-2)
      (ldu)
      (jmp done-1)
      false-2
      (ldu)
      (drop)
      (ldg y)
      (drop)
      (ldg z)
      done-1
      (retn)))

(reset-branch-index)
(s: (compile '((lambda x x))))
(r: '((usea 0 0)
      (ldu)
      (drop)
      (ldf lambda-1)
      (retn)
      lambda-1
      (usea 0 1)
      (ldu)
      (drop)
      (ldb 0 0)
      (retn)))

(s: (compile '(`(a b c))))
(r: '((usea 0 0)
      (ldu)
      (drop)
      (ldc 0) (ldg make-tc) (call)
      (ldc a) (ldc 2) (ldg tc-append!) (call)
      (ldc b) (ldc 2) (ldg tc-append!) (call)
      (ldc c) (ldc 2) (ldg tc-append!) (call)
      (ldc 1) (ldg tc->list) (call)
      (retn)))

(s: ((assemble (compile '(`(a b c))))))
(r: '(a b c))

(s: ((assemble (compile '(`(a b ,(+ 1 2) ,@(list 'x 'y)))))))
(r: '(a b 3 x y))

(s: ((assemble (compile '((+ 1 2 3))))))
(r: 6)

