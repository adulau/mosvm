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
(r: '((usen 0 0) 
      (retn)))

(s: (compile '(1)))
(r: '((usen 0 0) 
      (ldc 1)
      (retn)))

(s: (compile '(1 2)))
(r: '((usen 0 0) 
      (ldc 1)
      (ldc 2)
      (retn)))

(s: (compile '((fn))))
(r: '((usen 0 0)
      (newf)
      (ldg fn)
      (arg)
      (call)
      (retn)))

(s: (compile '((define x 1)(export nothing))))
(r: '((usen 0 2)
      (ldc 1)
      (stb 0 0)
      (retn)))

(s: (compile '((let ((x 1)) x))))
(r: '((usen 0 1)
      (ldc 1)
      (stb 0 0)
      (ldb 0 0)
      (retn)))

(s: (compile '((quote x))))
(r: '((usen 0 0)
      (ldc x)
      (retn)))

(s: (compile '((asm x))))
(r: '((usen 0 0)
      x
      (retn)))

(s: (compile '((begin))))
(r: '((usen 0 0)
      (retn)))

(s: (compile '((begin 1 2 3))))
(r: '((usen 0 0)
      (ldc 1)
      (ldc 2)
      (ldc 3)
      (retn)))

(s: (compile '(1 2 3)))
(r: '((usen 0 0)
      (ldc 1)
      (ldc 2)
      (ldc 3)
      (retn)))

(reset-branch-index)
(s: (compile '((if x y))))
(r: '((usen 0 0)
      (ldg x)
      (jf false-2)
      (ldg y)
      (jmp done-1)
      false-2
      done-1
      (retn)))

(reset-branch-index)
(s: (compile '((if x y z))))
(r: '((usen 0 0)
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
(r: '((usen 0 0)
      (ldg x)
      (jf false-2)
      (ldg y)
      (ldg z)
      (jmp done-1)
      false-2
      done-1
      (retn)))

(reset-branch-index)
(s: (compile '((unless x y z))))
(r: '((usen 0 0)
      (ldg x)
      (jf false-2)
      (jmp done-1)
      false-2
      (ldg y)
      (ldg z)
      done-1
      (retn)))

(reset-branch-index)
(s: (compile '((lambda x x))))
(r: '((usen 0 0)
      (clos anon-fn-1 after-2)
      (usea 0 1)
      (ldb 0 0)
      (retn)
      after-2
      (retn)))

(s: (compile '(`(a b c))))
(r: '((usen 0 0)
      (newf)
      (ldg list)
      (arg)
      (ldc a) (arg)
      (ldc b) (arg)
      (ldc c) (arg)
      (call)
      (retn)))

(s: ((assemble (compile '(`(a b c))))))
(r: '(a b c))

(s: ((assemble (compile '(`(a b ,(+ 1 2) ,@(list 'x 'y)))))))
(r: '(a b 3 x y))

(s: ((assemble (compile '((+ 1 2 3))))))
(r: 6)

