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
(import "lib/freeze")
(import "lib/assemble")

(enable-spot-tests)

(s: (thaw (freeze 101)))
(r: 101)

(s: (thaw (freeze -101)))
(r: -101)

(s: (thaw (freeze #t)))
(r: #t)

(s: (thaw (freeze #f)))
(r: #f)

(s: (thaw (freeze 'a)))
(r: 'a)

(s: (thaw (freeze '())))
(r: '())

(s: (thaw (freeze '(101))))
(r: '(101))

(s: (thaw (freeze '(a))))
(r: '(a))

(s: (thaw (freeze '(a b c))))
(r: '(a b c))

(s: (thaw (freeze '(a (b c)))))
(r: '(a (b c)))

(s: ((thaw (freeze (assemble '((usea 0 1)
                               (ldb 0 0)
                               (retn))))) 'a 'b 'c))
(r: '(a b c))

