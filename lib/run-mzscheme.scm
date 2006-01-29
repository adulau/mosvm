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

(require (lib "1.ss" "srfi"))
(require (lib "9.ss" "srfi"))

(define import #f)
(define reload #f)

(let ((cwd (current-directory))
      (cat '()))
 (set! import (lambda (key)
               (if (not (assoc key cat))
                (let ((path (string-append cwd "/" key ".scm")))
                 (set! cat (cons (cons key path) cat))
                 (reload key)))))
 (set! reload (lambda (key)
   (load (cdr (assoc key cat))))))

(import "lib/fakevm")
