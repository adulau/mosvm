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

(import "lib/repl")
(import "lib/with-io")
(import "lib/terminal")

(export nothing)

(define (do-mosvm)
  (case (argc)
    ((0) (repl)
         (exit))
  (else  
    (let ((r (load (car (argv)))))
      (if (? main)
        (apply main (cdr (argv))))
        r))))

(if *in-win32*
  (with-io (spawn-terminal "MOSVM")
    (do-mosvm))
  (do-mosvm))  

