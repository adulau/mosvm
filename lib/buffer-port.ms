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

(module "lib/buffer-port")
(import "lib/object")
(import "lib/port")

(define (open-buffer-port)
  (define buf (make-buffer))
  (define ps  #f)
  (make-port (lambda (p q)
               (cond
                 (ps (error 'buffer
                            "A process is already waiting on this port"))
                 ((and q (< (buffer-length buf) q))
                  (set! ps (active-process))
                  (suspend)))
               (if q
                 (read-buffer buf q)
                 (read-buffer buf)))
             (lambda (p d)
               (write-buffer buf d)
               (when ps
                 (resume ps)
                 (set! ps #f)))
             #f
             #f))

(export open-buffer-port)
