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

(module "lib/fuse")

(export fuse-ports)

(define (fuse-ports read-port write-port)
  (define read-fn (port-read-fn read-port))
  (define write-fn (port-write-fn write-port))

  (make-port (lambda (p x) (read-fn read-port x))
             (lambda (p x) (write-fn write-port x))
             (lambda (p)   (close read-port)
                           (close write-port))
             #f))

;;; MOSVM2
