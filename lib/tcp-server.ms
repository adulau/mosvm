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

(module "lib/tcp-server")
(import "lib/with-io")

(define (spawn-tcp-server portno fn)
  (define server (tcp-listen portno))
  (spawn (lambda ()
            (until (closed? server)
              ;; Born just a little too slooooooooow!
              (with-io (wait server)
                (spawn fn)))))
  server)

(export spawn-tcp-server)

;;; MOSVM2