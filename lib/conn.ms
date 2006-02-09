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

(define-class connection
              <port>
              (make-connection descr)
              connection?
              (descr connection-descr))

(define (read (<connection> connection))
  (or (read-descr (connection-descr connection))
      *eof*))

(define (write (<string> data) (<connection> connection))
  (write-descr (connection-descr connection) data))

(define (close (<connection> connection))
  (close-descr (connection-descr connection)))

(define (closed? (<connection> connection))
  (descr-closed? (connection-descr connection)))

(define (open-tcp-connection host port)
  (make-connection (connect-tcp host port)))

(define (spawn-tcp-server port fn)
  (define server (serve-tcp port))
  (spawn (lambda ()
            (until (descr-closed? server)
              (define conn (read-descr server))
              (define port (make-connection conn))
              ;; Born just a little too slooooooooow!
              (with-input-port port
                (with-output-port port
                  (spawn fn)))))))


