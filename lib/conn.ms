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

;TODO: make-connection should use the read/write/close slots!
(define-class connection
              <port>
              (make-connection descr read-fn write-fn close-fn)
              connection?
              (descr connection-descr)
              (read-fn port-read-fn)
              (write-fn port-write-fn)
              (close-fn port-close-fn))

(define (make-connection-from-socket socket)
    (make-connection socket
                     (lambda (x) (read-descr socket))
                     (lambda (x d) (write-descr socket d))
                     (lambda (x) (close-descr socket))))

(define (open-tcp-connection host port)
  (make-connection-from-socket (connect-tcp host port)))

(define (spawn-tcp-server port fn)
  (define server (serve-tcp port))
  (spawn (lambda ()
            (until (descr-closed? server)
              (define conn (read-descr server))
              (define port (make-connection-from-socket conn))
              ;; Born just a little too slooooooooow!
              (with-input-port port
                (with-output-port port
                  (spawn fn)))))))


