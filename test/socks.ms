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

(import "lib/test")

(enable-spot-tests)

(import "lib/tcp-server")
(import "lib/socks-server")
(import "lib/socks-client")


(define localhost (resolve-addr "127.0.0.1"))
(define server-portno (random-integer 10000 30000))
(define server-listener 
  (spawn-tcp-server server-portno (lambda ()
                                    (print "GOT CONNECTION\n")
                                    (send "HELO")
                                    (print "SENT HELLO\n")
                                    (send (wait))
                                    (print "SENT RESPONSE\n")
                                    (send 'close)
                                    (print "SENT CLOSE\n"))))


(define (test-conn conn)
  (define timer (timeout 5000 (output conn) 'timeout))
  (s: (wait conn))
  (r: 'connect)

  (s: (wait conn))
  (r: "HELO")

  (s: (send "Foo" conn))
  (s: (wait conn))
  (r: "Foo")

  (s: (wait conn))
  (r: 'close)
  (cancel-timeout timer))

(define (test-proxy proxy-addr proxy-portno server-addr)
  (define conn (tcp-socks4-connect "foo"
                                   proxy-addr proxy-portno 
                                   server-addr server-portno))
  (test-conn conn))
  
(define (main . args)
  (test-conn (tcp-connect "127.0.0.1" server-portno))

  (define proxy-portno (random-integer 10000 30000))
  (define proxy-listener (spawn-socks4-proxy proxy-portno
                                           (lambda (x) #t)
                                           tcp-connect))

  (test-proxy localhost proxy-portno localhost)
  (test-proxy localhost proxy-portno "localhost")

  (close-listener server-listener)
  (close-listener proxy-listener))


