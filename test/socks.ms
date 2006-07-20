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


(define server-portno (random-integer 10000 30000))
(spawn-tcp-server server-portno (lambda ()
                                  (print "GOT CONNECTION\n")
                                  (send "HELO")
                                  (print "SENT HELLO\n")
                                  (send (wait))
                                  (print "SENT RESPONSE\n")
                                  (send 'close)
                                  (print "SENT CLOSE\n")))

(define localhost (resolve-addr "127.0.0.1"))

(define conn (tcp-connect "127.0.0.1" server-portno))

(define timer (timeout 5000 (output conn) 'timeout))

(enable-trace)

(print "STEP 1\n")

(s: (wait conn))
(r: 'connect)

(print "STEP 2\n")

(s: (wait conn))
(r: "HELO")

(print "STEP 3\n")

(s: (send "Foo" conn))
(s: (wait conn))
(r: "Foo")

(print "STEP 4\n")

(s: (wait conn))
(r: 'close)

(print "STEP 5\n")

(cancel-timeout timer)

(print "STEP 6\n")
