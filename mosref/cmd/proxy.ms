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

(module "mosref/cmd/proxy")
(import "mosref/shell")
(import "mosref/node")
(import "lib/socks-server")
(import "lib/tcp-server")

;TODO: Add password authentication.
(define-cmd "proxy"
            "proxy [<portno>]"
            (string-append
              "Spawns a SOCKS 4a proxy on the console that will establish"
              " connections on the current node.  If the port number is"
              " omitted, it will be selected at random.")

  (define portno (or (opt-integer terms " proxy port")
                     (random-integer 20000 30000)))

  (spawn-node-proxy (mosref-shell-node shell) portno)
  (send-line "SOCKS Proxy created, listening on port " (format portno) ".")) 

(define *node-tcp-forward-prog* 
  (inline (export nothing)
          (define addr (wait))
          (define portno (wait))
          (define lapse (wait))
          (define conn (tcp-connect addr portno))
          (define timer (timeout lapse (output conn) 'timeout))
          (define evt (wait conn))
          (cond 
            ((eq? evt 'timeout) (send '(fail "timed out"))
                                (send 'close))

            ((eq? evt 'connect) (send 'connect)
                                (spawn (function (lane-to-conn)
                                                 (forever
                                                   (send (wait) conn))))
                                (spawn (function (conn-to-lane)
                                                 (forever
                                                   (send (wait conn))))))

            ((and (pair? evt) (eq? (car evt) 'fail)) (send evt)
                                                     (send 'close))

            (else (send "unrecognized response to connection attempt")
                  (send 'close))
            (halt))))

(define (node-tcp-connect (<console-node> node) addr portno lapse)
  (define conn (tcp-connect addr portno))
  (define xmit (input conn))
  (define recv (output conn))
  (define timer (timeout lapse xmit '(fail "timed out")))
  (list xmit recv))

(define (node-tcp-connect (<drone-node> node) addr portno lapse)
  (define conn (spawn-node-program node *node-tcp-listen-prog*))
  (define xmit (car conn))
  (define recv (cadr conn))
  (send addr xmit)
  (send portno xmit)
  (send lapse xmit)
  (list xmit recv))

(export node-tcp-connect)

(define (spawn-node-proxy node portno)
  ;TODO: Notify the console of each connection.
  (define log-channel (output))
  (define (log-line . bits)
    (send (apply string-append bits) log-channel))
  (define (node-proxy-session)
    (define req (guard (lambda (err)
                         (unless (eq? (error-key err) 'socks)
                           (re-error err))
                         (send (format-socks4-response #f 0 0))
                         (send 'close)
                         (halt))
                  (parse-socks4-request (wait))))
    (set! req (apply make-tc req))
    (define auth (tc-next! req))
    (define proto (tc-next! req))
    (define addr (tc-next! req))
    (define portno (tc-next! req))

    (unless (eq? proto 'tcp)
      (send (format-socks4-response #f portno addr)))

    ;TODO: Make lapse configurable.
    (define conn (node-tcp-connect node addr portno 10000))
    (define xmit (car conn))
    (define recv (cadr conn))
    (define evt (wait recv))

    (cond ((eq? evt 'close) (log-line "FAIL: " 
                                      (format-addr addr) ":" (format portno) 
                                      " -- "
                                      "Connection terminated before it"
                                      " connected.")) 
          ((eq? evt 'connect) (log-line "SUCC: "
                                      (format-addr addr) ":" (format portno) 
                                      " -- Connected.")
                              (send (format-socks4-response #t portno addr))
                              (spawn (lambda () (forever (send (wait) xmit))))
                              (forever (send (wait recv))))
          ((and (pair? evt) (eq? (car evt) 'fail))
                              (log-line "FAIL: " (cadr fail))))
    (send (format-socks4-response #f portno addr))
    (send 'close))

  (spawn-tcp-server portno node-proxy-session))

(define (format-addr addr)
  (if (integer? addr) (format-ipv4 addr) addr))

(export spawn-node-proxy)

