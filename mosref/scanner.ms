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

(module "mosref/scanner")
(import "lib/with-io")
(import "lib/coro")
(import "mosref/model")

; Yields each intersection of host and port in the scanner space.

(define-coro (scan-tasks scan-hosts scan-ports)
  (for-each (function (scan-task/host host)
              (for-each (function (scan-task/host-port port)
                           (yield (list host port)))
                        scan-ports))
              scan-hosts)
  ; scan-tasks can be consumed by many workers, concurrently -- it must produce
  ; 'done until they relent and forget about the coroutine.

  (forever (yield 'done)))

(define-macro (repeat count . body)
  `(let ((%ctr ,count))
     (until (<= %ctr 0)
       (set! %ctr (- %ctr 1))
       ,@body)))

(define (scan-port host port lapse yield)
  ;(print (string-append "Scanning " (format host) ":" (format port) "...\n"))
  (define conn (guard (lambda x #f) 
                 (tcp-connect host port)))
  (unless conn (return))
  (define t (timeout lapse (output conn) 'timeout))
  (define evt (wait conn))
  (send 'close conn)
  (when (eq? evt 'timeout) 
    ;(print (string-append "... Timeout " 
    ;(format host) ":" (format port) ".\n"))
    (return))

  (cancel-timeout t)

  (when (eq? evt 'connect)
    (print (string-append "... Connect " (format host) ":" (format port) ".\n"))
    (send (list 'connect host port) yield)))

; Given a list of hosts, a list of ports, a number of worker threads to spawn
; and a timeout in milliseconds to wait for any given connection attempt -- 
; spawns the required threads and yields a channel that will report each
; successful connection, and, when all possible combinations have been tried,
; a done.

(define (spawn-scanners hosts ports conns lapse)
  (define results (make-channel))
  (define next-task (scan-tasks hosts ports)) 
  (define (terminate)
    (set! conns (- conns 1))
    (when (= conns 0)
      (send 'done results)))
  (repeat conns
    (spawn (function (scanner-process)
              (forever
                (define evt (next-task))
                ; We are out of work.
                (when (eq? evt 'done) 
                  (terminate)
                  (return))
                (scan-port (car evt) (cadr evt) lapse results)))))
  results)

(define (integer-range first last)
  (when (> first last)
    (define temp last)
    (define last first)
    (define first temp))

  (define tc (make-tc))

  (until (>= first last)
    (tc-append! tc first)
    (set! first (+ first 1)))

  (tc->list tc))

(define (port-range first last)
  (integer-range first last))

(define (addr-range first last)
  (integer-range first last))

(export scan services-report port-range addr-range ipv4 format-ipv4)

