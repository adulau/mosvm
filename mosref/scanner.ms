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
(import "mosref/model")

(define (populate-services)
  (forever
    (define evt (wait))
    (define cmd (car evt))
    (define args (cdr evt))
    (cond ((eq? cmd 'done)
           (return))
          ((stream? cmd)
           (send 'close cmd)
           (foc-service (foc-address (car args)) (cadr args))))))
           
(define (scan-report)
  (define (scan-report/service service)
    `(svc (* (port ,(format (service-port service))))))

  (define (scan-report/address address)
    (define ip (address-ip address))

    (when (integer? ip)
      (set! ip (format-ipv4 ip)))
    
    `(addr (* (ip ,ip))
           ,@(map scan-report/service (find-service-by-address address))))
 
  `(scan ,@(map scan-report/address (find-clue table:address))))

(define (scan hosts ports timeout)
  (with-input (output (brutal hosts ports timeout))
    (populate-services)))

; Brutally aggressive, brutally simple, or just a brutal's idea of a port
; scanner..

(define (brutal hosts ports lapse)
  (define (brutal/host host)
    (define (brutal/host-port port)
      (define conn (guard (function (signal-refusal x)
                            ;(send (list 'refused host port))
                            #f)
                          (tcp-connect addr port)))

      (unless conn (return))

      (define timer (timeout lapse (output conn) 'timeout))

      (define evt (wait conn))

      (when (eq? evt 'timeout) 
        (send 'close conn)
        (return))
    
      (cancel-timeout timer)
      (send (list conn host port)))

    (define addr host)

    (when (string? addr)
      (set! addr (guard (lambda (x) #f) (resolve-addr host)))
      (unless addr
        (return (send (list 'not-found host)))))
        
    (if (list? ports)
      (for-each brutal/host-port ports)
      (brutal/host-port host ports)))

  (with-output (make-channel)
    (spawn (function (brute) 
             (if (list? hosts)
               (for-each brutal/host hosts)
               (brutal/host hosts))
  
             (send (list 'done hosts ports lapse))))))

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

(define (cidr base mask)
  (addr-range base (| base (- (<< 1 (- 32 mask)) 1))))

(define (ipv4 q1 q2 q3 q4)
  (+ (<< q1 24)
     (<< q2 16)
     (<< q3  8)
     q4))

(define (format-ipv4 i)
  (define buf (make-string 16))
  (string-append! buf (format (>> i 24)))
  (string-append! buf ".")
  (set! i (& i $FFFFFF))
  (string-append! buf (format (>> i 16)))
  (string-append! buf ".")
  (set! i (& i $FFFF))
  (string-append! buf (format (>> i 8)))
  (string-append! buf ".")
  (set! i (& i $FF))
  (string-append! buf (format i))
  buf)

(export scan scan-report port-range addr-range cidr ipv4 format-ipv4)
