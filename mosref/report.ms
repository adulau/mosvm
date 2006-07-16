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

(module "mosref/report")

; From here, on, lies code that needs to be scavenged for mosref/report
(define (collate-scan-results src)
  (forever
    (define evt (wait src))
    (when (memq (evt '(done close)) (return)))
    (when (eq? (car evt) 'connect)
      (apply collate-addr-port (cdr evt)))))

(define (services-report)
  (define (services-report/service service)
    `(svc (* (port ,(format (service-port service))))))

  (define (services-report/address address)
    (define ip (address-ip address))

    (when (integer? ip)
      (set! ip (format-ipv4 ip)))
    
    `(addr (* (ip ,ip))
           ,@(map services-report/service (find-service-by-address address))))
 
  `(scan ,@(map services-report/address (find-clue table:address))))

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
  (define (ub i)
    (if (< i 0) (+ i 256) i))

  (define buf (make-string 16))
  (string-append! buf (format (ub (>> i 24))))
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

(export scan services-report port-range addr-range cidr ipv4 format-ipv4)

