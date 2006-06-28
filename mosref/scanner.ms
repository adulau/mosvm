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
(import "mosref/brutal")
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
    `(svc (* (port ,(service-port service)))))

  (define (scan-report/address address)
    `(addr (* (ip ,(address-ip address)))
           ,@(map scan-report/service (find-service-by-address address))))
 
  `(scan ,@(map scan-report/address (find-clue table:address))))

(define (scan hosts ports timeout)
  (define results (make-channel))
  (with-input (output (brutal hosts ports timeout))
    (populate-services))
  (scan-report))

(export scan)
