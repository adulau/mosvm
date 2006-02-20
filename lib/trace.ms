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

(module "lib/trace")
(import "lib/format")

(define (traceback error) 
  (begin;buffer-output 
    (write "ERROR: ")
    (write (symbol->string (error-key error)))
    (define info (error-info error))
    (define context (error-context error))
    (when (and (not (null? info))
               (string? (car info)))
      (write " -- " )
      (write (car info))
      (set! info (cdr info)))
    (newline)
    (when (not (null? info))
      (write "INFO: ")
      (for-each (lambda (item)
                  (write " ")
                  (show item))
                info)
      (newline))
    (write "TRACE: ")
    (define first #t)
    (for-each (lambda (frame)
                (if first (set! first #f)
                  (write "       "))
                (write "(")
                (show (function-name (car frame)))
                (for-each (lambda (arg)
                            (write " ")
                            (show arg))
                          (cdr frame))
                (write ")")
                (newline))
              context)))

(define (traceback error (<port> port))
  (with-output-port port (traceback error)))

(define-macro (trace . stmts)
    `(guard (lambda (err) (disable-trace)
                          (re-error err))
            (enable-trace)
            (let ((%x (begin ,@stmts)))
              (disable-trace)
              %x)))

(export traceback trace)
