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
;  

(module "lib/port")

(import "lib/object")

;;; Specifies a magical "end of file" object returned by ports.
(define <eof> (make-tag 'eof))
(define *eof* (tag <eof> '*eof*))
(define (eof-object? value) (eq? *eof* value))

(export *eof* eof-object?)

(define-class port <object>
              (make-port read-fn write-fn close-fn closed)
              port?
              (read-fn port-read-fn)
              (write-fn port-write-fn)
              (close-fn port-close-fn)
              (closed port-closed? set-port-closed!))

(define (current-input-port)
  (or (process-input) *console-port*))

(define (current-output-port)
  (or (process-output) *console-port*))

(define (input-port? value)
  (and (port? value)
       (port-read-fn value)))

(define (output-port? value)
  (and (port? value)
       (port-write-fn value)))

(define (closed?) (closed? (current-input-port)))
(define (closed? (<port> other)) (port-closed? other))

(define (close) (close (current-input-port)))

(define (close (<port> port))
  (unless (closed? port)
    (define close-fn (port-close-fn port))
    (when close-fn (close-fn port))
    (set-port-closed! port #t)))

(define (read) (read (current-input-port)))

(define (read (<port> port))
  (read #f port))

(define (read (<process> process))
  (read #f process))

(define (read quantity (<process> process))
  (read quantity (process-output process)))

(define (read q (<port> port))
  (define fn (port-read-fn port))
  (cond
    ((closed? port) *eof*)
    (fn (define data (fn port q))
        (when (eq? data *eof*)
          (close port))
          ;(set-port-closed! port #t))
        data)
    (else
      (error 'io "Only input-ports may be read from."))))

(define *console-port* 
  (make-port (lambda (p q) (or (read-descr *console* q) *eof*))
             (lambda (p d) (write-descr *console* d))
             #f #f))

(define (write data) (write data (current-output-port)))
(define (write data (<port> port)) 
  (cond ((not (output-port? port))
         (error 'io "Only output-ports may be written to."))
        ((closed? port)
         (error 'io "You may not write to closed ports."))
        (else ((port-write-fn port) port data))))
(define (write data (<process> process))
  (write data (process-input process)))

(define (newline . rest) (apply write *line-sep* rest))

;;; Exhausts a port.
(define (read-all port)
  (define tc (make-tc))
  (define next (read port))
  (until (eof-object? next)
    (tc-append! tc next)
    (set! next (read port)))
  (tc->list tc))

;;; Reads a list of lines from a given port.
(define (read-lines port) 
  (split-lines (read-all port)))

;;; Reads all the expressions from a given port.
(define (read-exprs port)
  (define data (read-all port))
  (string->exprs (if (string? data)
                   data
                   (apply string-append data))))

(export current-input-port current-output-port input-port? output-port?
        port-read-fn port-write-fn port-close-fn
        closed? close read write *console-port* newline read-all 
        read-lines read-exprs <port> make-port port?)

