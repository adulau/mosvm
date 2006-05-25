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

(module "lib/string-port")
(import "lib/object")
(import "lib/port")

;;; SRFI-6 String Port Emulation
(define-class string-port <port>
              (make-string-port read-fn write-fn close-fn string)
              string-port?
              (string string-port-string))

(define (open-output-string)
  (define buf (make-string 256))
  (make-string-port (lambda (p q) (or (string-read buf (or q 256)) *eof*))
                    (lambda (p d) (string-write buf d))
                    #f
                    buf))

(define (open-input-string data)
  (define buf (make-string (string-length data)))
  (string-write buf data)
  (make-string-port (lambda (p q) (or (string-read buf (or q 256)) *eof*))
                    (lambda (p d) (string-write buf d))
                    #f
                    buf))

(define (string-input-port? value)
  (and (string-port? value) (port-read-fn value)))

(define (string-output-port? value)
  (and (string-port? value) (port-write-fn value)))

(define (write-byte byte (<string-port> port))
  (string-append-byte! (string-port-string port) byte))

(define (write-word word (<string-port> port))
  (string-append-word! (string-port-string port) word))

(define (write-quad quad (<string-port> port))
  (string-append-quad! (string-port-string port) quad))

(define (read-byte (<string-port> port))
  (string-read-byte (string-port-string port)))

(define (read-word (<string-port> port))
  (or (string-read-word (string-port-string port))
      *eof*))

(define (read-quad (<string-port> port))
  (or (string-read-quad (string-port-string port))
      *eof*))

(define (read-line (<string-port> port))
  (or (string-read-line (string-port-string port))
      *eof*))

(define (get-output-string (<string-port> port))
  (string-port-string port))

(export <string-port> open-input-string open-output-string string-port?
        read-byte read-word read-quad write-byte write-word write-quad
        get-output-string string-input-port? string-output-port?
        read-line)

