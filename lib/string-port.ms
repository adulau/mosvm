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
              (make-string-port read-fn write-fn close-fn buffer)
              string-port?
              (buffer string-port-buffer))

(define (open-output-string)
  (define buf (make-buffer 256))
  (make-string-port (lambda (p q) (or (read-buffer buf (or q 256)) *eof*))
                    (lambda (p d) (write-buffer buf d))
                    #f
                    buf))

(define (open-input-string data)
  (define buf (make-buffer (string-length data)))
  (write-buffer buf data)
  (make-string-port (lambda (p q) (or (read-buffer buf (or q 256)) *eof*))
                    (lambda (p d) (write-buffer buf d))
                    #f
                    buf))

(define (string-input-port? value)
  (and (string-port? value) (port-read-fn value)))

(define (string-output-port? value)
  (and (string-port? value) (port-write-fn value)))

(define (write-byte byte (<string-port> port))
  (write-buffer-byte (string-port-buffer port) byte))

(define (write-word word (<string-port> port))
  (write-buffer-word (string-port-buffer port) word))

(define (write-quad quad (<string-port> port))
  (write-buffer-quad (string-port-buffer port) quad))

(define (read-byte (<string-port> port))
  (read-buffer-byte (string-port-buffer port)))

(define (read-word (<string-port> port))
  (or (read-buffer-word (string-port-buffer port))
      *eof*))

(define (read-quad (<string-port> port))
  (or (read-buffer-quad (string-port-buffer port))
      *eof*))

(define (read-line (<string-port> port))
  (or (read-buffer-line (string-port-buffer port))
      *eof*))

(define (get-output-string (<string-port> port))
  (buffer->string (string-port-buffer port)))

(export <string-port> open-input-string open-output-string string-port?
        read-byte read-word read-quad write-byte write-word write-quad
        get-output-string string-input-port? string-output-port?)

