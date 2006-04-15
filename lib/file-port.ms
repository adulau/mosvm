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

(module "lib/file-port")

(import "lib/object")
(import "lib/port")

(define-class descr-port <port>
              (make-descr-port read-fn write-fn close-fn descr)
              descr-port?
              (descr port-descr))

(define (read-line (<descr-port> port))
  (define line (read-descr-line (port-descr port)))
  (unless line
    (close port)
    (set! line *eof*))
  line)

(define (descr-input-port? value)
  (and (descr-port? value) (port-read-fn value)))

(define (descr-output-port? value)
  (and (descr-port? value) (port-write-fn value)))

(export <descr-port> make-descr-port descr-port? port-descr descr-input-port? 
        descr-output-port? read-line)

(define-class file-port <descr-port>
              (make-file-port read-fn write-fn close-fn descr)
              file-port?)

(export <file-port> make-file-port file-port?)

;;; Stripped in functionality, but R5RS compliant.
(define (open-output-file path)
  (define descr (open-file-descr path "wc"))
  (file-seek descr 0)
  (make-file-port #f
                  (lambda (p d) (write-descr descr d))
                  (lambda (p)   (close-descr descr))
                  descr))

(define (file-seek (<file-port> port) posn)
  (file-seek (port-descr port) posn))

(define (file-skip (<file-port> port) skip)
  (file-skip (port-descr port) skip))

(define (file-pos (<file-port> port))
  (file-pos (port-descr port)))

(define (file-len (<file-port> port))
  (file-len (port-descr port)))

(export file-seek file-skip file-pos file-len)

(define (file-input-port? value)
  (and (file-port? value) (port-read-fn value)))

(define (file-output-port? value)
  (and (file-port? value) (port-write-fn value)))

(define (write-byte byte (<descr-port> port))
  (write-descr-byte (port-descr port) byte))

(define (write-word word (<descr-port> port))
  (write-descr-word (port-descr port) word))

(define (write-quad quad (<descr-port> port))
  (write-descr-quad (port-descr port) quad))

;;;TODO: read-byte, read-word, read-quad

(export open-output-file write-word write-quad write-byte file-input-port? 
        file-output-port?)

;;; Similar to an R5RS file, but returns raw strings.
(define (open-input-file path)
  (define descr (open-file-descr path "r"))
  (file-seek descr 0)
  (make-file-port (lambda (p q) (read-descr descr q))
                  #f
                  (lambda (p) (close-descr descr))
                  descr))

;;; TODO: Implement for connections.
(define (read-all (<descr-port> input-port))
  (read-descr-all (port-descr input-port)))

(define (closed? (<descr-port> port))
  (descr-closed? (port-descr port)))

(export open-input-file read-all closed?)

;;; Redundant, but R5RS specified
(define close-output-port close)
(define close-input-port close)

(export close-output-port close-input-port)

;;; Similar to an R5RS file with reads returning read s-exprs.
(define (open-lisp-input-file path)
  (define f (open-input-file path))
  (define e (read-exprs f))
  (define q (make-queue e))
  (close f)
  (make-port (lambda (x y) (if (queue-empty? q)
                               *eof*
                               (read-queue q)))
             (lambda (x i) (write-queue q i))
             (lambda (x)   (queue-empty? q))
             #f))

(export open-lisp-input-file)

