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

(define (open-buffer-port)
  (define buf (make-buffer))
  (define ps  #f)
  (make-port (lambda (p q) 
               (cond
                 (ps (error 'buffer 
                            "A process is already waiting on this port"))
                 ((and q (< (buffer-length buf) q))
                  (set! ps (active-process))
                  (suspend)))
               (if q 
                 (read-buffer buf q)
                 (read-buffer buf)))
             (lambda (p d) 
               (write-buffer buf d)
               (when ps
                 (resume ps)
                 (set! ps #f)))
             #f
             #f))

(export open-buffer-port)

(define-class queue <object>
              (make-queue-state tc ps)
              queue?
              (tc queue-tc)
              (ps queue-ps set-queue-ps!))

(define (make-queue . data) 
  (define tc (make-tc))
  (unless (null? data)
    (tc-splice! tc (car data)))
  (make-queue-state tc #f))

(define (read-queue queue)
  (define tc (queue-tc queue))
  (if (tc-empty? tc)
    (begin
      (when (queue-ps queue)
        (error 'queue 
               "A process is already waiting on this queue"))
      (set-queue-ps! queue (active-process))
      (suspend))
    (tc-next! tc)))

(define (write-queue queue data)
  (define tc (queue-tc queue))
  (define ps (queue-ps queue))
  (if (and (tc-empty? tc) ps)
    (begin (resume ps data)
           (set-queue-ps! queue #f))
    (tc-append! tc data)))

(define (queue-empty?  queue)
  (tc-empty? (queue-tc queue)))

(define (read-queue-all queue)
  (define tc (queue-tc queue))
  (define data (tc->list tc))
  (tc-clear! tc)
  data)

(define (open-queue-port)
  (define queue (make-queue))
  (make-port (lambda (x y) (read-queue queue))
             (lambda (x i) (write-queue queue i))
             #f
             #f))

(export <queue> make-queue read-queue write-queue read-queue-all make-queue
        open-queue-port)

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

(define (thaw-file path)
  (define p (open-input-file path))
  (define r (thaw (read-all p)))
  (close p)
  r)

(export thaw-file)

(define (path-join . items)
  (apply string-join *path-sep* items))

(define (convert-path path)
  (apply path-join (string-split* path "/")))

(export path-join convert-path)

(module "lib/core")
