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

(define *mosvm?* #t)

;;; for-each, map, find-tail, list-index, any, filter, fold and find from SRFI-1
(define (filter fn list)
  (define tc (make-tc))
  (until (null? list)
         (set! it (car list))
         (if (fn it)
           (tc-append! tc it))
         (set! list (cdr list)))
  (tc->list tc))

(define filter! filter)

(define (fold fn acc . lists)
  (until (memq '() lists)
         (set! acc (apply fn (append (map-car lists) (list acc))))
         (set! lists (map-cdr lists)))
  acc)

(define (for-each fn . lists)
  (until (memq '() lists)
         (apply fn (map-car lists))
         (set! lists (map-cdr lists))))

(define (map fn . lists)
  (define tc (make-tc))
  (until (memq '() lists)
         (tc-append! tc (apply fn (map-car lists)))
         (set! lists (map-cdr lists)))
  (tc->list tc))

(define (find-tail fn list)
  (define done #f)
  (until done 
    (cond ((null? list)    (set! done #t))
          ((fn (car list)) (set! done #t))
          (else (set! list (cdr list)))))
  (if (null? list)
    #f
    list))

(define (list-index fn . lists)
  (define done #f)
  (define index 0)
  (until done 
         (cond ((memq '() lists) (set! index #f)
                                 (set! done #t))
               ((apply fn (map-car lists)) (set! done #t))
               (else (set! index (+ index 1))
                     (set! lists (map-cdr lists)))))
  index)

(define (find fn list)
  (set! list (find-tail fn list))
  (if list (car list) #f))

(define (any fn . lists)
  (define done #f)
  (define found #f)
  (until done
         (cond ((memq '() lists) 
                (set! done #t))
               ((apply fn (map-car lists)) 
                (set! found #t)
                (set! done #t))
               (else 
                 (set! lists (map-cdr lists)))))
  found)

;;; Underpinnings of the define-class method of constructing new
;;; classes.
(define (make-class class-name super-class fields)
  (apply make-type 
         class-name super-class 
         (append (class-fields super-class) fields)))

(define (class-fields class) (type-info class))
 
(define (make-class-constructor class-name class arg-names)
  (define fields (class-fields class))
  (define field-count  (length fields))
  (define arg-offsets  
    (map (lambda (arg-name) 
           (or (list-index (lambda (x) (eq? x arg-name)) fields)
               (error 'class "constructor field is not a member of the class"
                      arg-name class-name)))
         arg-names))

  (lambda arg-values
    (let ((data (make-vector field-count)))
      (for-each (lambda (arg-offset arg-value) 
                  (vector-set! data arg-offset arg-value))
                arg-offsets
                arg-values)
      (tag class data))))

(define (make-field-accessor class field-name)
  (define field-offset (list-index (lambda (x) (eq? x field-name))
                                   (class-fields class)))
  (lambda (inst) (vector-ref (repr inst) field-offset)))

(define (make-field-modifier class field-name)
  (define field-offset (list-index (lambda (x) (eq? x field-name))
                                   (class-fields class)))
  (lambda (inst value) (vector-set! (repr inst) field-offset value)))

;;; This function is often used for methods that we want to ignore.
(define (ignore-method . dont-care))

;;; We use <object> as a root class for defined classes. 
(define <object> (make-type 'object <vector>))
(define (object? value) (eq? <object> (type value)))

;;; The base class for SRFI-9 Records
(define-class <record>
              <object>
              (make-record)
              record?)
              
;;; Specifies a magical "end of file" object returned by ports.
(define *eof* (tag (make-type 'eof <atom>) atom))
(define (eof-object? value) (eq? *eof* value))

(define-class <port> <object>
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
  (cond ((not (input-port? port))
         (error 'io "Only input-ports may be read from."))
        ((closed? port) *eof*)
        (else (define data ((port-read-fn port) port))
              (when (eq? data *eof*)
                (set-port-closed! port #t))
              data)))
(define (read (<process> process))
  (read (process-output process)))


(define *console-port* 
  (make-port (lambda (p) (or (read-descr *console*) *eof*))
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
  (split-lines (read-all input-port)))

;;; Reads all the expressions from a given port.
(define (read-exprs port)
  (define data (read-all port))
  (string->exprs (if (string? data)
                   data
                   (apply string-append data))))

(define-class <file-port> <port>
              (make-file-port read-fn write-fn close-fn descr)
              file-port?
              (descr file-port-descr))

;;; Stripped in functionality, but R5RS compliant.
(define (open-output-file path)
  (define descr (open-file path "wc"))
  (seek-file descr 0)
  (make-file-port #f
                  (lambda (p d) (write-descr descr d))
                  (lambda (p)   (close-descr descr))
                  descr))

(define (write-byte byte (<file-port> port))
  (write-file-byte (file-port-descr port) byte))

(define (write-word word (<file-port> port))
  (write-file-word (file-port-descr port) word))

(define (write-quad quad (<file-port> port))
  (write-file-quad (file-port-descr port) quad))

;;; Similar to an R5RS file, but returns raw strings.
(define (open-input-file path)
  (define descr (open-file path "r"))
  (seek-file descr 0)
  (make-file-port (lambda (p) (read-descr descr))
                  #f
                  (lambda (p) (close-descr descr))
                  descr))

(define (read-all (<file-port> input-port))
  (read-file-all (file-port-descr input-port)))

(define (closed? (<file-port> port))
  (descr-closed? (file-port-descr port)))

;;; Redundant, but R5RS specified
(define close-output-port close)
(define close-input-port close)

;;; SRFI-6 String Port Emulation
(define-class <string-port> <port>
              (make-string-port read-fn write-fn close-fn data)
              string-port?
              (data string-port-data))

(define (open-output-string)
  (let ((tc (make-tc)))
    (make-string-port #f
                      (lambda (p d) (tc-append! tc d))
                      #f
                      tc)))

(define (write-byte byte (<string-port> port))
  (tc-append! (string-port-data port) byte))

(define (write-word word (<string-port> port))
  (write-byte (quotient word 256) port)
  (write-byte (remainder word 256) port))

(define (write-quad quad (<string-port> port))
  (write-word (quotient quad 65536) port)
  (write-word (remainder quad 65536) port))

;;; TODO: This is very inefficient if the string was constructed, byte-by-byte.
(define (get-output-string (<string-port> port))
  ; Each call to g-o-s compresses the queued data into a single string
  ; object, alters the queue to contain that object, then returns
  ; the result.
  (define tc (string-port-data port))
  (define data (apply string-append (tc->list tc)))
  (tc-clear! tc)
  (tc-append! tc data)
  data)

;;; The queue is both an input, and an output, backed by a tconc.
(define-class <queue> <port>
              (make-queue read-fn write-fn close-fn tc ps)
              queue?
              (tc queue-tc)
              (ps queue-ps set-queue-ps!))

(define (open-queue . data) 
  (define tc (make-tc))
  (unless (null? data)
    (tc-splice! tc (car data)))
  (make-queue (lambda (p) 
                (if (tc-empty? tc)
                  (begin
                    (when (queue-ps p)
                      (error 'queue 
                             "A process is already waiting on this queue"
                             p))
                    (set-queue-ps! p (active-process))
                    (suspend))
                  (tc-next! tc)))
              (lambda (p d) 
                (define ps (queue-ps p))
                (if (and (tc-empty? tc) ps)
                  (begin (resume ps d)
                         (set-queue-ps! p #f))
                  (tc-append! tc d)))
              (lambda (p)
                (define ps (queue-ps p))
                (when ps (resume ps *eof*)))
              tc
              #f))

(define (empty? (<queue> queue))
  (tc-empty? (queue-tc queue)))

(define (read-all (<queue> queue))
  (define tc (queue-tc queue))
  (define data (tc->list tc))
  (tc-clear! tc)
  data)

(define (read-exprs (<queue> queue) (read-all queue)))

;;; Similar to an R5RS file with reads returning read s-exprs.
(define (open-lisp-input-file path)
  (define f (open-input-file path))
  (define e (read-exprs f))
  (define q (open-queue e))
  (close f)
  q)

(define (thaw-file path)
  (define p (open-input-file path))
  (define r (thaw (read-all p)))
  (close p)
  r)

;;; The omnipotent module loader
(define import #f)
(define reload #f)
(define export #f)

(define (load-mo path)
  (set! path (apply string-join *path-sep*
                                (string-split* path "/")))
  ((thaw-file path)))

(define (load-ms path)
  (set! path (apply string-join *path-sep*
                                (string-split* path "/")))
  (define file (open-input-file path))
  (define data (read-exprs file))
  ((assemble (optimize (compile data)))))

(define (load path)
  (cond ((string-ends-with? path ".mo") (load-mo path))
        ((string-ends-with? path ".ms") (load-ms path))
        ((string-ends-with? path ".scm") (load-ms path))
        (else (error 'load "load only handles scm, ms and mo files" path))))

(let ((*basedir* (getcwd))
      (*imports* (dict))
      (*last-imported-key* #f)
      (*last-imported-path* #f))
      
  (set! import (lambda (skey)
                 (define key (string->symbol skey))
                 (unless (dict-set? *imports* key)
                   (define path (string-append skey ".mo"))
                   (load-mo path))))

  (set! reload (lambda (skey)
                 (dict-remove! *imports* key)
                 (import key)))

  (set! export (lambda (skey . exports)
                 (define key (string->symbol skey))
                 (dict-set! *imports* key (if (eq? key *last-imported-key*)
                                            *last-imported-path*
                                            #t)))))

(export "lib/core")

