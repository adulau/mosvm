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
(define (object? value) (eq? <object> value))

;;; The base class for SRFI-9 Records
(define-class <record>
              <object>
              (make-record)
              record?)
              
;;; R5RS Specifies a magical "end of file" object returned by ports.
(define <eof> (tag (make-type 'eof <atom>) atom))
(define (eof-object? value) (eq? <eof> value))

(define-class <port> <object>
              (make-port close-fn)
              port?
              (close-fn port-close-fn))

;;; Specified by R5RS.
(define (close (<port> port))
  ((port-close-fn port) port))

(define-class <input-port> <port>
              (make-input-port close-fn read-fn)
              input-port?
              (read-fn input-port-read-fn))

;;; Conflicts with R5RS. 
(define (read) (read-descr *console*))
(define (read (<input-port> input-port))
  ((input-port-read-fn input-port) input-port))

;;; Exhausts a port.
(define (read-all (<input-port> input-port))
  (define tc (make-tc))
  (define nxt (read input-port))
  (until (eof-object? nx)
    (tc-append! tc nx)
    (set! nxt (read input-port)))
  (tc->list tc))

;;; Reads a list of lines from a given port.
(define (read-lines (<input-port> input-port))
  (split-lines (read-all input-port)))

;;; Reads all the expressions from a given port.
(define (read-exprs (<input-port> input-port))
  (define data (read-all input-port))
  (string->exprs (if (string? data)
                   data
                   (apply string-append data))))

(define-class <output-port> <port>
              (make-output-port close-fn write-fn)
              output-port?
              (write-fn output-port-write-fn))

;;; Conflicts with R5RS. 
(define (write data) (write-descr *console* data))
(define (write data (<output-port> output-port)) 
  ((output-port-write-fn output-port) output-port data))

(define-class <file-output-port> <output-port>
              (make-file-output-port close-fn write-fn descr)
              file-output-port?
              (descr file-port-descr))

;;; Stripped in functionality, but R5RS compliant.
(define (open-output-file path)
  (let ((f (open-file path "wc")))
    (seek-file f 0)
    (make-file-output-port (lambda (port) (close-descr f))
                           (lambda (port data) (write-descr f data)) 
                           f)))

(define (write-byte byte (<file-output-port> port))
  (write-file-byte (file-port-descr port) byte))

(define (write-word word (<file-output-port> port))
  (write-file-word (file-port-descr port) word))

(define (write-quad quad (<file-output-port> port))
  (write-file-quad (file-port-descr port) quad))

(define-class <file-input-port> <input-port>
              (make-file-input-port close-fn read-fn descr)
              file-input-port?
              (descr file-port-descr))

;;; Similar to an R5RS file, but returns raw strings.
(define (open-input-file path)
  (let ((f (open-file path "r")))
    (make-file-input-port 
      (lambda (port) (close-descr f))
      (lambda (port) 
        (let ((data (read-descr f)))
          (if (= 0 (string-length data)) <eof> data))) 
      f)))

(define (read-all (<file-input-port> input-port))
  (read-file-all (file-port-descr input-port)))

;;; Redundant, but R5RS specified
(define (close-output-port (<output-port> port))
  ((port-close-fn port)))

;;; Redundant, but R5RS specified
(define (close-input-port (<input-port> port))
  ((port-close-fn port)))

;;; SRFI-6 String Port Emulation
(define-class <string-output-port> <output-port>
              (make-string-output-port close-fn write-fn data)
              string-output-port?
              (data string-output-port-data))

(define (open-output-string)
  (let ((tc (make-tc)))
    (make-string-output-port ignore-method
                             (lambda (port data) (tc-append! tc data))
                             tc)))

(define (string-port? (<string-output-port> port)) #t)

(define (write-byte byte (<string-output-port> port))
  (tc-append! (string-output-port-data port) byte))

(define (write-word word (<string-output-port> port))
  (write-byte (quotient word 256) port)
  (write-byte (remainder word 256) port))

(define (write-quad quad (<string-output-port> port))
  (write-word (quotient quad 65536) port)
  (write-word (remainder quad 65536) port))

(define (get-output-string (<string-output-port> port))
  ; Each call to g-o-s compresses the queued data into a single string
  ; object, alters the queue to contain that object, then returns
  ; the result.
  (define tc (string-output-port-data port))
  (define data (apply string-append (tc->list tc)))
  (tc-clear! tc)
  (tc-append! tc data)
  data)

;;; The queue is both an input, and an output, backed by a tconc.
(define-class <queue> <port>
              (make-queue close-fn read-fn write-fn tc)
              queue?
              (close-fn port-close-fn)
              (read-fn input-port-read-fn)
              (write-fn output-port-write-fn)
              (tc queue-tc))

(define (input-port? (<queue> queue)) #t)

(define (output-port? (<queue> queue)) #t)

(define (open-queue data) 
  (define tc (make-tc))
  (if data (tc-splice! tc data))
  (make-queue ignore-method
              (lambda (port) (if (tc-empty? tc)
                               <eof>
                               (tc-next! tc)))
              (lambda (port data) (tc-append! tc data))
              tc))

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
  (cond ((string-ends-with path ".mo") (load-mo path))
        ((string-ends-with path ".ms") (load-ms path))
        ((string-ends-with path ".scm") (load-ms path))
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

(define (newline) (write *line-sep*))
(define (newline (<port> port) (write *linesep* port)))

(export "lib/core")

