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
(export *mosvm?*)

(define (eval expr)
  ((assemble (optimize (compile (list expr))))))

(export eval)

(define (read-data-file path)
  (define file (open-file-descr path "r"))
  (define data (read-descr-all file))
  (close-descr file)
  data)

(export read-data-file)

;;; for-each, map, find-tail, list-index, any, filter, fold and find from SRFI-1
(define (filter fn list)
  (define tc (make-tc))
  (until (null? list)
         (define it (car list))
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

(export filter filter! fold for-each map find-tail list-index find any)

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

(export make-class class-fields make-class-constructor make-field-accessor
        make-field-modifier ignore-method <object> object?)

;;; The base class for SRFI-9 Records
(define-class record
              <object>
              (make-record)
              record?)

(export <record> make-record record?)

;;; Specifies a magical "end of file" object returned by ports.
(define *eof* (tag (make-type 'eof <quark>) quark))
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
          (set-port-closed! port #t))
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

(define-class descr-port <port>
              (make-descr-port read-fn write-fn close-fn descr)
              descr-port?
              (descr port-descr))

(define (descr-input-port? value)
  (and (descr-port? value) (port-read-fn value)))

(define (descr-output-port? value)
  (and (descr-port? value) (port-write-fn value)))

(export <descr-port> make-descr-port descr-port? port-descr descr-input-port? 
        descr-output-port?)

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

(export <queue> make-queue read-queue write-queue read-queue-all make-queue)

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

;;; The omnipotent module loader
(define (load-mo path)
  (set! path (convert-path path))
  ((thaw-file path)))

(define (load-ms path)
  (set! path (convert-path path))
  (define file (open-input-file path))
  (define data (read-exprs file))
  ((assemble (optimize (compile data)))))

(define (load path)
  (cond ((string-ends-with? path ".mo") (load-mo path))
        ((string-ends-with? path ".ms") (load-ms path))
        ((string-ends-with? path ".scm") (load-ms path))
        (else (error 'load "load only handles scm, ms and mo files" path))))

(export load-mo load-ms load)

(define *basedir* (getcwd))
(define *imports* (dict))
(define *last-imported-key* #f)
(define *last-imported-path* #f)

(define (import skey)
  (define key (string->symbol skey))
  (unless (dict-set? *imports* key)
    (define path (string-append skey ".mo"))
    (load-mo path)))

(define (reload skey)
  (dict-remove! *imports* key)
  (import key))

(define (module skey)
  (define key (string->symbol skey))
  (dict-set! *imports* key (if (eq? key *last-imported-key*)
                             *last-imported-path*
                             #t)))

(export import reload module)

(module "lib/core")
