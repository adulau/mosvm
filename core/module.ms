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

(define (find-module-file filename)
  (define module-dirs (apply make-tc (or (site-config 'mod-path) '())))
  (define module-found #f)
  (until (or (tc-empty? module-dirs) module-found)
    (define module-dir (tc-next! module-dirs))
    (define module-path (path-join module-dir filename))
    (when (file-path? module-path)
      (set! module-found module-path)))
  module-found)

(define (read-module-source path)
  (read-lisp-file (find-module-file (string-append (convert-path path) 
                                                   ".ms"))))

(export find-module-file read-module-source)

(define (load-mo path)
  ((thaw (read-data-file path))))

(define (load path)
  (cond ((string-ends-with? path ".mo") (load-mo path))
        (else (error 'load "core/module load can only handle .mo files"))))

;;; Subsequent load implementations can handle .ms TODO

(export load-mo load)

(define *imports* (dict))

(define (imported? key)
  (dict-set? *imports* key))

(define (import key)
  (unless (imported? key)
    (define mo-path (find-module-file (string-append key ".mo")))
    (unless mo-path (error 'import "Module not imported, and cannot be found"))
    (load-mo mo-path)))

(define (module key)
  (dict-set! *imports* key #t))

(export imported? import module)
