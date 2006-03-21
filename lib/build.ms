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

(module "lib/build")

(import "lib/compile")
(import "lib/assemble")
(import "lib/optimize")
(import "lib/freeze")

(export add-module-dir! 
        resolve-module-location resolve-module-source resolve-module-object
        build-module build-dependencies)

(define *module-dirs* '("."))
(define *stub-dir* "./stubs")

(define (add-module-dir! path)
  (unless (member path *module-dirs*)
    (when (dir-path? path)
      (set! *module-dirs* (cons path *module-dirs*)))))

(define (resolve-module-path module-name)
  (define unchecked *module-dirs*)
  (define module-dir #f)
  (define module-path #f)
  
  (define (next-path)
    (if (null? unchecked)
      (set! module-path #f)
      (begin
        (set! module-dir (car unchecked))
        (set! module-path (path-join module-dir module-name))
        (set! unchecked (cdr unchecked))))
    module-path)

  (until (or (not (next-path))
             (file-path? module-path)))
  (and module-path module-dir))

(define (resolve-module-source module)
  (resolve-module-path (string-append module ".ms")))

(define (resolve-module-object module)
  (resolve-module-path (string-append module ".mo")))

(define (resolve-module-location module)
  (or (resolve-module-source module)
      (resolve-module-object module)))

(define (read-module-source module)
  (set! module (convert-path module))
  (define module-location (resolve-module-source module))
  (define module-source (string-append (path-join module-location module)
                                       ".ms"))
  (read-lisp-file module-source))

(define (build-module module)
  (set! module (convert-path module))
  (define module-location (resolve-module-location module))
  (unless module-location
    (error 'build "cannot find a source or object file for that module"))
  (define module-source (string-append (path-join module-location 
                                                  module)
                                       ".ms"))
  (define module-object (string-append (path-join module-location 
                                                  module)
                                       ".mo"))
  (define needs-build
    (if (file-path? module-source)
      (if (file-path? module-object)
        (> (path-mtime module-source) (path-mtime module-object))
        #t)
      #f))
  (if needs-build 
    (begin
      (define data (read-lisp-file module-source))
      (set! data (compile data))
      (set! data (optimize data))
      (set! data (assemble data))
      (set! data (freeze data))
      (define module-file (open-output-file module-object))
      (write data module-file)
      (close module-file)
      data)
    (read-data-file module-object)))

(define (determine-dependencies source)
  (define deps (make-tc "lib/core"))
  (define ignore (set "lib/core"))

  (define (process-code code)
    (for-each process-module 
              (map cadr
                   (filter (lambda (expr) (and (pair? expr)
                                               (= (length expr) 2)
                                               (eq? (car expr) 'import)
                                               (string? (cadr expr))))
                           code))))

  (define (process-module module)
    (unless (set-member? ignore module) 
      (set-add! ignore module)
      (process-code (read-module-source module))
      (tc-append! deps module)))

  (cond 
    ((string? source) (process-module source))
    ((pair? source) (process-code source))
    (else (error 'args "expected module name or module code for source")))
  (tc->list deps))

(define (build-dependencies source)
  (define dependencies (make-tc (determine-dependencies source)))
  (until (tc-empty? dependencies)
    (build-module (tc-next! dependencies))))

(define (glue buffer data)
  (write-buffer buffer data)
  (write-buffer-word buffer (string-length data))
  (write-buffer buffer "mvf2")
  buffer)

(export determine-dependencies read-module-source build-exe)

(define (build-exe platform main)
  (define stub-path (path-join *stub-dir* 
                               (if (string-begins-with? platform "win")
                                 (string-append "mosvm-stub-" platform ".exe")
                                 (string-append "mosvm-stub-" platform) )))
  (unless (file-path? stub-path)
    (error 'build "cannot find stub for platform"))
 
  (define buffer (make-buffer))
  (write-buffer buffer (read-data-file stub-path))
  (for-each glue (circle buffer) 
            (map build-module (determine-dependencies main)))
  (when (pair? main)
    (glue buffer (freeze (assemble (optimize (compile main))))))
  (buffer->string buffer))

