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
(import "lib/optimize")
(import "lib/eval")

(export build-module build-dependencies build-exe read-platform-stub)

(define (read-platform-stub platform)
  (define path (path-join (or (site-config 'stub-path) "./stubs") 
                          (string-append "mosvm-stub-" platform)))
  (when (string-begins-with? platform "winnt")
    (set! path (string-append path ".exe")))

  (if (file-path? path) (read-data-file path) #f))

;; TODO: Belongs in a string utility lib.
(define (replace-string-tail src tail)
  (string-append (substring src 0 (- (string-length src)
                                     (string-length tail)))
                 tail))

(define (build-module module)
  (define (compile-module ms-path mo-path)
    (define data (read-lisp-file ms-path))
    (set! data (compile data))
    (set! data (optimize data))
    (set! data (assemble data))
    (set! data (freeze data))
    (write-data-file mo-path data)
    data)

  (set! module (convert-path module))

  (define ms-path (find-module-file (string-append module ".ms")))
  (define mo-path (if ms-path
                    (replace-string-tail ms-path ".mo")
                    (find-module-file (string-append module ".mo"))))
  (define ms-exists (and ms-path (file-path? ms-path)))
  (define mo-exists (and mo-path (file-path? mo-path)))
  
  (cond
    ((and mo-exists ms-exists)
     (when (> (path-mtime ms-path) (path-mtime mo-path))
       (compile-module ms-path mo-path)))
    (mo-exists #t) ;No source -- we'll assume the module is built.
    (ms-exists
      (compile-module ms-path mo-path))
    (else
      (error 'build "cannot find a source or object file")))
 
  (read-data-file mo-path))

(define (build-dependencies source)
  (define dependencies (make-tc (code-dependencies source)))
  (until (tc-empty? dependencies)
    (build-module (tc-next! dependencies))))

(define (build-modules . modules)
  ;; Given a list of modules, build-modules will attempt to recompile them in
  ;; their dependent order.  Any module that is a dependency, but not listed
  ;; in these modules is ignored.
  
  (set! modules (map (lambda (item)
                        (if (or (string-ends-with? item ".ms")
                                (string-ends-with? item ".mo"))
                          (substring item 0 (- (string-length item) 3))
                          item))
                      modules))
  (let ((scope (apply set modules))
        (order (make-tc))
        (undone (apply make-tc modules))
        (item #f))

    (until (tc-empty? undone)
           (set! item (tc-next! undone))
           (when (set-member? scope item)
             (set-remove! scope item)
             (for-each (lambda (dep)
                         (when (set-member? scope dep)
                           (tc-append! order dep)
                           (set-remove! scope dep)))
                       (code-dependencies item))
             (tc-append! order item)))

    (set! order (tc->list order))
    (for-each build-module order)
    order)) 

(export build-modules)

(define (glue string data)
  (string-append! string data)
  (string-append-word! string (string-length data))
  (string-append! string "mvf2")
  string)

(define (build-exe platform main)
  (define string (make-string))
  (string-append! string (read-platform-stub platform))

  (for-each (function (glue-dep item) 
              (glue string item))
            (map build-module (code-dependencies main)))

  (if (pair? main)
    (glue string (freeze (assemble (optimize (compile main))))))

  string)

;;; MOSVM3
