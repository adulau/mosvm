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

; The Incremental REPL is useful for incrementally constructing an application,
; one function at a time; a file argument is loaded prior to starting the REPL
; session, and each command that does not result in an error is appended to the
; file.
; The Incrmental REPL: each instruction is saved in a file, and restored from
; that file at loadup.

(import "lib/optimize")
(import "lib/assemble")
(import "lib/compile")
(import "lib/format")
(import "lib/trace")
(import "lib/eval")

(define (mux-output . ports)
  (make-port #f
             (lambda (p d) (for-each write (circle d) ports))
             #f
             #f))

(define (join-lines head . lines)
  (if (null? lines)
    ""
    (string-append head (apply string-join (string-append *line-sep* head)
                               lines))))

(define (incr-repl file)
  (when (file-path? file) (load file))

  (define file (open-output-file file))
  (file-seek file (file-len file))
  (define user-output (current-output-port))
  (define succ-output (filter-output (lambda (data) 
                                       (apply join-lines ";;;" 
                                              (split-lines data)))
                                     file))
  (with-output (mux-output user-output succ-output)
    (until (closed?)
      (write "\n>> " user-output)
      (define data (read))
      (if (eof-object? data)
        (halt)
        (guard (lambda (e) (traceback e user-output))
               (set! result (exec (string->exprs data)))
               (write ":: ")
               (show data)
               (write "\n")))))
  (close-output-port file))

(define (main path)
  (incr-repl path))

(export nothink)
