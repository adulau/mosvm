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
(import "lib/compile")
(import "lib/format")
(import "lib/trace")
(import "lib/eval")
(import "lib/file-port")
(import "lib/filter")

;;; Belongs in a string library.
(define (lead-lines lead src)
  (if (string=? src "")
    ""
    (string-append lead (apply string-join 
                               (string-append *line-sep* lead)
                               (split-lines src)))))

(define (incr-repl file)
  (when (file-path? file) (load file))

  (define file-output (open-output-file file))
  (file-seek file-output (file-len file-output))
  
  (until (closed?)
     (write ">> ")
     (define data (read))
     (if (eof-object? data)
       (halt)
       (guard traceback
          (set! result (exec (string->exprs data)))
          (write data file-output)
          (when result
            (write ":: ")
            (show result)
            (newline)
            (write (lead-lines ";; " (value->string result)) file-output)
            (newline file-output)))))

  (close-output-port file))

(define (main path)
  (incr-repl path))

(export main)
