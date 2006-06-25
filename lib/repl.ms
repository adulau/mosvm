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
; under the terms of the GNU Lesser General Public License, version 2.1
; as published by the Free Software Foundation.

(module "lib/repl")

(import "lib/optimize")
(import "lib/compile")
(import "lib/eval")
(import "lib/line-filter")
(import "lib/s-filter")
(import "lib/filter")
(import "lib/trace")

(define (repl-syntax-err err)
  (send (string-append "SYNTAX: " (car (error-info err)) *line-sep* ">> ")))

(define (repl)
  (define cmds 
    (input-chain (input) 
                 (line-filter) 
                 (s-filter :promptN "   "
                           :errfn repl-syntax-err)))
  (forever
    (define cmd #f)
    (send ">> ")
    (until cmd
      (guard (lambda (x) 
               (traceback x (output))
               (set! cmd #f))
        (set! cmd (error-on-fail (wait cmds)))))
    (when (eq? cmd 'close) (return))
    (guard (lambda (x) (traceback x (output)))
      (define data (format (exec cmd)))
      (send (string-append ":: " data *line-sep*)))))

(export repl)
