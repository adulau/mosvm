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

(module "bin/mosref")
(import "mosref/console")
(import "mosref/shell")

(define (main . args)
  (define unparsed-args (apply make-tc args))

  (define (next-arg) (tc-next! unparsed-args))
  (define (more-args?) (not (tc-empty? unparsed-args)))

  (define (send-lines . lines)
    (send (apply string-join *line-sep* 
                 (map (lambda (i) (if (pair? i)
                                    (string-join " " i)
                                    i))
                      lines))))

  (define (send-line . items)
    (send (string-append (apply string-append items) *line-sep*)))

  (define (show-usage)
    (send-lines 
      "USAGE: mosref console-addr"
      "       console-addr -- The hostname or address of the console; this"
      "                       address should be reachable by any first tier"
      "                       drones."
      ""
      "EXAMPLE: mosref decoy.ephemeralsecurity.com"
      ""))

  (define (parse-error message)
      (show-usage)
      (send-line "ERROR: " message)
      (halt)) 

  (define (missing-error type purpose)
    (unless (more-args?)
      (parse-error (string-append "Missing " type " for " purpose "."))))

  (missing-error "address" "console listener")
  (define console (next-arg))

  (mosref-shell (make-console-node console)))

