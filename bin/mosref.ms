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
(import "lib/env")
(import "lib/with-io")
(import "lib/terminal")
(import "lib/iterate")
(import "mosref/console")
(import "mosref/shell")
(import "mosref/cmds")

(define (main . args)
  (if *in-win32* 
    (with-io (spawn-terminal "MOSREF")
             (do-mosref args))
    (do-mosref args)))

(define (do-mosref args)
  (define unparsed-args (apply make-tc args))

  (define (next-arg) (if (tc-empty? unparsed-args) 
                       #f
                       (tc-next! unparsed-args)))

  (define addr (next-arg))
  (define portno (next-arg))

  (define node (make-console-node addr portno))
  
  (run-mosref-shell node node))

