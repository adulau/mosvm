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

(module "mosref/cmd/set")
(import "mosref/shell")
(import "mosref/node")

(define-cmd "with"
            "with <key>[=<value>] [<command>]"
            "Performs the supplied command with key temporarily set to value."

  (define node (mosref-shell-node shell))
  (define key-val (req-term terms))
  (define command terms)
  (define key #f)
  (define val #f)

  (when key-val 
    (set! key-val (string-split key-val "="))
    (set! key (string->symbol (car key-val)))
    (set! val (if (null? (cdr key-val))  
                  #t
                  (parse-propval (cadr key-val)))))

  (define old-val (find-node-prop node key))
  (set-node-prop! node key val)
  (do-mosref-cmd shell command)
  (set-node-prop! node key old-val))

