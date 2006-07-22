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

(define-cmd "set"
            "set [<key>[=<value>] [<command>]]"
            (string-append
              "If no key is supplied, lists properties associated with the"
              " current node.  If a key and value is supplied, assigns the"
              " supplied value to the key, for the current node.  If only"
              " the key is supplied, the value is assumed to be \"true\"."
              "\n\n"
              "If a command is furnished, in addition to a key, it will be"
              "performed after the property has been updated."
              "\n\n"
              "The word 'set' may be omitted, if the key=value form is used.")

  (define node (mosref-shell-node shell))
  (define key-val (opt-term terms))
  (define command (if (and key-val (not (tc-empty? terms))) terms #f))
  (define key #f)
  (define val #f)

  (when key-val 
    (set! key-val (string-split key-val "="))
    (set! key (string->symbol (car key-val)))
    (set! val (if (null? (cdr key-val))  
                  #t
                  (parse-propval (cadr key-val)))))

  (cond (command (set-node-prop! node key val)
                 (do-mosref-cmd shell command))
        (key     (set-node-prop! node key val)
                 (send-line "Set."))
        (else    (send-line "Properties: "
                            (apply string-join "\n            " 
                                         (map format-property 
                                              (list-node-props node)))))))

(define (format-property key-val) (string-append (format (car key-val))
                                                 " = " 
                                                 (format-propval 
                                                   (cdr key-val))))

(define (format-propval val)
  (case val
    ((#t) "true")
    ((#f) "false")
    (else (format val))))

