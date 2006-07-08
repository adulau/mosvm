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

(module "mosref/shell")
(import "mosref/console")

(define *cmd-term* (make-regex "[^ \r\n\t]+"))

; TODO: Shim
(define *console-node* 'console)

; TODO: Shim
(define (find-mosref-node node)
  (string->symbol node))

; TODO: Shim
(define (node-id node)
  (symbol->string node))

; Assumes that each input is precisely one line.
(define (mosref-shell)
  (define current-node *console-node*)
  (define current-node-id "console")
 
  (define (send-prompt)
    (send (string-append current-node-id "> ")))

  (define (send-line . items)
    (send (string-append @items *line-sep*)))

  (define (send-err . items)
    (apply send-line "ERROR: " items)
    (error 'syn))

  (define (req-term terms . what)
    (when (tc-empty? terms)
      (apply send-err "Expected " what))
    (tc-next! terms))

  (define (req-node terms for)
    (define id (req-term terms "node identifier " for "."))
    (define node (find-mosref-node id))
    (unless node
      (send-err "Could not find " (format id) for ".")))

  (define commands 
    (dict (cons "on" (function (on-cmd terms)
                       (define node (req-node terms ""))

                       (define old-id current-node-id)
                       (define old-node current-node)

                       (set! current-node-id (node-id node))
                       (set! current-node node)
                       
                       (define (revert-node)
                         (set! current-node old-node)
                         (set! current-node-id old-id))

                       (unless (tc-empty? terms)
                         (guard (function (revert-node-before-err err)
                                   (revert-node)
                                   (re-error err))
                            (parse-cmd terms)
                            (revert-node)))))))
  
  (define (parse-cmd terms)
    (when (string? terms)
      (return (parse-cmd (apply make-tc (match-regex* *cmd-term* terms)))))

    (when (tc-empty? terms) 
      (return))

    (define verb (tc-next! terms))
    (define func (dict-ref commands verb))
    (unless func
      (send-err "I do not understand " (format verb) "."))
    
    (func terms))

  (send-prompt)

  (forever
    (define cmd (wait))
    (when (eq? cmd 'close) (return))
    (when (string? cmd)
      (guard (function (catch-syn err)
                (unless (eq? (error-key err) 'syn)
                  (re-error err)))
        (parse-cmd cmd))
      (send-prompt))))

