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
(import "mosref/node")

(define *cmd-term* (make-regex "[^ \r\n\t]+"))

; Assumes that each input is precisely one line.
(define (mosref-shell console)
  (define current-node #f)

  (define (set-current-node node)
    (set! current-node node))

  (define (send-prompt)
    (send (string-append (node-id current-node) "> ")))

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
    (define id (req-term terms "node identifier" for "."))
    (define node (find-mosref-node id))
    (unless node
      (send-err "Could not find " (format id) for ".")))

  (define (req-path terms for)
    (define path (req-term terms "file path" for "."))
    (unless (string-find path ":")
      (return (list current-node path)))
    (set! path (string-split path ":"))
    (define id (car path))
    (set! path (cadr path))
    (define node (find-mosref-node id))
    (unless node
      (send-err "Could not find node " (format id) for "."))
    (list node path))

  (define (opt-port terms for)
    (when (tc-empty? terms)
      (return (random-integer 10000 30000)))
    (define str (tc-next! terms))
    (guard (lambda (e)
             (send-err "Could not parse port number " (format str) "."))
           (string->integer str)))
        
  (define finished #f)

  (define commands 
    (dict (list "on" (function (on-cmd terms)
                       (define old-node current-node)
                       (define node (req-node terms ""))
                       (set-current-node node)
                       
                       (define (revert-node)
                         (set-current-node old-node))

                       (unless (tc-empty? terms)
                         (guard (function (revert-node-before-err err)
                                   (revert-node)
                                   (re-error err))
                            (parse-cmd terms)
                            (revert-node))))
                (string-append
                  "USAGE: on <node-id>\n"
                  "Instructs the console to perform subsequent commands on the"
                  " specified node.\n"
                  "USAGE: on <node-id> <command> <arg> ...\n\n"
                  "Performs the supplied command, with arguments, on the"
                  " specified host\n\n"))

          (list "nodes" (function (nodes-cmd terms)
                          (for-each (function (display-node node)
                                      (send-line (format (node-id node))
                                                 " -- "
                                                 (format (node-addr node))))
                                    (list-mosref-nodes)))
                (string-append
                  "USAGE: nodes\n"
                  "Lists the nodes currently known to the console, and their"
                  " addresses.\n\n"))
         
          (list "drone" (function (drone-cmd terms)
                          (define file (req-path terms " drone file"))
                          (define id (req-term terms " drone identifier"))
                          (define platform (req-term terms " drone platform"))
                          (define portno (opt-port terms " listener port"))
                          
                          (define ecdh (make-console-ecdh))
                          (define data 
                            (guard (lambda (e)
                                     (send-err "Could not compile drone."))
                              (make-drone-exe (node-addr current-node)
                                                    portno
                                                    ecdh
                                                    platform)))
                          (guard (lambda (e)
                                   (send-err "Could not write file "
                                             (format (cadr file)) "."))
                            (put-node-file @file data))
                        
                          (send-line "Drone executable created.")

                          (define listener 
                            (guard (lambda (e)
                                   (send-err "Could not listen to " 
                                             (format portno) "."))
                            (tcp-listen portno)))
                          
                          (send-line "Listening for drone on " (format portno)
                                     "...")

                          ;TODO: Spawn this off.
                          (define transport
                            (guard (lambda (e)
                                   (close-listener listener)
                                   (send-err "Affilation failed, "
                                             (car (error-info e))
                                             "."))
                               ;TODO: Make lapse configurable.
                               (await-drone-affiliation listener ecdh 60000)))
                        
                          (send-line "Drone affiliated.")

                          ;TODO: Where will we get addr?
                          (make-drone-node 
                            id #f (spawn-endpoint console-endpoint @transport)))

                (string-append
                  "USAGE: drone <file> <id> <platform> [<portno>]\n"
                  "Creates a new drone executable for the specified platform"
                  " and places it at file, then spawns a listener on the"
                  " current node.  When the drone connects to the listener, a"
                  " the drone will be bound to the specified identifier.\n\n"))

          (list "cp" (function (cp-cmd terms)
                       (define src (req-path terms " for source file"))
                       (define dst (req-path terms " for destination file"))

                       (send-line
                         "Copy from: " (format src) " to " (format dst))
                       
                       (define data (guard (lambda (e) 
                                             (send-err
                                               "Could not access file " 
                                               (format (cadr src)) "."))
                                      (get-node-file @src)))
                       
                       (guard (lambda (e) 
                                (traceback e)
                                (send-err
                                  "Could not alter file "
                                  (format (cadr dst)) "."))
                         (put-node-file @dst data)))

                (string-append
                  "USAGE: cp src-file dst-file\n"
                  "Copies source file to dest file.\n\n"))

          (list "help" (function (help-cmd terms)
                         (when (tc-empty? terms)
                           (send-line 
                             "Commands: "
                             (apply string-join " " (dict-keys commands)))
                           (return))
                         (define cmd (tc-next! terms))
                         (define data (dict-ref commands cmd))
                         (unless data
                           (send-err "Command " cmd " not found."))
                         (send (string-append "\n" (cadr data))))
                (string-append
                  "USAGE: help\n"
                  "Requests a list of all commands known by the console\n\n"
                  "USAGE: help <command>\n"
                  "Requests information about the syntax and usage of a "
                  " command\n\n"))

          (list "exit" (function (exit-cmd terms)
                         (set! finished #t))
                (string-append
                  "Terminates the console."))))
  
  (define (parse-cmd terms)
    (when (string? terms)
      (return (parse-cmd (apply make-tc (or (match-regex* *cmd-term* terms)
                                            '())))))

    (when (tc-empty? terms) 
      (return))

    (define verb (tc-next! terms))
    (define data (dict-ref commands verb))
    (unless data
      (send-err "I do not understand " (format verb) "."))
    
    ((car data) terms))

  (set-current-node console)

  (send-prompt)

  (until finished
    (define cmd (wait))
    (when (eq? cmd 'close) (return))
    (when (string? cmd)
      (guard (function (catch-syn err)
                (unless (eq? (error-key err) 'syn)
                  (re-error err)))
        (parse-cmd cmd))
      (unless finished (send-prompt)))))
