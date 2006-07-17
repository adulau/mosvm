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

(module "mosref/cmd/drone")
(import "mosref/shell")
(import "mosref/node")

(define-cmd "drone"
            "drone <file> <id> <platform> [<portno>]"
            (string-append
              "Creates a new drone executable for the specified platform"
              " and places it at file, then spawns a listener on the"
              " current node.  When the drone connects to the listener, a"
              " the drone will be bound to the specified identifier.")

  (define file (req-path terms " for drone executable"))
  (define id (req-term terms " drone identifier"))
  (define platform (req-term terms " drone platform"))
  (define portno (or (opt-integer terms " listener port")
                     (random-integer 20000 30000)))
  (define ecdh (make-console-ecdh))
  (define data (guard (lambda (e)
                        (send-err "Could not compile drone."))
                 (make-drone-exe (node-addr (mosref-shell-node shell))
                                 portno ecdh platform)))
  (guard (lambda (e)
           (send-err "Could not write file " (format (cadr file)) "."))
    (put-node-file @file data))

  (send-line "Drone executable created.")

  (define listener 
    (guard (lambda (e)
             (send-err "Could not listen to " 
                       (format portno) "."))
           (tcp-listen portno)))

  (send-line "Listening for drone on " (format portno)
             "...")

  (spawn (lambda ()
           (guard (lambda (e)
                    ;TODO: Make number of attempts permitted
                    ;      configurable
                    (close-listener listener)
                    (send-line "ERROR: Affilation of " 
                               id
                               " failed, "
                               (car (error-info e))
                               "."))
                  ;TODO: Make lapse configurable.
                  (define transport
                    (await-drone-affiliation listener ecdh 1800000))

                  (send-line "Drone " id " affiliated.")
                  ;TODO: Tag with platform.
                  ;TODO: Where will we get addr?

                  (make-drone-node 
                    id #f 
                    (spawn-endpoint console-endpoint @transport))))))

