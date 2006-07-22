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
(import "mosref/listener")

(define-cmd "drone"
            "drone <file> <id> <platform>"
            (string-append
              "Creates a new drone executable for the specified platform"
              " and places it at file, then spawns a listener on the"
              " current node.  When the drone connects to the listener, a"
              " the drone will be bound to the specified identifier.")

  (define file (req-path (mosref-shell-console shell)
                         terms " for drone executable"))
  (define id (req-term terms " drone identifier"))
  (define platform (req-term terms " drone platform"))
  (define node (mosref-shell-node shell))
  (define portno (or (node-portno node)
                     (random-integer 20000 30000)))
  (define ecdh (make-console-ecdh))
  (define addr (node-addr node))
  (unless addr
    (send-err " node address unknown, use set addr to assign one"))
  (define sin (node-make-sin node portno))
  (define data (guard (lambda (e)
                        (send-err "Could not compile drone."))
                 (make-drone-exe addr sin portno ecdh platform)))
  (guard (lambda (e)
           (send-err "Could not write file " (format (cadr file)) "."))
    (put-node-file @file data))

  (send-line "Drone executable created.")

  (send-line "Listening for drone on " (format portno) "...")

  (spawn (lambda ()
           (guard (lambda (e)
                    ;TODO: Make number of attempts permitted
                    ;      configurable
                    (traceback e)
                    (send-line "ERROR: Affilation of " id " failed, "
                               (car (error-info e)) ".")
                    (halt))
                  ;TODO: Make lapse configurable.

              (define transport
                (print (format (list node portno sin)))
                (print "\n")
                (apply console-affiliation ecdh (node-sin-listen node 
                                                                 portno 
                                                                 sin)))
            
              (send-line "Drone " id " affiliated.")
              ;TODO: Tag with platform.
              ;TODO: Where will we get addr?
              (define next (make-drone-node id #f #f
                               (spawn-endpoint console-endpoint 
                                               console-broken 
                                               @transport)))
              (set-node-prop! next 'platform platform)))))

(define *node-sin-listen-prog* 
  (inline (export nothing)
          (import "mosref/listener")
          (import "mosref/patch")
          (define bridge *drone-bridge*)
          (define what (wait))
          (define conn (mosref-sin-listen @what))
          (define lane (make-reserved-lane bridge))
         
          (patch2 conn lane)
          (send (lane-tag lane))
          (send 'close)))

(define (node-sin-listen (<drone-node> node) portno sin)
  (define conn (spawn-node-program node *node-sin-listen-prog*))
  (define xmit (car conn))
  (define recv (cadr conn))
  (define lanes (make-channel))
  (define bridge (drone-node-bridge node))

  (send (list portno sin) xmit)

  (define event (wait recv))

  (send 'close xmit)

  (when (string? event)
    (define lane (find-reserved-lane bridge event))
    (when lane 
      (return (list (lane-xmit lane) (lane-recv lane)))))

  (error 'mosref "Bogus message while waiting for session lane" event))

(define (node-sin-listen (<console-node> node) portno sin)
  (define portno (node-portno node))
  (define conn (mosref-sin-listen portno sin))
  (list (input conn) (output conn)))

(define *node-make-sin-prog*
  (inline (export nothing)
          (import "mosref/listener")
          (send (make-mosref-sin (wait)))))

(define (node-make-sin (<drone-node> node) portno)
  (define conn (spawn-node-program node *node-make-sin-prog*))
  (define xmit (car conn))
  (define recv (cadr conn))

  (send portno xmit)
  
  (define event (wait recv))
  
  (send 'close xmit)

  (when (string? event)
    (return event))

  (error 'mosref 
         "Bogus message while waiting for service identification number" event))

(define (node-make-sin (<console-node> node) portno)
  (make-mosref-sin portno))

(export node-sin-listen node-make-sin)
