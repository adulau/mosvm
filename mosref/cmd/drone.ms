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
  (define data (guard (lambda (e)
                        (send-err "Could not compile drone."))
                 (make-drone-exe addr 
                                 portno ecdh platform)))
  (guard (lambda (e)
           (send-err "Could not write file " (format (cadr file)) "."))
    (put-node-file @file data))

  (send-line "Drone executable created.")

  (send-line "Listening for drone on " (format portno) "...")

  (define listener (node-tcp-listen node portno))
  (define finish (car listener))
  (define conns (cadr listener))

  (spawn (lambda ()
           (guard (lambda (e)
                    ;TODO: Make number of attempts permitted
                    ;      configurable
                    (traceback e)
                    (send-line "ERROR: Affilation of " id " failed, "
                               (car (error-info e)) ".")
                    (finish)
                    (halt))
                  ;TODO: Make lapse configurable.

              (define transport
                (await-drone-affiliation conns ecdh 1800000))

              (send-line "Drone " id " affiliated.")
              ;TODO: Tag with platform.
              ;TODO: Where will we get addr?
              (finish)
              (make-drone-node id #f #f
                               (spawn-endpoint console-endpoint 
                                               console-broken @transport))))))

(define *node-tcp-listen-prog* 
  (inline (export nothing)
          (define bridge *drone-bridge*)
          (define portno (wait))
          (define listener (guard (function (report-failed-listen err)
                                    (print "Could not listen to ")
                                    (print (format portno))
                                    (print "\n")
                                    ;TODO: Signal failure of the listener.
                                    )
                             (tcp-listen portno)))
          (define (relay-conn conn lane)
            (define conn-input (input conn))
            (define conn-output (output conn))
            (define lane-input (lane-xmit lane))
            (define lane-output (lane-recv lane))
            (spawn (lambda ()
                     (forever
                       (send (wait conn-output) lane-input))))
            (spawn (lambda ()
                     (forever
                       (send (wait lane-output) conn-input)))))
          (spawn (lambda ()
                   (forever
                     (when (eq? (wait) 'close)
                       (close-listener listener))
                     (send 'close))))
          (forever
            (define conn (wait listener))
            ;TODO: Need to know the node.
            (define lane (make-reserved-lane bridge))
            (send (lane-tag lane))
            (relay-conn conn lane))))

(define (node-tcp-listen (<drone-node> node) portno)
  (define conn (spawn-node-program node *node-tcp-listen-prog*))
  (define xmit (car conn))
  (define recv (cadr conn))
  (define lanes (make-channel))
  (define bridge (drone-node-bridge node))
  (send portno xmit)

  (spawn (lambda ()
           (define done #f)
           (until done
              (define event (wait recv))
              (cond
                ((eq? event 'close)
                 (set! done #t))
                ((string? event)
                 (define lane (find-reserved-lane bridge event))
                 (send (if lane lane (list 'fail "unrecognized tag" event))
                       lanes))
                ((and (pair? event) (eq? (car event) 'fail))
                 (send event lanes))
                (else
                 (send (list 'fail "unrecognized event" event) lanes))))
           (send 'close xmit)))

  (list (function (halt-drone-listener)
          (send 'close xmit)
          (send 'close recv))
        lanes))

(define (node-tcp-listen (<console-node> node) portno)
  (define listener (tcp-listen portno))
  (list (function (halt-console-listener)
          (close-listener listener))
        listener))

(export node-tcp-listen)

