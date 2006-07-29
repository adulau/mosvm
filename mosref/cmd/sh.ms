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

(module "mosref/cmd/sh")
(import "mosref/shell")
(import "mosref/node")

(define-cmd "sh" 
            "sh <cmd>"
            (string-append
              "Evaluates the supplied host command on the current node --"
              " this will only work on non-Windows nodes, due to"
              " limitations in the Win32 command shell.")

  (spawn-node-shell (mosref-shell-node shell) (tc->list terms)))

(define *node-shell-prog*
  (inline (export nothing)
          (import "lib/env")
          (import "mosref/patch")
          (when (string-begins-with? *platform* "win")
            (error 'shell 
                   "MOSREF cannot spawn shell commands on Microsoft Windows"))

          (define cmd (wait))

          (guard (function (report-cmd-not-found err)
                   (error 'shell
                          (string-append "cannot find command " (car cmd))))
                (set-car! cmd (locate-cmd (car cmd))))
        
          (define stream (spawn-command (car cmd) (cdr cmd)))
          (define lane (make-reserved-lane *drone-bridge*))
          (send (list 'connect (lane-tag lane)))
          (patch2 stream lane)
          (send 'close)))

(define (spawn-node-shell (<drone-node> node) cmd)
  (define conn (spawn-node-program node *node-shell-prog*))
  (define xmit (car conn))
  (define recv (cadr conn))
  (define bridge (drone-node-bridge node))
  (send cmd xmit)
  (define event (wait recv))
  (print "EVENT: ")
  (print (format event))
  (print "\n")
  (send 'close xmit)
  (when (and (pair? event)
             (eq? (car event) 'connect))
    (define tag (cadr event))
    (define lane (find-reserved-lane bridge tag))
    (print "BRIDGE: ")
    (print (format bridge))
    (print " TAG: ")
    (print (format tag))
    (print " LANE: ")
    (print (format lane))
    (print "\n")
    (when lane
      (define lx (lane-xmit lane))
      (define lr (lane-recv lane))
      (define tx (output))
      (define tr (input))
      (spawn (lambda ()
               (forever
                 (define e (wait lr))
                 (when (eq? e 'done)
                   (return))
                 (when (eq? e 'close)
                   (send 'done tr)
                   (return))
                 (send e tx))))
      (forever
        (define e (wait tr))
        (when (eq? e 'done)
          (return))
        (send e lx)
        (when (eq? e 'close)
          (send 'done lr)
          (send e (output tr)))))
    (send-err "Could not resolve initial lane."))
    (send-err "Bogus message while waiting for command lane, " (format event)))

(define (spawn-node-shell (<console-node> node) cmd)
  (when (string-begins-with? *platform* "win")
    (send-err "MOSREF cannot spawn shell commands on Microsoft Windows"))
  
  (guard (function (report-cmd-not-found err)
                   (error 'shell
                          (string-append "cannot find command " (car cmd))))
         (set-car! cmd (locate-cmd (car cmd))))

  (define stream (spawn-command (car cmd) (cdr cmd)))

  (define sx (input stream))
  (define sr (output stream))
  (define tx (output))
  (define tr (input))

  (spawn (lambda ()
           (forever
             (define e (wait sr))
             (when (eq? e 'done)
               (return))
             (when (eq? e 'close)
               (send 'done tr)
               (return))
             (send e tx))))

  (forever
    (define e (wait tr))
    (send e sx)
    (when (eq? e 'done)
      (return))
    (when (eq? e 'close)
      (send 'done sr)
      (send e (output tr))
      (return))))
