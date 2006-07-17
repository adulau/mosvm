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

  (spawn-node-shell current-node (tc->list terms)))

(define (spawn-node-cmd (<console-node> node) cmd)
  (when (string-begins-with? *platform* "win")
    (send-line "ERROR: This version of MOSREF cannot spawn shell commands on "
               "Microsoft Windows.")
    (return))

  (set-car! cmd (locate-cmd (car cmd)))
  (define stream (spawn-command (car cmd) (cdr cmd)))
  (define done #f)

  (spawn (lambda ()
           (until done
                  (define evt (wait stream))
                  (when (eq? evt 'close) 
                    (unless done 
                      (set! done #t)
                      (send 'close (input)))
                    (return)))))

  (until done
    (define evt (wait (input)))
    (send evt stream)
    (when (eq? evt 'close)
      (set! done #t)))

  (pause))

(define *node-shell-prog*
  (inline (import "lib/env")
          (when (string-begins-with? *platform* "win")
            (error 'shell 
                   "MOSREF cannot spawn shell commands on Microsoft Windows"))

            (let ((cmd (wait)))
              (guard (lambda (err)
                       (error 'shell
                              (string-append "cannot find command " (car cmd))))
                (set-car! cmd (locate-cmd (car cmd))))

              (define stream (spawn-command (car cmd) (cdr cmd)))
              (define done #f)

  ;TODO: Many commands won't close stdin -- we must send a close to the
  ;      stream to cooerce it into doing the right thing.
  ;
  ;      A better strategy would be to watch the pid, and close it -- but this
  ;      requires a thread.
              (timeout 1000 (input stream) 'close)

              (until done
                (define evt (wait stream))
                (cond
                  ((eq? evt 'close) (set! done #t))
                  (else (send evt))))

              (send 'close))))

(define (spawn-node-shell node cmd)
  (with-node-program node *node-shell-prog*
    (send cmd xmit)
    (define done #f)
    (until done 
      (define evt (wait recv))
      (cond 
        ((eq? evt 'close) (set! done #t))
        ((string? evt) (send evt))))))

