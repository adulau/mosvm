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

(module "mosref/node")
(import "lib/object")
(import "lib/bridge")
(import "lib/filter")
(import "lib/package-filter")
(import "lib/with-io")
(import "mosref/report")

(define *nodes-by-id* (dict))

(define (send-line . items)
  (send (string-append @items *line-sep*)))

(define-class node <object>
              (make-node-record id addr)
              node?
              (id node-id)
              (addr node-addr))

(define-class console-node <node>
              (make-console-node-record id addr)
              console-node?
              (id node-id)
              (addr node-addr))

(define-class drone-node <node>
              (make-drone-node-record id addr bridge)
              drone-node?
              (id node-id)
              (addr node-addr)
              (bridge drone-node-bridge))

(define (list-mosref-nodes)
  (dict-values *nodes-by-id*))

(define (find-mosref-node id)
  (dict-ref *nodes-by-id* id))

(define (make-console-node addr)
  (define node (make-console-node-record "console" addr))
  (dict-set! *nodes-by-id* "console" node)
  node) 

(define (make-drone-node id addr bridge)
  (define node (make-drone-node-record id addr bridge))
  (dict-set! *nodes-by-id* id node)
  node)

(define (spawn-node-program (<console-node> node) program)
  (define xmit (make-channel))
  (define recv (make-channel))
  (with-input xmit (with-output recv (spawn program)))
  (list xmit recv))

(define (spawn-node-program (<drone-node> node) program)
  (define lane (make-lane (drone-node-bridge node)))
  (define xmit (output-chain (lane-xmit lane)
                             (freeze-filter)))
  (define recv (input-chain (lane-recv lane)
                            (thaw-filter)))
  (send program xmit)
  (list xmit recv))

(define (expect-data recv)
  ;TODO: timeout
  (define evt (wait recv))
  (when (eq? evt 'close)
    (error 'expect "channel closed while expecting data"))
  (guard (lambda (e)
           (apply error 'expect (error-info e)))
    evt))

(define (expect-signal recv)
  (define evt (expect-data recv))
  (unless (pair? evt)
    (error 'expect "got invalid data while expecting signal" evt))
  evt)

(define (expect-succ recv)
  (define evt (expect-signal recv))
  (when (eq? (car evt) 'fail)
    (error 'expect (string-append "expected success, got " (cadr evt))))
  (unless (eq? (car evt) 'succ)
    (error 'expect (string-append "expected success, got " (format evt))))
  (if (null? (cdr evt))
    #t 
    (cadr evt)))
    
(define-macro (with-node-program node program . stmts)
  `(begin
     (define conn (spawn-node-program ,node ,program))
     (define xmit (car conn))
     (define recv (cadr conn))
     (define result (guard (lambda (e)
                             (send 'close xmit)
                            (re-error e))
                      ,@stmts))
    (send 'close xmit)
    result))

(define (get-node-file (<console-node> node) path)
  (read-data-file path))

(define *drone-get-file-prog*
  (assemble
    (optimize
      (compile
        `((let ((path (wait))
                (data #f))
            (guard (lambda (e)
                     (send (list 'fail (car (error-info e)))))
              (set! data (read-data-file path))
              (until (empty-string? data)
                (send (string-read! data 16384)))
              (send 'done)))
          (send 'close))))))

(define (get-node-file (<drone-node> node) path)
  (with-node-program node *drone-get-file-prog*
     (send path xmit)
     (define data (make-string))
     (forever ;TODO: Bad, we can't use forever/return in w-n-p
       (define evt (expect-data recv))
       (cond
         ((eq? evt 'done) (return data))
         ((string? evt) (string-append! data evt))
         (else (error 'expect "expected string or done" evt))))))

(define *drone-put-file-prog*
  (assemble 
    (optimize 
      (compile 
        `((let ((path (wait))
                (data (make-string))
                (done #f))
            (guard (lambda (e)
                     (send (list 'fail (car (error-info e)))))
              (until done
                (define evt (wait))
                (cond ((eq? evt 'done) (set! done #t))
                      ((string? evt) (string-append! data evt))
                      (else (error 'fail "expected string or done" evt))))
              (write-data-file path data))
              (send '(succ)))
          (send 'close))))))

(define (put-node-file (<console-node> node) path data)
  (write-data-file path data))

(define (put-node-file (<drone-node> node) path data)
  (with-node-program node *drone-put-file-prog*
    (send path xmit)
    (until (empty-string? data)
      (send (string-read! data 16384) xmit))
    (send 'done xmit)
    (expect-succ recv)))

;; Not currently used -- intended for on drone repl

(define *drone-repl-prog*
  (assemble
    (optimize
      (compile
        `((export nothing) ;; All private..
          (import "lib/cons-filter")
          (import "lib/format-filter")
          (define err-output (output-chain (output)
                                           (cons-filter 'err)))
          (define res-output (output-chain (output)
                                           (cons-filter 'res)
                                           (format-filter)))
          (define out-output (output-chain (output)
                                           (cons-filter 'out)
                                           (format-filter)))
          (define (fwd-traceback err)
            (define s (make-string))
            (traceback err s)
            (send s err-output))

          (with-output out-output
             (spawn (function (drone-repl-process)
                      (forever
                        (guard fwd-traceback (send ((wait))
                                                   res-output)))))))))))

(define *drone-eval-prog*
  (assemble
    (optimize
      (compile
        `((export nothing) ;; All private..
          (import "lib/cons-filter")
          (import "lib/format-filter")
          (define okay #t)
          (define result #f)
            
          (define result
            (with-output (output-chain (output) ;TODO: Does not work.
                                       (cons-filter 'out)
                                       (format-filter))
              (guard (function (fwd-traceback err)
                       (define s (make-string))
                       (traceback err s)
                       (set! okay #f)
                       s)
                 (format ((wait))))))
          (send (cons (if okay 'succ 'fail) result))
          (send 'close))))))
                
(define (eval-node-expr (<console-node> node) expr)
  (guard traceback (send-line ":: " (format (exec expr)))))

(define (eval-node-expr (<drone-node> node) expr)
  (with-node-program node *drone-eval-prog*
    (send (assemble (optimize (compile expr))) xmit)                 
    (define done #f)
    (until done
      (define evt (expect-signal recv))
      (define key (car evt))
      (define val (cdr evt))
      ;(print "GOT: ") (print (format evt)) (print *line-sep*)
      (case key
        ((out) (when (string? val) (send-line val)))
        ((fail) (when (string? val) (send-line val))
                (set! done #t))
        ((succ) (when (string? val) (send-line ":: " val))
                (set! done #t))))
    (send 'close xmit)))

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
  (assemble
    (optimize
      (compile
        `((import "lib/env")
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

              (send 'close)))))))

(define (spawn-node-shell node cmd)
  (with-node-program node *node-shell-prog*
    (send cmd xmit)
    (define done #f)
    (until done 
      (define evt (wait recv))
      (cond 
        ((eq? evt 'close) (set! done #t))
        ((string? evt) (send evt))))))

(define *node-scan-prog*
  (assemble
    (optimize
      (compile
        `((export nothing)
          (import "mosref/scanner")
          (define results (apply spawn-scanners (wait)))
          (forever
            (define evt (wait results))
            (send evt)
            (when (eq? evt 'done)
              (return))))))))

(define (spawn-node-scan node hosts ports timeout conns)
  (with-node-program node *node-scan-prog*
    (send (list hosts ports timeout conns)
          xmit)
    
    (define done #f)

    (until done
      (define evt (wait recv))
      (cond
        ((eq? evt 'done)
         (send-line "Scan complete.")
         (send 'close xmit)
         (set! done #t))

        ((eq? evt 'close)
         (send-line "Scan interrupted.")
         (send 'close xmit)
         ; TODO: Scan was terminated abruptly.
         (set! done #t))

        ((not (list? evt))
         (send-line "Illegal scan event: " (format evt))
         (send 'close xmit)
         (send-line "Aborted scan.")
         (set! done #t))

        ((eq? (car evt) 'connect)
         (define args (cdr evt))
         (define addr (car args))
         (define port (cadr args))
         ; TODO: Scan found a port..
         (send-line "Found port: " (format-ipv4 addr) ":" (format port)))

        (else
         (send-line "Illegal scan event: " (format evt))
         (send 'close xmit)
         (send-line "Aborted scan.")
         (set! done #t))))))

