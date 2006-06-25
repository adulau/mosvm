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

(module "mosref/console")

(import "mosref/base")
(import "mosref/endpoint")

(import "lib/cfb")
(import "lib/crypto-filter")
(import "lib/buffer-channel")
(import "lib/build")

(import "lib/with-io")
(import "lib/line-filter")
(import "lib/s-filter")
(import "lib/package-filter")

(export console-affiliation console-repl make-drone-exe make-console-ecdh)

(import "lib/iterate")

;(define-macro (step . rest) '(begin))
(define (step label . items)
  (print (string-append "CONSOLE: "
                        (apply string-append label (map format items)) 
                        "..." 
                        *line-sep*)))

(define (make-console-ecdh) (make-ecdh-key *ecdh-keysize*))

(define (console-affiliation session-ecdh xmit recv)
  ;;;TODO: Configure timeout.
  (define read (buffer-channel recv))

  (define console-iv (make-iv))

  (step "Reading Drone Public Key")
  ;;; Drone --> Console, via plaintext, Dp
  (define drone-ecdh (import-ecdh (read 59)))
  (define aes-key (make-aes-key 256 
                                (ecdh-shared-secret session-ecdh drone-ecdh)))

  (step "Reading Drone IV")
  ;;; Drone --> Console, via KK, DD
  (define drone-iv (aes-decrypt aes-key (read 16)))

  (step "Transmitting Console IV")
  ;;; Console --> Drone, via KK, CC
  (send (aes-encrypt aes-key console-iv) xmit)
  
  (define report (make-mosref-recv recv aes-key drone-iv))
  (define command (make-mosref-xmit xmit aes-key console-iv))

  (step "Waiting for Drone to confirm Console IV")
  ;;; Drone --> Console, via RK, CC
  (unless (string=? (wait report) console-iv)
    (error 'aff "the drone failed to confirm affiliation"))

  (step "Confirming Drone IV")
  ;;; Console --> Drone, via CK, DD
  (send drone-iv command)

  ;;; TODO: We should probably create a pseudo-stream type..
  (step "Affiliation complete.")
  (list command report))

(define (make-drone-exe console-addr console-portno console-ecdh platform)
  (build-exe platform
             `((import "mosref/drone")
               (import "mosref/endpoint")
               (define conn (tcp-connect ,console-addr ,console-portno))
               (apply spawn-endpoint 
                      drone-endpoint
                      (drone-affiliation 
                        (import-ecdh
                          (base64-decode ,(base64-encode (export-public-ecdh 
                                                           console-ecdh))))
                        (input conn)
                        (output conn))))))

;;TODO: import handler.
(define (console-endpoint) (send 'close))

;; transmits the supplied program to be executed on the remote endpoint of
;; the supplied transport.

(define (mosref-spawn program endpoint)
  (define lane (make-lane endpoint))
  (define xmit (output-chain (lane-xmit lane)
                             (freeze-filter)))
  (define recv (input-chain (lane-recv lane)
                            (thaw-filter)))
  (send program xmit)
  (list xmit recv))

(define (mosref-eval expr endpoint)
  (define program 
    (guard (lambda (e) (error 'eval-compile e))
      (assemble (compile `((send (begin ,@expr)))))))

  (define conn (mosref-spawn program endpoint))
  (wait (cadr conn)))

(define (console-repl xmit recv)
  (define endpoint (spawn-endpoint console-endpoint xmit recv))

  (define (display-result item)
    (send (string-append ":: " (format item) *line-sep*)))

  (define (display-failure key info trace)
    (send trace))

  (define (quit-repl cmd)
    (send 'close xmit))

  (define (drone-cmd cmd)
    (display-result (mosref-eval cmd endpoint)))

  (define cmds 
    (dict (cons 'quit
                quit-repl)))

  (define (console-err-fn err)
    (send (string-append "SYNTAX: " (cadr err) *line-sep*)))

  (define default-cmd drone-cmd)

  (with-input (input-chain (input) 
                           (line-filter)
                           (s-filter :promptN "   "
                                     :errfn console-err-fn))
    (forever
      (send ">> ")
      (define cmd (wait))
      (if (eq? cmd 'close)
        (return (send 'close))
        ((dict-ref cmds cmd default-cmd) cmd)))))

