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

(export await-drone-affiliation console-affiliation 
        console-endpoint
        make-drone-exe make-console-ecdh)

(import "lib/iterate")

;(define-macro (step . rest) '(begin))
(define (step label . items)
  (print (string-append "  CONSOLE: "
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

(define (await-drone-affiliation conns ecdh lapse)
  (define timer (if lapse (timeout lapse (output conns) 'timeout) #f))
  (define conn (wait conns))
  (when (eq? conn 'timeout)
    (error 'aff "the drone did not connect"))
  (when timer (cancel-timeout timer))
  (console-affiliation ecdh conn conn))

(define (make-drone-exe console-addr console-portno console-ecdh platform)
  (build-exe platform
             `((import "mosref/drone")
               (import "mosref/endpoint")
               (define conn (tcp-connect ,console-addr ,console-portno))
               (define endpoint 
                 (apply spawn-endpoint 
                        drone-endpoint
                        (drone-affiliation 
                          (import-ecdh
                            (base64-decode ,(base64-encode (export-public-ecdh 
                                                             console-ecdh))))
                          (input conn)
                          (output conn))))
               (define (import key)
                  (unless (imported? key)
                    (define lane (make-lane endpoint))
                    (define xmit (lane-xmit lane))
                    (define recv (lane-recv lane))
                    (send (string-append key ".mo") xmit)
                    (define data (wait recv))
                    (send 'close xmit)
                    (unless (string? data)
                      (error 'import "could not retrieve module from console"
                             key))
                    ((thaw data))))
               (export import)))) ; Be afraid, be very afraid..

(define (console-endpoint) 
  ; We disregard this..
  (define bridge (wait))
  (define path (wait))
  (unless (string? path)
    (send 'close)
    (return))
  (set! path (find-module-file path))
  (send (if path (read-data-file path)
                 #f)))

;; transmits the supplied program to be executed on the remote endpoint of
;; the supplied transport.

