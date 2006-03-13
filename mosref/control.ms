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

(module "mosref/control")

(import "lib/cfb")
(import "lib/fuse")
(import "lib/crypto-port")

(define *sprng* (make-random "sprng"))

(define (make-iv)
  (random-string 16 *sprng*))

(define (drone-affiliation console-ecdh port)
  ;;;TODO: Configure timeout.

  (define drone-iv (make-iv))
  (define drone-ecdh (make-ecdh-key 384)) 
  (define aes-key (make-aes-key 256 
                                (ecdh-shared-secret console-ecdh drone-ecdh)))

  ;;; Drone --> Console, via plaintext, Dp
  (write (export-public-ecdh drone-ecdh) port)

  ;;; Drone --> Console, via KK, DD
  (write (aes-encrypt aes-key drone-iv) port)

  ;;; Console --> Drone, via KK, CC
  (define console-iv (aes-decrypt aes-key (read 16 port)))
 
  (define report-key (make-cfb aes-key drone-iv aes-encrypt))
  (define command-key (make-cfb aes-key console-iv aes-encrypt))
  
  (define report-port (encrypt-output port report-key cfb-encrypt))
  (define command-port (decrypt-input port command-key cfb-decrypt))

  ;;; Drone --> Console, via RK, CC
  (write console-iv report-port)

  ;;; Console --> Drone, via CK, DD
  (unless (string=? (read command-port) drone-iv)
    (error 'aff "the console failed to confirm affiliation"))

  (fuse-ports command-port report-port))
 
(define (console-affiliation console-ecdh port)
  ;;;TODO: Configure timeout.

  (define console-iv (make-iv))
 
  ;;; Drone --> Console, via plaintext, Dp
  (define drone-ecdh (import-ecdh (read 59 port)))
  (define aes-key (make-aes-key 256 
                                (ecdh-shared-secret console-ecdh drone-ecdh)))

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

