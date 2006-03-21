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

(module "mosref/broker")

(import "lib/cfb")
(import "lib/fuse")
(import "lib/crypto-port")

(define *sprng* (make-random "sprng"))
(define *ecdh-keysize* 384)
(define *sig-length* 16)

(define (spawn-mosref-listener addr portno)
  (define sessions (dict))
  (define listener (make-mosref-listener addr portno sessions))
  (define server (serve-tcp portno))

  (define (broker-session)
    (define client-sig (read *sig-length*))
    (define client-session (dict-ref sessions client-sig))

    (define (affiliate-session)
      (define client-port #f)

      (define (session-affiliated)
        (set-mosref-session-port! client-session client-port)
        (dict-remove! sessions client-sig)
        (define client-ps (mosref-session-ps session))
        (when client-ps
          (set-mosref-session-ps! session #f)
          (resume client-ps client-port)))

      (define aff-fn (mosref-session-aff-fn client-session))

      (guard 
        (lambda (x) 
          (close) 
          (unless (eq? (error-key x) 'aff)
            (re-error x)))

        (set! client-port 
          (aff-fn (client-session-ecdh) (current-input-port)))

        (if (and client-port
               (not (mosref-session-port client-session)))
            (session-affiliated)
            (close))))

    (if client-session
      (affiliate-session)
      (close)))

  ;;TODO: We should cache this process for clean shutdown of a listener.
  (spawn-tcp-server portno broker-session))

(define (make-drone-session listener) 
  (make-mosref-session listener drone-affiliation))

(define (make-console-session listener) 
  (make-mosref-session listener console-affiliation))

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

;; Returns a <mosref-session> expressing an executable that, when executed, will
;; attempt to connect to the console.
;;

(define (spawn-drone listener platform)
  ...)

;; Returns a list of drones connected to the console
(define (console-drones console)
  ...)

;; Evaluates the supplied program on the drone and returns the response.
(define (drone-exec drone program)
  ...)

