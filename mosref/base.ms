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

(module "mosref/base")

(import "lib/cfb")
(import "lib/fuse")
(import "lib/crypto-port")

(define *sprng* (make-random "sprng"))
(define *ecdh-keysize* 384)
(define *sig-length* 16)

(define (make-iv)
  (random-string 16 *sprng*))

(define-class <mosref-listener> <object>
              (make-mosref-listener addr portno sessions)
              mosref-listener? 
              (addr mosref-listener-addr)
              (portno mosref-listener-portno)
              (ecdh mosref-listener-ecdh set-mosref-listener-ecdh)
              (sessions mosref-listener-sessions set-mosref-listener-sessions!))

(define-class <mosref-session> <object>
              (make-mosref-session-state listener sig ecdh aff-fn port ps)
              mosref-session?
              (sig mosref-session-sig)
              (ecdh mosref-session-ecdh)
              (aff-fn mosref-session-aff-fn)
              (port mosref-session-port set-mosref-session-port!)
              (ps mosref-session-ps set-mosref-session-ps!)
              (ecdh mosref-session-ecdh))

(define-class <mosref-listener-session> <mosref-session>
              (make-mosref-listener-session-state sig ecdh aff-fn port ps)
              mosref-listener-session?
              (listener mosref-session-listener))

;;TODO: this should be a hash of the ecdh key
(define (make-session-sig ecdh)
  (substring (export-ecdh-public ecdh) 0 16))

(define (make-session-sig)
  (define sig (random-string *sig-length*))
  (if (dict-set? (mosref-listener-sessions listener)
                 sig)
    (make-session-sig listener)
    sig))

;;TODO: this should refuse to use keys with the same hash in the
;;      session table.
(define (make-session-ecdh) (make-ecdh-key *ecdh-keysize*))
  
(define (make-mosref-master-session listener)
  (define ecdh (make-ecdh-key *ecdh-keysize*))
  )
(define (make-mosref-session ecdh aff-fn)
  ;;; TODO: ecdh
  ;;; TODO: sig
  (define sig (make-session-sig ecdh))
  (define session (make-mosref-session listener sig ecdh aff-fn #f #f))
  (dict-set! (mosref-listener-sessions listener) sig session)
  session)

(define (make-mosref-listener-session listener aff-fn)
  (define sig (make-session-sig listener))
  (define ecdh (make-session-ecdh))
  (define session (make-mosref-session listener sig ecdh aff-fn #f #f))
  (dict-set! (mosref-listener-sessions listener) sig session)
  session)

(define (await-session-port session)
  (when (mosref-session-ps session)
    (error 'mos "another process is already waiting on that session"))
  (define port (mosref-session-port session))
  (if port
    port
    (begin
      (set-mosref-session-ps! session (active-process))
      (suspend))))

(define (await-session session)
  ;;(make-control-port (await-session-port session))
  (await-session-port session))

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

