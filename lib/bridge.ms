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

(define-class bridge <object>
              (make-bridge-state xmit-tags recv-tags binds lanes xmit recv)
              bridge?
              (xmit-tags bridge-xmit-tags)
              (recv-tags bridge-recv-tags)
              (binds bridge-binds)
              (lanes bridge-lanes)
              (xmit bridge-xmit)
              (recv bridge-recv))

(define-class lane <object>
              (make-lane-state tag xmit recv)
              lane?
              (tag lane-tag)
              (xmit lane-xmit)
              (recv lane-recv))

(define *bridge-tag-size* 8)

(define-macro (later . stmts)
    `(spawn (function (later-thunk) ,@stmts)))

(define (make-bridge xmit recv)
  (define bridge (make-bridge-state (dict) (dict)
                                    (make-channel) (make-channel) 
                                    xmit recv))
  (bridge-monitor bridge)
  bridge)

(define (make-bridge-tag tags)
  (forever
    (define tag (random-string *bridge-tag-size*))
    (unless (dict-ref tags tag)
      (return tag))))

(define (bridge-monitor bridge)
  (define binds       (bridge-binds     bridge))
  (define lanes       (bridge-lanes     bridge))
  (define xmit-tags   (bridge-xmit-tags bridge))
  (define recv-tags   (bridge-recv-tags bridge))
  (deflet b-xmit      (bridge-xmit      bridge))
  (deflet b-recv      (bridge-recv      bridge))

  (define (cmd-link id)
    (define lane (wait binds))
    (dict-set! recv-tags id lane))

  (define (cmd-make id)
    (define lane-xmit (make-channel))
    (define lane-recv (make-channel))
    (define recv-tag id)
    (define xmit-tag (make-bridge-tag xmit-tags))
    (define lane (make-lane-state xmit-tag lane-xmit lane-recv))
    (dict-set! recv-tags recv-tag lane)
    (dict-set! xmit-tags xmit-tag lane)
    (send (string-append 58 xmit-tag) b-xmit) 
    (send lane lanes)
    (lane-monitor bridge lane))

  (define (cmd-data data)
    (define recv-tag (string-read! data *bridge-tag-size*))
    (define lane (dict-ref recv-tags recv-tag))
    (unless lane (bridge-wtf data))
    (define recv (lane-recv lane))
    (send data recv))

  (define (bridge-wtf evt)
    (error 'bridge "unhandled message" evt))

  (later 
    (forever
      (define evt (wait b-recv))
      (cond 
        ((eq? evt 'close)) ; TODO: Signal the bridge is closed.
        ((not (string? evt))  (bridge-wtf evt))
        ((empty-string? evt)  (bridge-wtf evt))
        (else
          ((case (string-read-byte! evt)
             ((58) cmd-link) ; :
             ((62) cmd-make) ; >
             ((33) cmd-data) ; !
             (else bridge-wtf)) evt))))))
  
(define (lane-monitor bridge lane)
  (define b-xmit (bridge-xmit bridge))
  (define l-xmit (lane-xmit lane))
  (define xmit-tag (lane-tag lane))
  (later
    (forever
      (define evt (wait l-xmit))
      (when (string? evt)
        (send (string-append "!" xmit-tag evt) b-xmit)))))

; Directs the supplied bridge to create a new lane.

(define (make-lane bridge)
  (define lane-xmit (make-channel))
  (define lane-recv (make-channel))
  (define xmit-tags (bridge-xmit-tags bridge))
  (define xmit-tag (make-bridge-tag xmit-tags))
  (define lane (make-lane-state xmit-tag lane-xmit lane-recv))
  (dict-set! xmit-tags xmit-tag lane)
  (send (string-append ">" xmit-tag) (bridge-xmit bridge))
  (send lane (bridge-binds bridge))
  (lane-monitor bridge lane)
  lane)

(export make-lane lane-xmit lane-recv)

(export make-bridge bridge-lanes)

