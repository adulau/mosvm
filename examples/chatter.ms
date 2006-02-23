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

(import "lib/conn")
(import "lib/format")

(define (chatter portno)
  (spawn-tcp-server portno chatter-session))

(define (chatter-session)
  (emit "CONNECTED")
  (register-chatter-session! (active-process))
  (until (closed?)
     (emit (read)))
  (unregister-chatter-session! (active-process))
  (emit "DISCONNECTED"))

(define (register-chatter-session! process)
  (set! *chatter-sessions* (cons process *chatter-sessions*)))

(define (unregister-chatter-session! process)
  (set! *chatter-sessions* (filter (lambda (session) 
                                     (not (eq? session process)))
                                 *chatter-sessions*)))

(define (emit message)
  (unless (eof-object? message)
    (for-each (lambda (session) (write message session))
              *chatter-sessions*)))

(define *chatter-sessions* '())

(export chatter)
