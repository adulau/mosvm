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

(import "lib/tcp-server")
(import "lib/format")

(define-record-type chat-session 
                    (make-chat-session process username)
                    chat-session?
                    (process chat-session-process)
                    (username chat-session-username))

(define (chatter portno)
  (spawn-tcp-server portno chatter-session))

(define (chatter-session)
  (define (read-line)
    (define packet (read))
    (when (eof-object? packet)
      (error 'eof))
    ;TODO: We should be using a line splitter for this.
    (car (split-lines packet)))

  (define session #f)
  (define username #f)

  (guard (lambda (e) 
           (unregister-chatter-session! session)
           (unless (eq? (error-key e) 'eof) (re-error e))
           (if session (emit session "has disconnected.")))

    (write "User name? ")

    (set! session (make-chat-session (active-process) (read-line)))
    
    (emit session "has connected.")

    (register-chatter-session! session)

    (write (string-append "Welcome, " (chat-session-username session) "\n"))

    (until #f
      (emit session (string-append "says, \"" (read-line) "\"")))))

(define (register-chatter-session! process)
  (set! *chatter-sessions* (cons process *chatter-sessions*)))

(define (unregister-chatter-session! process)
  (set! *chatter-sessions* (filter (lambda (session) 
                                     (not (eq? session process)))
                                 *chatter-sessions*)))

(define (emit session message)
  (set! message (string-append (chat-session-username session) 
                               " "
                               message
                               "\n"))
  (for-each (lambda (session) (notify session message))
            *chatter-sessions*))

(define (notify session message)
  (write message (chat-session-process session)))

(define *chatter-sessions* '())

(export chatter)

;;; MOSVM2
;;; MOSVM2
