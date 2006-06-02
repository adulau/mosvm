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

(module "bin/mosref")
(import "mosref/console")
(import "lib/tcp-server")

(define unparsed-args (apply make-tc (cdr (argv))))

(define (next-arg) (tc-next! unparsed-args))
(define (more-args?) (not (tc-empty? unparsed-args)))

(define (write-lines . lines)
  (write (apply string-join *line-sep* 
                (map (lambda (i) (if (pair? i)
                                   (string-join " " i)
                                   i))
                     lines))))

(define (write-line . items)
  (write (apply string-append items))
  (newline))

(define (show-usage)
  (write-lines 
    "USAGE: mosref console-addr:console-port drone-platform drone-path"
    "       console-addr -- The hostname or address of the console."
    "       console-port -- The tcp port that the console will listen to."
    "       drone-platform -- One of: winnt-x86, openbsd-x86, linux-x86,"
    "                         darwin-ppc."
    "       drone-path -- The file to write the drone executable to."
    ""
    "EXAMPLE: mosref decoy.ephemeralsecurity.com:19191 openbsd-x86 a-drone"
    ""))

(define (parse-error message)
  (show-usage)
  (write-line "ERROR: " message)
  (exit 1)) 

(define (missing-error type purpose)
  (unless (more-args?)
    (parse-error (string-append "Missing " type " for " purpose "."))))

(missing-error "address" "console listener")
(define console (string-split (next-arg) ":"))

(unless (= 2 (length console))
  (parse-error (string-append "Format for console host must be address:port")))

(define console-addr (car console))
(define console-port (guard (lambda (e) 
                              (parse-error (car (error-info e))))
                            (string->integer (cadr console))))

(missing-error "platform" "drone compilation")
(define drone-platform (next-arg))
(unless (member drone-platform '("winnt-x86" "openbsd-x86" "linux-x86"
                                 "darwin-ppc"))
  (parse-error "This version of mosref has limited platform support"))

(missing-error "path" "drone output")
(define drone-path (next-arg))

(define console-ecdh (make-console-ecdh))

(write-line "Writing drone to " drone-path "...")

(write-data-file drone-path (make-drone-exe console-addr
                                            console-port
                                            console-ecdh
                                            drone-platform ))

(write-line "Starting listener on port " 
            (number->string console-port)
            "..." )

(define console-listener (serve-tcp console-port))
(define drone-port #f)

(until drone-port
  ;TODO: We need a timeout.
  (define client-descr (read-descr console-listener))
  (write-line "Client connected to port; awaiting affiliation...")
  (guard (lambda (e) 
           (unless (eq? (error-key e) 'aff) (re-error e))
           (write-line "Client failed to affiliate; rejected."))
         (set! drone-port 
           (console-affiliation console-ecdh (wrap-socket client-descr)))))

(write-line "Client confirmed as drone by affiliation; closing listener...")

(close-descr console-listener)

(write-line "Welcome to MOSREF; all instructions shall be evaluated on the"
            " drone, with results reported to the console.")

(write-line "To exit MOSREF; enter .quit")

(console-repl drone-port)

