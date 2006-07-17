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

(module "mosref/cmd/scan")
(import "mosref/shell")
(import "mosref/node")
          
(define-cmd "scan" 
            "scan hosts ports [timeout [conns]]"
            (string-append
                  "Performs a TCP port scan of the specified host, reporting"
                  " all ports  that respond with a connection within timeout"
                  " milliseconds.  The scanner will restrict itself to"
                  " conns ports at a time, with a default of 1000.")

  (define hosts (parse-host-spec
                  (req-term terms "hosts.")))
  (define ports (parse-port-spec 
                  (req-term terms "ports.")))
  (define timeout (or (opt-integer terms "timeout")
                      5000))
  (define conns (or (opt-integer terms "conns")
                    1000))
  (spawn-node-scan current-node 
                   hosts ports timeout conns))

(define *node-scan-prog*
  (inline (export nothing)
          (import "mosref/scanner")
          (define results (apply spawn-scanners (wait)))
          (forever
            (define evt (wait results))
            (send evt)
            (when (eq? evt 'done)
              (return)))))

(define (spawn-node-scan node hosts ports timeout conns)
  (with-node-program node *node-scan-prog*
    (send (list hosts ports timeout conns)
          xmit)
    
    (define done #f)

    (until done
      (define evt (wait recv))
      (cond
        ((eq? evt 'done)
         (send-line "Scan complete.")
         (send 'close xmit)
         (set! done #t))

        ((eq? evt 'close)
         (send-line "Scan interrupted.")
         (send 'close xmit)
         ; TODO: Scan was terminated abruptly.
         (set! done #t))

        ((not (list? evt))
         (send-line "Illegal scan event: " (format evt))
         (send 'close xmit)
         (send-line "Aborted scan.")
         (set! done #t))

        ((eq? (car evt) 'connect)
         (define args (cdr evt))
         (define addr (car args))
         (define port (cadr args))
         ; TODO: Scan found a port..
         (send-line "Found port: " (format-ipv4 addr) ":" (format port)))

        (else
         (send-line "Illegal scan event: " (format evt))
         (send 'close xmit)
         (send-line "Aborted scan.")
         (set! done #t))))))

