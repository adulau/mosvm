; Copyright (C) 2006, Ephemeral Security, LLC 
;  
; This library is free software; you can redistribute it and/or modify it  
; under the terms of the GNU Lesser General Public License as published by  
; the Free Software Foundation; either version 2.1 of the License, or (at  
; your option) any later version. 
;  
; This library is distributed in the hope that it will be useful, but WITHOUT  
; ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or  
; FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License  
; for more details. 
;  
; You should have received a copy of the GNU Lesser General Public License  
; along with this library; if not, write to the Free Software Foundation,  
; Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA  
;  

(import "lib/test")

(enable-spot-tests)

(define *wall* #f)
(define (tagger tag)
  (lambda ()
    (until #f 
     (set! *wall* tag) 
     (pause))))

(s: (process-status (active-process)))
(r: 'running)

(define t-foo #f)
(s: (spawn (tagger 'foo)))
(t: (set! t-foo _)
    (process? _))
(t: (eq? (process-status _) 'paused))

(s: (pause))
(t: (eq? *wall* 'foo))

(set! *wall* #f)

(s: (pause))
(t: (eq? *wall* 'foo))

(set! *wall* #f)

(s: (suspend t-foo)
    (pause))
(t: (not *wall*))

(s: (process-status t-foo))
(t: 'suspended)

(s: (resume t-foo)
    (pause))
(t: (eq? *wall* 'foo))

(s: (process-status t-foo))
(t: 'paused)

(set! *wall* #f)

(s: (halt t-foo)
    (pause))
(t: (not *wall*))

(s: (process-status t-foo))
(t: 'halted)

