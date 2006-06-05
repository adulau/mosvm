; Copyright (c) 2006, Scott W. Dunlop <sdunlop@users.sourceforge.net>
; All rights reserved.
; 
; under the terms of the GNU Lesser General Public License, version 2.1
; as published by the Free Software Foundation.
;     * Redistributions of source code must retain the above copyright 
;       notice, this list of conditions and the following disclaimer.
;     * Redistributions in binary form must reproduce the above copyright 
;       notice, this list of conditions and the following disclaimer in the 
;       documentation and/or other materials provided with the distribution.
;     * The names of its contributors may not be used to endorse or promote     
;       products derived from this software without specific prior written 
;       permission.
; 
; THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" 
; AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE 
; IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE 
; ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE 
; LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR 
; CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF 
; SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS 
; INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN 
; CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) 
; ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE 
; POSSIBILITY OF SUCH DAMAGE.

(module "lib/test")

(import "lib/port")
(import "lib/iterate")

(define *spot-test?* #f)
(define *spot-s* #f)
(define *spot-v* #f)

(define *spot-ect* 0)

(define (send-line . strings)
  (send (string-append @strings *line-sep*)))

(define (spot-error . lines)
  (set! *spot-ect* (+ *spot-ect* 1))
  (let ((lines (cons (cons "s:  " *spot-s*) 
                      lines)))
    (for-each (lambda (line) 
                (send "    ")
                (send (car line))
                (for-each (lambda (phrase)
                            (send (format phrase)))
                          (cdr line))
                (send *line-sep*))
              lines)))

(define (enable-spot-tests) (set! *spot-test?* #t))

(define (disable-spot-tests) (set! *spot-test?* #f))

(export *spot-s* *spot-v*)

(define (do-s expr fn)
  (unless *spot-test?* (return))
  (set! *spot-s* expr)
  (set! *spot-v* (fn)))

(define (do-r expr fn)
  (unless *spot-test?* (return))
  (let ((x (fn)))
    (if (not (equal? x *spot-v*))
      (spot-error (cons "r:  " expr)
                  (list "sv: " *spot-v*)
                  (list "rv: " x)))))

(define (do-t expr fn)
  (unless *spot-test?* (return))
  (let ((x (fn *spot-v*)))
    (if (not x)
      (spot-error (cons "t:  " expr)))))

(define (spot-report)
  (if (> *spot-ect* 0)
    (send-line "Test cases failed:" (format *spot-ect*))
    (send-line "All tests passed.")))

(define (main . ignored)
  (spot-report)
  (= *spot-ect* 0))

(export do-s do-r do-t spot-report main 
        enable-spot-tests disable-spot-tests)

(define-macro (s: expr . body)
    `(do-s ',(cons expr body) (function (s-test) ,expr ,@body)))

(define-macro (r: expr . body)
    `(do-r ',(cons expr body) (function (r-test) ,expr ,@body)))

(define-macro (t: expr . body)
    `(do-t ',(cons expr body) (function (t-test _) ,expr ,@body)))

(export s: r: t:)

