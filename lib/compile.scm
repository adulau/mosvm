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
;  

(export "lib/compile")
(import "lib/lib")

(define-record-type <context>
                    (make-context reality parent symbols slots rules)
                    context?
                    (reality context-reality)
                    (parent  context-parent)
                    (symbols context-symbols set-context-symbols!)
                    (slots context-slots set-context-slots!)
                    (rules context-rules set-context-rules!))
(define *mosvm-syntax*
  (list 
    (cons 's:
          (lambda (stmt . rest)
            `(if *spot-test?*
               (do-s '(,stmt ,@rest) (lambda () ,stmt ,@rest)))))
    (cons 'r:
          (lambda (stmt . rest)
            `(if *spot-test?*
               (do-r '(,stmt ,@rest) (lambda () ,stmt ,@rest)))))
    (cons 't:
          (lambda (stmt . rest)
            `(if *spot-test?*
               (do-t '(,stmt ,@rest) (lambda (_) ,stmt ,@rest)))))
    (cons 'define-class
        (lambda (class-name super-class make-proto pred-name . class-fields)
          (define (bind-field-accessor access-name field-name)
            `(define ,access-name 
               (make-multimethod 
                 (list ,class-name) 
                 (make-field-accessor ,class-name (quote ,field-name))
                 (or (? ,access-name) refuse-method))))

          (define (bind-field-modifier modif-name field-name)
            `(define ,modif-name 
               (make-multimethod 
                 (list ,class-name #t) 
                 (make-field-modifier ,class-name (quote ,field-name))
                 (or (? ,modif-name) refuse-method))))

          `(begin 
             (define ,class-name  (make-class ',class-name 
                                              ,super-class 
                                              ',(map-car class-fields)))
             (define (,pred-name %value) (isa? %value ,class-name))
             (define ,(car make-proto) (make-class-constructor 
                                         ',class-name 
                                         ,class-name
                                         ',(cdr make-proto)))
             ,@(map (lambda (field) 
                      (if (> (length field) 1)
                        (bind-field-accessor (cadr field) (car field))
                        '(begin)))
                    class-fields)

             ,@(map (lambda (field) 
                      (if (> (length field) 2)
                        (bind-field-modifier (caddr field) (car field))
                        '(begin)))
                    class-fields))))
    (cons 'define-record-type
          (lambda (record-name make-proto pred-name . record-fields)
            `(define-class ,record-name <record> ,make-proto ,pred-name 
                           ,@record-fields)))
    (cons 'guard
          (lambda (fn . rest)
            (let ((el (make-branch-symbol 'exit)))
              `(asm (mos ,fn)
                    (gar ,el)
                    (mos (begin ,@rest))
                    (rag)
                    ,el))))
    (cons 'case 
      (lambda (expr . branches)
        (let ((tc (make-tc))
              (done (make-branch-symbol 'done))
              (next #f))
          (tc-append! tc `(mos ,expr))
          (for-each (lambda (branch)
                      (when next (tc-append! tc next))
                      (set! next #f)
                      (let ((test (car branch))
                            (body (cdr branch)))
                        (if (eq? test 'else)
                          (begin 
                            (tc-append! tc '(drop))
                            (tc-append! tc `(mos ,@body))
                            (tc-append! tc `(jmp ,done)))
                          (let ((case-branch (make-branch-symbol 'case)))
                            (set! next (make-branch-symbol 'next))
                            (for-each (lambda (value)
                                        (tc-append! tc '(copy)) 
                                        (tc-append! tc `(ldc ,value))
                                        (tc-append! tc '(ldc 2))
                                        (tc-append! tc '(ldg eq?))
                                        (tc-append! tc '(call))
                                        (tc-append! tc `(jt ,case-branch)))
                                      test)
                            (tc-append! tc `(jmp ,next))
                            (tc-append! tc case-branch)
                            (tc-append! tc '(drop))
                            (tc-append! tc `(mos ,@body))
                            (tc-append! tc `(jmp ,done))))))
                    branches)
          (when next
            (tc-append! tc next)
            (tc-append! tc '(drop))
            (tc-append! tc '(ldu)))
          (tc-append! tc done)
          `(asm ,@(tc->list tc)))))

    (cons 'cond (lambda clauses 
                  ;TODO: Should raise an error if there is rest with else.
                  (if (null? clauses) 
                    #f
                    (let ((clause (car clauses))
                          (rest (cdr clauses)))
                      (if (eq? (car clause) 'else)
                        `(begin ,@(cdr clause))
                        `(if ,(car clause)
                           (begin ,@(cdr clause))
                           (cond ,@rest)))))))
    (cons 'when (lambda (test . rest)   `(if ,test (begin ,@rest))))
    (cons 'unless (lambda (test . rest) `(if ,test (begin) (begin ,@rest))))
    (cons 'while (lambda (test . rest)  
                   (let ((enter (make-branch-symbol 'enter))
                         (exit  (make-branch-symbol 'exit)))
                     `(asm (ldc #f)
                           ,enter
                           (mos ,test) 
                           (jf ,exit) 
                           (drop)
                           (mos ,@rest)
                           (jmp ,enter)
                           ,exit))))
    (cons 'until (lambda (test . rest)  
                   (let ((enter (make-branch-symbol 'enter))
                         (exit  (make-branch-symbol 'exit)))
                     `(asm (ldc #f)
                           ,enter
                           (mos ,test) 
                           (jt ,exit) 
                           (drop)
                           (mos ,@rest)
                           (jmp ,enter)
                           ,exit))))
    (cons 'or (lambda (test . rest)  
                (if (null? rest)
                      test
                  (let ((done (make-branch-symbol 'done)))
                    `(asm (mos ,test)
                          (copy)
                          (jt ,done)
                          (drop)
                          (mos (or ,@rest))
                          ,done)))))
    (cons 'and (lambda (test . rest)  
                 (if (null? rest)
                   test
                   (let ((done (make-branch-symbol 'done)))
                     `(asm (mos ,test)
                           (copy)
                           (jf ,done)
                           (drop)
                           (mos (and ,@rest))
                           ,done))))))) 

(define *mosvm-specials*
  (list
    (cons 'quasiquote
      (lambda (block env terms)
        (define temps '())
        (define (add-temp sym)
          (let ((r (make-branch-symbol sym)))
            (set! temps (cons (cons sym r)
                              temps))
            r))
        (define (get-temp sym) (let ((r (assq sym temps)))
                                 (if r (cdr r)
                                   (add-temp sym))))
        (define (inner-qq terms)
          (unless (or (pair? terms) (null? terms))
            (error 'compile 
                   "quasiquote requires a list argument for its template"
                   terms))
          ;Emit a call to make-tc
          (block-append! block '(ldc 0))
          (block-append! block '(ldg make-tc))
          (block-append! block '(call))
          ;For each term:
          (for-each (lambda (term)
                      (cond 
                        ;If the term isn't a pair:
                        ((and (symbol? term) (symbol-starts-with term 37))
                         (block-append! block (list 'ldc (get-temp term)))
                         (block-append! block '(ldc 2))
                         (block-append! block '(ldg tc-append!))
                         (block-append! block '(call)))

                        ((or (null? term) (not (pair? term)))
                         ;Emit an LDC, followed by a call to tc-append!    
                         (block-append! block (list 'ldc term))
                         (block-append! block '(ldc 2))
                         (block-append! block '(ldg tc-append!))
                         (block-append! block '(call)))

                        ;Or, if the start of the term is UNQUOTE:
                        ((eq? (car term) 'unquote)
                         ;Compile the unquoted expression, call tc-append!
                         (unless (= (length term) 2)
                           (error 'compile
                                  "unquote requires one argument" term))
                         (compile-expr block (cadr term) env)
                         (block-append! block '(ldc 2))
                         (block-append! block '(ldg tc-append!))
                         (block-append! block '(call)))

                        ;Or, if the start of the term is UNQUOTE-SPLICING:
                        ((eq? (car term) 'unquote-splicing)
                         ;Compile the unquoted expression, call tc-splice!
                         (unless (= (length term) 2)
                           (error 'compile 
                                  "unquote-splice requires one argument" 
                                  term))
                         (compile-expr block (cadr term) env)
                         (block-append! block '(ldc 2))
                         (block-append! block '(ldg tc-splice!))
                         (block-append! block '(call)))

                        ;Otherwise:
                        (else
                          ;Begin a new instance of QQ-LIST
                          ;Emit an LDC, followed by a call to tc-append!
                          (inner-qq term)
                          (block-append! block '(ldc 2))
                          (block-append! block '(ldg tc-append!))
                          (block-append! block '(call)))))
                    terms)
          ;Emit a call to tc->list!
          (block-append! block '(ldc 1))
          (block-append! block '(ldg tc->list))
          (block-append! block '(call)))
        (inner-qq terms)))
    (cons 'quote (lambda (block env value) 
                   (block-append! block `(ldc ,value))))
    (cons 'asm (lambda (block env . stmts)
                 (for-each 
                   (lambda (stmt) 
                     (if (and (pair? stmt) (eq? 'mos (car stmt)))
                       (compile-block block (cdr stmt) env)
                       (block-append! block stmt)))
                   stmts)))
    (cons 'begin (lambda (block env . stmts)
                   (compile-block block stmts env)))
    (cons 'if (lambda (block env test t-expr . rest)
                (define f-expr 
                  (case (length rest)
                    ((0) '(begin))
                    ((1) (car rest))
                    (else 
                      (error "if only accepts a test, and two branches."))))
                (let ((done-branch (make-branch-symbol 'done))
                      (false-branch (make-branch-symbol 'false)))
                  (compile-expr block test env)
                  (block-append! block (list 'jf false-branch))
                  (compile-expr block t-expr env)
                  (block-append! block (list 'jmp done-branch))
                  (block-append! block false-branch)
                  (compile-expr block f-expr env)
                  (block-append! block done-branch))))
    (cons 'let (lambda (block env defns . body)
                 (let ((n-env (make-virtual-context env (map car defns))))
                   (for-each 
                     (lambda (x) 
                       (compile-expr block (cadr x) env)
                       (blocq-append! 
                         block (cons 'stb 
                                     (context-symbol-addr n-env (car x)))))
                       defns)
                   (compile-block block body n-env))))
    (cons 'set!  (lambda (block env . expr)
                   (compile-store block expr env)
                   (block-append! block '(ldu))))
    (cons 'define (lambda (block env formals . expr)
                    (define key formals)
                    (define top #t)
                    (define addr #f)
                    (define func #f)
                    (define meth #f)
                    (when (context-parent env)
                      (set! top #f)
                      (set! addr (context-symbol-addr env key)))
                    (when (pair? formals) 
                      (set! func #t)
                      (set! key (car formals))
                      (set! formals (parse-formals (cdr formals))))
                    (when (and func (method-formals? formals))
                      (set! func #f)
                      (set! meth (if addr 
                                     `(or (asm (ldb ,@addr))
                                          refuse-method)
                                     `(or (get-global ',key)
                                          refuse-method))))
                    (unless top 
                      (add-context-binding! env key)
                      (set! addr (context-symbol-addr env key)))
                    (cond 
                      (func (compile-function block formals expr env))
                      (meth (compile-method block meth formals expr env))
                      (else (compile-expr block (car expr) env)))
                            ;;; Error if expr length != 1.
                    (if top
                      (block-append! block `(stg ,key)) 
                      (block-append! block (cons 'stb addr)))
                    (block-append! block '(ldu))))

    (cons 'lambda (lambda (block env formals . body)
                    (compile-function block
                                      (parse-formals formals)
                                      body
                                      env)))
    (cons '?  (lambda (block env key)
                (let ((addr (context-symbol-addr env key)))
                  (if addr 
                    (block-append! block (cons 'ldb addr))
                    (compile-expr block 
                                  `(get-global (quote ,key)) 
                                  env)))))
    
    ))

    
(define (add-context-slot! context slot)
  (set-context-slots! context (append! (context-slots context) (list slot))))

(define (add-context-symbol! context symbol)
  (set-context-symbols! context (cons symbol (context-symbols context))))

(define (add-context-rule! context key function)
  (set-context-rules! context (cons (cons key function) 
                                    (context-rules context))))

(define (find-context-rule context key)
  (if context
    (let ((rule (assq key (context-rules context))))
      (if rule 
        (cdr rule)
        (find-context-rule (context-parent context) key)))
    #f))

(define (add-context-binding! local symbol)
  (add-context-slot! (find-actual-context local)
                     (cons symbol local))
  (add-context-symbol! local symbol))

(define (make-slots context symbols)
  (map (lambda (symbol) 
         (cons symbol context))
       symbols))

(define (make-actual-context parent symbols)
  (let ((new-context (make-context #t parent symbols #f '())))
    (set-context-slots! new-context 
                        (make-slots new-context symbols))
    new-context))

(define (make-top-context)
  (let ((new-context (make-actual-context #f '(*args*))))
    (set-context-rules! new-context *mosvm-syntax*)
    new-context))

(define (is-actual-context? context)
  (context-reality context))

(define (is-virtual-context? context)
  (not (context-reality context)))

(define (context-slot-count context)
  (length (context-slots context)))

(define (find-actual-context context)
  (cond
    ((not context) #f)
    ((is-actual-context? context) context)
    (else (find-actual-context (context-parent context)))))

(define (make-virtual-context parent symbols)
  (let ((new-context (make-context #f parent symbols #f '()))
        (actual-context (find-actual-context parent)))
    (set-context-slots! actual-context
                        (append (context-slots actual-context)
                                (make-slots new-context symbols)))
    new-context))

(define (context-defines-symbol? context symbol)
  (if (memq symbol (context-symbols context)) 
      #t #f))

(define (context-slot-index context slot-context slot-symbol)
  (list-index (lambda (x) (and (eq? (car x)
                                    slot-symbol)
                               (eq? (cdr x)
                                    slot-context)))
              (context-slots context)))

(define (context-symbol-addr context symbol)
  (define result #f)
  (define actuals 0)
  (while context
    (cond ((context-defines-symbol? context symbol)
           (set! result 
             (list actuals
                   (context-slot-index (find-actual-context context)
                                       context
                                       symbol)))
           (set! context #f))
          ((is-actual-context? context)
           (set! context (context-parent context))
           (set! actuals (+ actuals 1)))
          (else
           (set! context (context-parent context)))))
  result)

(define (make-scheme-program) (make-tc))

(define (make-block scheme-program) 
  (let ((block (cons scheme-program (make-tc))))
    (tc-append! scheme-program block)
    block))  

(define (block-scheme-program block) (car block))

(define (block-append! block stmt) 
  (tc-append! (cdr block) stmt))

(define (block-prepend! block stmt) 
  (tc-prepend! (cdr block) stmt))

(define blocq-append! block-append!)

(define (scheme-program->list scheme-program) 
  (let ((pl (make-tc)))
    (for-each (lambda (block)
                (for-each (lambda (stmt) 
                            (tc-append! pl stmt))
                          (tc->list (cdr block))))
              (tc->list scheme-program))
    (tc->list pl)))

(define (expand-loop expr env)
  (cond
    ((null? expr) expr)
    ((pair? expr) (cons (expand (car expr) env)
                        (expand-loop (cdr expr) env)))
    (else (expand expr env))))

(define (expand expr env)
  (cond ((null? expr) '())
        ((not (pair? expr)) expr)
        ((assq (car expr) *mosvm-specials*) expr)
        (else   
          (set! expr (expand-loop expr env))
          (let ((syn (find-context-rule env (car expr))))
            (if syn (expand (apply syn (cdr expr)) env)
                    expr)))))

(define (compile code)
  (let ((scheme-program (make-scheme-program)))
    (let ((base-block (make-block scheme-program))
          (env (make-top-context)))
      (compile-block base-block code env)
      (block-prepend! base-block 
                      (list 'usea 0 (context-slot-count env)))
      (block-append! base-block '(retn)))
    (scheme-program->list scheme-program)))

(define (compile-block block code env)
  ;; This will produce an extra ldu/drop at the beginning of any non-null
  ;; block, but the optimizer will detect and remove it.
  (block-append! block '(ldu))
  (until (null? code)
    (block-append! block '(drop))
    (compile-expr block (car code) env)
    (set! code (cdr code))))

(define (compile-expr block expr env)
  ;(write (list 'compile-expr expr))
  ;(newline)
  (cond ((null? expr)    (compile-null block env))
        ((list? expr)    (compile-form block expr env))
        ((integer? expr) (compile-integer block expr env))
        ((string? expr)  (compile-string block expr env))
        ((symbol? expr)  (compile-load block expr env))
        ((eq? expr #f)   (compile-false block env))
        ((eq? expr #t)   (compile-true block env))
        (else (error "Unrecognized element ~a." expr))))

(define (compile-null block env) (compile-constant block '() env))
(define (compile-true block env) (compile-constant block #t env))
(define (compile-false block env) (compile-constant block #f env))
(define (compile-string block expr env)   (compile-constant block expr env))
(define (compile-integer block expr env)  (compile-constant block expr env))
(define (compile-constant block expr env) (block-append! block (list 'ldc expr)))

(define (compile-form block expr env)
  (set! expr (expand expr env))
  (if (pair? expr)
    (let ((rule (assq (car expr) *mosvm-specials*)))
      (if rule 
        (apply (cdr rule) block env (cdr expr))
        (compile-call block env expr)))
    (compile-expr block expr env)))

(define-record-type <formals>
                    (make-formals fluidf signature slots)
                    formals?
                    (fluidf fluid-formals?)
                    (signature formal-signature)
                    (slots formal-slots))

(define (method-formals? formals) (formal-signature formals))

(define (parse-signature args)
  (if (any pair? (unkink args))
    (map (lambda (i) 
           (if (pair? i) 
             (car i)
             #t))
         args)
    #f))

(define (parse-slots args)
  (map (lambda (i)
         (if (pair? i)
           (cadr i)
           i))
       args))

(define (parse-formals formals)
  (cond 
    ((symbol? formals)     (make-formals #t #f (list formals)))
    ((null? formals)       (make-formals #f #f '()))
    ((not (pair? formals)) (error 'compile "indecipherable formals" formals))
    ((symbol? (cdr (last-pair formals)))
     (set! formals (unkink formals))
     (make-formals #t (parse-signature formals) (parse-slots formals)))
    (else (make-formals #f (parse-signature formals) (parse-slots formals)))))


(define (compile-function outer formals body env)
  (set! env (make-actual-context env (formal-slots formals)))
  (let ((label (make-branch-symbol 'lambda))
        (inner (make-block (block-scheme-program outer)))
        (args  (formal-slots formals)))
    
    (compile-block inner body env)
    (block-append! inner '(retn))
    (block-prepend! inner (if (fluid-formals? formals)
                            (list 'usea 
                                  (- (length args) 1) 
                                  (context-slot-count env))
                            (list 'usen 
                                  (length args) 
                                  (context-slot-count env))))
    (block-prepend! inner label)

    (block-append! outer (list 'ldf label))))

(define (compile-method block genexpr formals body env)
  (compile-expr block 
                (list 'make-multimethod 
                      (cons 'list (formal-signature formals))
                      (cons 'lambda 
                            (cons (formal-slots formals) 
                                  body))
                      genexpr)
                env))

(define (compile-load block sym env) 
  (let ((addr (context-symbol-addr env sym)))
    (block-append! block (if addr (cons 'ldb addr)
                                  (list 'ldg sym)))))

(define (compile-store block expr env) 
  (let ((sym (car expr))
        (val (cadr expr)))
    (compile-expr block val env)
    (let ((addr (context-symbol-addr env sym)))
      (block-append! block (if addr (cons 'stb addr)
                                    (list 'stg sym))))))

(define (fix-mixed-formals formals)
  (let ((tc (make-tc)))
    (while (pair? formals)
      (tc-append! tc (car formals))
      (set! formals (cdr formals)))
    (tc-append! tc formals)
    (tc->list tc)))

(define (compile-mixed-lambda block formals body env)
  (set! formals (fix-mixed-formals formals))
  (set! env (make-actual-context env formals))
  (compile-block block body env)
  (block-prepend! block (list 'usea 
                              (- (length formals) 1)
                              (context-slot-count env))))

(define (compile-call block env expr) 
  (compile-args block (cdr expr) env)
  (compile-expr block (car expr) env)
  (block-append! block '(call)))

(define (compile-args block args env)
  (for-each (lambda (arg) 
              (compile-expr block arg env))
            args)
  (block-append! block (list 'ldc (length args))))

