 k� �
	    
	    
	    
	    
	    
	    
	 	  
 � � � � �
	  � � �F��
	  �� � ��
	  �� � �  � � �k��
	  �� � ��
	  �� � �  
	  �� �  �j
	  �  �j� � ��� �
	    � � 	  � �
	   ���� ��� �� � ��
	  �� � �   
	  ��   
	    	      & '����
	 ( � �  	 &  '
	 )  & 	 &  * � �
	 - 
	 . 	 &  
	 / 	 &  !  
	 0 
	 1  2  ��
	 1  2 ��	 3  2
	 - 
	 . 	 &  
	 / 	 &  #  
	 0 
	 1  4  �
	 1  4 �		 3  4
	 - 
	 . 	 &  
	 / 	 &  %  
	 0 
	 1  5  �2
	 1  5 �3	 3  5
	 - 
	 . 	 & �  
	 6 	 &  !  
	 0 
	 1  7  �^
	 1  7 �_	 3  7
	 - 
	 . 	 & �  
	 6 	 &  #  
	 0 
	 1  8  ��
	 1  8 ��	 3  8
	 - 
	 . 	 & �  
	 6 	 &  %  
	 0 
	 1  9  ��
	 1  9 ��	 3  9
	   : 	   ;  C D����
	 ( � �  	 C  D
	 )  C 	 C  E � �
	 - 
	 . 	 C  
	 / 	 C  <  
	 0 
	 1  I  �
	 1  I �	 3  I
	 - 
	 . 	 C  
	 / 	 C  >  
	 0 
	 1  J  �+
	 1  J �,	 3  J
	 - 
	 . 	 C  
	 / 	 C  @  
	 0 
	 1  K  �U
	 1  K �V	 3  K
	 - 
	 . 	 C  
	 / 	 C  B  
	 0 
	 1  L  �
	 1  L ��	 3  L
	 M � � N��� � 
	 O ��  N P����
	 Q �� � �  
�� � �  � � � � � �   P R����
	 S �� � �   R
	 T  U  U����
	 .  P � �  � � � � 
	 .  V 
	 . 
	 W  X � �    Y  Z  � �   [�<��
	 \ � � �
	 [ � �  
	 ] 
	 ^ ��  � � ��� �
	 _ � � ��
	 ` � � � �
	 S �� � � � �� �� �/
	 a  b 
	 c � �   d 

	 L � �  � �  � �  [ e�+��
�� 
	 f   g�Y��
�� 
	 f  
	 h � �  �"
�� � � � �  � � � i�~� � 
	  
	  
	 j 
	 2 ��    k  � �
� � 
	 5 � � �
	 l � �
	 m � �  n ����
	 \ � � � o���
	 p � �  � �
	 q � �  r ���
	 q � �  t ��
	 v  w 
	 x 
	 y � �    �
	 q � �  z ��
	 y � �  � �
	 v  | 
	 c 
	 } � �    ~ 
	 x � �  �
	 h � �  �
	 [ � � � � 
	 5 � � �
� � ����
	   n 
�� 
	 f   e module mosref/shell import 	lib/catch mosref/console mosref/node mosref/parse mosref/format 
make-regex [^ 
	]+ set add-shell-display! + set-add! remove-shell-display! - set-remove! <= exit alert string-append ALERT:  
*line-sep* for-each 	anon-fn-7 
anon-fn-10 send 	set->list 
make-class mosref-shell <object> ! " node # $ console %� running <mosref-shell> mosref-shell? isa? make-class-constructor ! + # , %� make-multimethod list make-field-accessor 	function? 
get-global mosref-shell-node refuse-method mosref-shell-console mosref-shell-running make-field-modifier set-mosref-shell-node! set-mosref-shell-console! set-mosref-shell-running! 
mosref-cmd < = verb > ? usage @ A info B� impl <mosref-cmd> mosref-cmd? < F > G @ H B� mosref-cmd-verb mosref-cmd-usage mosref-cmd-info mosref-cmd-impl dict mosref-cmds dict-values bind-mosref-cmd 	dict-set! find-mosref-cmd dict-ref 
set-macro! 
define-cmd function make-symbol cmd- shell terms do-mosref-cmd string? make-tc match-regex* 	tc-empty? tc-next! send-err I do not understand  format . run-mosref-shell output 
anon-fn-48 re-error send-prompt node-id >  wait eq? close 
anon-fn-58 	error-key memq s� syn u� off 	send-line 	OFFLINE:  car 
error-info {� parse PARSE: For  cadr , 