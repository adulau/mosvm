 g�� �
	    
	    
	    
	     ����
	  � �
	 	 � �   
���� �r� �
	  � � 
	    
	  
	  
	  ��    
	    
	  
	  � �   
	    
	  ��  � �  
�� 
	  �� � �   � �  � �
	  � �    � �
	  � � ��
� � ��
	  �� � � � �
	  � � ��
� � ��
	    
	  
	  
	  � �    
	    
	  
	  � �  
	    
	  � �  � �   
	     ����
	    � �  
	    
	      !  � �   �U��
	 " 
	  
	 # �  	 $    % 
	  
	 # �  	 $    % 
	  
	 # �  	 $    % 
	  
	 # �  	 $   � �
	  � �  � � �G�S
	 & � �  � � � � � ���  '�c��
	 ( 
	  � �    ' )����
	 * � � �  ��
	 + � �  � � 
	 , � � � � ��f� � � �  -����
	 . � �  � �
	 / � � �  ��
	 0 � � � � � ���
��  � �  � � � � � � ������ ������ � 
	 1 � �
	 * � � �  ��
	 2 � �  �����
	 3 � � 
	 4 � �   
	 + � �  � � 
	 , � � � � ���
	 5 � � � � 6����
	 7 
	  � �    6 8���
�� 
	 9 
	  � �    � � �  8 :�*��
�� 
	 9 
	  � �    � � � �  : ;�8��
	 < 
	  � �    ; =�F��
	 > 
	  � �    = ?�Q��
	 @ � �  � �  ? A�_��
	 @ � �  � � �^� � A B�m��
	 C 
	  � �    B D�v��
	 E � �   D F����
	 E � �  � �  F G����
	 E � �  � � ��� �� � H����� �  H I����
	 J � � ��  K 
	 L 
	 "  M � �   � �  
	 N � � ��
	 O � � ��� �  I
	   P  P����
	   I     Q 
	   R 
	   S   � �   
	   T  T���
	   I     Q 
	   R 
	   U   � �   
	   V  V�)��
	   I     Q 
	   R 
	   W   � �   
	   X  X��� Y�y��
	 4 � �  � �
	 Z � �  � �
	 + 
	 + � �   � �
	  � � 
	  
	 [  \ � �  ] 
	 ^ 
	  
	 . � �      Q � � � � _����
	 ` �� � �  � �
	   a 
	     b  
	    
	     !   
	       
	   c 
	  
	   Q 
	   d  !    
	   c 
� � � �   
	     e  
	    
	     Q   
	       � �
	     f      module lib/http-flow import lib/xml lib/iterate lib/http-server 
spawn-flow dict spawn-http-server flow-broker new-session make-channel print Sending request;  url->string http-request-url  to new session  format 
 send make-flow-sid http-request-cookie sid not dict-ref  to existing session  
set-macro! define-flow list define lambda 
^flow-sid^ 	^flow-in^ string-append random-integer 	*max-imm* - 	dict-set! flow-arg-auth/0 url-auth 	list-tail <= cdr - sublist length < + make-tc null? 
tc-append! car tc->list flow-arg-path/0 url-path flow-arg-path/1 http-url-path flow-arg-path/2 flow-arg-frag/0 url-frag flow-arg-query/0 	url-query flow-arg-query/1 http-request-arg flow-arg-query/2 flow-arg-scheme/0 
url-scheme flow-arg-cookies/0 http-request-cookies flow-arg-cookies/1 flow-arg-cookie/2 flow-arg-req/0 flow-ok write-http-response OK cons Set-cookie: sid= list? sxml->string html-ok 
^flow-req^ quote Content-type: text/html css-ok Content-type: text/css xml-ok Content-type: text/xml flowlet process-flow-var cadr make-symbol 	flow-arg- / string->symbol process-flow-vars map begin Waiting on  let wait Got  Exiting flow.