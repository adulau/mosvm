 x	B� �
	    
	    
	    
	     �=��
	  � � �#�*
	 	 � � � �
	 
   � �   � �
	  � � � �    �z��
	  � � �O
	 	 � � � ��O
	 
   � �     
	  
	  � �       � �   � � � �
	  � � � �   
	    � � 
	    � �
	  � �  �  � � �A��
	  � ��� � ��� �
	  �� ����������
	   ��  � � 
	  � �  ��
	 ! �� � �  ��� � ��� � ��� � "���� � ������� � 
	 # 
	  ��  � �  �
	   ��  � �
	  � � ��
	 ! �� � � �
	 $ � �  % �
	 & �� 
	  ��  �� ���
	 & �� � �  � �
	 ' 
	  
� �   �2
	 (  )  * � � �2
	 + �� � � � �� ��>�H
	 (  )  , � � 
	 - � � � �
	 . � � � � /�d��
	 (  )  0 �� �� �m
	 1 � � � �
	 . 
	 2 � �  � �
	 3 � �	 4��� �
	 ' 
	  
��   ��
	 (  )  5 �� ��
	 6 �� ����	��
	 + ��  �� � � � � ����
	 (  )  7 �� 
	 8 ��	 
	 - � �   
	 . � �   ��� �

� �
 �� �
	 9 � �	  : � ��� �� ��� ;����
	 (  )  < �� ��
	 1 � � � ���
� � � � � �
	  � � �	�
	 (  )  = � � 
	 9 � �	  > � �
	 ? � �  @ �1
	 
 	 A  B � �  A�1
	 C � � � � � �	 � � � 	 D  
	 E  F 	 G  H � � U�W��
	 V � �  ��  U
	 W  X � �  Y  C
	 _ 
	 ` � �  
	 a � �  I  
	 b 
	 c  d  ��
	 c  d ��	 e  d
	 _ 
	 ` � �  
	 a � �  K  
	 b 
	 c  f  ��
	 c  f ��	 e  f
	 _ 
	 ` � �  
	 a � �  M  
	 b 
	 c  g  ��
	 c  g ��	 e  g
	 _ 
	 ` � �  
	 a � �  O  
	 b � � ��� ���	 e � �
	 _ 
	 ` � �  
	 a � �  Q  
	 b 
	 c  h  �'
	 c  h �(	 e  h
	 _ 
	 ` � �  
	 a � �  D  
	 b 
	 c  i  �Q
	 c  i �R	 e  i
	 _ 
	 ` � �  
	 a � �  T  
	 b 
	 c  j  �{
	 c  j �|	 e  j k����� �
	  � � ��� �� �
	 l � � � ���
	 	 � � � �
	 m � � ����
	 (  )  n 
	 o 
	 p � �  
	 q � � ���P � �
	   � � � �
	 $ � �  r ����
	   % � � 
	 (  )  s � �  t����
	   % �� 
	 u � �  �
� �  � � � � � �
	  � � � �	
	   % � � � �	� � v���
�� 	  � �   v w�*��
�� 	  � �  � � � �  w module lib/http-client import 
lib/object lib/url lib/http-url send-http-get string? url->string string-append GET   HTTP/1.0

 send send-http-post url? POST   HTTP/1.0
 Content-Length:  number->string string-length 
 Content-Type:  

 
make-regex ^([^:]+):[[:space:]]+(.*)$ ?([Hh][Tt][Tt][Pp]/[0-9.]+)[[:space:]]+([0-9]+)[[:space:]]+(.*)$ * read-http-response make-string 	next-line string-read-line! wait string-append! 
next-block >= eq? close string-read! not error http expected response line match-regex could not parse server response car cadr bad-code could not parse response code string->integer cdr dict read-headers !expected header line or null line empty-string? header line malformed 	dict-set! dict-ref Content-Length anon-fn-606 content length malformed content body malformed Content-Type equal? !application/x-www-form-urlencoded url ? make-http-response input 
make-class http-response <object> I J method K L code M N message O P headers Q R body D S T� output http-response? isa? make-class-constructor <http-response> K Z M [ O \ Q ] D ^ T� make-multimethod list make-field-accessor 	function? 
get-global http-response-method refuse-method http-response-code http-response-message http-response-body http-response-input http-response-output with-http-url string->url 	http-url?  malformed url; expected HTTP URL tcp-connect http-url-host http-url-portno connect could not connect to host close-before-fail re-error http-get 	http-post