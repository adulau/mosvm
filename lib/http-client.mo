 u�� �
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
	 E  F 	 G  H � � S�W��
	 T � �  ��  S
	 U  V � �  W  C
	 ] 
	 ^ � �  
	 _ � �  I  
	 ` 
	 a  b  ��
	 a  b ��	 c  b
	 ] 
	 ^ � �  
	 _ � �  K  
	 ` 
	 a  d  ��
	 a  d ��	 c  d
	 ] 
	 ^ � �  
	 _ � �  M  
	 ` � � ��� ���	 c � �
	 ] 
	 ^ � �  
	 _ � �  O  
	 ` 
	 a  e  ��
	 a  e ��	 c  e
	 ] 
	 ^ � �  
	 _ � �  D  
	 ` 
	 a  f  �'
	 a  f �(	 c  f
	 ] 
	 ^ � �  
	 _ � �  R  
	 ` 
	 a  g  �Q
	 a  g �R	 c  g h������ �
	  � � �j� �� �
	 i � � � ��q
	 	 � � � �
	 j � � �y��
	 (  )  k 
	 l 
	 m � �  
	 n � � ���P � �
	   � � � �
	 $ � �  o ����
	   % � � 
	 (  )  p � �  q����
	   % �� 
	 r � �  ��
� �  � � � � � �
	  � � � �	
	   % � � � �	� � s����
�� 	  � �   s t� ��
�� 	  � �  � � � �  t module lib/http-client import 
lib/object lib/url lib/http-url send-http-get string? url->string string-append GET   HTTP/1.0

 send send-http-post url? POST   HTTP/1.0
 Content-Length:  number->string string-length 
 Content-Type:  

 
make-regex ^([^:]+):[[:space:]]+(.*)$ ?([Hh][Tt][Tt][Pp]/[0-9.]+)[[:space:]]+([0-9]+)[[:space:]]+(.*)$ * read-http-response make-string 	next-line string-read-line! wait string-append! 
next-block >= eq? close string-read! not error http expected response line match-regex could not parse server response car cadr bad-code could not parse response code string->integer cdr dict read-headers !expected header line or null line empty-string? header line malformed 	dict-set! dict-ref Content-Length 
anon-fn-40 content length malformed content body malformed Content-Type equal? !application/x-www-form-urlencoded url ? make-http-response input 
make-class http-response <object> I J code K L message M N headers O P body D Q R� output http-response? isa? make-class-constructor <http-response> I X K Y M Z O [ D \ R� make-multimethod list make-field-accessor 	function? 
get-global http-response-code refuse-method http-response-message http-response-body http-response-input http-response-output with-http-url string->url 	http-url?  malformed url; expected HTTP URL tcp-connect http-url-host http-url-portno connect could not connect to host close-before-fail re-error http-get 	http-post