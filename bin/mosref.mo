 [-� � 
	    
	    
	     ��� �#
	  � � � � �$� � 
	 	 �� � � 
�2� � 
	  
	  ��  � � �\� �
	  
	  	  
	   �T��
	  � �  �R
	    � �  �S� �  � �   � � �q� �
	  
	  
	  � �  	   � � ��� � 
��                   � �  ����
�� 
��  ! � �  
	 " � � #����
�� ����
�� 
	   $ � �   % � �  &  � �
� �  '  ( 
	 ) 
� �   * � �	
	 + � 
	 , � �	  ����
� � 
	   -  
	 . � �	 � �

	 / 
	 0 � �	   1 �
	 2 � �0 �& 3���
�� 
	 . 
	 4 � �    �&
	 5 
	 0 � �	  � �
� �  6  7 
� � � �
	 8 � �  9 �>�D
� �  A 
� �  B  C 
� � � �
	 D � �
� �  E � �  F 
	 G � � 
	 H � �
 � � � � � �  
� �  I 
	 J � �   F 
	 K � � � ��� �� ���
	 L � � � �!
� �  M  N����
	 O 
	 P � �    Q ����
	 R � �  
��  S ��
	 T � � 
	 U � �!  
	 V � �!  � ���
� �  W 
� �  X  Y 
	 Z � �  module 
bin/mosref import mosref/console lib/tcp-server main make-tc next-arg tc-next! 
more-args? not 	tc-empty? 
send-lines send string-join 
*line-sep* map 
anon-fn-10 pair?   	send-line string-append 
show-usage AUSAGE: mosref console-addr:console-port drone-platform drone-path >       console-addr -- The hostname or address of the console. D       console-port -- The tcp port that the console will listen to. C       drone-platform -- One of: winnt-x86, openbsd-x86, linux-x86, $                         darwin-ppc. ?       drone-path -- The file to write the drone executable to.   EEXAMPLE: mosref decoy.ephemeralsecurity.com:19191 openbsd-x86 a-drone parse-error ERROR:  halt missing-error Missing   for  . address console listener string-split : = length ,Format for console host must be address:port car string=? cadr * random-integer 
anon-fn-25 
error-info string->integer platform drone compilation member : ; 	winnt-x86 < = openbsd-x86 > ? 	linux-x86 @� 
darwin-ppc 3This version of mosref has limited platform support path drone output make-console-ecdh Writing drone to  ... write-data-file make-drone-exe Starting listener on port  number->string 
tcp-listen wait 1Client connected to port; awaiting affiliation... 
anon-fn-32 eq? 	error-key aff re-error %Client failed to affiliate; rejected. console-affiliation input output =Client confirmed as drone by affiliation; closing listener... =Welcome to MOSREF; all instructions shall be evaluated on the - drone, with results reported to the console. console-repl