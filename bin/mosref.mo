 9�� � 
	    
	    
	     �8� �
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
��                        � � !����
�� 
��  " � �  
	 # � � $����
�� ����
�� 
	   % � �   & � �  '  � �
� �  (  ) 
	 * 
� �   + � �	
	 , � 
	 - � �	  ����
� � 
	   .  
	 / � �	 � �

	 0 
	 1 � �	   2 �
	 3 � �0 �* 4���
�� 
	 / 
	 5 � �    �*
	 6 
	 1 � �	  � �
	 7 
	 8 � �
 � �    module 
bin/mosref import mosref/console mosref/shell main make-tc next-arg tc-next! 
more-args? not 	tc-empty? 
send-lines send string-join 
*line-sep* map 
anon-fn-10 pair?   	send-line string-append 
show-usage 'USAGE: mosref console-addr:console-port C       console-addr -- The hostname or address of the console; this D                       address should be reachable by any first tier                        drones.   D       console-port -- The tcp port that the console will listen to; B                       if "*" is specified, a random port shall be                         selected. 1EXAMPLE: mosref decoy.ephemeralsecurity.com:19191 parse-error ERROR:  halt missing-error Missing   for  . address console listener string-split : = length ,Format for console host must be address:port car string=? cadr * random-integer 
anon-fn-25 
error-info string->integer mosref-shell make-console-node