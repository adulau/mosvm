 8�� � 
	    
	    
	    
	    
	    
	    
	   	  
�p� �	 �i
	  
	      �f� �
	  ��  �[
	    
	    
	  � � 
	  � �  �� �[
	  
	  � �    �o
	  � �   
 �1��
	  � � � � ��� � 
	  �� � � ��� � 
	  
	  ��  � � ��� �
	  
	  	  
	    !����
	 " � �  ��
	   # � �  ��� �  � �   � � $��� �
	  
	 % 
	 % � �  	   � � &��� � 
��  '  (  )  *  +  ,  + � � -����
�� 
��  . � �  
	 / � � 0���
�� � �
�� 
	 %  1 � �   2 � �  3  � �
� �  4  5 
� � � �	
	 6 � �	 � �

	 7 � �
 � �
   module 
bin/mosref import lib/env lib/with-io lib/terminal lib/iterate mosref/console mosref/shell main 
*in-win32* 
do-with-io spawn-terminal MOSREF inner-io-func null? send %What is the address of this console?
 >  wait list 	do-mosref make-tc next-arg tc-next! 
more-args? not 	tc-empty? 
send-lines string-join 
*line-sep* map 
anon-fn-44 pair?   	send-line string-append 
show-usage USAGE: mosref console-addr C       console-addr -- The hostname or address of the console; this D                       address should be reachable by any first tier                        drones.   +EXAMPLE: mosref decoy.ephemeralsecurity.com parse-error ERROR:  halt missing-error Missing   for  . address console listener make-console-node mosref-shell