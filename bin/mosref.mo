 f�� � 
	    
	    
	    
	  
	    	�%� � 
	 
 	   	 �3� � 
	  
	  	     �]� �
	  
	  	  
	   �U��
	  � �  �S
	    � �  �T� �  � �    
	     �x� �
	  
	  
	  � �  	     ��� � 
	                  !      "����
	  
	   # � �  
	 $  " %����
	  ����
	 " 
	   & � �   ' � �  (   %
	 %  )  * 
	 + 
	 	   ,  -
	 . � 
	 / 	 -  ����
	 " 
	   0  
	 1 	 -  2
	 3 
	 4 	 -   5 �
	 6 � �0 �- 7� ��
	 " 
	 1 
	 8 � �    �-
	 9 
	 4 	 -   :
	 %  ;  < 
	 	  =
	 > 	 =  ? �E�K
	 "  G 
	 %  H  I 
	 	  J
	 K  L
	   M 	 J  N 
	 O 	 J 
	 P 	 2 	 : 	 L 	 =  
	   Q 
	 R 	 :   N 
	 S 	 :  T� U	 U��
	 V 	 T  W
	   X  Y����
	 Z 
	 [ � �    \ ����
	 ] � �  
	   ^ ��
	 _ 	 L 
	 ` 	 W  
	 a 	 W   U��
	   b 
	   c  d 
	 e 	 U module 
bin/mosref import mosref/console lib/tcp-server make-tc argv unparsed-args next-arg tc-next! 
more-args? not 	tc-empty? 
send-lines send string-join 
*line-sep* map 
anon-fn-31 pair?   	lib/trace 	send-line string-append 
show-usage AUSAGE: mosref console-addr:console-port drone-platform drone-path >       console-addr -- The hostname or address of the console. D       console-port -- The tcp port that the console will listen to. C       drone-platform -- One of: winnt-x86, openbsd-x86, linux-x86, $                         darwin-ppc. ?       drone-path -- The file to write the drone executable to.   EEXAMPLE: mosref decoy.ephemeralsecurity.com:19191 openbsd-x86 a-drone parse-error ERROR:  halt missing-error Missing   for  . address console listener string-split : console = length ,Format for console host must be address:port car console-addr string=? cadr * random-integer 
anon-fn-46 
error-info string->integer console-port platform drone compilation drone-platform member @ A 	winnt-x86 B C openbsd-x86 D E 	linux-x86 F� 
darwin-ppc 3This version of mosref has limited platform support path drone output 
drone-path make-console-ecdh console-ecdh Writing drone to  ... write-data-file make-drone-exe Starting listener on port  number->string 
tcp-listen console-listener 
drone-port wait client 1Client connected to port; awaiting affiliation... 
anon-fn-53 eq? 	error-key aff re-error %Client failed to affiliate; rejected. console-affiliation input output =Client confirmed as drone by affiliation; closing listener... =Welcome to MOSREF; all instructions shall be evaluated on the - drone, with results reported to the console. console-repl