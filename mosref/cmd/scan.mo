 55� � 
	    
	    
	    
	      
	 	  
         �i��

	  
	  � �    � �
	  
	  � �    � �
	  � �   �O��� �
	  � �   �Z��� �
	  	  � � � � � � � �      �w��
	 ! � �  	   � �
	 " � � � �
	 # � � � � $����
	   % �� 
	 & � �  �l
	  
	 ' � � � � � � � �  � � �� �� ��k
	  � � � �
	  � �   ��
	 (  ) 
	   % � � �� ��j
	  � �  % ��
	 (  * 
	   % � � �� ��j
	 + 
	 , � �  �
	 (  - 
	 . � �  
	   % � � 
	 (  / �� ��j
	  
	 " � �   0 �M
	 1 � � � �
	 " � � � �
	 # � � � �
	 (  2 
	 3 � �   4 
	 . � �  �j
	 (  - 
	 . � �  
	   % � � 
	 (  / �� ���� �
	   % � � � �  module mosref/cmd/scan import mosref/shell mosref/node bind-mosref-cmd scan *scan <hosts> <ports> [<timeout> [<conns>]] string-append 9Performs a TCP port scan of the specified host, reporting 9 all ports  that respond with a connection within timeout 3 milliseconds.  The scanner will restrict itself to / conns ports at a time, with a default of 1000. cmd-scan parse-host-spec req-term hosts. parse-port-spec ports. opt-integer timeout conns spawn-node-scan current-node Y� �
	    
	  
	  � � 
	  � �  � �
	  � � 
	  � �   �)�)� mosref/scanner spawn-scanners wait send eq? done *node-scan-prog* spawn-node-program car cadr 	anon-fn-9 close re-error list 	send-line Scan complete. Scan interrupted. not list? Illegal scan event:  format Aborted scan. connect cdr Found port:  format-ipv4 :