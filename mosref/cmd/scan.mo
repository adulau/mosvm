 5>� � 
	    
	    
	    
	      
	 	  
         �n��

	  
	  � �    � �
	  
	  � �    � �
	  � �   �O��� �
	  � �   �Z�,� �
	  
	  � �   � � � � � � � �      �|��
	 ! � �  	   � �
	 " � � � �
	 # � � � � $����
	   % �� 
	 & � �  �q
	  
	 ' � � � � � � � �  � � �� �� ��p
	  � � � �
	  � �   ��
	 (  ) 
	   % � � �� ��o
	  � �  % ��
	 (  * 
	   % � � �� ��o
	 + 
	 , � �  �
	 (  - 
	 . � �  
	   % � � 
	 (  / �� ��o
	  
	 " � �   0 �R
	 1 � � � �
	 " � � � �
	 # � � � �
	 (  2 
	 3 � �   4 
	 . � �  �o
	 (  - 
	 . � �  
	   % � � 
	 (  / �� ���� �
	   % � � � �  module mosref/cmd/scan import mosref/shell mosref/node bind-mosref-cmd scan *scan <hosts> <ports> [<conns> [<timeout>]] string-append 9Performs a TCP port scan of the specified host, reporting 9 all ports  that respond with a connection within timeout 3 milliseconds.  The scanner will restrict itself to . conns ports at a time, with a default of 500. cmd-scan parse-host-spec req-term hosts. parse-port-spec ports. opt-integer timeout conns spawn-node-scan mosref-shell-node Y� �
	    
	  
	  � � 
	  � �  � �
	  � � 
	  � �   �)�)� mosref/scanner spawn-scanners wait send eq? done *node-scan-prog* spawn-node-program car cadr 
anon-fn-58 close re-error list 	send-line Scan complete. Scan interrupted. not list? Illegal scan event:  format Aborted scan. connect cdr Found port:  format-ipv4 :