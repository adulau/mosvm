 :R� � 
	    
	    
	    
	      
	 	  
                   �x��

	  
	  � �    � �
	  
	  � �    � �
	  � �   �Y��� �
	  � �   �d��� �
	  
	  � �   � � � � � � � �    % ����
	 & � �  	 % � �
	 ' � � � �
	 ( � � � � )����
	 "  * �� 
	 + � �  �{
	 " 
	 , � � � � � � � �  � � �� �� ��z
	 ! � � � �
	 # � �  $ ��
	 -  . 
	 "  * � � �� ��y
	 # � �  * ��
	 -  / 
	 "  * � � �� ��y
	 0 
	 1 � �  �"
	 -  2 
	 3 � �  
	 "  * � � 
	 -  4 �� ��y
	 # 
	 ' � �   5 �\
	 6 � � � �
	 ' � � � �
	 ( � � � �
	 -  7 
	 8 � �   9 
	 3 � �  �y
	 -  2 
	 3 � �  
	 "  * � � 
	 -  4 �� ���� �
	 "  * � � � �  module mosref/cmd/scan import mosref/shell mosref/node bind-mosref-cmd scan *scan <hosts> <ports> [<conns> [<timeout>]] string-append 9Performs a TCP port scan of the specified host, reporting 8 all ports that respond with a connection within timeout > milliseconds.  The scanner will limit the number of attempted  connections to conns. 

 >When omitted, timeout defaults to 15000, and conns defaults to 4 500.  Scan will only try each connection once -- to 8 exhaustively test unreliable or congested environments, ; perform the scan multiple times to get an accurate sample. cmd-scan parse-host-spec req-term hosts. parse-port-spec ports. opt-integer conns timeout spawn-node-scan mosref-shell-node Y� �
	    
	   
	 ! � � 
	 ! � �  � �
	 " � � 
	 # � �  $ �)�)� mosref/scanner spawn-scanners wait send eq? done *node-scan-prog* spawn-node-program car cadr 	anon-fn-9 close re-error list 	send-line Scan complete. Scan interrupted. not list? Illegal scan event:  format Aborted scan. connect cdr Found port:  format-ipv4 :