 Qs� �
	    
	    
	    
	    
	    
	   	  
 
	          �a��
	  � �   �D
	  �  �0 � �
	  
	  � �   � � 
	    
	  � �      � � 
	 - 
	 . 	 / � � �   0����
	  � � � � � �
	 1 � � � �
	  � � � �
	  � � � �  2 � �
	 . � � � �  
	 4 
	 5  0  ��
	 5  0 ��	 6  0
	 - 
	 . 	 7 � � �   0���

	 8 � �  ��  � �
	 + � � � �
	 9 � � � �
	  � � � � 
	  � � � � 
	  � � � � 
	 . � � � �  
	 4 
	 5  0  �
	 5  0 �	 6  0 ����
	  � � :�4� �
	  � � 	 ; � �
	  � � �� � � <��� � =�g��
	  
	 > � �    ? �H�N
	 @ � �  
	  
	 A � �  �   
	   $ 
	 B �r
	 C 
	   � � 
	 D � � � � 
	 E � �  � �
	 E � �  � �
	 E � �  � �
	 E � �  � �
	  � �  F ����
	  
	 A � � � � �  
	 0 ��  � � � � � � �
	 + � � � �
	 9 � � � �
	  � � � �
	  � �  $ ��
��  G 
	 H � �   I 
	  � �   J  K  L �o
	  � �  % �L
��  M 
	 H � �   I 
	  � �   N 
	  
	 A � � � � �  
	 '  O�;� �
	  � � 
	  � �  �� �, 
	  � � � �
	  � � �=�o
	 * � � �`
	  
	 + � �   ! �o
��  G 
	 9 	 !  �o
	  
	 A � � � � �  
	   $ � �
	 P � � � �   module mosref/cmd/proxy import mosref/shell mosref/node lib/socks-server lib/tcp-server bind-mosref-cmd proxy proxy [<portno>] string-append :Spawns a SOCKS 4a proxy on the console that will establish 8 connections on the current node.  If the port number is ( omitted, it will be selected at random. 	cmd-proxy opt-integer  proxy port random-integer spawn-node-proxy mosref-shell-node 	send-line 'SOCKS Proxy created, listening on port  format .�� �
	  � � 
	  � �
	  � �
	  � �  � � � �
	  � � 
	  � �    � �
	  � � � �
	  � �   �F
	     
	   $ ��
	  � �  % ��
	   % 
	 & � � 
	 '  (�o� �
	  � � 
	  � �  �� �` 
	 '  )��� �
	  �� � � 
	  � �  �v ��
	 * � � ��
	  
	 + � �   ! ��
	  � � 
	   $ ��
	   , 
	   $  wait tcp-connect timeout output eq? send ! " fail #� 	timed out close connect cancel-timeout spawn lane-to-conn conn-to-lane pair? car +unrecognized response to connection attempt make-multimethod list <console-node> node-tcp-connect input ! 3 #� 	function? 
get-global refuse-method <drone-node> spawn-node-program cadr log-line 
*line-sep* node-proxy-session 
anon-fn-88 	error-key socks re-error format-socks4-response halt parse-socks4-request make-tc tc-next! tcp FAIL:  format-addr :  --  Connection terminated before it  connected. SUCC:   -- Connected. 
anon-fn-98 spawn-tcp-server