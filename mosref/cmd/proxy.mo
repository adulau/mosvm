 R�� �
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
	 , 
	 - 	 . � � �   /����
	  � � � � � �
	 0 � � � �
	  � � � �
	  � � � �  1 � �
	 - � � � �  
	 3 
	 4  /  ��
	 4  / ��	 5  /
	 , 
	 - 	 6 � � �   /���

	 7 � �  ��  � �
	 * � � � �
	 8 � � � �
	  � � � � 
	  � � � � 
	  � � � � 
	 - � � � �  
	 3 
	 4  /  �
	 4  / �	 5  / ����
	  � � 9�4� �
	  � � 	 : � �
	  � � �� � � ;��� � <�g��
	  
	 = � �    > �H�N
	 ? � �  
	  
	 @ � �  �   
	   $ 
	 A �r
	 B 
	   � � 
	 C � � � � 
	 D � �  � �
	 D � �  � �
	 D � �  � �
	 D � �  � �
	  � �  E ����
	  
	 @ � � � � �  
	 / ��  � � � � � � �
	 * � � � �
	 8 � � � �
	  � � � �
	  � �  $ ��
��  F 
�� � �   G 
	  � �   H  I  J �k
	  � �  % �H
��  K 
�� � �   G 
	  � �   L 
	  
	 @ � � � � �  
	 &  M�9� � 
	  
	   �� �, 
	  
	  � �  �;�k
	 ) � � �\
	  
	 * � �   ! �k
��  F 
	 8 	 !  �k
	  
	 @ � � � � �  
	   $ � �
	 N � � � �   O����
	 P � �  ��
	 Q � �  ��� � � � module mosref/cmd/proxy import mosref/shell mosref/node lib/socks-server lib/tcp-server bind-mosref-cmd proxy proxy [<portno>] string-append :Spawns a SOCKS 4a proxy on the console that will establish 8 connections on the current node.  If the port number is ( omitted, it will be selected at random. 	cmd-proxy opt-integer  proxy port random-integer spawn-node-proxy mosref-shell-node 	send-line 'SOCKS Proxy created, listening on port  format .a� �
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
	  � �  % �~
	   % 
	 &  '�g� � 
	  
	   �� �Z 
	 &  (�{� � 
	  
	  ��  �n ��
	 ) � � ��
	  
	 * � �   ! ��
	  � � 
	   $ ��
	   + 
	   $  wait tcp-connect timeout output eq? send ! " fail #� 	timed out close connect spawn lane-to-conn conn-to-lane pair? car +unrecognized response to connection attempt make-multimethod list <console-node> node-tcp-connect input ! 2 #� 	function? 
get-global refuse-method <drone-node> spawn-node-program cadr log-line 
*line-sep* node-proxy-session 
anon-fn-24 	error-key socks re-error format-socks4-response halt parse-socks4-request make-tc tc-next! tcp FAIL:  :  --  Connection terminated before it  connected. SUCC:   -- Connected. 
anon-fn-34 spawn-tcp-server format-addr integer? format-ipv4