 Y$� �
	    
	    
	    
	    
	    
	   	  
 
	                �p��
	  � �   �J
	  �  �0 � �
	  � � � �
	  
	  � �   � � � � 
	    
	  � �      � � 
	 1 
	 2 	 3 � � �   4����
	  � � � � � �
	 5 � � � �
	 ! � � � �
	   � � � �  6 � �
	 2 � � � �  
	 8 
	 9  4  ��
	 9  4 ��	 :  4
	 1 
	 2 	 ; � � �   4���

	 < � �  ��  � �
	 / � � � �
	 = � � � �
	 # � � � � 
	 # � � � � 
	 # � � � � 
	 2 � � � �  
	 8 
	 9  4  �%
	 9  4 �&	 :  4 ����	
	 ! � � >�C� �
	  � � 	 ? � �
	 # � � �� � � @��� � A�v��
	 " 
	 B � �    C �W�]
	 D � �  
	 # 
	 E � �  �   
	 #  ( 
	 F ��
	 G 
	   � � 
	 H � � � � 
	 I � �  � �
	 I � �  � �
	 I � �  � �
	 I � �  � �
	 " � �  J ����
	 # 
	 E � � � � �  
	 #  ( 
	 F 
	 K �� ��
	 L �� � � ���
��  M 
	  ��   N 
	  � �  
	 # 
	 E � � � � �  
	 #  ( 
	 F 
	 4 ��  � � � � � � �
	 / � � � �
	 = � � � �
	  � � � �
	 " � �  ( �P
��  O 
	 P � �   Q 
	  � �   R  S  T ��
	 " � �  ) ��
��  U 
	 P � �   Q 
	  � �   V 
	 # 
	 E � � � � �  
	 +  W��� �
	  � � 
	 # � �  �� �� 
	  � � � �
	 # � � ����
	 . � � ��
	 " 
	 / � �   % ��
��  O 
	 = 	 %  ��
	 # 
	 E � � � � �  
	 #  ( � �
	 X � � � �   module mosref/cmd/proxy import mosref/shell mosref/node lib/socks-server lib/tcp-server bind-mosref-cmd proxy proxy [<portno> [<secret>]] string-append :Spawns a SOCKS 4a proxy on the console that will establish 8 connections on the current node.  If the port number is ( omitted, it will be selected at random. 

 BIf a shared secret is supplied, the authentication supplied to the / socks proxy must be match the supplied secret. 	cmd-proxy opt-integer  proxy port random-integer opt-term spawn-node-proxy mosref-shell-node 	send-line 'SOCKS Proxy created, listening on port  format .�� �
	  � � 
	  � �
	  � �
	  � �  � � � �
	   � � 
	 ! � �     � �
	  � � � �
	 " � �    �F
	 #  $ 
	 #  ( ��
	 " � �  ) ��
	 #  ) 
	 * � � 
	 +  ,�o� �
	  � � 
	 # � �  �� �` 
	 +  -��� �
	  �� � � 
	 # � �  �v ��
	 . � � ��
	 " 
	 / � �   % ��
	 # � � 
	 #  ( ��
	 #  0 
	 #  (  wait tcp-connect timeout output eq? send % & fail '� 	timed out close connect cancel-timeout spawn lane-to-conn conn-to-lane pair? car +unrecognized response to connection attempt make-multimethod list <console-node> node-tcp-connect input % 7 '� 	function? 
get-global refuse-method <drone-node> spawn-node-program cadr log-line 
*line-sep* node-proxy-session 
anon-fn-24 	error-key socks re-error format-socks4-response halt parse-socks4-request make-tc tc-next! tcp not string=? &AUTH: Failed authentication, expected  , got  FAIL:  format-addr :  --  Connection terminated before it  connected. SUCC:   -- Connected. 
anon-fn-37 spawn-tcp-server