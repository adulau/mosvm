 ^�� �
	    
	    
	    
	    
	     	 
	 
           �>��
	  
	  � �   � �   � �
	  � �   � �
	  � �   � �
	  � �  � �
	  � � �g
	  �  �0 � �
	  � �
	  � � � �� ��w�}
	    
	  � � � � � �	 ����
	    ��
	   � � � �	 � � � � � � � �
 !����
	   " 
	 # 
	 $ ��    % ��
	 & � �� �
 
	 '  ( 
	 '  ) 
	 # � �   * 
	 +  ,�<� � -����
	 . � �  
	 '  / ��  0 
	 1 
	 2 � �     % 
	 3 �;
	 4 �� 
	 5 �� �� ��	 � � 
	 '  6 ��  7 
	 8 �� � � 
	 9 	 : 	 ; � �  � �
	 < � �  = ��    >� � 
	 H 
	 I 	 J � �   5����
	 K � �  ��  � �
	 1 � � � �
	 $ � � � �
	 L � �
	 M � �  � �
	 E 
	 I � � � �  � � 
	 A � � � �
	 E  G � � 
	 N � � ��
	 O � � � � � �� ���
	 I 
	 P � �  
	 Q � �  ����
	 R  S  T � �  
	 U 
	 V  5  ��
	 V  5 ��	 W  5
	 H 
	 I 	 X � �   5���
	  � �  � �
	 B � � � � � �
	 I 
	 Y � �  
	 Z � �   
	 U 
	 V  5  �!
	 V  5 �"	 W  5 [� �
	 H 
	 I 	 J �   �w��

	 K � �  �� � �
	 1 � � � �
	 $ � � � �
	 E � � � � 
	 A � � � �
	 E  G � � 
	 N � � �m� ��m
	 R  S  ] � �  
	 U 
	 V    ��
	 V   ��	 W  
	 H 
	 I 	 X �   ����
	 \ � �  
	 U 
	 V    ��
	 V   ��	 W   module mosref/cmd/drone import mosref/shell mosref/node mosref/listener bind-mosref-cmd drone drone <file> <id> <platform> string-append 9Creates a new drone executable for the specified platform 5 and places it at file, then spawns a listener on the : current node.  When the drone connects to the listener, a 5 the drone will be bound to the specified identifier. 	cmd-drone req-path mosref-shell-console  for drone executable req-term  drone identifier  drone platform mosref-shell-node node-portno random-integer make-console-ecdh 	node-addr send-err 1 node address unknown, use set addr to assign one node-make-sin 	anon-fn-6 Could not compile drone. make-drone-exe 	anon-fn-9 Could not write file  format cadr . put-node-file 	send-line Drone executable created. Listening for drone on  ... spawn 
anon-fn-11 
anon-fn-14 	traceback ERROR: Affilation of  	 failed,  car 
error-info halt console-affiliation node-sin-listen Drone   affiliated. make-drone-node spawn-endpoint console-endpoint console-broken set-node-prop! platform }� �
	    
	   ? 	 @� � 
	 A � �
	 B � �� �
	 C � �  � �
	 D � � � � 
	 E 
	 F � �  
	 E  G  mosref/patch *drone-bridge* wait mosref-sin-listen make-reserved-lane patch2 send lane-tag close make-multimethod list <drone-node> spawn-node-program make-channel drone-node-bridge string? find-reserved-lane 	lane-xmit 	lane-recv error mosref ,Bogus message while waiting for session lane 	function? 
get-global refuse-method <console-node> input output #� � 
	    
	 E 
	 \ 
	 A    make-mosref-sin =Bogus message while waiting for service identification number