 `�� �
	    
	    
	    
	    
	     	 
	 
           �X��
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
	 +  ,�V� � -����
	 . � �  
	 '  / ��  0 
	 1 
	 2 � �     % 
	 3 �U
	 4 
	 # 
	 5 �� �� ��	   
	 4  6 
	 7 �� 
	 8 �� �� ��	 � � 
	 '  9 ��  : 
	 ; �� � � 
	 < 	 = 	 > � �  � �
	 ? � �  @ ��    A� � 
	 K 
	 5 	 L � �   8����
	 M � �  ��  � �
	 1 � � � �
	 $ � � � �
	 N � �
	 O � �  � �
	 H 
	 5 � � � �  � � 
	 D � � � �
	 H  J � � 
	 P � � ��
	 Q � � � � � �� ���
	 5 
	 R � �  
	 S � �  ����
	 T  U  V � �  
	 W 
	 X  8  ��
	 X  8 ��	 Y  8
	 K 
	 5 	 Z � �   8�'��
	  � �  � �
	 E � � � � � �
	 5 
	 [ � �  
	 \ � �   
	 W 
	 X  8  �;
	 X  8 �<	 Y  8 ]� �
	 K 
	 5 	 L �   ����

	 M � �  �� � �
	 1 � � � �
	 $ � � � �
	 H � � � � 
	 D � � � �
	 H  J � � 
	 P � � ��� ���
	 T  U  _ � �  
	 W 
	 X    ��
	 X   ��	 Y  
	 K 
	 5 	 Z �   ����
	 ^ � �  
	 W 
	 X    ��
	 X   ��	 Y   module mosref/cmd/drone import mosref/shell mosref/node mosref/listener bind-mosref-cmd drone drone <file> <id> <platform> string-append 9Creates a new drone executable for the specified platform 5 and places it at file, then spawns a listener on the : current node.  When the drone connects to the listener, a 5 the drone will be bound to the specified identifier. 	cmd-drone req-path mosref-shell-console  for drone executable req-term  drone identifier  drone platform mosref-shell-node node-portno random-integer make-console-ecdh 	node-addr send-err 1 node address unknown, use set addr to assign one node-make-sin 	anon-fn-6 Could not compile drone. make-drone-exe 	anon-fn-9 Could not write file  format cadr . put-node-file 	send-line Drone executable created. Listening for drone on  ... spawn 
anon-fn-11 
anon-fn-14 	traceback ERROR: Affilation of  	 failed,  car 
error-info halt print list 
 console-affiliation node-sin-listen Drone   affiliated. make-drone-node spawn-endpoint console-endpoint console-broken set-node-prop! platform }� �
	    
	   B 	 C� � 
	 D � �
	 E � �� �
	 F � �  � �
	 G � � � � 
	 H 
	 I � �  
	 H  J  mosref/patch *drone-bridge* wait mosref-sin-listen make-reserved-lane patch2 send lane-tag close make-multimethod <drone-node> spawn-node-program make-channel drone-node-bridge string? find-reserved-lane 	lane-xmit 	lane-recv error mosref ,Bogus message while waiting for session lane 	function? 
get-global refuse-method <console-node> input output #� � 
	    
	 H 
	 ^ 
	 D    make-mosref-sin =Bogus message while waiting for service identification number