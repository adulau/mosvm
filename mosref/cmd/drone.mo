 a� �
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
	  � �
	  � � � �� ��g�m
	    
	  � � � �� ��w��
	  �  �0 � �
	  � � � � 
	    
	   � �   ! 
	 " � � � � � �	 #����
	   $ ��
	 % � � � �	 � � � � � � � �
 &����
	   ' 
	   
	 ( ��    ) ��
	 * � �� �
 
	   + 
	   , 
	   � �   - 
	 .  /�V� � 0���
	 1 � �  
	   2 ��  3 
	 4 
	 5 � �     ) 
	 6 �U
	 7 �� 
	 8 �� �� ��	 � � 
	   9 ��  : 
	 ; �� � � 
	 < 	 = 	 > � �  � �
	 ? � �  @ ��    A� � 
	 K 
	 L 	 M � �   8����
	 N � �  ��  � �
	 4 � � � �
	 ( � � � �
	 O � �
	 P � �  � �
	 H 
	 L � � � �  � � 
	 D � � � �
	 H  J � � 
	 Q � � ��
	 R � � � � � �� ���
	 L 
	 S � �  
	 T � �  ����
	 U  V  W � �  
	 X 
	 Y  8  ��
	 Y  8 ��	 Z  8
	 K 
	 L 	 [ � �   8�'��
	  � �  � �
	 E � � � � � �
	 L 
	 \ � �  
	 ] � �   
	 X 
	 Y  8  �;
	 Y  8 �<	 Z  8 ^� �
	 K 
	 L 	 M �   "����

	 N � �  �� � �
	 4 � � � �
	 ( � � � �
	 H � � � � 
	 D � � � �
	 H  J � � 
	 Q � � ��� ���
	 U  V  ` � �  
	 X 
	 Y  "  ��
	 Y  " ��	 Z  "
	 K 
	 L 	 [ �   "����
	 _ � �  
	 X 
	 Y  "  ��
	 Y  " ��	 Z  " module mosref/cmd/drone import mosref/shell mosref/node mosref/listener bind-mosref-cmd drone drone <file> <id> <platform> string-append 9Creates a new drone executable for the specified platform 5 and places it at file, then spawns a listener on the : current node.  When the drone connects to the listener, a 5 the drone will be bound to the specified identifier. 	cmd-drone req-path mosref-shell-console  for drone executable req-term  drone identifier  drone platform mosref-shell-node make-console-ecdh 	node-addr send-err 1 node address unknown, use set addr to assign one node-portno random-integer set-node-portno! 	send-line >NOTE: This node does not have a listener port assigned, using  format  for this node. node-make-sin 	anon-fn-7 Could not compile drone. make-drone-exe 
anon-fn-10 Could not write file  cadr . put-node-file Drone executable created. Listening for drone on  ... spawn 
anon-fn-12 
anon-fn-15 	traceback ERROR: Affilation of  	 failed,  car 
error-info halt console-affiliation node-sin-listen Drone   affiliated. make-drone-node spawn-endpoint console-endpoint console-broken set-node-prop! platform }� �
	    
	   B 	 C� � 
	 D � �
	 E � �� �
	 F � �  � �
	 G � � � � 
	 H 
	 I � �  
	 H  J  mosref/patch *drone-bridge* wait mosref-sin-listen make-reserved-lane patch2 send lane-tag close make-multimethod list <drone-node> spawn-node-program make-channel drone-node-bridge string? find-reserved-lane 	lane-xmit 	lane-recv error mosref ,Bogus message while waiting for session lane 	function? 
get-global refuse-method <console-node> input output #� � 
	    
	 H 
	 _ 
	 D    make-mosref-sin =Bogus message while waiting for service identification number