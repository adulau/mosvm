 ]�� �
	    
	    
	    
	    
	     	 
	 
           �5��
	  
	  � �   � �   � �
	  � �   � �
	  � �   � �
	  � �  � �
	  � �
	  � � � �� ��g�m
	    
	  � � � �
	  � � � � � �	 ����
	    ��
	  � � � �	 � � � � � � � �
  ����
	   ! 
	 " 
	 # ��    $ ��
	 % � �� �
 
	 &  ' 
	 &  ( 
	 " � �   ) 
	 *  +�3� � ,����
	 - � �  
	 &  . ��  / 
	 0 
	 1 � �     $ 
	 2 �2
	 3 �� 
	 4 �� �� ��	 � � 
	 &  5 ��  6 
	 7 �� ��	 �� 
	 8 	 9 	 : � �  � �
	 ; � �  < ��    =� � 
	 G 
	 H 	 I � �   4����
	 J � �  ��  � �
	 0 � � � �
	 # � � � �
	 K � �
	 L � �  � �
	 D 
	 H � � � �  � � 
	 @ � � � �
	 D  F � � 
	 M � � ��
	 N � � � � � �� ���
	 H 
	 O � �  
	 P � �  ����
	 Q  R  S � �  
	 T 
	 U  4  ��
	 U  4 ��	 V  4
	 G 
	 H 	 W � �   4���
	  � �  � �
	 A � � � � � �
	 H 
	 X � �  
	 Y � �   
	 T 
	 U  4  �
	 U  4 �	 V  4 Z� �
	 G 
	 H 	 I �   �n��

	 J � �  �� � �
	 0 � � � �
	 # � � � �
	 D � � � � 
	 @ � � � �
	 D  F � � 
	 M � � �d� ��d
	 Q  R  \ � �  
	 T 
	 U    ��
	 U   ��	 V  
	 G 
	 H 	 W �   ����
	 [ � �  
	 T 
	 U    ��
	 U   ��	 V   module mosref/cmd/drone import mosref/shell mosref/node mosref/listener bind-mosref-cmd drone drone <file> <id> <platform> string-append 9Creates a new drone executable for the specified platform 5 and places it at file, then spawns a listener on the : current node.  When the drone connects to the listener, a 5 the drone will be bound to the specified identifier. 	cmd-drone req-path mosref-shell-console  for drone executable req-term  drone identifier  drone platform mosref-shell-node make-console-ecdh 	node-addr send-err 1 node address unknown, use set addr to assign one 	node-port node-make-sin 
anon-fn-36 Could not compile drone. make-drone-exe 
anon-fn-39 Could not write file  format cadr . put-node-file 	send-line Drone executable created. Listening for drone on  ... spawn 
anon-fn-41 
anon-fn-44 	traceback ERROR: Affilation of  	 failed,  car 
error-info halt console-affiliation node-sin-listen Drone   affiliated. make-drone-node spawn-endpoint console-endpoint console-broken set-node-prop! platform }� �
	    
	   > 	 ?� � 
	 @ � �
	 A � �� �
	 B � �  � �
	 C � � � � 
	 D 
	 E � �  
	 D  F  mosref/patch *drone-bridge* wait mosref-sin-listen make-reserved-lane patch2 send lane-tag close make-multimethod list <drone-node> spawn-node-program make-channel drone-node-bridge string? find-reserved-lane 	lane-xmit 	lane-recv error mosref ,Bogus message while waiting for session lane 	function? 
get-global refuse-method <console-node> input output #� � 
	    
	 D 
	 [ 
	 @    make-mosref-sin =Bogus message while waiting for service identification number