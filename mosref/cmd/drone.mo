 cE� �
	    
	    
	    
	    
	     	 
	 
           ����
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
	 ( � � � � � �	 � � � �
	 ) � �  * � � 
	 + � � � �   +�l��

	  � �  � �
	 , � � � �
	 - � � � �
	 . � � � �
	 &  / 
	 " � �   0 
	 1  2�j� � 3�3��
	 4 � �  
	 &  5 ��  6 
	 7 
	 8 � �     $ 
	 9 �F
	 : �� 
	 ; ��  �� �� � � 
	 &  < ��  = 
	 > �� � 
	 ? �� 
	 @ 	 A 	 B � �    + C� � 
	 M 
	 N 	 O � �   ;����
	 P � �  ��  � �
	 7 � � � �
	 # � � � �
	 Q � �
	 R � �  � �
	 J 
	 N � � � �  � � 
	 F � � � �
	 J  L � � 
	 S � � ��
	 T � � � � � �� ���
	 N 
	 U � �  
	 V � �  ����
	 W  X  Y � �  
	 Z 
	 [  ;  �
	 [  ; �	 \  ;
	 M 
	 N 	 ] � �   ;�:��
	  � �  � �
	 G � � � � � �
	 N 
	 ^ � �  
	 _ � �   
	 Z 
	 [  ;  �N
	 [  ; �O	 \  ; `� �
	 M 
	 N 	 O �   ����

	 P � �  �� � �
	 7 � � � �
	 # � � � �
	 J � � � � 
	 F � � � �
	 J  L � � 
	 S � � ��� ���
	 W  X  b � �  
	 Z 
	 [    ��
	 [   ��	 \  
	 M 
	 N 	 ] �   ����
	 a � �  
	 Z 
	 [    ��
	 [   ��	 \   module mosref/cmd/drone import mosref/shell mosref/node mosref/listener bind-mosref-cmd drone drone <file> <id> <platform> string-append 9Creates a new drone executable for the specified platform 5 and places it at file, then spawns a listener on the : current node.  When the drone connects to the listener, a 5 the drone will be bound to the specified identifier. 	cmd-drone req-path mosref-shell-console  for drone executable req-term  drone identifier  drone platform mosref-shell-node make-console-ecdh 	node-addr send-err 1 node address unknown, use set addr to assign one 	node-port node-make-sin anon-fn-112 Could not compile drone. make-drone-exe anon-fn-115 Could not write file  format cadr . put-node-file 	send-line Drone executable created. make-drone-node set-node-prop! platform spawn-drone-listener node-id drone-node-sin drone-node-ecdh Listening for drone on  ... spawn anon-fn-118 anon-fn-121 	traceback ERROR: Affilation of  	 failed,  car 
error-info halt console-affiliation node-sin-listen Drone   affiliated. set-node-online! set-node-bridge! spawn-endpoint console-endpoint console-broken }� �
	    
	   D 	 E� � 
	 F � �
	 G � �� �
	 H � �  � �
	 I � � � � 
	 J 
	 K � �  
	 J  L  mosref/patch *drone-bridge* wait mosref-sin-listen make-reserved-lane patch2 send lane-tag close make-multimethod list <drone-node> spawn-node-program make-channel drone-node-bridge string? find-reserved-lane 	lane-xmit 	lane-recv error mosref ,Bogus message while waiting for session lane 	function? 
get-global refuse-method <console-node> input output #� � 
	    
	 J 
	 a 
	 F    make-mosref-sin =Bogus message while waiting for service identification number