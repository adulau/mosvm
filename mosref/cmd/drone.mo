 _�� �
	    
	    
	    
	      
	 	  
         �"��
	  
	  � �   � �   � �
	  � �   � �
	  � �   � �
	  � �   �\
	  �  �0 � �
	  � � �j��
	    ��
	  
	  
	  � �    � � � � � � � � ����
	    
	   
	 ! ��    " ��
	 # � �� � 
	 $  %  &����
	   ' 
	   ��   " ��
	 ( � � � �
	 $  ) 
	   � �   * 
	 +  ,� � � -����
	 . �� 
	 $  / ��  0 
	 1 
	 2 � �     " �
	 3 �� ��  4 � � 
	 $  5 ��  6 
	 7 �� � 
	 8 	 9 � �     :� � 
	 K 
	 L 	 M �   N����
	 O � �  ��  � �
	 1 � � � �
	 ! � � � �
	 P � �
	 Q � �  � �
	 +  R��� ��� � � � ��
	 ; �� � �
	 G � �  H �s�� � ��
	 S � � ��
	 T �� � � � �
	 D � ���� ���
	 L  U  V � �  �� ��
	 W � � ��
	 G 
	 1 � �   U ��
	 D � � �� ��
	 D 
	 L  U  X � �  �� �^ 
	 D  H � �  
	 L  Y��� � 
	 D  H �� 
	 D  H ��  � �  
	 Z 
	 [  N  �
	 [  N �	 \  N
	 K 
	 L 	 ] �   N�*��
	 ( � � � �
	 L  ^�&� � 
	 . ��  � �  
	 Z 
	 [  N  �>
	 [  N �?	 \  N module mosref/cmd/drone import mosref/shell mosref/node bind-mosref-cmd drone 'drone <file> <id> <platform> [<portno>] string-append 9Creates a new drone executable for the specified platform 5 and places it at file, then spawns a listener on the : current node.  When the drone connects to the listener, a 5 the drone will be bound to the specified identifier. 	cmd-drone req-path mosref-shell-node  for drone executable req-term  drone identifier  drone platform opt-integer  listener port random-integer make-console-ecdh 	anon-fn-4 send-err Could not compile drone. make-drone-exe 	node-addr 	anon-fn-7 Could not write file  format cadr . put-node-file 	send-line Drone executable created. 
anon-fn-10 Could not listen to  
tcp-listen Listening for drone on  ... spawn 
anon-fn-12 
anon-fn-15 close-listener ERROR: Affilation of  	 failed,  car 
error-info await-drone-affiliation  w@ Drone   affiliated. make-drone-node spawn-endpoint console-endpoint|� �
	 ; � � 
	 ; � � <���	 =�
	 ( � � � � >�b��

	 ? � �  � �
	 @ � �  � �
	 A � � � �
	 B � � � �
	 +  C�J� � 
	 D 
	 ; ��  �� �; 
	 +  E�`� � 
	 D 
	 ; ��  �� �Q � �
	 +  F��� � 
	 G 
	 ;   H �{
	 . �� �{
	 D  H �h 
	 ; � � � �
	 I � �  � �	
	 D 
	 J � �	  
� � � � � �	 �� wait report-failed-listen TODO 
relay-conn input output 	lane-xmit 	lane-recv 
anon-fn-20 send 
anon-fn-23 
anon-fn-26 eq? close make-reserved-lane lane-tag make-multimethod list <drone-node> node-tcp-listen spawn-node-program make-channel node-bridge 
anon-fn-33 string? find-reserved-lane fail unrecognized tag pair? unrecognized event halt-drone-listener 	function? 
get-global refuse-method <console-node> halt-console-listener