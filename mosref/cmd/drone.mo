 `�� �
	    
	    
	    
	      
	 	  
         �0��
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
	 $  % 
	 $  & 
	   � �   ' 
	 ( 
	  � �   � � � �
	 ) � � � �	
	 ! � � � �

	 *  +�.� � ,���
	 - � �  
	 $  . ��  / 
	 ) 
	 0 � �     " 
��	 
	 1 �-
	 2 ��
 ��  3 � � 
	 $  4 ��  5 
��	 
	 6 �� � 
	 7 	 8 � �     9� � 
	 M 
	 N 	 O �   (����
	 P � �  ��  � �
	 ) � � � �
	 ! � � � �
	 Q � �
	 R � �  � �
	 *  S��� ��� � � � ��
	 ; �� � �
	 H � �  I ���� � ��
	 T � � ��
	 U �� � � � �
	 E � ���� ���
	 N  V  W � �  �� ��
	 X � � ��
	 H 
	 ) � �   V ��
	 E � � �� ��
	 E 
	 N  V  Y � �  �� �l
	 E  I ��  
	 N  Z��� � 
	 E  I �� 
	 E  I ��  � �  
	 [ 
	 \  (  �
	 \  ( �	 ]  (
	 M 
	 N 	 ^ �   (�6��
	 > � � � �
	 N  _�2� � 
	 J ��  � �  
	 [ 
	 \  (  �J
	 \  ( �K	 ]  ( module mosref/cmd/drone import mosref/shell mosref/node bind-mosref-cmd drone 'drone <file> <id> <platform> [<portno>] string-append 9Creates a new drone executable for the specified platform 5 and places it at file, then spawns a listener on the : current node.  When the drone connects to the listener, a 5 the drone will be bound to the specified identifier. 	cmd-drone req-path mosref-shell-node  for drone executable req-term  drone identifier  drone platform opt-integer  listener port random-integer make-console-ecdh 	anon-fn-4 send-err Could not compile drone. make-drone-exe 	node-addr 	anon-fn-7 Could not write file  format cadr . put-node-file 	send-line Drone executable created. Listening for drone on  ... node-tcp-listen car spawn 	anon-fn-9 
anon-fn-12 	traceback ERROR: Affilation of  	 failed,  
error-info halt await-drone-affiliation  w@ Drone   affiliated. make-drone-node spawn-endpoint console-endpointy� �	 :� � 
	 ; � � <���	 =�
	 > � � � � ?�_��

	 @ � �  � �
	 A � �  � �
	 B � � � �
	 C � � � �
	 *  D�G� � 
	 E 
	 ; ��  �� �8 
	 *  F�]� � 
	 E 
	 ; ��  �� �N � �
	 *  G��� � 
	 H 
	 ;   I �x
	 J �� �x
	 E  I �e 
	 ; � � � �
	 K � �  � �	
	 E 
	 L � �	  
� � � � � �	 �� *drone-bridge* wait report-failed-listen TODO 
tcp-listen 
relay-conn input output 	lane-xmit 	lane-recv 
anon-fn-17 send 
anon-fn-20 
anon-fn-23 eq? close close-listener make-reserved-lane lane-tag make-multimethod list <drone-node> spawn-node-program make-channel drone-node-bridge 
anon-fn-30 string? find-reserved-lane fail unrecognized tag pair? unrecognized event halt-drone-listener 	function? 
get-global refuse-method <console-node> halt-console-listener