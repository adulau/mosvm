 c$� �
	    
	    
	    
	      
	 	  
         �;��
	  
	  � �   � �   � �
	  � �   � �
	  � �   � �
	  � �   �\
	  �  �0 � �
	  � �
	  
	  � �   � �� ��q�w
	     ���
	    ��
	  � � � � � � � � � � ����
	     
	 ! 
	 " ��    # ��
	 $ � �� � 
	 %  & 
	 %  ' 
	 ! � �   ( 
	 ) 
	  � �   � � � �	
	 * � �	 � �

	 " � �	 � �
	 +  ,�9� � -���
	 . � �  
	 %  / ��  0 
	 * 
	 1 � �     # 
��
 
	 2 �8
	 3 �� ��  4 � � 
	 %  5 ��  6 
��
 
	 7 �� � 
	 8 	 9 � �     :� � 
	 P 
	 Q 	 R �   )���
	 S � �  ��  � �
	 * � � � �
	 " � � � �
	 T � �
	 U � �  � �
	 H � � � � 
	 +  V��� ��� � � � ��
	 < �� � �
	 K � �  L ���� � ��
	 W � � ��
	 X �� � � � �
	 H � ���� ���
	 Q  Y  Z � �  �� ��
	 [ � � ��
	 K 
	 * � �   Y ��
	 H � � �� ��
	 H 
	 Q  Y  \ � �  �� �
	 H  L ��  
	 Q  ]�	� � 
	 H  L �� 
	 H  L ��  � �  
	 ^ 
	 _  )  �!
	 _  ) �"	 `  )
	 P 
	 Q 	 a �   )�I��
	 A � � � �
	 Q  b�E� � 
	 M ��  � �  
	 ^ 
	 _  )  �]
	 _  ) �^	 `  ) module mosref/cmd/drone import mosref/shell mosref/node bind-mosref-cmd drone 'drone <file> <id> <platform> [<portno>] string-append 9Creates a new drone executable for the specified platform 5 and places it at file, then spawns a listener on the : current node.  When the drone connects to the listener, a 5 the drone will be bound to the specified identifier. 	cmd-drone req-path mosref-shell-node  for drone executable req-term  drone identifier  drone platform opt-integer  listener port random-integer make-console-ecdh 	node-addr send-err 1 node address unknown, use set addr to assign one 	anon-fn-6 Could not compile drone. make-drone-exe 	anon-fn-9 Could not write file  format cadr . put-node-file 	send-line Drone executable created. Listening for drone on  ... node-tcp-listen car spawn 
anon-fn-11 
anon-fn-14 	traceback ERROR: Affilation of  	 failed,  
error-info halt await-drone-affiliation  w@ Drone   affiliated. make-drone-node spawn-endpoint console-endpoint�� �	 ;� � 
	 < � � =�!��
	 >  ? 
	 > 
	 ! ��  
	 >  @ �)
	 A � � � � B�t��

	 C � �  � �
	 D � �  � �
	 E � � � �
	 F � � � �
	 +  G�\� � 
	 H 
	 < ��  �� �M 
	 +  I�r� � 
	 H 
	 < ��  �� �c � �
	 +  J��� � 
	 K 
	 <   L ��
	 M �� ��
	 H  L �z 
	 < � � � �
	 N � �  � �	
	 H 
	 O � �	  
� � � � � �	 �� *drone-bridge* wait report-failed-listen print Could not listen to  
 
tcp-listen 
relay-conn input output 	lane-xmit 	lane-recv 
anon-fn-19 send 
anon-fn-22 
anon-fn-25 eq? close close-listener make-reserved-lane lane-tag make-multimethod list <drone-node> spawn-node-program make-channel drone-node-bridge 
anon-fn-32 string? find-reserved-lane fail unrecognized tag pair? unrecognized event halt-drone-listener 	function? 
get-global refuse-method <console-node> halt-console-listener