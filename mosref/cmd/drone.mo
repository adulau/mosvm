 d+� �
	    
	    
	    
	      
	 	  
         �:��
	  
	  � �   � �   � �
	  � �   � �
	  � �   � �
	  � �  � �
	  � � �a
	  �  �0 � �
	  � �
	  � � � �� ��q�w
	     ���
	    ��
	  � � � � � � � � � �	 ����
	     
	 ! 
	 " ��    # ��
	 $ � �� �	 
	 %  & 
	 %  ' 
	 ! � �   ( 
	 ) � � � � � �

	 * � �
 � �
	 " � �
 � �
	 +  ,�8� � -���
	 . � �  
	 %  / ��  0 
	 * 
	 1 � �     # 
�� 
	 2 �7
	 3 �� ��  4 � � 
	 %  5 ��  6 
�� 
	 7 �� � � 
	 8 	 9 	 : � �     ;� � 
	 Q 
	 R 	 S �   )���
	 T � �  ��  � �
	 * � � � �
	 " � � � �
	 U � �
	 V � �  � �
	 I � � � � 
	 +  W��� ��� � � � ��
	 = �� � �
	 L � �  M ���� � ��
	 X � � ��
	 Y �� � � � �
	 I � ���� ���
	 R  Z  [ � �  �� ��
	 \ � � ��
	 L 
	 * � �   Z ��
	 I � � �� ��
	 I 
	 R  Z  ] � �  �� �~
	 I  M ��  
	 R  ^�� � 
	 I  M �� 
	 I  M ��  � �  
	 _ 
	 `  )  � 
	 `  ) �!	 a  )
	 Q 
	 R 	 b �   )�H��
	 B � � � �
	 R  c�D� � 
	 N ��  � �  
	 _ 
	 `  )  �\
	 `  ) �]	 a  ) module mosref/cmd/drone import mosref/shell mosref/node bind-mosref-cmd drone drone <file> <id> <platform> string-append 9Creates a new drone executable for the specified platform 5 and places it at file, then spawns a listener on the : current node.  When the drone connects to the listener, a 5 the drone will be bound to the specified identifier. 	cmd-drone req-path mosref-shell-console  for drone executable req-term  drone identifier  drone platform mosref-shell-node node-portno random-integer make-console-ecdh 	node-addr send-err 1 node address unknown, use set addr to assign one 	anon-fn-6 Could not compile drone. make-drone-exe 	anon-fn-9 Could not write file  format cadr . put-node-file 	send-line Drone executable created. Listening for drone on  ... node-tcp-listen car spawn 
anon-fn-11 
anon-fn-14 	traceback ERROR: Affilation of  	 failed,  
error-info halt await-drone-affiliation  w@ Drone   affiliated. make-drone-node spawn-endpoint console-endpoint console-broken�� �	 <� � 
	 = � � >�!��
	 ?  @ 
	 ? 
	 ! ��  
	 ?  A �)
	 B � � � � C�t��

	 D � �  � �
	 E � �  � �
	 F � � � �
	 G � � � �
	 +  H�\� � 
	 I 
	 = ��  �� �M 
	 +  J�r� � 
	 I 
	 = ��  �� �c � �
	 +  K��� � 
	 L 
	 =   M ��
	 N �� ��
	 I  M �z 
	 = � � � �
	 O � �  � �	
	 I 
	 P � �	  
� � � � � �	 �� *drone-bridge* wait report-failed-listen print Could not listen to  
 
tcp-listen 
relay-conn input output 	lane-xmit 	lane-recv 
anon-fn-19 send 
anon-fn-22 
anon-fn-25 eq? close close-listener make-reserved-lane lane-tag make-multimethod list <drone-node> spawn-node-program make-channel drone-node-bridge 
anon-fn-32 string? find-reserved-lane fail unrecognized tag pair? unrecognized event halt-drone-listener 	function? 
get-global refuse-method <console-node> halt-console-listener