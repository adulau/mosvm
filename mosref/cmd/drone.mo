 :b� � 
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
	 8 	 9 � �     module mosref/cmd/drone import mosref/shell mosref/node bind-mosref-cmd drone 'drone <file> <id> <platform> [<portno>] string-append 9Creates a new drone executable for the specified platform 5 and places it at file, then spawns a listener on the : current node.  When the drone connects to the listener, a 5 the drone will be bound to the specified identifier. 	cmd-drone req-path mosref-shell-node  for drone executable req-term  drone identifier  drone platform opt-integer  listener port random-integer make-console-ecdh 	anon-fn-4 send-err Could not compile drone. make-drone-exe 	node-addr 	anon-fn-7 Could not write file  format cadr . put-node-file 	send-line Drone executable created. 
anon-fn-10 Could not listen to  
tcp-listen Listening for drone on  ... spawn 
anon-fn-12 
anon-fn-15 close-listener ERROR: Affilation of  	 failed,  car 
error-info await-drone-affiliation  w@ Drone   affiliated. make-drone-node spawn-endpoint console-endpoint