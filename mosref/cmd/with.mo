 A� � 
	    
	    
	    
	       	  
����
	  � �  � �
	  � � � �� �� ��� ��� �� ��d
	  � �   � �
	  
	  � �  � �
	  
	  � �  �W��b
	  
	  � �  � ��d
	  � � � � � �
	  � � � � � � 
	  � �  � � 
	  � � � � � �   module mosref/cmd/set import mosref/shell mosref/node bind-mosref-cmd with  with <key>[=<value>] [<command>] @Performs the supplied command with key temporarily set to value. cmd-with mosref-shell-node req-term string-split = string->symbol car null? cdr parse-propval cadr find-node-prop set-node-prop! do-mosref-cmd