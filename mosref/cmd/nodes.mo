  �� � 
	    
	    
	    
	         	�g��
	 
   
	    
	   �\��
	  � �  � �
	  
	  � �   
	  � �  �G �H  � ��Y
	    
	  � �  �Z   
	      module mosref/cmd/nodes import mosref/shell mosref/node bind-mosref-cmd nodes /Lists the nodes currently known to the console. 	cmd-nodes 	send-line NODES:  string-join 
        map format-node 	node-addr string-append node-id node-online  online  offline 
 address:  format-addr   list-mosref-nodes