 � � 
	    
	    
	    
	         	����
	 
   
	    
	   �u��
	  � �  � �
	  � �  � �
	  
	  � �   
	  � �  �N �O  � ��`
	    
	  � �  �a  � ��r
	    
	  � �  �s   
	      module mosref/cmd/nodes import mosref/shell mosref/node bind-mosref-cmd nodes /Lists the nodes currently known to the console. 	cmd-nodes 	send-line NODES:  string-join 
        map format-node 	node-addr node-portno string-append node-id node-online  online  offline 
 address:  format-addr    port:  format list-mosref-nodes