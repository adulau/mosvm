 #@� � 
	    
	    
	    
	    
	    
	   	  
 
	                ����

	  � �   � �
	  � � � �
	  � � �Q�`
	    
	  � �    
	  � � �n
	    �n
	  � � � �
	  � � �}��
	    
	  
	  � �      
	 ! � �
	 " � � � �   module mosref/cmd/recover import mosref/shell mosref/node mosref/listener mosref/cmd/drone bind-mosref-cmd recover recover <id> string-append ;If the specified node is currently offline, and the node it > affiliates to is currently online, directs the listening node > to once again listen for the drone.  While this is useful for : drones that have been terminated abruptly, it can greatly 6 simplify man in the middle attacks and should be used  carefully. cmd-recover req-term  drone identifier find-mosref-node drone-node? send-err Drone node  format  not found. node-online /Drone is still online, and cannot be recovered. drone-node-link Intermediate node  node-id  is not online. make-console-ecdh spawn-drone-listener