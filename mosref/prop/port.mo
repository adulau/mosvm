 /� � 
	    
	    
	    
	    
	     	    �H��
	  � �  �1
	  � �  �3�B
	    
	  � �     
	  � �   �  �m��
	  � �    � �� ��Z�k
	  � �0 � �
	  � �  � � � �  �z��
	  � �    � �   ����
	  � �      module mosref/prop/port import mosref/node mosref/parse mosref/format register-prop port 
  portno � pn_Assigns a TCP port for incoming DCNR sessions.  Drones that need to contact the node will attempt to contact this port.

The node will only listen to this port when it is informed that one or more drones are expected to affiliate with the node.  If a port has not been assigned, a random one will be assigned, in the range 10000 to 30000, inclusive.

 is-valid-port? string? integer? send-err Expected a port number, not  format . 
parse-port 	node-port find-node-prop random-integer set-node-port! set-node-prop! node-has-port? has-node-prop?