 ?� �
	    
	    
	    
	    
	    
	    
	   	 
	    
	   
 
	     �^��
	  
	    
	  � �  
	  	  � �    	   � �  ���
	  � � � �
��    
	  � �
	  �� � �
	  �  
	  � � � �   � �
��    
	  
	  � �  � � 
��    
	  
	  � � � �  � � 
��     
	 ! � � 
� � �  � �
	 " � � � � � � � �
	 # � � � � � � � �	
��   $ 
	  � � � � 
��   % 
	 & 
	 ' � �	  � � ���
	 (  )  * 
��   + 
	 , � � � �	   -�1��
	 , 	 . 
	 / � �   
	  
	 0 � �    � �� 1 2�p��	 1�9�;� �  1
	 3 
	 4 
	 5  
	 6    7�n� �
	 ' � � 
	 8 
	 9 
	 :  
	 ;    <�l� � 
��     2 =�y��
	 > �   = module mosref/drone import lib/cfb lib/buffer-channel lib/iterate lib/crypto-filter lib/package-filter lib/tag-filter lib/with-io mosref/transport step print string-append 	  DRONE:  map format ... 
*line-sep* drone-affiliation buffer-channel Preparing keys make-iv make-ecdh-key make-aes-key ecdh-shared-secret Sending Drone Public Key send export-public-ecdh Sending Drone IV aes-encrypt Reading Console IV aes-decrypt make-mosref-xmit make-mosref-recv Confirming Console IV 'Waiting for Console to confirm Drone IV string=? wait error aff )the console failed to confirm affiliation Affiliation complete. list format-fallback fmt car cdr *drone-bridge* drone-endpoint do-with-input input-chain input thaw-filter inner-input-func do-with-output output-chain output freeze-filter inner-output-func drone-broken exit