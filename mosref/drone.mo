 <� �
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
	 0 � �    � � 1�{� �
	 ' 	 2 � � 
	 3 
	 4 
	 2  
	 5    6�y� �
	 ' � � 
	 7 
	 8 
	 9  
	 :    ;�w� � 
	  ��  
	 2  
��     1 module mosref/drone import lib/cfb lib/buffer-channel lib/iterate lib/crypto-filter lib/package-filter lib/tag-filter lib/with-io mosref/base step print string-append 	  DRONE:  map format ... 
*line-sep* drone-affiliation buffer-channel Preparing keys make-iv make-ecdh-key make-aes-key ecdh-shared-secret Sending Drone Public Key send export-public-ecdh Sending Drone IV aes-encrypt Reading Console IV aes-decrypt make-mosref-xmit make-mosref-recv Confirming Console IV 'Waiting for Console to confirm Drone IV string=? wait error aff )the console failed to confirm affiliation Affiliation complete. list format-fallback fmt car cdr drone-endpoint input do-with-input input-chain thaw-filter inner-input-func do-with-output output-chain output freeze-filter inner-output-func