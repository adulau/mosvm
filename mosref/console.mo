 Z{� �
	    
	    
	    
	    
	    
	    
	   	 
	   
 
	    
	    
	    
	     �j��
	  
	    
	  � �  
	  	  � �    	   � �  �s� � 
	  	    ���
	  � � � �
	  � �
��    
	  
� � �;  � �
	  �  
	   � �  � �  � �
��   ! 
	 " � � 
� � �  � �
��   # 
	 $ 
	 % � � � �  � � 
	 & � � � � � � � �
	 ' � � � � � � � �	
��   ( 
	 ) 
	 * � �  � � ��� 
	 +  ,  - 
��   . 
	 $ � � � �	 
��   / 
	 0 � �	 � �   1�_��� ��1
	 2 � � 
	 3 � �    2 �2�� �
	 * � �  � �
	 4 � �  2 �L
	 +  ,  5 �L� ��U
	 6 � � �U
	  � � � � � �  1 7����
	 8 � � 
	 0 
	 0    9  
	 0      
	 0  :  ; 
	 0  < � �  � �   
	 0  :  = 
	 0  >  ?  @ 
	 0  A 
	 0   
	 0  B 
	 C 
	 D � �     
	 0  E  ;  
	 0  3  ;     
	 0  : 
	 0    F  
	 0  G 
	 0  H  F  
	 0  :  I 
	 0  J  =   
	 0  :  K 
	 0  L  I   
	 0  :  M 
	 0  N  I   
	 0  $ 
	 0    F  O   K  
	 0  :  P 
	 0  *  M   
	 0  $ 
	 0  Q  R   K  
	 0  G 
	 0  S  P  
	 0  + 
	 0  Q     T  F   
	 0 
	 0  U  P     
	 0  V      7 W��� �
	 * � � 
	 S � �  ����
	 $  R 
	 X � �  � � 
	 $ � � ��
	 Y � �  ���  W module mosref/console import mosref/base mosref/endpoint lib/cfb lib/crypto-filter lib/buffer-channel 	lib/build lib/with-io lib/line-filter lib/s-filter lib/package-filter lib/iterate step print string-append   CONSOLE:  map format ... 
*line-sep* make-console-ecdh make-ecdh-key *ecdh-keysize* console-affiliation buffer-channel make-iv Reading Drone Public Key import-ecdh make-aes-key ecdh-shared-secret Reading Drone IV aes-decrypt Transmitting Console IV send aes-encrypt make-mosref-recv make-mosref-xmit 'Waiting for Drone to confirm Console IV string=? wait error aff 'the drone failed to confirm affiliation Confirming Drone IV Affiliation complete. list await-drone-affiliation timeout output eq? the drone did not connect cancel-timeout make-drone-exe 	build-exe mosref/drone define conn tcp-connect endpoint apply spawn-endpoint drone-endpoint drone-affiliation base64-decode base64-encode export-public-ecdh input key unless 	imported? lane 	make-lane xmit 	lane-xmit recv 	lane-recv .mo data quote close string? &could not retrieve module from console thaw export console-endpoint find-module-file read-data-file