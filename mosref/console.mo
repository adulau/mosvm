 ]f� �
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
	 0 � �	 � �   1�y��
	 2 � � 
	 0 
	 0    3  
	 0      
	 0  4  5 
	 0  6 � �  � �   
	 0  $ 
	 0  7 
	 8 � �    5  
	 0  4  9 
	 0  :  ;  <  = 
	 0  > 
	 0   
	 0  7 
	 8 
	 ? � �     
	 0  @  5  
	 0  A  5     
	 0  4 
	 0    B  
	 0  C 
	 0  D  B  
	 0  4  E 
	 0  F  9   
	 0  4  G 
	 0  H  E   
	 0  4  I 
	 0  J  E   
	 0  $ 
	 0    B  K   G  
	 0  4  L 
	 0  *  I   
	 0  $ 
	 0  M  N   G  
	 0  C 
	 0  O  L  
	 0  + 
	 0  M     P  B   
	 0 
	 0  Q  L     
	 0  R      1 S����
	 * � �
	 O � � ����
	 $  N 
	 T � � � �
	 $ � ���
	 U � � ���  S V����
	 W � �  � �
	 X � � � �
	 Y  Z 
	  � �   [ 
	 \ 
	 W � �   �  V module mosref/console import mosref/transport lib/cfb lib/crypto-filter lib/buffer-channel 	lib/build lib/with-io lib/line-filter lib/s-filter lib/package-filter 
lib/bridge lib/iterate step print string-append   CONSOLE:  map format ... 
*line-sep* make-console-ecdh make-ecdh-key *ecdh-keysize* console-affiliation buffer-channel make-iv Reading Drone Public Key import-ecdh make-aes-key ecdh-shared-secret Reading Drone IV aes-decrypt Transmitting Console IV send aes-encrypt make-mosref-recv make-mosref-xmit 'Waiting for Drone to confirm Console IV string=? wait error aff 'the drone failed to confirm affiliation Confirming Drone IV Affiliation complete. list make-drone-exe 	build-exe mosref/drone define conn tcp-connect base64-decode base64-encode endpoint apply spawn-endpoint drone-endpoint drone-broken drone-affiliation export-public-ecdh input output key unless 	imported? lane 	make-lane xmit 	lane-xmit recv 	lane-recv .mo data quote close string? &could not retrieve module from console thaw export console-endpoint find-module-file read-data-file console-broken find-drone-by-bridge node-id alert Drone   has lost connection. set-node-online!