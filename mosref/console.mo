 eM� �
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
	 0 � �	 � �   1����� ��1
	 2 � � 
	 3 � �    2 �2�� �
	 * � �  � �
	 4 � �  2 �L
	 +  ,  5 �L� ��U
	 6 � � �U
	  � � 
	 7 � � �t
	 0 
	 8 � �  
	 9 � �  ��
	 : � � ��
	 0 
	 ; � �  
	 3 � �  ��
	 +  ,  < � �  1 =����
	 > � � 
	 0 
	 0    ?  
	 0      
	 0  @  A 
	 0  B � �  � �   
	 0  @  C 
	 0  D  E  F  G 
	 0  H 
	 0   
	 0  I 
	 J 
	 K � �     
	 0  ;  A  
	 0  3  A     
	 0  @ 
	 0    L  
	 0  M 
	 0  N  L  
	 0  @  O 
	 0  P  C   
	 0  @  Q 
	 0  8  O   
	 0  @  R 
	 0  9  O   
	 0  $ 
	 0    L  S   Q  
	 0  @  T 
	 0  *  R   
	 0  $ 
	 0  U  V   Q  
	 0  M 
	 0  W  T  
	 0  + 
	 0  U     X  L   
	 0 
	 0  Y  T     
	 0  Z      = [���
	 * � �
	 W � � ����
	 $  V 
	 \ � � � �
	 $ � ��	
	 ] � � �
�  [ ^�9��
	 _ � �  � �
	 ` � � � �
	 a  b 
	  � �   c 
	 d 
	 _ � �   �  ^ module mosref/console import mosref/transport lib/cfb lib/crypto-filter lib/buffer-channel 	lib/build lib/with-io lib/line-filter lib/s-filter lib/package-filter 
lib/bridge lib/iterate step print string-append   CONSOLE:  map format ... 
*line-sep* make-console-ecdh make-ecdh-key *ecdh-keysize* console-affiliation buffer-channel make-iv Reading Drone Public Key import-ecdh make-aes-key ecdh-shared-secret Reading Drone IV aes-decrypt Transmitting Console IV send aes-encrypt make-mosref-recv make-mosref-xmit 'Waiting for Drone to confirm Console IV string=? wait error aff 'the drone failed to confirm affiliation Confirming Drone IV Affiliation complete. list await-drone-affiliation timeout output eq? the drone did not connect cancel-timeout lane? 	lane-xmit 	lane-recv stream? input expected stream or lane make-drone-exe 	build-exe mosref/drone define conn tcp-connect endpoint apply spawn-endpoint drone-endpoint drone-broken drone-affiliation base64-decode base64-encode export-public-ecdh key unless 	imported? lane 	make-lane xmit recv .mo data quote close string? &could not retrieve module from console thaw export console-endpoint find-module-file read-data-file console-broken find-drone-by-bridge node-id alert Drone   has lost connection. set-node-online!