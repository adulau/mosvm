 fW� �
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
	    
	     �p��
	  
	    
	  � �  
	  	  � �    	   � �  �y� � 
	  	    �"��
	  � � � �
	  � �
��    
	  
� � �;  � �
	   �  
	 ! � �  � �  � �
��   " 
	 # � � 
� � �  � �
��   $ 
	 % 
	 & � � � �  � � 
	 ' � � � � � � � �
	 ( � � � � � � � �	
��   ) 
	 * 
	 + � �  � � ���
	 ,  -  . 
��   / 
	 % � � � �	 
��   0 
	 1 � �	 � �   2����� ��7
	 3 � � 
	 4 � �    3 �8�� �
	 + � �  � �
	 5 � �  3 �R
	 ,  -  6 �R� ��[
	 7 � � �[
	  � � 
	 8 � � �z
	 1 
	 9 � �  
	 : � �  ��
	 ; � � ��
	 1 
	 < � �  
	 4 � �  ��
	 ,  -  = � �  2 >����
	 ? � � 
	 1 
	 1    @  
	 1      
	 1  A  B 
	 1  C � �  � �   
	 1  A  D 
	 1  E  F  G  H 
	 1  I 
	 1   
	 1  J 
	 K 
	 L � �     
	 1  <  B  
	 1  4  B     
	 1  A 
	 1    M  
	 1  N 
	 1  O  M  
	 1  A  P 
	 1  Q  D   
	 1  A  R 
	 1  9  P   
	 1  A  S 
	 1  :  P   
	 1  % 
	 1    M  T   R  
	 1  A  U 
	 1  +  S   
	 1  % 
	 1  V  W   R  
	 1  N 
	 1  X  U  
	 1  , 
	 1  V     Y  M   
	 1 
	 1  Z  U     
	 1  [      > \���
	 + � �
	 X � � ����
	 %  W 
	 ] � � � �
	 % � ��
	 ^ � � ��  \ _�?��
	 ` � �  � �
	 a � � � �
	 b  c 
	  � �   d 
	 e 
	 ` � �   �  _ module mosref/console import mosref/base mosref/endpoint lib/cfb lib/crypto-filter lib/buffer-channel 	lib/build lib/with-io lib/line-filter lib/s-filter lib/package-filter 
lib/bridge lib/iterate step print string-append   CONSOLE:  map format ... 
*line-sep* make-console-ecdh make-ecdh-key *ecdh-keysize* console-affiliation buffer-channel make-iv Reading Drone Public Key import-ecdh make-aes-key ecdh-shared-secret Reading Drone IV aes-decrypt Transmitting Console IV send aes-encrypt make-mosref-recv make-mosref-xmit 'Waiting for Drone to confirm Console IV string=? wait error aff 'the drone failed to confirm affiliation Confirming Drone IV Affiliation complete. list await-drone-affiliation timeout output eq? the drone did not connect cancel-timeout lane? 	lane-xmit 	lane-recv stream? input expected stream or lane make-drone-exe 	build-exe mosref/drone define conn tcp-connect endpoint apply spawn-endpoint drone-endpoint drone-broken drone-affiliation base64-decode base64-encode export-public-ecdh key unless 	imported? lane 	make-lane xmit recv .mo data quote close string? &could not retrieve module from console thaw export console-endpoint find-module-file read-data-file console-broken find-drone-by-bridge node-id alert Drone   has lost connection. set-node-online!