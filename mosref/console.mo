 ^�� �
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
	 1  E  F  G 
	 1  H 
	 1   
	 1  I 
	 J 
	 K � �     
	 1  <  B  
	 1  4  B     
	 1  A 
	 1    L  
	 1  M 
	 1  N  L  
	 1  A  O 
	 1  P  D   
	 1  A  Q 
	 1  9  O   
	 1  A  R 
	 1  :  O   
	 1  % 
	 1    L  S   Q  
	 1  A  T 
	 1  +  R   
	 1  % 
	 1  U  V   Q  
	 1  M 
	 1  W  T  
	 1  , 
	 1  U     X  L   
	 1 
	 1  Y  T     
	 1  Z      > [���
	 + � �
	 W � � ����
	 %  V 
	 \ � � � �
	 % � ��
	 ] � � ��  [ module mosref/console import mosref/base mosref/endpoint lib/cfb lib/crypto-filter lib/buffer-channel 	lib/build lib/with-io lib/line-filter lib/s-filter lib/package-filter 
lib/bridge lib/iterate step print string-append   CONSOLE:  map format ... 
*line-sep* make-console-ecdh make-ecdh-key *ecdh-keysize* console-affiliation buffer-channel make-iv Reading Drone Public Key import-ecdh make-aes-key ecdh-shared-secret Reading Drone IV aes-decrypt Transmitting Console IV send aes-encrypt make-mosref-recv make-mosref-xmit 'Waiting for Drone to confirm Console IV string=? wait error aff 'the drone failed to confirm affiliation Confirming Drone IV Affiliation complete. list await-drone-affiliation timeout output eq? the drone did not connect cancel-timeout lane? 	lane-xmit 	lane-recv stream? input expected stream or lane make-drone-exe 	build-exe mosref/drone define conn tcp-connect endpoint apply spawn-endpoint drone-endpoint drone-affiliation base64-decode base64-encode export-public-ecdh key unless 	imported? lane 	make-lane xmit recv .mo data quote close string? &could not retrieve module from console thaw export console-endpoint find-module-file read-data-file