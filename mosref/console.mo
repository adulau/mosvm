 �	� �

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
	 0 � �	 � �   1����
	 2 � � 
	 0 
	 0    3  
	 0      
	 0    4  
	 0    5  
	 0  6  7 
	 0  8 � �  � �   
	 0  9  :  ; 
	 0  < 
	 0   
	 0  = 
	 > 
	 ? � �     
	 0  @  7  
	 0  A  7      1 B��� � 
	 $  C � � D����
	 E � � � �
	 F 
	 G � �  
	 H  � �
	 I 
	 J � �  
	 K  � �
	 $ � �  � � 
	 0 � � � � � �
	 L 
	 M 
	 N 
	 0 
	 0  O  P  
	 0  6  Q 
	 0  F 
	 0  A  
	 0  R 
	 0  S  T     
	 0  6  U 
	 0  F 
	 0  A  
	 0  R 
	 0  S  V   
	 0  W    
	 0  6  X 
	 0  F 
	 0  A  
	 0  R 
	 0  S  Y   
	 0  W    
	 0  6 
	 0  Z  T  
	 0  6  [ 
	 0  \   
	 0  ]  T  [  
	 0  $  [  Q   
	 0  ^  X 
	 0  _ 
	 0  ` 
	 0  a  
	 0  b 
	 0  c  Z 
	 0  $ 
	 0 
	 0  *    U          � � d�	��
�� �� � �  � � e����
	 : �� � �  � � � �
�� � � � �
	 f � � � �
	 g � � � � h�B��
	 $ 
	   i 
	 g � �   	   � � j�R��
	 ] � �  
	 A  �� � k�]��
	 $ � �  �� � l�o��
	 $ 
	   m � �  	   � �	 n����
	 $ 
	   o � �  	   � �

	 _  p��� �
	 * �� � � 
	 q � �   C ����
	 r 
	 s � �   ����
	 q 
	 f � �    T ��
�� 
	 t � �   ��
	 q 
	 f � �    V ��
��	 
	 t � �   ��
	 q 
	 f � �    Y ��
��
 
	 t � �   ����  u���
	 $  C ��  � � v�%�����
	 L 
	 M 
	 N � �    � �� ���
	 $ � � �� � �
	 w 
	 x  y � �  � �� �� �
	 z 
	 I 
	 @  
	 {  
	 | 	 }  ~ 	  � �    ���� �
	 $  � 
	 * � � 
	 q � �   C �r
	 $  C ��

	 � �� � �  ��  � �  �W  e module mosref/console import mosref/base mosref/endpoint lib/cfb lib/crypto-filter lib/buffer-channel 	lib/build lib/with-io lib/line-filter lib/s-filter lib/package-filter lib/iterate step print string-append   CONSOLE:  map format ... 
*line-sep* make-console-ecdh make-ecdh-key *ecdh-keysize* console-affiliation buffer-channel make-iv Reading Drone Public Key import-ecdh make-aes-key ecdh-shared-secret Reading Drone IV aes-decrypt Transmitting Console IV send aes-encrypt make-mosref-recv make-mosref-xmit 'Waiting for Drone to confirm Console IV string=? wait error aff 'the drone failed to confirm affiliation Confirming Drone IV Affiliation complete. list make-drone-exe 	build-exe mosref/drone lib/cons-filter lib/format-filter define conn tcp-connect apply spawn-endpoint drone-endpoint drone-affiliation base64-decode base64-encode export-public-ecdh input output console-endpoint close spawn-drone-program 	make-lane output-chain 	lane-xmit freeze-filter input-chain 	lane-recv thaw-filter assemble optimize compile export nothing 
err-output cons-filter quote err 
res-output res format-filter 
out-output out fwd-traceback s make-string 	traceback with-output spawn function drone-repl-process forever guard spawn-drone-repl console-repl car cadr display-syntax-error SYNTAX:  display-compile-error display-remote-error display-result ::  display-output --  
anon-fn-16 eq? not pair? cdr 	quit-repl 	eval-expr dict cons quit do-with-input line-filter s-filter :promptN     :errfn inner-input-func >>  dict-ref