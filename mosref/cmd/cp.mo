 G�� �
	    
	    
	    
	      
	 	  
         ����

	  � �  � �
	  � � � �   � �
	  � � � �   � �
	    
	  � �    
	  � �   �r��
	    
	  
	  ��     �z
	  � �� � ����
	  � �  
	     
	  
	  ��     ��
	 ! � �� �   "� � 
	 / 
	 & 	 0 �   ����
	 * � �  
	 1 
	 2    ��
	 2   ��	 3  
	 / 
	 & 	 4 �   �O��
	 5 � �  ��  � �
	 ( � � � �
	  � � � � 6���
	 %  . �� 
	 7 � �  �D
	 % � � � � 
	 8 � �

	 9 � � � �
	 : � �  - �(� �
�B
	 ; � � �8
	 < � �
 � � �B
	 =  >  ? � � �� �
	 %  . � � � � 
	 1 
	 2    �c
	 2   �d	 3   @� �
	 / 
	 & 	 0 � �   !����
	 B � � � �  
	 1 
	 2  !  ��
	 2  ! ��	 3  !
	 / 
	 & 	 4 � �   !�
��
	 5 � �  �� � �
	 ( � � � �
	  � � � � E����
	 %  . �� 
	 7 � �  ��
	 % � � � � 
	 + � � ��
	 % 
	 , � � �   � � ��
	 %  - � � 
	 F � � � �
	 %  . � � � � 
	 1 
	 2  !  �
	 2  ! �	 3  ! module mosref/cmd/cp import mosref/shell mosref/node bind-mosref-cmd cp cp <src-file> <dst-file> string-append >Copies source file to the destination file.  Either the source > or the destination file path may be on a drone or console; to = specify a path on a node other than the current node, prefix * the path with the node name, and a colon. cmd-cp mosref-shell-node req-path  for source file  for destination file 	send-line 
Copy from  format-path  to  	anon-fn-3 send-err Could not access file  format cadr . get-node-file 	anon-fn-6 	traceback Could not alter file  put-node-file �� �
	 # � � 
	 # � ��� � $�&��
	 % 
	 &  ' 
	 ( 
	 ) � �     �J
	 * � � � �
	 + � � �C
	 % 
	 , � � �   �.
	 %  - 
	 %  .  wait 	anon-fn-9 send list fail car 
error-info read-data-file empty-string? string-read! done close make-multimethod <console-node> 	function? 
get-global refuse-method <drone-node> spawn-node-program 
anon-fn-18 re-error make-string expect-data eq? string? string-append! error expect expected string or done �� �
	 # � � 
	 # � �
	 8 � ��� � A�+��
	 % 
	 &  ' 
	 ( 
	 ) � �     �c� ��Z
	 # � �
	 : � �  - �?�� ��Y
	 ; � � �O
	 < � � � � �Y
	 =  '  ? � � �,
	 B � � � � 
	 %  C 
	 %  .  
anon-fn-28 write-data-file D� succ 
anon-fn-41 expect-succ