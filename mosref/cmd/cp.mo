 Fj� �
	    
	    
	    
	      
	 	  
         ����
	  � �   � �
	  � �   � �
	    
	  � �    
	  � �   �g��
	    
	  
	  ��     �o
	  � �� � ����
	  � �  
	    
	  
	  ��     ��
	   � �� �   !� � 
	 . 
	 % 	 / �   ����
	 ) � �  
	 0 
	 1    ��
	 1   ��	 2  
	 . 
	 % 	 3 �   �D��
	 4 � �  ��  � �
	 ' � � � �
	  � � � � 5����
	 $  - �� 
	 6 � �  �9
	 $ � � � � 
	 7 � �

	 8 � � � �
	 9 � �  , �� �
�7
	 : � � �-
	 ; � �
 � � �7
	 <  =  > � � �
� �
	 $  - � � � � 
	 0 
	 1    �X
	 1   �Y	 2   ?� �
	 . 
	 % 	 / � �    �v��
	 A � � � �  
	 0 
	 1     ��
	 1    ��	 2   
	 . 
	 % 	 3 � �    ����
	 4 � �  �� � �
	 ' � � � �
	  � � � � D����
	 $  - �� 
	 6 � �  ��
	 $ � � � � 
	 * � � ��
	 $ 
	 + � � �   � � ��
	 $  , � � 
	 E � � � �
	 $  - � � � � 
	 0 
	 1     �
	 1    �	 2    module mosref/cmd/cp import mosref/shell mosref/node bind-mosref-cmd cp cp <src-file> <dst-file> string-append >Copies source file to the destination file.  Either the source > or the destination file path may be on a drone or console; to = specify a path on a node other than the current node, prefix * the path with the node name, and a colon. cmd-cp req-path  for source file  for destination file 	send-line 
Copy from  format-path  to  	anon-fn-3 send-err Could not access file  format cadr . get-node-file 	anon-fn-6 	traceback Could not alter file  put-node-file �� �
	 " � � �� � #�!��
	 $ 
	 %  & 
	 ' 
	 ( � �     �E
	 ) � �  � �
	 * � � �>
	 $ 
	 + � � �   �)
	 $  , 
	 $  -  wait 	anon-fn-9 send list fail car 
error-info read-data-file empty-string? string-read! done close make-multimethod <console-node> 	function? 
get-global refuse-method <drone-node> spawn-node-program 
anon-fn-18 re-error make-string expect-data eq? string? string-append! error expect expected string or done �� �
	 " � � 
	 7 � ��� � @�&��
	 $ 
	 %  & 
	 ' 
	 ( � �     �^� ��U
	 " � �
	 9 � �  , �:�� ��T
	 : � � �J
	 ; � � � � �T
	 <  &  > � � �'
	 A � �  � � 
	 $  B 
	 $  -  
anon-fn-28 write-data-file C� succ 
anon-fn-41 expect-succ