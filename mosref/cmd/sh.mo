 Dm� � 
	    
	    
	    
	      
	 	  
       �9��
	  
	  � �   
	  � �     *
	 + 
	  	 , �   ����
	 - � �  	 * � �
	  � � � �
	 . � � � �
	 / � �  � �
	  � � � � 
	  � � � �
	    � � 
	 0 � �   ��
	    � � 
	 1  2 ��
	 3 � � ����
	    � � 
	 1  4 
	 " � �  
	 0 
	  � �   ' �d
	 . � � � �
	 5 � � � � � �� ��]
	 6 � � � �
	 7 � � � �
	 8 � �
	 9 � �
	 :  ;� � �
	  �� � � 
	 0 � �   < ��
	 0 � �    �
	   < �� �
	  � �  �� �� 
	  � � � �
	 0 � �  < �4�4
	  � � � � 
	 0 � �   �[
	   < � � 
	  � � 
	 8 � �  �[�"�]
	 1  = �d
	 0 
	  � �    ��
	    � � 
	 1 
	 . � �  �� 
	 > 
	 ?    ��
	 ?   ��	 @  
	 + 
	  	 A �   �z��
	  	    ��
	 1   ��
	  � � � �
	  � � � �
	   � � � �� �����
	 1  B 
	 " 
	  � �    # 
	 $ � � � � � �
	 9 � � � �
	 8 � � � �
	 8 � �
	 9 � �
	 :  C�=� �
	  �� � � 
	 0 � �   < �!�!
	 0 � �    �3
	   < �� �3
	  � �  �� � 
	  � � � �
	  � � � � 
	 0 � �  < �Y�Y
	 0 � �   �x
	   < � � 
	  � � 
	 8 � �  �x�? 
	 > 
	 ?    ��
	 ?   ��	 @   module mosref/cmd/sh import mosref/shell mosref/node bind-mosref-cmd sh sh <cmd> string-append :Evaluates the supplied host command on the current node -- 1 this will only work on non-Windows nodes, due to ( limitations in the Win32 command shell. cmd-sh spawn-node-shell mosref-shell-node tc->list9� �

	    
	    
	  	    �.
	  
	       
	    
	  �.
	  � � 
	  � �  � �
	  � �  � �
	   � � � �� ��K�q
	  
	    
	 	  ! 
	 " 
	  � �     #   
	    
	 $ � � � � � �
	 % 	 & � �
	  
	   ' 
	 ( � �   
	 ) � � � � 
	     lib/env mosref/patch string-begins-with? 
*platform* win send list error 7MOSREF cannot spawn shell commands on Microsoft Windows close halt wait car cdr 
locate-cmd Drone cannot find  format . spawn-command make-reserved-lane *drone-bridge* connect lane-tag patch2 *node-shell-prog* make-multimethod <drone-node> spawn-node-program cadr drone-node-bridge eq? send-err #Lost connection with shell process. pair? Unusual message received:  find-reserved-lane 	lane-xmit 	lane-recv output input spawn 
anon-fn-15 done Could not resolve initial lane. 	function? 
get-global refuse-method <console-node> Cannot find command  
anon-fn-36