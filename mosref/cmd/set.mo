 I�� � 
	    
	    
	    
	      
	 	  
                 ����
	  � �  � �
	  � � � �� ��L
	  
	  � �  �O� ��P�� ��� ��� �� ���
	  � �   � �
	  
	  � �  � �
	  
	  � �  �z���
	  
	  � �  � ���� ���
	  � � � � � �
	   � � � � � � 
	 ! � �  � � 
	   � � � � � � ��� ���
	   � � � � � � 
	 "  # ��
	 "  $ 
	 %  & 
	 ' 	 ( 
	 ) � �     (� ��
	 	 
	 * 
	  � �     + 
	 , 
	  � �     ( ,�"��� � � �
	 - � �  . � /�!
	 - � �  0 � 1�!
	 * � �   , �=��
	 2 � �   3 �0��<
	 2 � �   > �;��<� �   module mosref/cmd/set import mosref/shell mosref/node bind-mosref-cmd set !set [<key>[=<value>] [<command>]] string-append ;If no key is supplied, lists properties associated with the ; current node.  If a key and value is supplied, assigns the : supplied value to the key, for the current node.  If only 8 the key is supplied, the value is assumed to be "true". 

 =If a command is furnished, in addition to a key, the property ; will be reset to its original value after the execution of  the specified command. cmd-set mosref-shell-node opt-term not 	tc-empty? string-split = string->symbol car null? cdr parse-propval cadr find-node-prop set-node-prop! do-mosref-cmd 	send-line Set. Properties:  string-join 
             map format-property list-node-props format  =  format-propval memq�� true�� false member 4 5 Yes 6 7 yes 8 9 YES : ; True < = TRUE /� ? @ No A B no C D NO E F False G H FALSE 1�