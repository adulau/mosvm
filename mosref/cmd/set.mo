 1Y� � 
	    
	    
	    
	      
	 	  
                   ����
	  � �  � �
	  � � � �� ��N
	  
	  � �  �Q� ��R�� ��� ��� �� ���
	  � �   � �
	  
	  � �  � �
	  
	  � �  �|���
	  
	  � �  � ���� ���
	  � � � � � � 
	   � �  � � ��� ���
	  � � � � � � 
	 !  " ��
	 !  # 
	 $  % 
	 & 	 ' 
	 ( � �     '����
	 	 
	 ) 
	  � �     * 
	 + 
	  � �     ' +���� � � �
	 , � �  - �� .�
	 , � �  / �
 0�
	 ) � �   + module mosref/cmd/set import mosref/shell mosref/node bind-mosref-cmd set !set [<key>[=<value>] [<command>]] string-append ;If no key is supplied, lists properties associated with the ; current node.  If a key and value is supplied, assigns the : supplied value to the key, for the current node.  If only 8 the key is supplied, the value is assumed to be "true". 

 ;If a command is furnished, in addition to a key, it will be .performed after the property has been updated. =The word 'set' may be omitted, if the key=value form is used. cmd-set mosref-shell-node opt-term not 	tc-empty? string-split = string->symbol car null? cdr parse-propval cadr set-node-prop! do-mosref-cmd 	send-line Set. Properties:  string-join 
             map format-property list-node-props format  =  format-propval memq�� true�� false