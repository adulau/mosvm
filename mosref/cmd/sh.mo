 8�� � 
	    
	    
	    
	      
	 	  
       �9��
	  
	  � �   
	  � �   
	  
	  	  �   ����
	  	    �[
	      �[
	  � � 
	  
	  � �   
	  
	  � �  
	  � �  � ��� �
	    !��� �����
	 " �� � � 
	 # � �   $ �����������
	 %  $ 
	 &  ���� � ���
	 " 
	 &  � �
	 % � � � � 
	 # � �  $ ���� �����
	 '  
	 ( 
	 )    ��
	 )   ��	 *   + 2 �R��
	 3 � �  	 2 � �
	  � � � �
	 4 � � � � 5���
	 %  $ �� 
	 6 � �  �G
	 % � � � � �� �
� �
�F
	 " � � � �
	 # � �  $ �7�� �
�E
	 7 � � �E
	 % � � �E�"� �
	 %  $ � � � �  module mosref/cmd/sh import mosref/shell mosref/node bind-mosref-cmd sh sh <cmd> string-append :Evaluates the supplied host command on the current node -- 1 this will only work on non-Windows nodes, due to ( limitations in the Win32 command shell. cmd-sh spawn-node-shell mosref-shell-node tc->list make-multimethod list <console-node> spawn-node-cmd string-begins-with? 
*platform* win 	send-line =ERROR: This version of MOSREF cannot spawn shell commands on  Microsoft Windows. set-car! 
locate-cmd car spawn-command cdr spawn monitor-sh-response wait eq? close send input pause 	function? 
get-global refuse-method	� �
	   , 
	  	    �
	 -  .  / �
	 " � �  0�4��
	 -  . 
	 	  1 
	  ��    �H
	  � �  
	  
	  � �    
	  
	  � �   
	  � �   � ��� �� ��y
	 " � � � �
	 # � �  $ �r�� ��x
	 % � � �]
	 %  $  lib/env error shell 7MOSREF cannot spawn shell commands on Microsoft Windows report-cmd-not-found cannot find command  *node-shell-prog* spawn-node-program cadr 
anon-fn-28 re-error string?