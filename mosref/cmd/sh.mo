 :�� � 
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
	 )   ��	 *   + 4 �R��
	 5 � �  	 4 � �
	  � � � �
	 6 � � � � 7���
	 %  $ �� 
	 8 � �  �G
	 % � � � � �� �
� �
�F
	 " � � � �
	 # � �  $ �7�� �
�E
	 9 � � �E
	 % � � �E�"� �
	 %  $ � � � �  module mosref/cmd/sh import mosref/shell mosref/node bind-mosref-cmd sh sh <cmd> string-append :Evaluates the supplied host command on the current node -- 1 this will only work on non-Windows nodes, due to ( limitations in the Win32 command shell. cmd-sh spawn-node-shell mosref-shell-node tc->list make-multimethod list <console-node> spawn-node-cmd string-begins-with? 
*platform* win 	send-line =ERROR: This version of MOSREF cannot spawn shell commands on  Microsoft Windows. set-car! 
locate-cmd car spawn-command cdr spawn anon-fn-172 wait eq? close send input pause 	function? 
get-global refuse-method-� �
	   , 
	 "  -
	  	    �
	 .  /  0 �
	 " � �  1�9��
	 .  / 
	 	  2 
	  ��    �M
	  � �  
	  
	  � �    
	  
	  � �   
	  � �   � ��� �
	 3 �� 
	 & � �   $ � ���
	 " � � � �
	 # � �  $ ���� ���
	 % � � �q
	 %  $  lib/env bridge error shell 7MOSREF cannot spawn shell commands on Microsoft Windows anon-fn-189 cannot find command  timeout *node-shell-prog* spawn-node-program cadr anon-fn-197 re-error string?