 9�� � 
	    
	    
	    
	      
	 	  
       �4��
	  	  
	  � �   
	  
	  	  �   ����
	  	    �V
	      �V
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
	 )   ��	 *   + 3 �M��
	 4 � �  	 3 � �
	  � � � �
	 5 � � � � 6���
	 %  $ �� 
	 7 � �  �B
	 % � � � � �� �
� �
�A
	 " � � � �
	 # � �  $ �2�� �
�@
	 8 � � �@
	 % � � �@�� �
	 %  $ � � � �  module mosref/cmd/sh import mosref/shell mosref/node bind-mosref-cmd sh sh <cmd> string-append :Evaluates the supplied host command on the current node -- 1 this will only work on non-Windows nodes, due to ( limitations in the Win32 command shell. cmd-sh spawn-node-shell current-node tc->list make-multimethod list <console-node> spawn-node-cmd string-begins-with? 
*platform* win 	send-line =ERROR: This version of MOSREF cannot spawn shell commands on  Microsoft Windows. set-car! 
locate-cmd car spawn-command cdr spawn anon-fn-142 wait eq? close send input pause 	function? 
get-global refuse-method$� �
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
	  � �   � ��� �
	 2 �� 
	 & � �   $ � ���
	 " � � � �
	 # � �  $ ���� ���
	 % � � �l
	 %  $  lib/env error shell 7MOSREF cannot spawn shell commands on Microsoft Windows anon-fn-159 cannot find command  timeout *node-shell-prog* spawn-node-program cadr anon-fn-167 re-error string?