 �V� � 
	    
	    
	    
	     �(� �
	  
	 	 � � 	 
   
	      ���� �7��� � ��� � �S��
	 	 
	  
	  � �      
	  � �   � � �h� � 
	  
	 	 
	  ��     � � �y� �
	    � � 
	    � � ����
	  � �  ��
��   � ���
	  � �  � � ����
�� � �     � �  ! � �
	 " � � � �� �����
��  # 
	 $ � �  � �  ! � � %���
�� � �   & � �  ! � �
	 ' � �   ����
	 ( �� � � 
	 ) � �   � �
	  � � � �
	  � � � �
	 " � � � �� ���
��  * 
	 $ � �  � �  ! 
	 ( � � � � � � +�N��
	  � �  �-
	 , � �0 �-
	  � �  � � -�E��
��  . 
	 $ ��   ! �M
	 / � � � �	�� �

	 0 
	 (  1  2������� �
�� � �   3 � �
�� � �  4�t� � 
�� �� � �
	  � �  �}�� 5����
�� 
	 6 � �  ��
�� � �  
� �  
	 	  7  8  9  :  ;  <   
	 (  =  >����
	 ?  @����
	  
	 $ 
	  � �     A 
	 $ 
	 B � �     
	 C   
	 	  D  E  F   
	 (  G  H����
�� � �   I � �
�� � �   J � �
�� � �   K � �
��	 � �   L � �
	 M � � N�!��
��  O �4
	 P 
	 B ��  � � � � � � � � Q�K��
��  R 
	 $ 
	  ��    ! �U
	 S � �� � 
	 T  U 
	   V  W�r��
��  X 
	 $ ��   ! �z
	 Y � � � �
	   Z 
	 $ � �   [ 
	 \  ]��� � ^����
	 _ �� 
	   ` ��  a 
	  
	 b � �     ! ��
	 c �� ��  d � � 
	   e ��  f 
	 g �� � 
	 h 	 i � �    
	 	  j  k  l  m  n   
	 (  o  p�a��
�� � �   q � �
�� � �   r � �
	   s 
�� � �   t 
�� � �   u�1��
��  v 
	 $ 
	  ��    ! �9
	 w � �� � x�V��
	 y � �  
��  z 
	 $ 
	  ��    ! �`
	 S � �� �  
	 	  {  |   
	 (  }  ~����
	  � �  ��
	    
	 �  � 
	 � ��  ��
	  � �  � �
	 � �� � � � �� �����
��  � � �  � 
	  
	 	  � 
	  � �    
	 	  �  �  �  �  �   
	 (  �  �����
	 �  � 
	 � � �  � �
	 � �� 
	 � � �   
	 	  �  �  �   
	 (  �  ����
	 � �� 
	 � � �    
	 	  �  �  �  �   
	 (  �  ��B��
	 � 
�� � �   �  � �
	 � �� � �  
	 	  �  �  �  �   
	 (  �  ��\�����
 
	 	  �   
	 (  �  �����	
�� � �  � � � �
�� � �  � � � �
	 � � �   � � �
	 � � �   � � �
	 � �� � � � � � � � �  
	 	  �  �  �  �  �   
	 (  �  �����
	 � 
	 � 
	  � �  �� ���
	  � �     ���� ���� � 
	 \  ���� � 
	  ��  ��     
	 	  �  �  �   � � ��I��
	 � � �  �
�� 
	 � 
	 � 	  � �  �� �
	  � �  ��
	  � �  � �
	 � �� � � � �� ��/�>
��  � 
	 $ � �   ! 

	  � �  � �  � �
� � � �
��
	 � � �
	 � � �  � �`�`
	 � � � �� ��
	 � 
	 � � �     �x�~
	 6 � �  ��
� � � � � �
����
� � ���N
	   �   module mosref/shell import mosref/console mosref/node lib/terminal 	send-line send string-append 
*line-sep* 
make-regex [^ 
	]+ 
*cmd-term* mosref-shell set-current-node format-path node-id car : cadr send-prompt >  send-err ERROR:  error syn req-term 	tc-empty? 	Expected  tc-next! req-node node identifier . find-mosref-node Could not find  format req-path 	file path string-find list string-split Could not find node  opt-port random-integer anon-fn-493 Could not parse port number  string->integer dict on on-cmd   revert-node revert-node-before-err re-error USAGE: on <node-id>
 ;Instructs the console to perform subsequent commands on the  specified node.
 )USAGE: on <node-id> <command> <arg> ...

 5Performs the supplied command, with arguments, on the  specified host

 nodes 	nodes-cmd for-each display-node  --  	node-addr list-mosref-nodes USAGE: nodes
 9Lists the nodes currently known to the console, and their  addresses.

 drone 	drone-cmd  for drone executable  drone identifier  drone platform  listener port make-console-ecdh anon-fn-505 Could not compile drone. make-drone-exe anon-fn-508 Could not write file  put-node-file print Node file transmitted.
 Drone executable created. anon-fn-511 Could not listen to  
tcp-listen Listening for drone on  ... spawn anon-fn-513 anon-fn-516 close-listener ERROR: Affilation of  	 failed,  
error-info await-drone-affiliation  w@ Drone   affiliated. make-drone-node spawn-endpoint console-endpoint /USAGE: drone <file> <id> <platform> [<portno>]
 9Creates a new drone executable for the specified platform 5 and places it at file, then spawns a listener on the : current node.  When the drone connects to the listener, a 7 the drone will be bound to the specified identifier.

 cp cp-cmd  for source file  for destination file 
Copy from   to  anon-fn-520 Could not access file  get-node-file anon-fn-523 	traceback Could not alter file  USAGE: cp src-file dst-file
 "Copies source file to dest file.

 help help-cmd 
Commands:  string-join   	dict-keys dict-ref Command   not found. 
 USAGE: help
 6Requests a list of all commands known by the console

 USAGE: help <command>
 5Requests information about the syntax and usage of a  
 command

 do eval-cmd tc->list eval-node-expr string->exprs USAGE: do <lisp-expr>
 ;Evaluates the supplied lisp expression on the current node,  and outputs the result.

 sh sh-cmd spawn-node-shell USAGE: sh <cmd>
 :Evaluates the supplied host command on the current node -- 1 this will only work on non-Windows nodes, due to * limitations in the Win32 command shell.

 load read-lisp-file for evaluation USAGE: load <path>
 ;Loads the specified file on the current node, and evaluates : it; note that path, here, is always local to the console. 

 exit exit-cmd Terminates the console.

 scan scan-cmd opt-integer timeout conns spawn-node-scan *USAGE: scan hosts ports [timeout [conns]]
 9Performs a TCP port scan of the specified host, reporting 9 all ports  that respond with a connection within timeout 3 milliseconds.  The scanner will restrict itself to 1 conns ports at a time, with a default of 1000.

 fork fork-cmd 
do-with-io spawn-terminal MOSREF inner-io-func anon-fn-539 USAGE: fork [<window-name>]
 ;Creates a new MOSREF console shell session that may be used $ in parallel with the current one.

 	parse-cmd string? make-tc match-regex* I do not understand  wait eq? close 	catch-syn 	error-key