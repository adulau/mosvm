  �� � 
	    
	    
	    
	    
	     	 
	 
       �d��
	  
	  
	  � � �: �@
	  � �    �b� �
	  ��  � � 
	  ��  � �
	   �`� � 
	  ��  ��     module mosref/cmd/fork import mosref/shell mosref/node lib/terminal bind-mosref-cmd fork fork [<window-name>] string-append ;Creates a new MOSREF console shell session that may be used $ in parallel with the current one.

 cmd-fork 
do-with-io spawn-terminal 	tc-empty? MOSREF tc-next! inner-io-func mosref-shell-console mosref-shell-node spawn 
anon-fn-40 run-mosref-shell