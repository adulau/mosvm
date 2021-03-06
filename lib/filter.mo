 *b       
	    
	   	  
D
	     (
	  
	        B
	  	       ;
	    A
	    C   
 dý 
	   ^
	  
              ý 
	   ~
	  
             
	     ¿
	       
	    
	       
	    
	    ÿ 
	             
	       
	   ! 
	   " 
	   #  $  
	   % 
	    
	   &    
	   '  $  
	   ( 
	   )  $    $            	filter -- A process that waits for data from an input channel, and 
           sends data to an output channel.  Filters are constructed using
           a constructor function, then wired together using either the 
           input-chain or output-chain functions.input-chain -- The input-chain function, given an input channel and zero or more
               filters, connects the filters together in such a way that when 
               a message is sent to the input channel, it will propagate
               through the filters until it arrives in a final output channel.
               
               This output channel is returned by the input-chain function.±output-chain -- The output-chain function, given an output channel and zero 
                 or more filters, connects the filters together in such a 
                 way that when a message is sent to the input channel, it 
                 will propagate through the filters until it arrives in a 
                 final output channel.
               
                 This input channel is returned by the input-chain function.error-on-fail -- Given a message, raises an error if a failure was signalled,
               using the (fail info ...) or (fail info ... error) convention.
               If the later convention is used, the error's context will match
               the original context of the error. þfail-on-error -- Given a channel and zero or more statements, guards the
               evaluation of the statements with a function that will send
               a (fail info ... error) message to the specified channel if
               an error occurs. module 
lib/filter import lib/iterate error-on-fail pair? eq? car fail find error? re-error error output-chain for-each chain-filter make-channel input-chain 
set-macro! define-filter list define lambda in out spawn fail-on-error guard function fail-for-error err send quote 	error-key scatter 
error-info