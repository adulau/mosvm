Object.prototype.clone = function(){
    var newObject = new this.constructor();
    newObject.__proto__ = this;
    return newObject;
}

Root = new Object();
Connection = Root.clone();

netscape.security.PrivilegeManager.enablePrivilege("UniversalXPConnect"); 

//Components.classes[ "@mozilla.org/network/socket-transport-service;1" ].getService( Components.interfaces.nsISocketTransportService );

Connection.transportService = Components.classes[ 
    "@mozilla.org/network/socket-transport-service;1" 
].getService( Components.interfaces.nsISocketTransportService );

Connection.connectTo = function( hostName, portNumber ){
    netscape.security.PrivilegeManager.enablePrivilege("UniversalXPConnect"); 

    this.transport = this.transportService.createTransport( 
        null, 0, hostName, portNumber, null 
    );
    
    this.outStream = this.transport.openOutputStream( 0, 0, 0 );
    
    var _inStream = this.transport.openInputStream( 0, 0, 0 );
    var inStream = Components.classes[ 
        "@mozilla.org/scriptableinputstream;1" 
    ].createInstance( Components.interfaces.nsIScriptableInputStream );
    inStream.init( _inStream );
    
    this.inStream = inStream;

    var pump = Components.classes[
        "@mozilla.org/network/input-stream-pump;1"
    ].createInstance( Components.interfaces.nsIInputStreamPump );
    
    pump.init( _inStream, -1, -1, 0, 0, false );

    pump.asyncRead( this, null );
}
Connection.onStartRequest = function( request, context ){
    this.connected();
}
Connection.onStopRequest = function( request, context, status ){
    netscape.security.PrivilegeManager.enablePrivilege("UniversalXPConnect"); 
    this.disconnected();
    this.inStream.close();
}
Connection.onDataAvailable = function( request, context, inputStream, 
                                       offset, count ){
    netscape.security.PrivilegeManager.enablePrivilege("UniversalXPConnect"); 
    this.received( this.inStream.read( count ) );
}
Connection.disconnected = function( ){
    alert( "Disconnected" );
}
Connection.connected = function( ){
    alert( "Connected" );
}
Connection.received = function( data ){
    alert( "Received: '" + data + "'" );
}
Connection.send = function( data ){
    netscape.security.PrivilegeManager.enablePrivilege("UniversalXPConnect"); 
    this.outStream.write( data, data.length );
}

Display = Root.clone();
Display.writeOutputLine = function( line ){
    var rli = document.createElement( "richlistitem" );
    var des= document.createElementNS( "http://www.w3.org/1999/xhtml", "html:div" );
    //var des = document.createElement( "description" );
    des.appendChild( document.createTextNode( line ) );
    
    rli.appendChild( des );
    this.output.appendChild( rli );
    this.output.ensureElementIsVisible( rli );
}
Display.tail = "";
Display.writeOutput = function( data ){
    //outputScroll.appendChild( br );
    //var element = document.createElementNS( "http://www.w3.org/1999/xhtml", "html:div" );
    //element.appendChild( document.createTextNode( data ) );
    //var element = document.createElement( "button" );
    //element.setAttribute( "label", data );
    data = this.tail + data;
    var lines = data.split( /[\r\n][\r\n]*/ );
    this.tail = lines.pop();
    var i = 0
    while( i < lines.length ){
        this.writeOutputLine( lines[i] );
        i++;
    }
}

Display.readInput = function( ){
    netscape.security.PrivilegeManager.enablePrivilege("UniversalXPConnect"); 
    var data = this.input.value;
    this.writeOutput( data + "\n" );
    this.input.select();
    return data
}

ReplConnection = Connection.clone();
ReplConnection.connected = function( ){
    this.print( "-- connected --\n")
}
ReplConnection.disconnected = function( ){
    this.print( "-- disconnected --\n")
}
ReplConnection.received = function( data ){
    this.print( data )
}
ReplConnection.print = function( data ){
    this.display.writeOutput( data );
}

function on_load( ){
//    Display.output = document.getElementById( "output" );
    //Display.input = document.getElementById( "input" );
    //Display.output = document.getElementsByTagName( "scrollbox" )[0];
    Display.output = document.getElementsByTagName( "richlistbox" )[0];
    alert( Display.output )
    /*.contentDocument /*.getElementsByTagName( 
        "body" 
    )[0];
    */
    Display.input = document.getElementsByTagName( "textbox" )[0];
    testConnection = ReplConnection.clone();
    testConnection.display = Display;
    testConnection.connectTo( "localhost", 9191 );
    Display.connection = testConnection;
}

function cmd_enter( ){
    Display.connection.send( Display.readInput( ) + "\n" );
}
