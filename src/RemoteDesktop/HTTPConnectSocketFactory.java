package RemoteDesktop;

import java.io.IOException;
import java.net.Socket;


class HTTPConnectSocketFactory implements SocketFactory  {

	


	  public Socket createSocket(String host, int port)
	    throws IOException {

		  HTTPConnectSocket s =
			      new HTTPConnectSocket(host, port);
	    return (Socket)s;
	  }


	
	

}
