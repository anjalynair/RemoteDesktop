package RemoteDesktop;

import java.applet.Applet;
import java.io.IOException;
import java.net.Socket;

public interface SocketFactory {

	
	 public Socket createSocket(String host, int port, Applet applet)
			    throws IOException;
	 
	 public Socket createSocket(String host, int port, String[] args)
			    throws IOException;
}
