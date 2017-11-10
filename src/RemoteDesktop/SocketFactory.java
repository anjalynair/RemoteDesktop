package RemoteDesktop;

import java.io.IOException;
import java.net.Socket;

public interface SocketFactory {

	
	 public Socket createSocket(String host, int port)
			    throws IOException;
}
