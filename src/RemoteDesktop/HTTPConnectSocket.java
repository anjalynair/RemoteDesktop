package RemoteDesktop;

import java.io.DataInputStream;
import java.io.IOException;
import java.net.Socket;

public class HTTPConnectSocket extends Socket {
	
	 public HTTPConnectSocket(String host, int port) throws IOException {
		 //sending request
		 getOutputStream().write(("CONNECT " + host + ":" + port+ " HTTP/1.0\r\n\r\n").getBytes());
		
		 //Reading the response
		 DataInputStream is = new DataInputStream(getInputStream());
		    String str = is.readLine();
		    
		 // Check the HTTP error code -- it should be "200" on success
		    if (!str.startsWith("HTTP/1.0 200 ")) {
		      if (str.startsWith("HTTP/1.0 "))
			str = str.substring(9);
		      throw new IOException("Proxy reports \"" + str + "\"");
		    }
		    // Success -- skip remaining HTTP headers
		    do {
		      str = is.readLine();
		    } while (str.length() != 0);
		  
	 }

}
