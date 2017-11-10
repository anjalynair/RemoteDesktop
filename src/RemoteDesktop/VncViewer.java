package RemoteDesktop;

import java.io.IOException;

import javax.swing.JOptionPane;

public class VncViewer {

	String[] mainArgs;
	String socketFactory;
	String passwordParam;
	Boolean inAnApplet=true;
	public static void main(String[] args) throws Exception {
		
		
		 String host = JOptionPane.showInputDialog("Please enter server IP");
	        String port = JOptionPane.showInputDialog("Please enter server port");
	        new VncViewer().ConnectAndAuthenticate(host, Integer.parseInt(port));
		

	}
	
	void ConnectAndAuthenticate(String host,int port ) throws Exception {
		
		System.out.println("Initializing...");
		System.out.println("Connecting to " + host + ", port " + port + "...");
		
		 RfbProto rfb = new RfbProto(host,port);
		 System.out.println("Connected to server");
		 
		 rfb.readVersionMsg();
		 System.out.println("RFB server supports protocol version " +
				 rfb.serverMajor + "." + rfb.serverMinor);
		 
		 rfb.writeVersionMsg();
		System.out.println("Using RFB protocol version " +
				 rfb.clientMajor + "." + rfb.clientMinor);
		
		int secType = rfb.negotiateSecurity();
		int authType;
	    if (secType == RfbProto.SecTypeTight) {
	      System.out.println("Enabling TightVNC protocol extensions");
	      rfb.setupTunneling();
	      authType = rfb.negotiateAuthenticationTight();
	    } else {
	      authType = secType;
	    }
	    switch (authType) {
	    case RfbProto.AuthNone:
	      System.out.println("No authentication needed");
	      rfb.authenticateNone();
	      break;
	    case RfbProto.AuthVNC:
	    	System.out.println("Performing standard VNC authentication");
	        String pw = askPassword();
	        rfb.authenticateVNC(pw);
	      
	      break;
	    default:
	      throw new Exception("Unknown authentication scheme " + authType);
	    }
		 
		 
		 
	}
	String askPassword() {
		passwordParam="1234";
		return passwordParam;
		//Write password entry...
		
		
		
	}
	
	
	void readParameters() {
		socketFactory = readParameter("SocketFactory", false);
	}
	
	
	 public String readParameter(String name, boolean required) {
		 if (inAnApplet) {
		      String s = name;
		      if ((s == null) && required) {
			fatalError(name + " parameter not specified");
		      }
		      return s;
		    }
		 
		 for (int i = 0; i < mainArgs.length; i += 2) {
		      if (mainArgs[i].equalsIgnoreCase(name)) {
			try {
			  return mainArgs[i+1];
			} catch (Exception e) {
			  if (required) {
			    fatalError(name + " parameter not specified");
			  }
			  return null;
			}
		      }
		    }
		    if (required) {
		      fatalError(name + " parameter not specified");
		    }
		 return null;
	 }
	 
	 synchronized public void fatalError(String str) {
		 System.out.println(str);
	 }

}
