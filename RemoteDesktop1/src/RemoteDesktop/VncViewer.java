package RemoteDesktop;

import java.awt.Container;
import java.awt.event.ComponentListener;
import java.awt.event.WindowListener;
import java.io.IOException; 


import javax.swing.JOptionPane;


public class VncViewer extends java.applet.Applet implements Runnable
 {
	
	
	boolean inAnApplet = true;
	
	
	public static void main(String[] argv) {
		
		
        
		
		
		
	    VncViewer v = new VncViewer();
	    v.mainArgs = argv;
	    v.inAnApplet = false;
	   

	    v.init();
	    v.start();
	  }
	String[] mainArgs;
	 RfbProto rfb;
	 Thread rfbThread;
	 Container vncContainer;
	 String socketFactory;
	  String host;
	  int port;
	  String passwordParam;
	  
	  // Reference to this applet for inter-applet communication.
	  public static java.applet.Applet refApplet;

	  public void init() {
		  
		  readParameters();

		    refApplet = this;
		    rfbThread = new Thread(this);
		    rfbThread.start();
		  
	  }
	  
	  public void run() {}
	  
	// Connect to the RFB server and authenticate the user.
	  //

	  void connectAndAuthenticate() throws Exception
	  {
		 
	       host="127.0.0.1";
	       port=5901;
		  
		  
		  
		  System.out.println("Connecting to " + host + ", port " + port + "...");

		    rfb = new RfbProto(host, port, this);
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
		      if (passwordParam != null) {
		        rfb.authenticateVNC(passwordParam);
		      } /*else {
		        String pw = askPassword();
		        rfb.authenticateVNC(pw);
		      }*/
		      break;
		    default:
		      throw new Exception("Unknown authentication scheme " + authType);
		    }
		  }
	  
	  void readParameters() {
		  
		  readPasswordParameters();
		  socketFactory = readParameter("SocketFactory", false);
	  }
	  
	  private void readPasswordParameters() {
		  
		  passwordParam = readParameter("1234", false);
	  }
	  
	  public String readParameter(String name, boolean required) {
		  
		  String s = name;
		  if ((s == null) && required) {
				fatalError(name + " parameter not specified");
			     return s; }
		  
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
		    System.exit(1);
	  }
	  
	  synchronized public void fatalError(String str, Exception e) {
		  
		    if (rfb != null && rfb.closed()) {
		      // Not necessary to show error message if the error was caused
		      // by I/O problems after the rfb.close() method call.
		      System.out.println("RFB thread finished");
		      return;
		    }

		    System.out.println(str);
		    e.printStackTrace();

		    if (rfb != null)
		      rfb.close();
	  }
	  
	  public void stop() {
		    System.out.println("Stopping applet");
		    rfbThread = null;
		  }

	  
	  
	  
	  
	  
	  }
	 
