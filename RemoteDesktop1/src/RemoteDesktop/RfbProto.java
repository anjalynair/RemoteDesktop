package RemoteDesktop;

import java.io.BufferedInputStream; 
import java.io.DataInputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.net.Socket;



import javax.net.SocketFactory;


public class RfbProto {
	
	final static int
    AuthNone      = 1,
    AuthVNC       = 2,
    AuthUnixLogin = 129;
	
	 final static int
	    NoTunneling = 0;
	
	final static String
    versionMsg_3_3 = "RFB 003.003\n",
    versionMsg_3_7 = "RFB 003.007\n",
    versionMsg_3_8 = "RFB 003.008\n";
	
	final static int
    SecTypeInvalid = 0,
    SecTypeNone    = 1,
    SecTypeVncAuth = 2,
    SecTypeTight   = 16;
	
	final static int
    VncAuthOK      = 0,
    VncAuthFailed  = 1,
    VncAuthTooMany = 2;
	
	String host;
	  int port;
	  Socket sock;
	  OutputStream os;
	  SessionRecorder rec;
	  boolean inNormalProtocol = false;
	  VncViewer viewer;
	  
	  private DataInputStream is;
	  private long numBytesRead = 0;
	  public long getNumBytesRead() { return numBytesRead; }
	  
	  int serverMajor, serverMinor;
	  int clientMajor, clientMinor;
	  boolean protocolTightVNC;
	  CapsContainer tunnelCaps, authCaps;
	  CapsContainer serverMsgCaps, clientMsgCaps;
	  CapsContainer encodingCaps;
	  private boolean closed;
	  
	// Constructor. Make TCP connection to RFB server.
	  
	  RfbProto(String h, int p, VncViewer v) throws IOException {
		  
		  viewer = v;
		    host = h;
		    port = p;
		    
		    if (viewer.socketFactory == null) {
		        sock = new Socket(host, port);
		        sock.setTcpNoDelay(true);
		      } else {
		        try {
		  	Class factoryClass = Class.forName(viewer.socketFactory);
		  	SocketFactory factory = (SocketFactory)factoryClass.newInstance();
		  	if (viewer.inAnApplet)
		  	  sock = factory.createSocket(host, port, viewer);
		  	else
		  	  sock = factory.createSocket(host, port, viewer.mainArgs);
		        } catch(Exception e) {
		  	e.printStackTrace();
		  	throw new IOException(e.getMessage());
		        }
		      }
		      is = new DataInputStream(new BufferedInputStream(sock.getInputStream(),
		  						     16384));
		      os = sock.getOutputStream();

		      
		    }
	  synchronized void close() {
		    try {
		      sock.close();
		      closed = true;
		      System.out.println("RFB socket closed");
		      if (rec != null) {
			rec.close();
			rec = null;
		      }
		    } catch (Exception e) {
		      e.printStackTrace();
		    }
		  }

		  synchronized boolean closed() {
		    return closed;
		  }
		  
		  void readVersionMsg() throws Exception {

			    byte[] b = new byte[12];

			    //readFully(b);

			    if ((b[0] != 'R') || (b[1] != 'F') || (b[2] != 'B') || (b[3] != ' ')
				|| (b[4] < '0') || (b[4] > '9') || (b[5] < '0') || (b[5] > '9')
				|| (b[6] < '0') || (b[6] > '9') || (b[7] != '.')
				|| (b[8] < '0') || (b[8] > '9') || (b[9] < '0') || (b[9] > '9')
				|| (b[10] < '0') || (b[10] > '9') || (b[11] != '\n'))
			    {
			      throw new Exception("Host " + host + " port " + port +
						  " is not an RFB server");
			    }

			    serverMajor = (b[4] - '0') * 100 + (b[5] - '0') * 10 + (b[6] - '0');
			    serverMinor = (b[8] - '0') * 100 + (b[9] - '0') * 10 + (b[10] - '0');

			    if (serverMajor < 3) {
			      throw new Exception("RFB server does not support protocol version 3");
			    }
			  }
		  
		  // Write our protocol version message
		  //

		  void writeVersionMsg() throws IOException {
		    clientMajor = 3;
		    if (serverMajor > 3 || serverMinor >= 8) {
		      clientMinor = 8;
		      os.write(versionMsg_3_8.getBytes());
		    } else if (serverMinor >= 7) {
		      clientMinor = 7;
		      os.write(versionMsg_3_7.getBytes());
		    } else {
		      clientMinor = 3;
		      os.write(versionMsg_3_3.getBytes());
		    }
		    protocolTightVNC = false;
		   // initCapabilities();
		  }
		  
		  int negotiateSecurity() throws Exception {
			    return (clientMinor >= 7) ?
			      selectSecurityType() : readSecurityType();
			  }
		  int readSecurityType() throws Exception {
			    int secType = readU32();

			    switch (secType) {
			    case SecTypeInvalid:
			    	System.out.println("Connection failure reason..");
			      //readConnFailedReason();
			      return SecTypeInvalid;	// should never be executed
			    case SecTypeNone:
			    case SecTypeVncAuth:
			      return secType;
			    default:
			      throw new Exception("Unknown security type from RFB server: " + secType);
			    }
			  }
		  
		  int selectSecurityType() throws Exception {
			    int secType = SecTypeInvalid;

			    // Read the list of secutiry types.
			    int nSecTypes = readU8();
			    if (nSecTypes == 0) {
			    	System.out.println("Connection failure reason..");
			     // readConnFailedReason();
			      return SecTypeInvalid;	// should never be executed
			    }
			    byte[] secTypes = new byte[nSecTypes];
			   // readFully(secTypes);

			    // Find out if the server supports TightVNC protocol extensions
			    for (int i = 0; i < nSecTypes; i++) {
			      if (secTypes[i] == SecTypeTight) {
				protocolTightVNC = true;
				os.write(SecTypeTight);
				return SecTypeTight;
			      }
			    }

			    // Find first supported security type.
			    for (int i = 0; i < nSecTypes; i++) {
			      if (secTypes[i] == SecTypeNone || secTypes[i] == SecTypeVncAuth) {
				secType = secTypes[i];
				break;
			      }
			    }

			    if (secType == SecTypeInvalid) {
			      throw new Exception("Server did not offer supported security type");
			    } else {
			      os.write(secType);
			    }

			    return secType;
			  }
		  
		  void authenticateNone() throws Exception {
			    if (clientMinor >= 8)
			      readSecurityResult("No authentication");
			  }

			  //
			  // Perform standard VNC Authentication.
			  //

			  void authenticateVNC(String pw) throws Exception {
			    byte[] challenge = new byte[16];
			   // readFully(challenge);

			    if (pw.length() > 8)
			      pw = pw.substring(0, 8);	// Truncate to 8 chars

			    // Truncate password on the first zero byte.
			    int firstZero = pw.indexOf(0);
			    if (firstZero != -1)
			      pw = pw.substring(0, firstZero);

			    byte[] key = {0, 0, 0, 0, 0, 0, 0, 0};
			    System.arraycopy(pw.getBytes(), 0, key, 0, pw.length());

			    DesCipher des = new DesCipher(key);

			    des.encrypt(challenge, 0, challenge, 0);
			    des.encrypt(challenge, 8, challenge, 8);

			    os.write(challenge);

			    readSecurityResult("VNC authentication");
			  }
			  
			  void readSecurityResult(String authType) throws Exception {
				    int securityResult = readU32();

				    switch (securityResult) {
				    case VncAuthOK:
				      System.out.println(authType + ": success");
				      break;
				    case VncAuthFailed:
				      if (clientMinor >= 8)
				    	  System.out.println("Connection failure reason..");
				        //readConnFailedReason();
				      throw new Exception(authType + ": failed");
				    case VncAuthTooMany:
				      throw new Exception(authType + ": failed, too many tries");
				    default:
				      throw new Exception(authType + ": unknown result " + securityResult);
				    }
				  }
			  

			  //
			  // Setup tunneling (TightVNC protocol extensions)
			  //

			  void setupTunneling() throws IOException {
			    int nTunnelTypes = readU32();
			    if (nTunnelTypes != 0) {
			      readCapabilityList(tunnelCaps, nTunnelTypes);

			      // We don't support tunneling yet.
			      writeInt(NoTunneling);
			    }
			  }

			  //
			  // Negotiate authentication scheme (TightVNC protocol extensions)
			  //

			  int negotiateAuthenticationTight() throws Exception {
			    int nAuthTypes = readU32();
			    if (nAuthTypes == 0)
			      return AuthNone;

			    readCapabilityList(authCaps, nAuthTypes);
			    for (int i = 0; i < authCaps.numEnabled(); i++) {
			      int authType = authCaps.getByOrder(i);
			      if (authType == AuthNone || authType == AuthVNC) {
				writeInt(authType);
				return authType;
			      }
			    }
			    throw new Exception("No suitable authentication scheme found");
			  }

			  //
			  // Read a capability list (TightVNC protocol extensions)
			  //

			  void readCapabilityList(CapsContainer caps, int count) throws IOException {
			    int code;
			    byte[] vendor = new byte[4];
			    byte[] name = new byte[8];
			    for (int i = 0; i < count; i++) {
			      code = readU32();
			      //readFully(vendor);
			     // readFully(name);
			      caps.enable(new CapabilityInfo(code, vendor, name));
			    }
			  }

			  //
			  // Write a 32-bit integer into the output stream.
			  //

			  void writeInt(int value) throws IOException {
			    byte[] b = new byte[4];
			    b[0] = (byte) ((value >> 24) & 0xff);
			    b[1] = (byte) ((value >> 16) & 0xff);
			    b[2] = (byte) ((value >> 8) & 0xff);
			    b[3] = (byte) (value & 0xff);
			    os.write(b);
			  }

			  final int readU8() throws IOException {
				    int r = is.readUnsignedByte();
				    numBytesRead++;
				    return r;
				  }
			  
			  final int readU32() throws IOException {
				    int r = is.readInt();
				    numBytesRead += 4;
				    return r;
				  }
	  }
	
	
	
	
