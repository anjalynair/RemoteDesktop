package RemoteDesktop;

import java.io.BufferedInputStream;
import java.io.DataInputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.net.Socket;



import javax.net.SocketFactory;


public class RfbProto {
	
	final static String
	versionMsg_3_3 = "RFB 003.003\n",
	versionMsg_3_7 = "RFB 003.007\n",
	versionMsg_3_8 = "RFB 003.008\n";
	
	// VNC authentication results
	  final static int
	    VncAuthOK      = 0,
	    VncAuthFailed  = 1,
	    VncAuthTooMany = 2;
	
	// Security types
	  final static int
	    SecTypeInvalid = 0,
	    SecTypeNone    = 1,
	    SecTypeVncAuth = 2,
	    SecTypeTight   = 16;
	  
	  private long numBytesRead = 0;
	  public long getNumBytesRead() { return numBytesRead; }
	
	String host;
	  int port;
	  VncViewer viewer;
	  Socket sock;
	  OutputStream os;
	  private DataInputStream is;
	  int serverMajor, serverMinor;
	  int clientMajor, clientMinor;
	  boolean protocolTightVNC;
	  CapsContainer tunnelCaps, authCaps;
	// Supported authentication types
	  final static int
	    AuthNone      = 1,
	    AuthVNC       = 2,
	    AuthUnixLogin = 129;
	  
	  // Supported tunneling types
	  final static int
	    NoTunneling = 0;
	  final static String
	    SigNoTunneling = "NOTUNNEL";
	

	public RfbProto(String h, int p) throws  IOException {
		// TODO Auto-generated constructor stub
		
		host = h;
	    port = p;
	    
	    if (viewer.socketFactory == null) {
	        sock = new Socket(host, port);
	        sock.setTcpNoDelay(true);
	      }else {
	    	  try {
	    	  Class factoryClass = Class.forName(viewer.socketFactory);
	    	  SocketFactory factory = (SocketFactory)factoryClass.newInstance();
	    	  sock = factory.createSocket(host, port);
	    	  }catch(Exception e) {
	    			e.printStackTrace();}
	      }
	    
	    is = new DataInputStream(new BufferedInputStream(sock.getInputStream()));
	    os = sock.getOutputStream();
	}
	
	void readVersionMsg() throws Exception{
		
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
		   
		  }

	 int negotiateSecurity() throws Exception {
		    return (clientMinor >= 7) ?
		      selectSecurityType() : readSecurityType();
		  }
	 
	 int readSecurityType() throws Exception {
		    int secType = readU32();

		    switch (secType) {
		    case SecTypeInvalid:
		      System.out.println("Connection failure reason print..");
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
		     // readConnFailedReason();
		    	System.out.println("connectiion failure reason..");
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
	  
	  void setupTunneling() throws IOException {
		    int nTunnelTypes = readU32();
		    if (nTunnelTypes != 0) {
		      readCapabilityList(tunnelCaps, nTunnelTypes);

		      // We don't support tunneling yet.
		      writeInt(NoTunneling);
		    }
		  }
	  
	  void writeInt(int value) throws IOException {
		    byte[] b = new byte[4];
		    b[0] = (byte) ((value >> 24) & 0xff);
		    b[1] = (byte) ((value >> 16) & 0xff);
		    b[2] = (byte) ((value >> 8) & 0xff);
		    b[3] = (byte) (value & 0xff);
		    os.write(b);
		  }
	  
	  void readCapabilityList(CapsContainer caps, int count) throws IOException {
		    int code;
		    byte[] vendor = new byte[4];
		    byte[] name = new byte[8];
		    for (int i = 0; i < count; i++) {
		      code = readU32();
		      //readFully(vendor);
		      //readFully(name);
		      caps.enable(new CapabilityInfo(code, vendor, name));
		    }
		  }
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
	  
	  void authenticateNone() throws Exception {
		    if (clientMinor >= 8)
		      readSecurityResult("No authentication");
		  }
	  void readSecurityResult(String authType) throws Exception {
		    int securityResult = readU32();

		    switch (securityResult) {
		    case VncAuthOK:
		      System.out.println(authType + ": success");
		      break;
		    case VncAuthFailed:
		      if (clientMinor >= 8)
		        System.out.println("Connection failed");
		      //readConnFailedReason();
		      throw new Exception(authType + ": failed");
		    case VncAuthTooMany:
		      throw new Exception(authType + ": failed, too many tries");
		    default:
		      throw new Exception(authType + ": unknown result " + securityResult);
		    }
		  }
	  void authenticateVNC(String pw) throws Exception {
		    byte[] challenge = new byte[16];
		    //readFully(challenge);

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
