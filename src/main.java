import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.*;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;
//can only use InetAddress.geyByAddress
public class main {

	enum QueryType {
		A((byte) 0x1), NS((byte) 0x2), CNAME((byte) 0x5), MX((byte) 0xf);
		
		QueryType(byte code) {
			this.code = code;
		}
		private byte code;
		private byte getCode() {
			return code;
		}
		public static Optional<QueryType> valueOf(byte code) {
			return Arrays.stream(values()).filter(q -> q.code == code).findFirst();
		}
	}
	private static String USAGE_STRING = "java DnsClient [-t timeout] [-r max-retries] [-p port][-mx|-ns] @server name";
	public static void main(String[] args) {
		if (args.length < 2) {
			System.out.println(String.format("Usage: %s", USAGE_STRING));
			return;
		}
		// TODO Auto-generated method stub
		int timeout = 5;
		int maxRetries = 3;
		int port = 53;
		QueryType queryType = QueryType.A;
		InetAddress dnsServer = null;
		String name = null;
		for (int i = 0; i < args.length; i++) {
			String arg = args[i];
			if (arg.equals("-t")) {
				i++;
				timeout = Integer.parseInt(args[i]);
			} else if (arg.equals("-r")) {
				i++;
				maxRetries = Integer.parseInt(args[i]);
			} else if (arg.equals("-p")) {
				i++;
				port = Integer.parseInt(args[i]);
			} else if (arg.equals("-mx")) {
				queryType = QueryType.MX;
			} else if (arg.equals("-ns")) {
				queryType = QueryType.NS;
			} else { //DNS server and name
				try {
					if (arg.split("@").length != 2) {
						System.out.println("Please input DNS server ip as @<server>");
						return;
					}
					arg = arg.split("@")[1];
					String[] ipParts = arg.split("\\.");
					byte[] ipNumParts = new byte[ipParts.length];
					for (int j = 0; j < ipParts.length; j++) {
						ipNumParts[j] = (byte) Integer.parseInt(ipParts[j]);
					}
					dnsServer = InetAddress.getByAddress(ipNumParts);
				} catch (UnknownHostException e) {
					System.out.println("Invalid server ip");
					e.printStackTrace();
				}
				i++;
				name = args[i];
			}
		}
		System.out.println(String.format("DnsClient sending request for: %s", name));
		System.out.println(String.format("Server: %s", dnsServer.getHostAddress()));
		System.out.println(String.format("Request type: %s", queryType));
		
		//Start UDP socket
		DatagramSocket clientSocket = null;
		try {
			clientSocket = new DatagramSocket();
		} catch (SocketException e1) {
			e1.printStackTrace();
		}
		byte[] sendData = composeDNSQuery(name, queryType);
		byte[] receiveData = new byte[1024];
		DatagramPacket sendPacket = new DatagramPacket(sendData, sendData.length, dnsServer, port);
		DatagramPacket receivePacket = new DatagramPacket(receiveData, receiveData.length);
		
		try {
			clientSocket.send(sendPacket);
			clientSocket.receive(receivePacket);
		} catch (IOException e) {
			e.printStackTrace();
		}
		parseDNSResponse(receiveData);
		String response = new String(receivePacket.getData());
		System.out.println(String.format("From server: %s", response));
		clientSocket.close();
		
		
	}
	
	private static byte[] composeDNSQuery(String name, QueryType queryType) {
		Byte[] header = new Byte[12];
		//ID
		int id = (int) (Math.random() * 65536);
		header[0] = (byte) id;
		header[1] = (byte) (id >>> 8);
		//QR to RCODE
		header[2] = 0x1;
		header[3] = 0x0;
		//QDCOUNT
		header[4] = 0x0;
		header[5] = 0x1;
		//ANCOUNT
		header[6] = 0x0;
		header[7] = 0x0;
		//NSCOUNT (can ignore in response)
		header[8] = 0x0;
		header[9] = 0x0;
		//ARCOUNT
		header[10] = 0x0;
		header[11] = 0x0;
		
		//QUESTION SECTION
		ArrayList<Byte> question = new ArrayList<Byte>();
		//QNAME
		String[] labels = name.split("\\.");
		for (int i = 0; i < labels.length; i++) {
			String label = labels[i];
			question.add((byte) label.length());
			
			byte[] bytes = label.getBytes();
			Byte[] labelBytes = new Byte[bytes.length];
			for (int j = 0; j < bytes.length; j++) {
				labelBytes[j] = bytes[j];
			}
			question.addAll(Arrays.asList(labelBytes));
		}
		question.add((byte) 0x0);
		//QTYPE
		question.add((byte) 0x0);
		question.add(queryType.getCode());
		//QCLASS
		question.add((byte) 0x0);
		question.add((byte) 0x1);
		//Put header and question together, convert Byte to byte
		ArrayList<Byte> byteList = new ArrayList<Byte>();
		byteList.addAll(Arrays.asList(header));
		byteList.addAll(question);
		Byte[] byteArray = byteList.toArray(new Byte[0]);
		byte[] bytes = new byte[byteArray.length];
		for (int i = 0; i < byteArray.length; i++) {
			bytes[i] = byteArray[i].byteValue();
		}
		return bytes;

	}
	
	private static void parseDNSResponse(byte[] response) {
		int AA = response[2] & 0x4;
		int RA = response[3] & 0x80;
		int RCODE = response[3] & 0xF;
		int ANCOUNT = (response[6] << 8) + response[7];
		int ARCOUNT = (response[10] << 8) + response[11];
		boolean authoritative = AA == 0 ? false : true;
		boolean recursionSupported = RA == 0 ? false : true;
		if (RCODE == 1) {
			System.out.println(String.format("ERROR [RCODE: %d] Format error", RCODE));
		} else if (RCODE == 2) {
			System.out.println(String.format("ERROR	[RCODE: %d] Server failure", RCODE));
		} else if (RCODE == 3 && authoritative) {
			System.out.println(String.format("ERROR	[RCODE: %d] Name error", RCODE));
		} else if (RCODE == 4) {
			System.out.println(String.format("ERROR	[RCODE: %d] Not implemented error", RCODE));
		} else if (RCODE == 5) {
			System.out.println(String.format("ERROR	[RCODE: %d] Refused", RCODE));
		}
		//Start of question section is response[12];
		int i = 12;
		//NAME
		ArrayList<String> labels = new ArrayList<String>();
		while (response[i] != 0x0) {
				int labelLength = response[i];
				i++;
				
				//byteArray is from i to i+labelLength
				byte[] byteArray = Arrays.copyOfRange(response, i, i+labelLength);
				try {
					labels.add(new String(byteArray, "UTF-8"));
				} catch (UnsupportedEncodingException e) {
					e.printStackTrace();
				}
				
				i += labelLength;
		}
		String questionName = String.join(".", labels);
		i += 5; //skip the question type, and question class
		
		//ANSWER section starts here
		String name = null;
		boolean isPointer = ((int) response[i] & 0b11000000) == 192;
		if (isPointer) {
			int pointer = (((int) response[i] & 0b00111111) << 8) + response[++i];
			int startIndex = pointer - 12;
			name = questionName.substring(startIndex, questionName.length());
		}
		i += 2;
		
		//QTYPE
		QueryType qType = QueryType.valueOf(response[i]).get();
		i++;
		//CLASS
		int qClass = (response[i] << 8) + response[++i];
		if (qClass != 1) {
			System.out.println("ERROR Answer class is not 1.");
			return;
		}
		i++;
		//TTL
		//eg 1100 0000, 0000 1100, 0000 0000, 0000 0001
		int ttl = (response[i] << 24) + (response[++i] << 16) + (response[++i] << 8) + response[++i];
		i++;
		//RDLENGTH
		int rdLength = (response[i] << 8) + response[++i];
		i++;
		//RDATA (of length rdLength)
		switch(qType) {
			case A:
				//IP address
				byte[] ipBytes = Arrays.copyOfRange(response, i, i+rdLength);
				ArrayList<String> ipParts = new ArrayList<String>();
				for (int j=0; j < rdLength; j++) {
					ipParts.add(Byte.toUnsignedInt(ipBytes[j]) + "");
				}
				String ipAddress = String.join(".", ipParts);
				break;
			case CNAME:
				break;
			case MX:
				break;
			case NS:
				break;
			default:
				break;
		}
		
	}
}
