import java.io.IOException;
import java.net.*;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
//can only use InetAddress.geyByAddress
public class main {

	enum QueryType {
		A((byte) 0x1), NS((byte) 0x2), MX((byte) 0xf);
		
		QueryType(byte code) {
			this.code = code;
		}
		private byte code;
		private byte getCode() {
			return code;
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
		String[] labels = name.split("//.");
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
}
