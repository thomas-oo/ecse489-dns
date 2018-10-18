import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.*;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;

import javafx.util.Pair;
//can only use InetAddress.geyByAddress
public class DnsClient {

	private static final String AUTH = "auth";
	private static final String NOAUTH = "noauth";
	private static final int HEADER_BYTE_LENGTH = 12;

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
			clientSocket.setSoTimeout(timeout * 1000);
		} catch (SocketException e1) {
			e1.printStackTrace();
		}
		byte[] sendData = composeDNSQuery(name, queryType);
		byte[] receiveData = new byte[1024];
		DatagramPacket sendPacket = new DatagramPacket(sendData, sendData.length, dnsServer, port);
		DatagramPacket receivePacket = new DatagramPacket(receiveData, receiveData.length);
		
		int retries = 0;
		boolean done = false;
		long startTime = System.currentTimeMillis();
		while (!done && retries < maxRetries) {
			try {
				clientSocket.send(sendPacket);
				clientSocket.receive(receivePacket);
				done = true;
			} catch (Exception e) {
				retries++;
			}
		}
		if (!done) {
			//exceeded max-retries	
			System.out.println(String.format("No response received after %d retries", maxRetries));
		}
		long endTime = System.currentTimeMillis();
		System.out.println(String.format("Response received after %d seconds (%d retries)", (endTime-startTime)/1000L, retries));
		
		parseDNSResponse(receiveData);
		clientSocket.close();
	}
	
	private static byte[] composeDNSQuery(String name, QueryType queryType) {
		Byte[] header = new Byte[HEADER_BYTE_LENGTH];
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
		int NSCOUNT = (response[8] << 8) + response[9];
		int ARCOUNT = (response[10] << 8) + response[11];
		boolean authoritative = AA == 0 ? false : true;
		boolean recursionSupported = RA == 0 ? false : true;
		if (!recursionSupported) {
			System.out.println("ERROR\tRecursive queries are not supported");
		}
		if (RCODE == 1) {
			System.out.println(String.format("ERROR\t[RCODE: %d] Format error", RCODE));
		} else if (RCODE == 2) {
			System.out.println(String.format("ERROR\t[RCODE: %d] Server failure", RCODE));
		} else if (RCODE == 3 && authoritative) {
			System.out.println(String.format("NOT FOUND\t[RCODE: %d] Domain name does not exist", RCODE));
		} else if (RCODE == 4) {
			System.out.println(String.format("ERROR\t[RCODE: %d] Not implemented error", RCODE));
		} else if (RCODE == 5) {
			System.out.println(String.format("ERROR\t[RCODE: %d] Refused", RCODE));
		}
		//Start of question section is response[12];
		int i = HEADER_BYTE_LENGTH;
		//NAME
		Pair<String, Integer> nameIndexPair = parseName(response, i);
		String questionName = nameIndexPair.getKey();
		i = nameIndexPair.getValue();
		i += 4; //skip the question type, and question class
		
		//ANSWER section starts here
		if (ANCOUNT > 0) {
			System.out.println(String.format("***Answer Section (%d records)***", ANCOUNT));
		}
		for (int j = 0; j < ANCOUNT; j++) {
			i = parseAnswer(response, i, questionName, authoritative, false);
		}
		if (NSCOUNT > 0) {
			System.out.println(String.format("***Authority Section (%d records)***", NSCOUNT));
		}
		for (int j = 0; j < NSCOUNT; j++) {
			//skip authority section
			i = parseAnswer(response, i, questionName, authoritative, true);
		}
		if (ARCOUNT > 0) {
			System.out.println(String.format("***Additional Section (%d records)***", ARCOUNT));
		}
		for (int j = 0; j < ARCOUNT; j++) {
			//skip authority section
			i = parseAnswer(response, i, questionName, authoritative, false);
		}
	}
	
	private static Pair<String, Integer> parsePointerOrName(byte[] byteArray, int i, String qName) {
		String name;
		boolean isPointer = ((int) byteArray[i] & 0b11000000) == 192;
		if (isPointer) {
			int pointer = (((int) byteArray[i] & 0b00111111) << 8) + byteArray[++i];
			int startIndex = pointer - HEADER_BYTE_LENGTH;
			name = qName.substring(startIndex, qName.length());
		} else {
			Pair<String, Integer> nameIndexPair = parseName(byteArray, i);
			i = nameIndexPair.getValue();
			name = nameIndexPair.getKey();
		}
		return new Pair<String, Integer>(name, i);
	}
	
	private static Pair<String, Integer> parseName(byte[] byteArray, int i) {
		ArrayList<String> labels = new ArrayList<String>();
		boolean requestIsPointer = ((int) byteArray[i] & 0b11000000) == 192;
		while (byteArray[i] != 0x0) {
				int labelLength = byteArray[i];
				boolean isPointer = ((int) byteArray[i] & 0b11000000) == 192;
				if (isPointer) {
					int pointer = (((int) byteArray[i] & 0b00111111) << 8) + (byteArray[++i] & 0b11111111);
					Pair<String, Integer> nameIndexPair = parseName(byteArray, pointer);
					labels.add(nameIndexPair.getKey());
					i++;
					continue;
				}
				
				i++;
				
				//byteArray is from i to i+labelLength
				byte[] labelBytes = Arrays.copyOfRange(byteArray, i, i+labelLength);
				try {
					labels.add(new String(labelBytes, "UTF-8"));
				} catch (UnsupportedEncodingException e) {
					e.printStackTrace();
				}
				
				i += labelLength;
		}
		if (!requestIsPointer) {
			i++;
		}
		String name = String.join(".", labels);
		return new Pair<>(name, i);
	}
	
	private static int parseAnswer(byte[] byteArray, int i, String qName, boolean authoritative, boolean isAuthoritySection) {
		String name = null;
		boolean isPointer = ((int) byteArray[i] & 0b11000000) == 192;
		if (isPointer) {
			Pair<String, Integer> nameIndexPair = parseName(byteArray, i);
			i++;
			name = nameIndexPair.getKey();
		} else {
			Pair<String, Integer> nameIndexPair = parseName(byteArray, i);
			i = nameIndexPair.getValue();
			name = nameIndexPair.getKey();
		}
		i += 2;
		
		QueryType qType = null;
		if(isAuthoritySection) {
			//skip QTYPE and CLASS section
			i += 3;
		} else {
			//QTYPE
			qType = QueryType.valueOf(byteArray[i++]).get();
			//CLASS
			int qClass = (byteArray[i] << 8) + byteArray[++i];
			if (qClass != 1) {
				System.out.println("ERROR Answer class is not 1.");
			}
			i++;
		}
		
		//TTL - masking to make it unsigned
		long ttl = ((byteArray[i] << 24) + (byteArray[++i] << 16) + (byteArray[++i] << 8) + byteArray[++i]) & 0xffffffffL;
		i++;
		//RDLENGTH
		int rdLength = (byteArray[i] << 8) + byteArray[++i];
		if (rdLength == 0) {
			return i;
		}
		
		i++;
		//RDATA (of length rdLength)
		String auth = authoritative ? AUTH : NOAUTH;
		if (isAuthoritySection) {
			i += rdLength;
		} else {
			switch(qType) {
				case A: {
					//IP address
					byte[] ipBytes = Arrays.copyOfRange(byteArray, i, i+rdLength);
					ArrayList<String> ipParts = new ArrayList<String>();
					for (int j=0; j < rdLength; j++) {
						ipParts.add(Byte.toUnsignedInt(ipBytes[j]) + "");
					}
					String ipAddress = String.join(".", ipParts);
					System.out.println(String.format("IP \t %s \t %d \t %s", ipAddress, ttl, auth));
					i += rdLength;
					break;
				}
				case CNAME: {
					Pair<String,Integer> aliasIndexPair = parsePointerOrName(byteArray, i, qName);
					System.out.println(String.format("CNAME \t %s \t %d \t %s", aliasIndexPair.getKey(), ttl, auth));
					i = aliasIndexPair.getValue();
					break;
				}
				case MX: {
					//next 2 bytes are preference
					long preference = (byteArray[i++] << 8) + byteArray[i++];
					Pair<String,Integer> aliasIndexPair = parsePointerOrName(byteArray, i, qName);
					System.out.println(String.format("MX \t %s \t %d \t %d \t %s", aliasIndexPair.getKey(), preference, ttl, auth));
					i = aliasIndexPair.getValue();
					break;
				}
				case NS: {
					Pair<String,Integer> aliasIndexPair = parsePointerOrName(byteArray, i, qName);
					System.out.println(String.format("NS \t %s \t %d \t %s", aliasIndexPair.getKey(), ttl, auth));
					i = aliasIndexPair.getValue();
					break;
				}
			}
		}
		//return start of the next answer
		return i;
	}
}
