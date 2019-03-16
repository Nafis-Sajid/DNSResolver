import java.io.*;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.SocketTimeoutException;

public class DNSResolver {

    private static DataInputStream dataInputStream;
    private static DataOutputStream dataOutputStream;
    //all root server ip addresses
    private static String[] rootServer = {"192.112.36.4", "192.203.230.10", "192.33.4.12", "192.36.148.17", "192.5.5.241", "192.58.128.30", "193.0.14.129", "198.41.0.4", "198.97.190.53", "199.7.83.42", "199.7.91.13", "199.9.14.201", "202.12.27.33"};
    private static String nameServer;
    //DOMAIN_NAME == host name that is asked for ip
    private static String DOMAIN_NAME;

    public static void main(String[] args) {

        if (args.length == 0) {
            System.out.println("Error");
        }

        //get the domain name from first argument of command line
        DOMAIN_NAME = args[0];
        nameServer = DOMAIN_NAME;

        //print the query domain name
        System.out.println("\n\n;; QUESTION SECTION:");
        printAnswer(DOMAIN_NAME, 0, "A", " ");

        //print the answers
        System.out.println("\n\n;; ANSWER SECTION:");

        //loop through all root server addresses. If any one of them is active , then dns query is sent to the root address.
        for (int i = 0; i < rootServer.length; i++) {
            String ipAddress = getIP(DOMAIN_NAME, rootServer[i], i);     //getIP() method does the iterative query for DOMAIN_NAME
            if (!(ipAddress.equals("time out"))) {
                break;
            }
        }
    }

    private static void writeData(String domainName) throws IOException {
        //Header section
        dataOutputStream.writeShort(0x1234);    //Transaction ID
        dataOutputStream.writeShort(0x0000);    //Flags. Flag = 0x0000 means , "do query iteratively"
        dataOutputStream.writeShort(0x0001);    //Number of questions
        dataOutputStream.writeShort(0x0000);    //Number of answers
        dataOutputStream.writeShort(0x0000);    //Number of authoritative RRs
        dataOutputStream.writeShort(0x0000);    //Number of additional RRs

        //split the domain name into domainNameParts[] array.
        String[] domainNameParts = domainName.split("\\.");
        //get a byte array from domainNameParts[]
        for (String domainNamePart : domainNameParts) {
            byte[] b = domainNamePart.getBytes();
            dataOutputStream.writeByte(b.length);
            dataOutputStream.write(b);
        }

        //Header section
        dataOutputStream.writeByte(0x00);
        dataOutputStream.writeShort(0x0001);
        dataOutputStream.writeShort(0x0001);
    }

    private static String getIP(String domainName, String serverAddress, int serverNo) {

        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        dataOutputStream = new DataOutputStream(byteArrayOutputStream);

        try {

            writeData(domainName);
            byte[] dnsQueryMessage = byteArrayOutputStream.toByteArray();
            int msgLen = dnsQueryMessage.length;


            //Create a datagram socket and a datagram packet at port 53 and root server address
            DatagramSocket datagramSocket = new DatagramSocket();
            DatagramPacket datagramPacket = new DatagramPacket(dnsQueryMessage, msgLen, InetAddress.getByName(serverAddress), 53);
            //send the packet
            datagramSocket.send(datagramPacket);
            //set time out 1s (1000 ms)
            datagramSocket.setSoTimeout(1000);

            byte[] answer = new byte[1024];
            try {

                DatagramPacket receivedPacked = new DatagramPacket(answer, answer.length);
                datagramSocket.receive(receivedPacked);
            } catch (SocketTimeoutException e)   //if time is out , then the getIP() method will return a message "time out"
            {
                return "time out";
            }

            //the DNS reply message is stored in answer[] array
            ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(answer);
            dataInputStream = new DataInputStream(byteArrayInputStream);

            dataInputStream.readShort();    //Transaction ID
            dataInputStream.readShort();    //Flags
            dataInputStream.readShort();    //Questions
            short answerRRs = dataInputStream.readShort();
            short authorityRRs = dataInputStream.readShort();
            short additionalRRs = dataInputStream.readShort();

            //Query section
            getDomainName(answer);
            dataInputStream.readShort();    //Query Type
            dataInputStream.readShort();    //Class : IN

            //loop through all answer RRs
            for (int i = 1; i <= answerRRs; i++) {

                String name = getDomainName(answer);  //Name :
                String type = getQueryType(dataInputStream.readShort());
                dataInputStream.readShort();    //Class : IN
                int timeToLive = dataInputStream.readInt();      //Time to live :
                dataInputStream.readShort();    //Data length :

                String ip = "";
                switch (type) {
                    case "A": {
                        //read four parts of IPv4 address
                        ip = getipV4Address();
                        if (name.equals(DOMAIN_NAME)) {
                            printAnswer(DOMAIN_NAME, timeToLive, type, ip); //if ip address belongs to DOMAIN_NAME , then it will be printed
                        }
                        break;
                    }
                    case "AAAA": {
                        String ipv6Address = getipV6Address();
                        if (name.equals(DOMAIN_NAME)) {
                            printAnswer(DOMAIN_NAME, timeToLive, type, ipv6Address);
                        }
                        break;
                    }
                    case "CNAME":
                        String cname = getDomainName(answer);
                        printAnswer(DOMAIN_NAME, timeToLive, type, cname);
                        if (name.equals(DOMAIN_NAME)) {
                            DOMAIN_NAME = cname;
                            return getIP(DOMAIN_NAME, rootServer[serverNo], serverNo);    //CNAME will be printed
                        }
                        break;
                    case "SOA":
                        System.out.println("        " + domainName + "  :  Does Not Exist");    //SOA means the domain name dose not exist.
                        return "Does Not Exist";
                }
                if (i == answerRRs) {
                    return ip;
                }
            }

            //loop through all authority RRs
            for (int i = 0; i < authorityRRs; i++) {
                getDomainName(answer);
                String type = getQueryType(dataInputStream.readShort());
                initialRead();

                switch (type) {
                    case "CNAME":
                        String cname = getDomainName(answer);
                        return getIP(cname, rootServer[serverNo], serverNo);
                    case "NS":
                        nameServer = getDomainName(answer);
                        if (additionalRRs == 0) {
                            String nameServerIp = getIP(nameServer, rootServer[serverNo], serverNo);
                            String ip = getIP(domainName, nameServerIp, serverNo);
                            if (!(ip.equals("time out"))) {
                                return ip;
                            }
                        }
                        break;
                    case "SOA":
                        System.out.println("        " + domainName + "  :  Does Not Exist");
                        return "Does Not Exist";
                }
            }

            //loop through all additional RRs
            for (int i = 0; i < additionalRRs; i++) {
                String name = getDomainName(answer);  //Name :
                String type = getQueryType(dataInputStream.readShort());
                initialRead();

                if (type.equals("A")) {
                    String str = getipV4Address();

                    if (name.equals(domainName)) {
                        return str;
                    }
                    String ip = getIP(domainName, str, serverNo);
                    if (!(ip.equals("time out"))) {
                        return ip;
                    }
                } else if (type.equals("AAAA")) {
                    getipV6Address();
                }

            }
        } catch (Exception e) {
            System.out.println("Error ");
            e.printStackTrace();
        }
        return getIP(nameServer, rootServer[serverNo], serverNo);
    }

    private static void initialRead() throws IOException {
        dataInputStream.readShort();    //Class : IN
        dataInputStream.readInt();      //Time to live :
        dataInputStream.readShort();    //Data length :
    }

    private static String getipV6Address() throws IOException {
        int a = dataInputStream.readShort();
        int b = dataInputStream.readShort();
        int c = dataInputStream.readShort();
        int d = dataInputStream.readShort();
        int e = dataInputStream.readShort();
        int f = dataInputStream.readShort();
        int g = dataInputStream.readShort();
        int h = dataInputStream.readShort();
        return String.format("%x:%x:%x:%x:%x:%x:%x:%x", a, b, c, d, e, f, g, h);
    }

    private static String getipV4Address() throws IOException {
        int a = dataInputStream.readByte() & 0x000000ff;
        int b = dataInputStream.readByte() & 0x000000ff;
        int c = dataInputStream.readByte() & 0x000000ff;
        int d = dataInputStream.readByte() & 0x000000ff;
        return String.format("%d.%d.%d.%d", a, b, c, d);
    }

    private static String getDomainName(byte[] answer) throws Exception {
        byte[] DomainNameByteArray = new byte[1024];
        int i = 0;
        while (true) {
            byte k = dataInputStream.readByte();
            if (k == 0) {
                break;
            }
            if (String.format("%x", k).equals("c0")) {
                int index = dataInputStream.readByte() & 0x000000ff;
                int j = answer[index++];
                while (j > 0) {
                    if (i > 0) {
                        DomainNameByteArray[i++] = '.';
                    }
                    for (int l = 0; l < j; l++) {
                        DomainNameByteArray[i++] = answer[index++];
                    }
                    j = answer[index++];
                }
                break;
            }
            if (i > 0) {
                DomainNameByteArray[i++] = '.';
            }
            for (int j = 0; j < k; j++, i++) {
                DomainNameByteArray[i] = dataInputStream.readByte();
            }
        }
        return new String(DomainNameByteArray, 0, i);
    }

    private static String getQueryType(int a) {
        switch (a) {
            case 1:
                return "A";
            case 2:
                return "NS";
            case 5:
                return "CNAME";
            case 6:
                return "SOA";
            case 28:
                return "AAAA";
            default:
                return "Unknown";
        }
    }

    private static void printAnswer(String domainName, int timeToLive, String type, String address) {
        System.out.println(String.format("%30s", domainName) + "  " + String.format("%10s", timeToLive) + "    IN  " + String.format("%10s", type) + "    " + address);
    }
}