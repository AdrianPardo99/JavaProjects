
package captura;
import com.sun.xml.internal.ws.api.message.Packet;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.io.*;
import Checksum.Checksum;
import org.jnetpcap.Pcap;
import org.jnetpcap.PcapIf;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.PcapPacketHandler;
import org.jnetpcap.PcapBpfProgram;
import org.jnetpcap.protocol.lan.Ethernet;
import org.jnetpcap.protocol.tcpip.*;
import org.jnetpcap.protocol.network.*;
import org.jnetpcap.nio.JBuffer;
import org.jnetpcap.packet.Payload;
import org.jnetpcap.protocol.network.Arp;
import org.jnetpcap.protocol.lan.IEEE802dot2;
import org.jnetpcap.protocol.lan.IEEE802dot3;


public class Captura {

	/**
	 * Main startup method
	 *
	 * @param args
	 *          ignored
	 */
   private static String asString(final byte[] mac) {
    final StringBuilder buf = new StringBuilder();
    for (byte b : mac) {
      if (buf.length() != 0) {
        buf.append(':');
      }
      if (b >= 0 && b < 16) {
        buf.append('0');
      }
      buf.append(Integer.toHexString((b < 0) ? b + 256 : b).toUpperCase());
    }

    return buf.toString();
  }

	public static void main(String[] args) {
		List<PcapIf> alldevs = new ArrayList<PcapIf>(); // Will be filled with NICs
		StringBuilder errbuf = new StringBuilder(); // For any error msgs

		/***************************************************************************
		 * First get a list of devices on this system
		 **************************************************************************/
		int r = Pcap.findAllDevs(alldevs, errbuf);
		if (r == Pcap.NOT_OK || alldevs.isEmpty()) {
			System.err.printf("Can't read list of devices, error is %s", errbuf
			    .toString());
			return;
		}

		System.out.println("Network devices found:");

		int i = 0;
                try{
		for (PcapIf device : alldevs) {
			String description =
			    (device.getDescription() != null) ? device.getDescription()
			        : "No description available";
                        final byte[] mac = device.getHardwareAddress();
			String dir_mac = (mac==null)?"No tiene direccion MAC":asString(mac);
                        System.out.printf("#%d: %s [%s] MAC:[%s]\n", i++, device.getName(), description, dir_mac);

		}//for

		PcapIf device = alldevs.get(0); // We know we have atleast 1 device
		System.out
		    .printf("\nChoosing '%s' on your behalf:\n",
		        (device.getDescription() != null) ? device.getDescription()
		            : device.getName());

		/***************************************************************************
		 * Second we open up the selected device
		 **************************************************************************/
                /*"snaplen" is short for 'snapshot length', as it refers to the amount of actual data captured from each packet passing through the specified network interface.
                64*1024 = 65536 bytes; campo len en Ethernet(16 bits) tam máx de trama */

		int snaplen = 64 * 1024;           // Capture all packets, no trucation
		int flags = Pcap.MODE_PROMISCUOUS; // capture all packets
		int timeout = 10 * 1000;           // 10 seconds in millis
                Pcap pcap =
		    Pcap.openLive(device.getName(), snaplen, flags, timeout, errbuf);

		if (pcap == null) {
			System.err.printf("Error while opening device for capture: "
			    + errbuf.toString());
			return;
		}//if

                       /********F I L T R O********/
            PcapBpfProgram filter = new PcapBpfProgram();
            String expression =""; // "port 80";
            int optimize = 0; // 1 means true, 0 means false
            int netmask = 0;
            int r2 = pcap.compile(filter, expression, optimize, netmask);
            if (r2 != Pcap.OK) {
                System.out.println("Filter error: " + pcap.getErr());
            }//if
            pcap.setFilter(filter);
                /****************/


		/***************************************************************************
		 * Third we create a packet handler which will receive packets from the
		 * libpcap loop.
		 **********************************************************************/
		PcapPacketHandler<String> jpacketHandler = new PcapPacketHandler<String>() {

			public void nextPacket(PcapPacket packet, String user) {
                                /*Direccion macO, macD,Tipo*/
				System.out.printf("Received packet at %s caplen=%-4d len=%-4d %s\n",
				    new Date(packet.getCaptureHeader().timestampInMillis()),
				    packet.getCaptureHeader().caplen(),  // Length actually captured
				    packet.getCaptureHeader().wirelen(), // Original length
				    user                                 // User supplied object
				    );
                                System.out.print("Trama: \n");
                                /******Desencapsulado********/
                                for(int i=0;i<packet.size();i++){
                                System.out.printf("%02X ",packet.getUByte(i));                                
                                if(i%16==15)
                                    System.out.println("");
                                }
                                System.out.print("\n\nMAC Origen: ");
                                for(int i=0;i!=6;i++){
                                    System.out.printf("%02X ",packet.getUByte(i));
                                }
                                System.out.print("\nMAC Destino: ");
                                for(int i=6;i!=12;i++){
                                    System.out.printf("%02X ",packet.getUByte(i));
                                }
                                System.out.print("\nTipo: ");
                                for(int i=12;i!=14;i++){
                                    System.out.printf("%02X ",packet.getUByte(i));
                                }
                                int tipo=packet.getUByte(12)*256+packet.getUByte(13);
                                char c=(char) packet.getUByte(12);
                                if(0x08==c){
                                    c=(char) packet.getUByte(13);
                                    if(0x00==c){
                                        int l=packet.getUByte(14);
                                        l=l&0x0f;
                                        System.out.printf("\n%02X \n",l);
                                        l*=4;
                                        byte arrb[];
                                        arrb=new byte[l];
                                        for(int i=0;i!=l;i++){
                                            arrb[i]=(byte)packet.getUByte(14+i);
                                        }
                                        System.out.print("Trama de datos capa de transporte para checksum: ");
                                        for(byte s:arrb){
                                            System.out.printf("%02X ",s);
                                        }
                                        arrb[10]=0x00;
                                        arrb[11]=0x00;
                                        long che=Checksum.calculateChecksum(arrb),pa=(packet.getUByte(24)*16*16)+(packet.getUByte(25));
                                        System.out.printf("\nChecksum algoritmo: %02X\n",che);
                                        System.out.printf("Checksum paquete: %02X%02X\n",packet.getUByte(24),packet.getUByte(25));
                                        System.out.printf("%s\n",(che==pa)?("Checksum correcto"):("Checksum incorrecto"));
                                        System.out.printf("Byte 10: %02X %s\n",arrb[9],(arrb[9]==0x06)?("-> TCP"):((arrb[9]==0x11)?("-> UDP"):("")));
                                        //23+48= 72-> UDP 
                                        if(arrb[9]==0x11){
                                            l=3;
                                            l*=4;
                                            arrb=new byte[l];
                                            for(int i=0;i!=l;i++){
                                                arrb[i]=(byte)packet.getUByte(22+i);
                                            }
                                            System.out.print("Trama de datos capa de red para checksum: ");
                                            for(byte s:arrb){
                                                System.out.printf("%02X ",s);
                                            }
                                            System.out.println("");
                                        }
                                        
                                    }
                                }
                                System.out.println("\n");
                                
			}
                        
		};

		/***************************************************************************
		 * Fourth we enter the loop and tell it to capture 10 packets. The loop
		 * method does a mapping of pcap.datalink() DLT value to JProtocol ID, which
		 * is needed by JScanner. The scanner scans the packet buffer and decodes
		 * the headers. The mapping is done automatically, although a variation on
		 * the loop method exists that allows the programmer to sepecify exactly
		 * which protocol ID to use as the data link type for this pcap interface.
		 **************************************************************************/
		pcap.loop(5, jpacketHandler, "jNetPcap rocks!");

		/***************************************************************************
		 * Last thing to do is close the pcap handle
		 **************************************************************************/
		pcap.close();
                }catch(IOException e){e.printStackTrace();}
	}
}
