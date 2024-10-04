#![crate_name = "doc"]

use std::usize;

use super::ip_protocol;
use crate::ethernet_frame;
use ethernet_frame::EthernetFrame;

pub struct IPv4 {
    /// (14-bytes) Ethernet Frame
    pub eth_frame: EthernetFrame,
    /// (32-bit) Source address - May be affected by NAT
    pub src_addr: [u8; 4],
    /// (32-bit) Destination address - May be affected by NAT
    pub dest_addr: [u8; 4],
    /// (4-bit) Version of IP packet - IPv4 equal to 4
    pub version: u8,
    /// (4-bit) Internet Header Length (IHL)
    pub ihl: u8,
    /// (6-bit) Differentiated Services Code Point (DSCP)
    pub dscp: u8,
    /// (2-bit) Explicit Congestion Notification (ECN)
    pub ecn: u8,
    /// (16-bit) Total Length of packet size
    pub total_length: u16,
    /// (16-bit) Identification - Used for fragmentation and reassembly
    pub identification: u8,
    /// (3-bit) Flags, order: MSB to LSB - Used to control or identify fragments
    /// bit 0: Reserved - Always zero
    /// bit 1: DF (Don't Fragment)
    /// bit 2: MF (More Fragments) - Set on all fragmented packets, except the last
    pub flags: u8,
    /// (13-bit) Fragment offset - Specifies the position of the fragment in the original
    /// fragmented IP packet
    pub fragment_offset: u16,
    /// (8-bit) Time to Live - Prevent routing loop by decrementing live field by 1
    pub time_to_live: u8,
    /// (8-bit) Protocol that is encapsulated in the IP packet
    /// https://en.wikipedia.org/wiki/List_of_IP_protocol_numbers
    pub protocol: String,
    /// (16-bit) Header Checksum - Receiver can check for errors in the header
    pub header_checksum: String,
    /// (40-bit) Options that are not often used - Active if IHL > 5 (6-15)
    /// Options Types:
    /// Single-byte: No operation (Type 1), End of option (Type 0)
    /// Multiple-byte: Record route (Type 7), Strict source route (Type 137),
    /// Loose source route (type 131), Timestamp (Type 68)
    pub options: Vec<Option>,
}

/// Option can max be 40-bytes, where type+size+data+padding = 1+1+(4*9)+2 = 40
pub struct Option {
    /// (8-bit) Type of option
    /// Option behavior:
    /// (1-bit) Set to 1 if the options need to be copied into all fragments of a fragmented packet.
    /// (2-bit) 0 is for control options, and 2 is for debugging and measurement. 1 and 3 are reserved
    /// (5-bit) Specifies an option
    pub r#type: u8,
    /// (8-bit) The size of the option including type, size, data
    pub size: u8,
    /// (36-bytes) Data
    pub data: Vec<u8>,
}

impl IPv4 {
    fn src_addr(packet: &pcap::Packet) -> [u8; 4] {
        [packet[30], packet[31], packet[32], packet[33]]
    }

    fn dst_addr(packet: &pcap::Packet) -> [u8; 4] {
        [packet[34], packet[35], packet[33], packet[34]]
    }

    fn version(packet: &pcap::Packet) -> u8 {
        packet[14] >> 4
    }

    fn ihl(packet: &pcap::Packet) -> u8 {
        (packet[14] << 4 >> 4) * 32 / 8
    }

    fn dscp(packet: &pcap::Packet) -> u8 {
        packet[15] >> 2        
    }

    fn ecn(packet: &pcap::Packet) -> u8 {
        packet[15] << 6 >> 6
    }

    fn total_length(packet: &pcap::Packet) -> u16 {
        u16::from_be_bytes([packet[16], packet[17]])
    }

    fn identification(packet: &pcap::Packet) ->u8 {
        packet[18]
    }

    fn flags(packet: &pcap::Packet) -> u8 {
        packet[19] << 5 >> 5
    }

    fn fragment_offset(packet: &pcap::Packet) -> u16 {
        u16::from_be_bytes([packet[19], packet[20]]) << 13 >> 13
    }

    fn time_to_live(packet: &pcap::Packet) -> u8 {
        packet[21]
    }

    fn protocol(packet: &pcap::Packet) -> String {
        format!("0x{:02x}", packet[22])
    }
    
    fn header_checksum(packet: &pcap::Packet) -> String {
        format!("0x{:04x}", u16::from_be_bytes([packet[23], packet[24]]))
    }

    fn options(packet: &pcap::Packet) -> Vec<Option> {
        let ihl = packet[14] << 4 >> 4;
        let ihl_bytes = ihl * 32 / 8;
        if ihl > 5 {          
            let mut options: Vec<Option> = vec![];
            let mut init_packet = 25;
            let option_length = packet[init_packet] << 3 >> 3;
            while option_length <= ihl_bytes && option_length <= 38 {
                let r#type = packet[init_packet];
                let size = packet[init_packet + 1];
                // let mut size = packet[25] << 3 >> 3;
                // let copied = packet[25] >> 7;
                // let option_class = packet[25] << 1 >> 5;
                // option_length = packet[25] << 3 >> 3;
                let mut data = Vec::new();

                for i in (init_packet + 2)..option_length as usize {
                    if ihl_bytes as usize <= i { 
                        init_packet = i;
                        break; 
                    }

                    data.push(packet[i]);
                }

                options.push(Option {
                    r#type,
                    size,
                    data,
                });
            }

            options

        } else {
            vec![Option {
                r#type: 0,
                size: 0,
                data: vec![0],
            }]
        }
    }
}

impl IPv4 {
    fn to_string_addr(addr: [u8; 4]) -> String {
        format!("{}.{}.{}.{}", addr[0], addr[1], addr[2], addr[3])
    }
}

impl ip_protocol::ToString for IPv4 {
    fn src_addr(&self) -> String {
        IPv4::to_string_addr(self.src_addr)
    }

    fn dest_addr(&self) -> String {
        IPv4::to_string_addr(self.dest_addr)
    }
}

impl ip_protocol::Packet for IPv4 {
    fn serialize(
        packet: &pcap::Packet,
        eth_frame: ethernet_frame::EthernetFrame,
    ) -> Box<dyn ip_protocol::Packet> {
        Box::new(IPv4 {
            eth_frame,
            src_addr: IPv4::src_addr(packet),
            dest_addr: IPv4::dst_addr(packet),
            version: IPv4::version(packet),
            ihl: IPv4::ihl(packet),
            dscp: IPv4::dscp(packet),
            ecn: IPv4::ecn(packet),
            total_length: IPv4::total_length(packet),
            identification: IPv4::identification(packet),
            flags: IPv4::flags(packet),
            fragment_offset: IPv4::fragment_offset(packet),
            time_to_live: IPv4::time_to_live(packet),
            protocol: IPv4::protocol(packet),
            header_checksum: IPv4::header_checksum(packet),
            options: IPv4::options(packet),
        })
    }

    fn get_eth_frame(&self) -> &EthernetFrame {
        &self.eth_frame
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

