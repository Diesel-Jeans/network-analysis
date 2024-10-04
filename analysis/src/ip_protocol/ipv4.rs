#![crate_name = "doc"]

use super::ip_protocol;
use crate::ethernet_frame;
use ethernet_frame::EthernetFrame;

pub struct IPv4<'a> {
    /// (14-bytes) Ethernet Frame
    pub eth_frame: &'a EthernetFrame,
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
    pub protocol: u8,
    /// (16-bit) Header Checksum - Receiver can check for errors in the header
    pub header_checksum: u16,
    /// (40-bit) Options that are not often used - Active if IHL > 5 (6-15)
    /// Options Types:
    /// Single-byte: No operation (Type 1), End of option (Type 0)
    /// Multiple-byte: Record route (Type 7), Strict source route (Type 137),
    /// Loose source route (type 131), Timestamp (Type 68)
    pub options: [Option],
}

/// Option can max be 40-bytes, where type+size+data+padding = 1+1+(4*9)+2 = 40
struct Option {
    /// (8-bit) Type of option
    /// Option behavior:
    /// (1-bit) Set to 1 if the options need to be copied into all fragments of a fragmented packet.
    /// (2-bit) 0 is for control options, and 2 is for debugging and measurement. 1 and 3 are reserved
    /// (5-bit) Specifies an option
    pub r#type: u8,
    /// (8-bit) The size of the option including type, size, data
    pub size: u8,
    /// (36-bytes) Data
    pub data: [u8; 9],
}

impl IPv4<'_> {
    fn to_string_addr(addr: [u8; 4]) -> String {
        format!("{}.{}.{}.{}", addr[0], addr[1], addr[2], addr[3])
    }
}

impl ip_protocol::ToString for IPv4<'_> {
    fn src_addr(&self) -> String {
        IPv4::to_string_addr(self.src_addr)
    }

    fn dest_addr(&self) -> String {
        IPv4::to_string_addr(self.dest_addr)
    }
}

impl<'a> ip_protocol::Packet<'a> for IPv4<'a> {
    fn serialize(
        packet: &pcap::Packet,
        eth_frame: &'a ethernet_frame::EthernetFrame,
    ) -> Box<IPv4<'a>> {
        Box::new(IPv4 {
            eth_frame,
            src_addr: [packet[30], packet[31], packet[32], packet[33]],
            dest_addr: [packet[34], packet[35], packet[33], packet[34]],
            ihl,
        })
    }

    fn get_eth_frame(&self) -> &EthernetFrame {
        &self.eth_frame
    }
}
